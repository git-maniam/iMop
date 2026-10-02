import Darwin
import Foundation

// MARK: - Outcomes

/// Per-item result of an execution run (spec §5.4, §11).
public enum ItemStatus: Sendable, Hashable {
    case quarantined(entryID: UUID)
    case trashed(resultPath: String)
    case commandSucceeded(exitCode: Int32)
    case permanentlyRemoved
    case skipped(SafetyRejection)
    case failed(ErrorCategory, message: String)

    /// `true` when the item was acted on and the action was verified.
    public var succeeded: Bool {
        switch self {
        case .quarantined, .trashed, .commandSucceeded, .permanentlyRemoved: return true
        case .skipped, .failed: return false
        }
    }
}

public struct ItemOutcome: Sendable, Hashable, Identifiable {
    /// The plan item id (== target id).
    public let id: UUID
    public let ruleID: String
    public let path: String
    public let estimatedBytes: Int64
    public let status: ItemStatus

    public init(id: UUID, ruleID: String, path: String, estimatedBytes: Int64, status: ItemStatus) {
        self.id = id
        self.ruleID = ruleID
        self.path = path
        self.estimatedBytes = estimatedBytes
        self.status = status
    }
}

public struct ExecutionReport: Sendable {
    /// Identifier of this run (used as `sessionID` in every audit event of the run).
    public let sessionID: UUID
    /// The Quarantine session the run's quarantined items went into (begun lazily; `nil` if none).
    public let quarantineSessionID: UUID?
    public let outcomes: [ItemOutcome]
    /// Sum of `reclaimableBytes` over items whose action succeeded.
    public let estimatedReclaimBytes: Int64
    /// Sum of `reclaimableBytes` over items now in Quarantine (not freed until the Quarantine is emptied).
    public let quarantinedBytes: Int64
    public let measuredFreeBefore: Int64?
    public let measuredFreeAfter: Int64?
    public let measuredDelta: Int64?
    /// Spec §7.3 honest reasons when the measured reclaim is lower than estimated.
    public let explanations: [String]
    public let cancelled: Bool
    public let mutationDisabled: Bool

    public init(sessionID: UUID, quarantineSessionID: UUID?, outcomes: [ItemOutcome], estimatedReclaimBytes: Int64,
                quarantinedBytes: Int64, measuredFreeBefore: Int64?, measuredFreeAfter: Int64?, measuredDelta: Int64?,
                explanations: [String], cancelled: Bool, mutationDisabled: Bool) {
        self.sessionID = sessionID
        self.quarantineSessionID = quarantineSessionID
        self.outcomes = outcomes
        self.estimatedReclaimBytes = estimatedReclaimBytes
        self.quarantinedBytes = quarantinedBytes
        self.measuredFreeBefore = measuredFreeBefore
        self.measuredFreeAfter = measuredFreeAfter
        self.measuredDelta = measuredDelta
        self.explanations = explanations
        self.cancelled = cancelled
        self.mutationDisabled = mutationDisabled
    }
}

public enum ExecutionEvent: Sendable {
    case started(sessionID: UUID, total: Int)
    case itemStarted(UUID)
    case itemFinished(ItemOutcome)
    case finished(ExecutionReport)
}

// MARK: - Executor

/// Spec §3.1 / §5.4: the last step of the pipeline and the ONLY component that acts on plan items.
///
/// The only public entry point is `execute(_:)`, which accepts a `ConfirmedPlan` (built from a
/// `CleanupPlan` plus explicit user confirmation). There is NO `delete(path:)` API.
public actor Executor {
    public static let mutationDisabledMessage = MutationPolicy.disabledMessage
    public static let anotherRunMessage = "another cleanup is running"
    /// Reason given when a `ConfirmedPlan` is executed a second time.
    public static let alreadyExecutedDetail = "this confirmed plan was already executed; review and confirm a new plan"

    /// Plans (by `planID`) whose execution has started in this process. Shared by every Executor so a
    /// confirmed plan is single-use even across Executor instances.
    private static let executedPlans = ExecutedPlanRegistry()

    private let environment: SafeCleanEnvironment
    private let gate: SafetyGate
    private let quarantine: Quarantine
    private let auditLog: AuditLog
    private let trash: any TrashMoving
    private let remover: any PermanentRemoving
    private let mutationPolicy: MutationPolicy

    /// Token of the run in progress (`nil` when idle). Only one run at a time.
    private var currentRun: UUID?
    private var cancelRequested = false

    public init(environment: SafeCleanEnvironment, gate: SafetyGate, quarantine: Quarantine, auditLog: AuditLog,
                trash: any TrashMoving = FinderTrash(), remover: any PermanentRemoving = RemovefileRemover()) {
        self.init(environment: environment, gate: gate, quarantine: quarantine, auditLog: auditLog,
                  trash: trash, remover: remover, mutationPolicy: .compiledIn)
    }

    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, gate: SafetyGate, quarantine: Quarantine, auditLog: AuditLog,
                trash: any TrashMoving, remover: any PermanentRemoving, mutationPolicy: MutationPolicy) {
        self.environment = environment
        self.gate = gate
        self.quarantine = quarantine
        self.auditLog = auditLog
        self.trash = trash
        self.remover = remover
        self.mutationPolicy = mutationPolicy
    }

    /// Runs the confirmed plan. Events end with exactly one `.finished`, after which the stream finishes.
    public func execute(_ plan: ConfirmedPlan) -> AsyncStream<ExecutionEvent> {
        let (stream, continuation) = AsyncStream<ExecutionEvent>.makeStream(bufferingPolicy: .unbounded)
        let runID = UUID()

        guard currentRun == nil else {
            // Single executor at a time: refuse the whole plan without touching anything.
            let outcomes = plan.items.map {
                ItemOutcome(id: $0.id, ruleID: $0.rule.id, path: $0.target.path,
                            estimatedBytes: $0.target.reclaimableBytes,
                            status: .failed(.inUse, message: Self.anotherRunMessage))
            }
            let report = ExecutionReport(sessionID: runID, quarantineSessionID: nil, outcomes: outcomes,
                                         estimatedReclaimBytes: 0, quarantinedBytes: 0, measuredFreeBefore: nil,
                                         measuredFreeAfter: nil, measuredDelta: nil, explanations: [],
                                         cancelled: false, mutationDisabled: !mutationPolicy.isEnabled)
            let log = auditLog
            let now = environment.clock.now
            Task {
                await log.record(AuditEvent(timestamp: now, sessionID: runID, action: "run.refused",
                                            verdict: "failed", rejectionReason: Self.anotherRunMessage))
            }
            continuation.yield(.finished(report))
            continuation.finish()
            return stream
        }

        // SAFETY-DECISION: one user confirmation allows ONE execution. Restore keeps (dev, ino), so a
        // replayed plan would pass identity pinning and act again on items the user just restored (and
        // re-run irreversible commands). A plan whose hash does not verify is never acted on anyway
        // and is reported as such below, so only verifiable plans are claimed.
        if plan.verifyHash(), !Self.executedPlans.claim(plan.planID) {
            let rejection = SafetyRejection.doesNotMatchRule(detail: Self.alreadyExecutedDetail)
            let outcomes = plan.items.map {
                ItemOutcome(id: $0.id, ruleID: $0.rule.id, path: $0.target.path,
                            estimatedBytes: $0.target.reclaimableBytes, status: .skipped(rejection))
            }
            let report = ExecutionReport(sessionID: runID, quarantineSessionID: nil, outcomes: outcomes,
                                         estimatedReclaimBytes: 0, quarantinedBytes: 0, measuredFreeBefore: nil,
                                         measuredFreeAfter: nil, measuredDelta: nil, explanations: [],
                                         cancelled: false, mutationDisabled: !mutationPolicy.isEnabled)
            let log = auditLog
            let now = environment.clock.now
            let planID = plan.planID
            Task {
                await log.record(AuditEvent(timestamp: now, sessionID: runID, action: "run.refused", verdict: "skipped",
                                            rejectionReason: rejection.reason, detail: "plan \(planID.uuidString)"))
            }
            continuation.yield(.finished(report))
            continuation.finish()
            return stream
        }

        currentRun = runID
        cancelRequested = false
        continuation.onTermination = { [weak self] termination in
            // SAFETY-DECISION: if the consumer goes away mid-run, stop at the next item boundary rather
            // than keep acting with nobody watching. Never interrupts an item in progress.
            guard case .cancelled = termination, let self else { return }
            Task { await self.cancelRun(runID) }
        }
        Task {
            await self.run(plan, runID: runID, continuation: continuation)
        }
        return stream
    }

    /// Requests cancellation. Honoured BETWEEN items, never mid-item.
    public func cancel() {
        if currentRun != nil { cancelRequested = true }
    }

    private func cancelRun(_ runID: UUID) {
        if currentRun == runID { cancelRequested = true }
    }

    // MARK: - Run

    private func run(_ plan: ConfirmedPlan, runID: UUID, continuation: AsyncStream<ExecutionEvent>.Continuation) async {
        continuation.yield(.started(sessionID: runID, total: plan.items.count))
        await audit(runID, action: "run.started", verdict: "started",
                    detail: "plan \(plan.planID.uuidString), \(plan.items.count) item(s), hash \(plan.contentHash)")
        if !mutationPolicy.isEnabled {
            await audit(runID, action: "run.mutationPolicy", verdict: "mutationDisabled",
                        rejectionReason: Self.mutationDisabledMessage)
        }

        // SAFETY-DECISION: a plan whose contents no longer match the hash computed at confirmation is
        // not what the user approved. Every item is skipped as "changed since scan"; nothing is acted on.
        let hashValid = plan.verifyHash()
        if !hashValid {
            await audit(runID, action: "plan.verifyHash", verdict: "rejected",
                        rejectionReason: "plan hash mismatch", detail: plan.contentHash)
        }

        let homePath = environment.homePath
        let freeBefore = environment.volumes.availableCapacityForImportantUsage(at: homePath)

        var state = RunState()
        var outcomes: [ItemOutcome] = []
        var seen = Set<UUID>()
        var cancelled = false

        for item in plan.items {
            if cancelRequested {
                cancelled = true
                break
            }
            continuation.yield(.itemStarted(item.id))
            let status: ItemStatus
            if !hashValid {
                status = .skipped(.changedSinceScan)
                await audit(runID, item: item, action: "item.skip", verdict: "skipped",
                            rejectionReason: "plan hash mismatch")
            } else if !seen.insert(item.id).inserted {
                let rejection = SafetyRejection.doesNotMatchRule(detail: "duplicate plan item")
                status = .skipped(rejection)
                await audit(runID, item: item, action: "item.skip", verdict: "skipped", rejectionReason: rejection.reason)
            } else {
                status = await process(item, runID: runID, state: &state)
            }
            let outcome = ItemOutcome(id: item.id, ruleID: item.rule.id, path: item.target.path,
                                      estimatedBytes: item.target.reclaimableBytes, status: status)
            outcomes.append(outcome)
            continuation.yield(.itemFinished(outcome))
        }

        let notProcessed = plan.items.count - outcomes.count
        if cancelled {
            await audit(runID, action: "run.cancelled", verdict: "cancelled",
                        detail: "\(notProcessed) item(s) not processed")
        }

        let freeAfter = environment.volumes.availableCapacityForImportantUsage(at: homePath)
        let delta: Int64? = {
            guard let before = freeBefore, let after = freeAfter else { return nil }
            return after - before
        }()

        let succeeded = outcomes.filter { $0.status.succeeded }
        let estimated = succeeded.reduce(Int64(0)) { $0 + max(0, $1.estimatedBytes) }
        let quarantinedBytes = outcomes.reduce(Int64(0)) { total, outcome in
            if case .quarantined = outcome.status { return total + max(0, outcome.estimatedBytes) }
            return total
        }
        let trashedBytes = outcomes.reduce(Int64(0)) { total, outcome in
            if case .trashed = outcome.status { return total + max(0, outcome.estimatedBytes) }
            return total
        }
        var explanations = Self.explanations(estimated: estimated, delta: delta,
                                             quarantinedBytes: quarantinedBytes, trashedBytes: trashedBytes)
        if cancelled {
            explanations.append("Cleanup was cancelled; \(notProcessed) item(s) were not processed.")
        }
        let disabled = !mutationPolicy.isEnabled || outcomes.contains {
            if case .failed(.mutationDisabled, _) = $0.status { return true }
            return false
        }

        let report = ExecutionReport(sessionID: runID, quarantineSessionID: state.quarantineSessionID,
                                     outcomes: outcomes, estimatedReclaimBytes: estimated,
                                     quarantinedBytes: quarantinedBytes, measuredFreeBefore: freeBefore,
                                     measuredFreeAfter: freeAfter, measuredDelta: delta,
                                     explanations: explanations, cancelled: cancelled, mutationDisabled: disabled)
        await audit(runID, action: "run.finished", bytes: estimated, verdict: "finished",
                    detail: "succeeded \(succeeded.count)/\(plan.items.count); measured delta \(delta.map(String.init) ?? "unavailable")")

        if let quarantineSession = state.quarantineSessionID {
            // The run no longer adds items to its session: it may now be cleaned up once finished.
            await quarantine.endSession(quarantineSession)
        }
        currentRun = nil
        cancelRequested = false
        continuation.yield(.finished(report))
        continuation.finish()
    }

    private struct RunState {
        var quarantineSessionID: UUID?
    }

    // MARK: - One item

    private func process(_ item: PlanItem, runID: UUID, state: inout RunState) async -> ItemStatus {
        let target = item.target
        let rule = item.rule

        // Defence in depth: ConfirmedPlan only carries actionable items, but re-check anyway.
        if let rejection = consistencyRejection(item) {
            await audit(runID, item: item, action: "item.skip", verdict: "skipped", rejectionReason: rejection.reason)
            return .skipped(rejection)
        }

        // Spec §3.3: SafetyGate AGAIN, immediately before acting (TOCTOU defence).
        let verdict = await gate.validate(target: target, rule: rule, phase: .execute)
        switch verdict {
        case .allowed:
            await audit(runID, item: item, action: "item.validate", verdict: "allowed")
        case .rejected(let rejection), .downgradedToRed(let rejection):
            // SAFETY-DECISION: a sanity downgrade at execute time is never acted on either.
            let label: String = { if case .rejected = verdict { return "rejected" } else { return "downgradedToRed" } }()
            await audit(runID, item: item, action: "item.validate", verdict: label, rejectionReason: rejection.reason)
            return .skipped(rejection)
        }

        // Compile-time / fixture mutation policy.
        // SAFETY-DECISION: a command item's path is informational (it may be a UDID or a model name,
        // not a path). For such an item the policy is asked about the home directory the command acts
        // for, so a disabled policy still refuses and a fixture policy still requires a fixture home;
        // a command item whose path does look like a path is checked against that path as usual.
        let policyPath: String
        if case .commandItem = target.kind, !SafetyGate.looksLikePath(target.path) {
            policyPath = environment.homePath
        } else {
            policyPath = target.path
        }
        guard mutationPolicy.permits(path: policyPath, environment: environment) else {
            await audit(runID, item: item, action: "item.\(Self.actionName(item.action))", verdict: "mutationDisabled",
                        rejectionReason: Self.mutationDisabledMessage)
            return .failed(.mutationDisabled, message: Self.mutationDisabledMessage)
        }

        switch item.action {
        case .advisory:
            let rejection = SafetyRejection.doesNotMatchRule(detail: "advisory items are never acted on")
            await audit(runID, item: item, action: "item.skip", verdict: "skipped", rejectionReason: rejection.reason)
            return .skipped(rejection)

        case .command(let spec, let argument):
            return await runCommand(spec, argument: argument, item: item, runID: runID)

        case .quarantine, .trash, .permanentDelete:
            if let rejection = lastMomentIdentityRejection(item) {
                await audit(runID, item: item, action: "item.recheck", verdict: "rejected", rejectionReason: rejection.reason)
                return .skipped(rejection)
            }
            return await actOnFilesystem(item, runID: runID, state: &state)
        }
    }

    private func actOnFilesystem(_ item: PlanItem, runID: UUID, state: inout RunState) async -> ItemStatus {
        let target = item.target
        let actionName = "item.\(Self.actionName(item.action))"
        let status: ItemStatus

        switch item.action {
        case .quarantine(let retentionHours):
            do {
                let sessionID: UUID
                if let existing = state.quarantineSessionID {
                    sessionID = existing
                } else {
                    sessionID = try await quarantine.beginSession()
                    state.quarantineSessionID = sessionID
                    await audit(runID, action: "quarantine.beginSession", verdict: "succeeded",
                                detail: "quarantine session \(sessionID.uuidString)")
                }
                // The confirmed (hashed) retention is passed on and must equal the rule's.
                let entry = try await quarantine.quarantine(target: target, rule: item.rule, tier: item.effectiveTier,
                                                            sessionID: sessionID, retentionHours: retentionHours)
                await audit(runID, item: item, action: actionName, verdict: "succeeded",
                            detail: "quarantine session \(sessionID.uuidString), entry \(entry.id.uuidString), \(entry.quarantinedName)")
                status = .quarantined(entryID: entry.id)
            } catch let error as QuarantineError {
                let mapped = Self.status(for: error)
                await auditFailure(runID, item: item, action: actionName, status: mapped)
                return mapped
            } catch {
                let (category, message) = Self.category(for: error)
                await auditFailure(runID, item: item, action: actionName, status: .failed(category, message: message))
                return .failed(category, message: message)
            }

        case .trash:
            guard let pinned = target.identity else { return .skipped(.missingIdentity) }
            do {
                let result = try trash.moveToTrash(path: target.path, expectedIdentity: pinned)
                // SAFETY-DECISION: the object now in the Trash must be the pinned item; otherwise the
                // item is reported as failed (whatever was trashed stays in the Trash, restorable).
                guard let trashed = environment.fileSystem.lstat(result), trashed.identity == pinned else {
                    let message = "The item moved to the Trash (\(result)) is not the reviewed item; it was left in the Trash"
                    await audit(runID, item: item, action: "item.verify", verdict: "failed", rejectionReason: message)
                    return .failed(.safetyRejected("could not verify the trashed item"), message: message)
                }
                await audit(runID, item: item, action: actionName, verdict: "succeeded", detail: "moved to \(result)")
                status = .trashed(resultPath: result)
            } catch {
                let (category, message) = Self.category(for: error)
                await auditFailure(runID, item: item, action: actionName, status: .failed(category, message: message))
                return .failed(category, message: message)
            }

        case .permanentDelete:
            guard let pinned = target.identity else { return .skipped(.missingIdentity) }
            do {
                try remover.removePermanently(path: target.path, expectedIdentity: pinned)
                await audit(runID, item: item, action: actionName, verdict: "succeeded")
                status = .permanentlyRemoved
            } catch {
                let (category, message) = Self.category(for: error)
                await auditFailure(runID, item: item, action: actionName, status: .failed(category, message: message))
                return .failed(category, message: message)
            }

        case .command, .advisory:
            // Unreachable: routed elsewhere by `process`.
            let rejection = SafetyRejection.doesNotMatchRule(detail: "not a file-system action")
            return .skipped(rejection)
        }

        // Verify outcome: the original path must no longer exist (lstat, no symlink following).
        if environment.fileSystem.lstat(target.path) != nil {
            let message = "Item is still present at its original location after \(Self.actionName(item.action))"
            await audit(runID, item: item, action: "item.verify", verdict: "failed", rejectionReason: message)
            return .failed(.safetyRejected("could not verify removal"), message: message)
        }
        await audit(runID, item: item, action: "item.verify", verdict: "succeeded")
        return status
    }

    private func runCommand(_ spec: CommandSpec, argument: String?, item: PlanItem, runID: UUID) async -> ItemStatus {
        let actionName = "item.command"
        // SAFETY-DECISION: a per-item command without an argument would pass the literal "{ITEM}" token
        // (or act on everything); an argument that is empty, starts with "-" (option injection) or
        // contains control characters is refused.
        if spec.isPerItem {
            guard let argument, Self.isSafeCommandArgument(argument) else {
                let rejection = SafetyRejection.doesNotMatchRule(detail: "missing or unsafe command argument")
                await audit(runID, item: item, action: actionName, verdict: "skipped", rejectionReason: rejection.reason)
                return .skipped(rejection)
            }
        } else if argument != nil {
            // SAFETY-DECISION (M4): a whole-rule command never takes a per-item argument.
            let rejection = SafetyRejection.doesNotMatchRule(detail: "this command takes no per-item argument")
            await audit(runID, item: item, action: actionName, verdict: "skipped", rejectionReason: rejection.reason)
            return .skipped(rejection)
        }
        let arguments = spec.resolvedArguments(item: spec.isPerItem ? argument : nil)
        // SAFETY-DECISION (M4): before anything is resolved or started, the exact invocation must be an
        // action entry of the Swift-coded `CommandAllowList` that this rule and tier may use, with the
        // `{ITEM}` value accepted by that entry's validator (the live `CommandRunner` checks the same
        // table again). A tampered or invalid item is refused here and never reaches a runner.
        guard let entry = CommandAllowList.standard.entry(tool: spec.tool, arguments: arguments, purpose: .action),
              entry.permits(ruleID: item.rule.id, tier: item.rule.tier) else {
            let rejection = SafetyRejection.doesNotMatchRule(detail: "command is not on the reviewed allow-list for this rule")
            await audit(runID, item: item, action: actionName, verdict: "skipped", rejectionReason: rejection.reason)
            return .skipped(rejection)
        }
        guard let executable = environment.commands.resolveExecutable(spec.tool) else {
            let message = "\(spec.tool) was not found in a trusted location"
            await audit(runID, item: item, action: actionName, verdict: "failed", rejectionReason: message)
            return .failed(.safetyRejected("untrusted or missing executable"), message: message)
        }
        // A rule may shorten a command's reviewed timeout, never extend it.
        let timeout = min(spec.timeout, TimeInterval(entry.maximumTimeoutSeconds))
        // Only the Executor ever asks for `.action`; the live runner re-checks the allow-list.
        let result = await environment.commands.run(executable: executable, arguments: arguments,
                                                    timeout: timeout, purpose: .action)
        let half = AuditEvent.maxDetailBytes / 2 - 64
        let detail = "\(executable) \(arguments.joined(separator: " "))\nstdout:\n"
            + AuditEvent.truncated(result.stdout, limit: half)
            + "\nstderr:\n" + AuditEvent.truncated(result.stderr, limit: half)

        if result.timedOut {
            await audit(runID, item: item, action: actionName, verdict: "failed", rejectionReason: "timeout",
                        commandExitCode: result.exitCode, detail: detail)
            return .failed(.timeout, message: "\(spec.tool) did not finish within \(Int(timeout)) s")
        }
        guard result.exitCode == 0 else {
            await audit(runID, item: item, action: actionName, verdict: "failed",
                        rejectionReason: "exit code \(result.exitCode)", commandExitCode: result.exitCode, detail: detail)
            let stderr = AuditEvent.truncated(result.stderr, limit: 1024)
            return .failed(.commandFailed(result.exitCode),
                           message: stderr.isEmpty ? "\(spec.tool) exited with code \(result.exitCode)" : stderr)
        }
        await audit(runID, item: item, action: actionName, verdict: "succeeded",
                    commandExitCode: result.exitCode, detail: detail)
        return .commandSucceeded(exitCode: result.exitCode)
    }

    // MARK: - Checks

    /// The planned action must match the item's rule and target kind, and the item must be actionable.
    private func consistencyRejection(_ item: PlanItem) -> SafetyRejection? {
        let target = item.target
        let rule = item.rule
        guard target.ruleID == rule.id else { return .doesNotMatchRule(detail: "target belongs to another rule") }
        guard item.planVerdict.isAllowed else {
            return item.planVerdict.rejection ?? .doesNotMatchRule(detail: "not allowed at plan time")
        }
        guard item.isActionable else { return .doesNotMatchRule(detail: "item is not actionable") }
        // SAFETY-DECISION: the effective tier may only be stricter than the rule's tier (a lower tier would
        // skip confirmation steps the rule requires, e.g. Red per-item confirmation).
        guard item.effectiveTier >= rule.tier else { return .doesNotMatchRule(detail: "tier lower than rule tier") }

        // SAFETY-DECISION: the planned action may never be more destructive than the rule's action.
        // Quarantine is accepted for quarantine and permanent-delete rules (restorable is safer);
        // trash, permanent delete and commands must match the rule exactly.
        switch item.action {
        case .quarantine:
            guard target.kind == .filesystem else { return .doesNotMatchRule(detail: "not a file-system item") }
            switch rule.action {
            case .quarantine, .permanentDelete: return nil
            default: return .doesNotMatchRule(detail: "planned action does not match rule")
            }
        case .trash:
            guard target.kind == .filesystem else { return .doesNotMatchRule(detail: "not a file-system item") }
            guard rule.action == .trash else { return .doesNotMatchRule(detail: "planned action does not match rule") }
            return nil
        case .permanentDelete:
            guard target.kind == .filesystem else { return .doesNotMatchRule(detail: "not a file-system item") }
            guard rule.action == .permanentDelete else { return .doesNotMatchRule(detail: "planned action does not match rule") }
            // SAFETY-DECISION: RuleCatalog only loads `.permanentDelete` for its allow-listed rules; a
            // hand-built rule that skipped the catalog is refused here too (defence in depth).
            guard RuleCatalog.permanentDeleteAllowList.contains(rule.id) else {
                return .doesNotMatchRule(detail: "permanent delete is not allowed for this rule")
            }
            return nil
        case .command(let spec, let argument):
            guard rule.action == .command(spec) else { return .doesNotMatchRule(detail: "planned command does not match rule") }
            guard target.kind == .commandItem(argument: argument) else {
                return .doesNotMatchRule(detail: "command argument does not match target")
            }
            return nil
        case .advisory:
            return .doesNotMatchRule(detail: "advisory items are never acted on")
        }
    }

    /// Last look right before a file-system action: the item must still exist with the pinned identity.
    private func lastMomentIdentityRejection(_ item: PlanItem) -> SafetyRejection? {
        guard let pinned = item.target.identity else { return .missingIdentity }
        guard let current = environment.fileSystem.lstat(item.target.path) else { return .itemMissing }
        if current.isSymlink && !item.rule.allowSymlinkTarget { return .symlinkInPath(component: item.target.path) }
        guard current.identity == pinned else { return .changedSinceScan }
        return nil
    }

    static func isSafeCommandArgument(_ argument: String) -> Bool {
        guard !argument.isEmpty, !argument.hasPrefix("-") else { return false }
        return !argument.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }

    // MARK: - Error mapping

    static func status(for error: QuarantineError) -> ItemStatus {
        switch error {
        case .mutationDisabled:
            return .failed(.mutationDisabled, message: mutationDisabledMessage)
        case .crossVolume:
            return .failed(.crossVolume, message: "Item is on a different volume than the Quarantine (never copied)")
        case .sourceMissing:
            return .failed(.changedSinceScan, message: "Item no longer exists")
        case .destinationExists:
            return .failed(.safetyRejected("quarantine destination exists"), message: "Quarantine destination already exists")
        case .originalParentMissing:
            return .failed(.changedSinceScan, message: "Original folder is missing")
        case .manifestCorrupt:
            return .failed(.safetyRejected("quarantine manifest unreadable"), message: "Quarantine manifest could not be read")
        case .safetyRejected(let rejection):
            return .skipped(rejection)
        case .io(let message):
            let lowered = message.lowercased()
            if lowered.contains("permission denied") || lowered.contains("operation not permitted") {
                return .failed(.permissionDenied, message: message)
            }
            if lowered.contains("cross-device") { return .failed(.crossVolume, message: message) }
            if lowered.contains("busy") { return .failed(.inUse, message: message) }
            return .failed(.safetyRejected("I/O error"), message: message)
        }
    }

    /// Maps POSIX / Cocoa errors to spec §11 categories.
    static func category(for error: any Error) -> (ErrorCategory, String) {
        if let action = error as? FileActionError {
            switch action {
            case .mutationDisabled: return (.mutationDisabled, mutationDisabledMessage)
            case .changedSinceScan: return (.changedSinceScan, SafetyRejection.changedSinceScan.reason)
            case .identityRequired: return (.safetyRejected("identity required"), "The item's identity is required")
            case .unverifiedResult(let path):
                return (.safetyRejected("could not verify the result"), "The item at \(path) is not the reviewed item")
            case .invalidPath(let path): return (.safetyRejected("invalid path"), "Refusing to act on \(path)")
            case .refusedInTestRun: return (.safetyRejected("refused in test run"), "The real Trash is never used in tests")
            case .missingResultingLocation: return (.safetyRejected("no resulting location"), "The Trash did not report where the item went")
            }
        }
        if let posix = error as? POSIXError { return category(errno: posix.code.rawValue, message: error.localizedDescription) }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain { return category(errno: Int32(nsError.code), message: nsError.localizedDescription) }
        if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError, underlying.domain == NSPOSIXErrorDomain {
            return category(errno: Int32(underlying.code), message: nsError.localizedDescription)
        }
        if nsError.domain == NSCocoaErrorDomain {
            switch nsError.code {
            case NSFileReadNoPermissionError, NSFileWriteNoPermissionError, NSFileWriteVolumeReadOnlyError:
                return (.permissionDenied, nsError.localizedDescription)
            case NSFileNoSuchFileError, NSFileReadNoSuchFileError:
                return (.changedSinceScan, nsError.localizedDescription)
            default: break
            }
        }
        return (.safetyRejected("unexpected error"), nsError.localizedDescription)
    }

    static func category(errno code: Int32, message: String) -> (ErrorCategory, String) {
        switch code {
        case EACCES, EPERM, EROFS: return (.permissionDenied, message)
        case EXDEV: return (.crossVolume, message)
        case EBUSY, ETXTBSY: return (.inUse, message)
        case ENOENT: return (.changedSinceScan, message)
        case ETIMEDOUT: return (.timeout, message)
        default: return (.safetyRejected(String(cString: strerror(code))), message)
        }
    }

    static func actionName(_ action: PlannedAction) -> String {
        switch action {
        case .quarantine: return "quarantine"
        case .trash: return "trash"
        case .command: return "command"
        case .permanentDelete: return "permanentDelete"
        case .advisory: return "advisory"
        }
    }

    // MARK: - Reporting

    /// Spec §7.3: honest reasons when measured free space grew less than estimated.
    static func explanations(estimated: Int64, delta: Int64?, quarantinedBytes: Int64, trashedBytes: Int64) -> [String] {
        guard estimated > 0 else { return [] }
        guard let delta else {
            return ["Free space could not be measured before and after cleanup, so only the estimate is shown."]
        }
        guard delta < estimated else { return [] }
        var result: [String] = []
        if quarantinedBytes > 0 {
            result.append("\(format(quarantinedBytes)) is still in Quarantine. " + Quarantine.spaceNotice)
        }
        if trashedBytes > 0 {
            result.append("\(format(trashedBytes)) was moved to the Trash and still uses space until the Trash is emptied.")
        }
        result.append("Time Machine local snapshots may still hold the removed data; macOS frees that space when the snapshots expire.")
        result.append("APFS clones share storage with other files, so removing one copy can free less than its size.")
        result.append("macOS accounts for purgeable space separately, so reported free space can differ from what was removed.")
        return result
    }

    private static func format(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    // MARK: - Audit helpers

    private func audit(_ runID: UUID, item: PlanItem? = nil, action: String, bytes: Int64? = nil, verdict: String,
                       rejectionReason: String? = nil, commandExitCode: Int32? = nil, detail: String? = nil) async {
        let event = AuditEvent(timestamp: environment.clock.now, sessionID: runID, ruleID: item?.rule.id,
                               path: item?.target.path, action: action,
                               bytes: bytes ?? item?.target.reclaimableBytes, verdict: verdict,
                               rejectionReason: rejectionReason, commandExitCode: commandExitCode, detail: detail)
        await auditLog.record(event)
    }

    private func auditFailure(_ runID: UUID, item: PlanItem, action: String, status: ItemStatus) async {
        switch status {
        case .skipped(let rejection):
            await audit(runID, item: item, action: action, verdict: "skipped", rejectionReason: rejection.reason)
        case .failed(let category, let message):
            let verdict = category == .mutationDisabled ? "mutationDisabled" : "failed"
            await audit(runID, item: item, action: action, verdict: verdict, rejectionReason: message,
                        detail: String(describing: category))
        default:
            break
        }
    }
}

/// Process-wide record of the confirmed plans whose execution started (single-use plans).
final class ExecutedPlanRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var planIDs: Set<UUID> = []

    /// `true` the first time `planID` is claimed, `false` afterwards.
    func claim(_ planID: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return planIDs.insert(planID).inserted
    }
}
