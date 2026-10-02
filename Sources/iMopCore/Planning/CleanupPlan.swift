import CryptoKit
import Foundation

// Spec §3.1: the plan is immutable and built by read-only code. Nothing in this file touches the
// file system; it only describes what the Executor MAY do after the user confirms.

// MARK: - PlannedAction

/// What the Executor will do with one confirmed plan item.
public enum PlannedAction: Sendable, Hashable, Codable {
    /// Move into the Quarantine (spec §5.1), purged after `retentionHours`.
    case quarantine(retentionHours: Int)
    /// Move to the Finder Trash (spec §5.2).
    case trash
    /// Run the owning tool's cleanup command (spec §5.3). `argument` replaces `{ITEM}`.
    case command(CommandSpec, argument: String?)
    /// One-step permanent removal (only the rules described on `Action.permanentDelete`).
    case permanentDelete
    /// Explain only — never acted on.
    case advisory(AdvisoryKind)
    /// `leftovers.launchAgents` only (Milestone 6): `launchctl bootout gui/<uid> <plist>`, then the
    /// plist goes to the Finder Trash.
    case bootoutAndTrash

    /// Quarantine and Trash can be undone; commands, permanent removal and a bootout cannot.
    /// SAFETY-DECISION (M6): `bootoutAndTrash` is not restorable (see `Action.bootoutAndTrash`), so it
    /// needs the explicit irreversible-action acknowledgement as well as the Red per-item confirmation.
    public var isRestorable: Bool {
        switch self {
        case .quarantine, .trash: return true
        case .command, .permanentDelete, .advisory, .bootoutAndTrash: return false
        }
    }

    public var isAdvisory: Bool {
        if case .advisory = self { return true }
        return false
    }
}

// MARK: - PlanItem

/// One candidate in a `CleanupPlan`, with the plan-time SafetyGate verdict.
public struct PlanItem: Sendable, Hashable, Identifiable {
    public var id: UUID { target.id }
    public let target: ScanTarget
    public let rule: Rule
    /// The rule's tier, or `.red` when SafetyGate downgraded the item (sanity limit, spec §3.3 #13).
    public let effectiveTier: Tier
    public let action: PlannedAction
    /// Precondition results from the plan-time validation (empty when an earlier check rejected).
    public let preconditions: [PreconditionResult]
    public let planVerdict: SafetyVerdict

    init(target: ScanTarget, rule: Rule, effectiveTier: Tier, action: PlannedAction,
         preconditions: [PreconditionResult], planVerdict: SafetyVerdict) {
        self.target = target
        self.rule = rule
        self.effectiveTier = effectiveTier
        self.action = action
        self.preconditions = preconditions
        self.planVerdict = planVerdict
    }

    /// Test-only construction of arbitrary items (e.g. to prove the Executor re-validates).
    @_spi(FixtureTesting)
    public static func makeForTesting(target: ScanTarget, rule: Rule, effectiveTier: Tier, action: PlannedAction,
                                      preconditions: [PreconditionResult] = [], planVerdict: SafetyVerdict) -> PlanItem {
        PlanItem(target: target, rule: rule, effectiveTier: effectiveTier, action: action,
                 preconditions: preconditions, planVerdict: planVerdict)
    }

    /// Passed SafetyGate at plan time and is not advisory. A `.downgradedToRed` item is never
    /// actionable (it is shown for manual review only).
    public var isActionable: Bool { planVerdict.isAllowed && !action.isAdvisory }

    /// Spec §3.2: only Green items are preselected.
    // SAFETY-DECISION: a one-step permanent removal is never preselected, even for a Green rule; the
    // user must opt in to every irreversible deletion that has no undo at all.
    public var selectedByDefault: Bool {
        guard effectiveTier == .green, isActionable else { return false }
        if case .permanentDelete = action { return false }
        return true
    }

    /// Spec §3.2 / §9.5: Red items need a per-item confirmation dialog naming the item.
    public var requiresPerItemConfirmation: Bool { effectiveTier == .red }

    public var isRestorable: Bool { action.isRestorable }

    /// The user-facing skip reason, when the item is not actionable.
    public var skipReason: String? {
        if let rejection = planVerdict.rejection { return rejection.reason }
        if action.isAdvisory { return SafetyGate.advisoryRejection.reason }
        return nil
    }
}

// MARK: - CleanupPlan

/// Immutable result of `PlanBuilder` (spec §3.1). Contains every candidate — including blocked
/// ones — so the UI can show skip reasons.
public struct CleanupPlan: Sendable {
    public let id: UUID
    public let createdAt: Date
    public let items: [PlanItem]
    /// The "Always quarantine" setting the plan was built with (spec §9.9). `confirm` refuses a
    /// permanent deletion when either this or its own `alwaysQuarantine` argument is on.
    public let alwaysQuarantine: Bool

    init(id: UUID = UUID(), createdAt: Date, items: [PlanItem], alwaysQuarantine: Bool = true) {
        self.id = id
        self.createdAt = createdAt
        self.items = items
        self.alwaysQuarantine = alwaysQuarantine
    }

    /// Test-only construction of a plan from hand-made items.
    @_spi(FixtureTesting)
    public static func makeForTesting(id: UUID = UUID(), createdAt: Date, items: [PlanItem],
                                      alwaysQuarantine: Bool = true) -> CleanupPlan {
        CleanupPlan(id: id, createdAt: createdAt, items: items, alwaysQuarantine: alwaysQuarantine)
    }

    public var actionableItems: [PlanItem] { items.filter(\.isActionable) }
    public var blockedItems: [PlanItem] { items.filter { !$0.isActionable } }

    /// IDs preselected per tier (spec §3.2).
    public var defaultSelection: Set<UUID> { Set(items.filter(\.selectedByDefault).map(\.id)) }
}

// MARK: - Confirmation

/// What the review sheet (spec §9.4/§9.5) collected from the user.
public struct UserConfirmation: Sendable {
    public let reviewPresentedAt: Date
    public let confirmedAt: Date
    /// Red items the user confirmed one by one.
    public let perItemConfirmed: Set<UUID>
    /// The user acknowledged the explicit list of non-undoable actions.
    public let acknowledgedIrreversible: Bool

    public init(reviewPresentedAt: Date, confirmedAt: Date, perItemConfirmed: Set<UUID>, acknowledgedIrreversible: Bool) {
        self.reviewPresentedAt = reviewPresentedAt
        self.confirmedAt = confirmedAt
        self.perItemConfirmed = perItemConfirmed
        self.acknowledgedIrreversible = acknowledgedIrreversible
    }
}

public enum ConfirmationError: Error, Sendable, Equatable {
    case emptySelection
    case unknownItem(UUID)
    case notActionable(UUID)
    case missingPerItemConfirmation(UUID)
    case irreversibleNotAcknowledged
    case permanentDeleteBlockedByAlwaysQuarantine(UUID)
    case confirmedTooQuickly
}

// MARK: - ConfirmedPlan

/// The only input the Executor accepts (spec §3.1). Built exclusively from a `CleanupPlan` plus an
/// explicit user confirmation, and sealed with a SHA-256 hash of its contents that the Executor
/// verifies before acting.
public struct ConfirmedPlan: Sendable {
    public let planID: UUID
    /// The selected, actionable items, in plan order.
    public let items: [PlanItem]
    /// Lower-case hex SHA-256 of `ConfirmedPlan.canonicalBytes(planID:items:)`.
    public let contentHash: String
    public let confirmedAt: Date

    /// Spec §9.4: the Clean button is disabled for 2 seconds after the review sheet appears.
    public static let minimumReviewInterval: TimeInterval = 2

    private init(planID: UUID, items: [PlanItem], contentHash: String, confirmedAt: Date) {
        self.planID = planID
        self.items = items
        self.contentHash = contentHash
        self.confirmedAt = confirmedAt
    }

    /// Test-only: a plan with an arbitrary (possibly wrong) hash, to prove the Executor's hash check.
    @_spi(FixtureTesting)
    public static func makeForTesting(planID: UUID, items: [PlanItem], contentHash: String, confirmedAt: Date) -> ConfirmedPlan {
        ConfirmedPlan(planID: planID, items: items, contentHash: contentHash, confirmedAt: confirmedAt)
    }

    public static func confirm(plan: CleanupPlan, selectedItemIDs: Set<UUID>, confirmation: UserConfirmation,
                               alwaysQuarantine: Bool) throws -> ConfirmedPlan {
        guard !selectedItemIDs.isEmpty else { throw ConfirmationError.emptySelection }

        // SAFETY-DECISION: written as `!(elapsed >= 2)` so a NaN or negative interval (clock moved
        // backwards, confirmation dated before the sheet appeared) is also refused.
        let elapsed = confirmation.confirmedAt.timeIntervalSince(confirmation.reviewPresentedAt)
        guard elapsed >= minimumReviewInterval else { throw ConfirmationError.confirmedTooQuickly }

        var countByID: [UUID: Int] = [:]
        for item in plan.items { countByID[item.id, default: 0] += 1 }

        // Deterministic error order: unknown IDs sorted by their string form.
        for id in selectedItemIDs.sorted(by: { $0.uuidString < $1.uuidString }) where countByID[id] == nil {
            throw ConfirmationError.unknownItem(id)
        }

        var selected: [PlanItem] = []
        for item in plan.items where selectedItemIDs.contains(item.id) {
            // SAFETY-DECISION: an ID shared by several plan items is ambiguous; none of them is acted on.
            guard countByID[item.id] == 1, item.isActionable else { throw ConfirmationError.notActionable(item.id) }
            if item.requiresPerItemConfirmation, !confirmation.perItemConfirmed.contains(item.id) {
                throw ConfirmationError.missingPerItemConfirmation(item.id)
            }
            // SAFETY-DECISION: the setting recorded in the plan and the caller's value must BOTH be off;
            // the two can never disagree in the permissive direction.
            if case .permanentDelete = item.action, alwaysQuarantine || plan.alwaysQuarantine {
                throw ConfirmationError.permanentDeleteBlockedByAlwaysQuarantine(item.id)
            }
            if !item.isRestorable, !confirmation.acknowledgedIrreversible {
                throw ConfirmationError.irreversibleNotAcknowledged
            }
            selected.append(item)
        }
        // Unreachable (every selected ID is known and checked above); kept as a fail-closed guard.
        guard !selected.isEmpty else { throw ConfirmationError.emptySelection }

        return ConfirmedPlan(planID: plan.id, items: selected,
                             contentHash: hash(planID: plan.id, items: selected),
                             confirmedAt: confirmation.confirmedAt)
    }

    /// Recomputes the hash over the current contents and compares it with `contentHash`.
    public func verifyHash() -> Bool {
        let recomputed = Self.hash(planID: planID, items: items)
        // Constant-length comparison of two hex digests.
        let lhs = Array(recomputed.utf8), rhs = Array(contentHash.utf8)
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }

    // MARK: Hashing

    /// Version of the byte serialization below. Bump on any change to it.
    static let hashFormatVersion: UInt8 = 1

    /// Exposed to the fixture tests only, so they can forge a plan whose hash VERIFIES and prove the
    /// Executor's own last-moment checks (SafetyGate again, the command allow-list) still refuse it.
    @_spi(FixtureTesting)
    public static func hash(planID: UUID, items: [PlanItem]) -> String {
        let digest = SHA256.hash(data: canonicalBytes(planID: planID, items: items))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Canonical, deterministic serialization: fixed field order, big-endian integers, every
    /// string and list length-prefixed, every optional preceded by a presence byte.
    static func canonicalBytes(planID: UUID, items: [PlanItem]) -> Data {
        var w = PlanHashWriter()
        w.bytes(Array("iMop.ConfirmedPlan".utf8))
        w.u8(hashFormatVersion)
        w.uuid(planID)
        w.count(items.count)
        for item in items { w.item(item) }
        return Data(w.buffer)
    }
}

// MARK: - Serialization helper

private struct PlanHashWriter {
    var buffer: [UInt8] = []

    mutating func u8(_ value: UInt8) { buffer.append(value) }

    mutating func bool(_ value: Bool) { u8(value ? 1 : 0) }

    mutating func u64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { buffer.append(UInt8(truncatingIfNeeded: value >> UInt64(shift))) }
    }

    mutating func i64(_ value: Int64) { u64(UInt64(bitPattern: value)) }

    mutating func int(_ value: Int) { i64(Int64(value)) }

    mutating func count(_ value: Int) { u64(UInt64(max(0, value))) }

    mutating func bytes(_ value: [UInt8]) {
        count(value.count)
        buffer.append(contentsOf: value)
    }

    mutating func string(_ value: String) { bytes(Array(value.utf8)) }

    mutating func strings(_ values: [String]) {
        count(values.count)
        for value in values { string(value) }
    }

    mutating func optionalString(_ value: String?) {
        if let value { u8(1); string(value) } else { u8(0) }
    }

    mutating func optionalInt(_ value: Int?) {
        if let value { u8(1); int(value) } else { u8(0) }
    }

    mutating func optionalStrings(_ values: [String]?) {
        if let values { u8(1); strings(values) } else { u8(0) }
    }

    mutating func uuid(_ value: UUID) {
        let t = value.uuid
        buffer.append(contentsOf: [t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7,
                                   t.8, t.9, t.10, t.11, t.12, t.13, t.14, t.15])
    }

    mutating func date(_ value: Date?) {
        if let value { u8(1); u64(value.timeIntervalSinceReferenceDate.bitPattern) } else { u8(0) }
    }

    mutating func tier(_ value: Tier) { string(value.rawValue) }

    mutating func command(_ spec: CommandSpec) {
        string(spec.tool)
        strings(spec.arguments)
        optionalStrings(spec.dryRunArguments)
        optionalInt(spec.timeoutSeconds)
        bool(spec.idempotentSafe)
    }

    mutating func item(_ item: PlanItem) {
        let target = item.target
        // Target.
        uuid(target.id)
        string(target.ruleID)
        string(target.path)
        if let identity = target.identity {
            u8(1); i64(identity.device); u64(identity.inode)
        } else {
            u8(0)
        }
        switch target.kind {
        case .filesystem: u8(1)
        case .commandItem(let argument): u8(2); optionalString(argument)
        case .advisory: u8(3)
        }
        i64(target.allocatedBytes)
        i64(target.reclaimableBytes)
        // Inputs SafetyGate uses again at execute time (sanity limit, owner, age).
        int(target.itemCount)
        optionalString(target.owningBundleID)
        date(target.lastUsed)

        // Planned action and tier.
        action(item.action)
        tier(item.effectiveTier)

        // Rule: identity plus every field SafetyGate consults, so the rule an item is re-validated
        // against cannot differ from the one the user reviewed.
        rule(item.rule)
    }

    mutating func action(_ value: PlannedAction) {
        switch value {
        case .quarantine(let hours): u8(1); int(hours)
        case .trash: u8(2)
        case .command(let spec, let argument): u8(3); command(spec); optionalString(argument)
        case .permanentDelete: u8(4)
        case .advisory(let kind): u8(5); string(kind.rawValue)
        case .bootoutAndTrash: u8(6)
        }
    }

    mutating func rule(_ rule: Rule) {
        string(rule.id)
        int(rule.version)
        tier(rule.tier)
        string(rule.category.rawValue)
        switch rule.discovery {
        case .glob(let patterns): u8(1); strings(patterns)
        case .command(let spec): u8(2); command(spec)
        case .inspector(let id): u8(3); string(id.rawValue)
        }
        strings(rule.allowRoots)
        int(rule.minDepthBelowRoot)
        count(rule.preconditions.count)
        for precondition in rule.preconditions { self.precondition(precondition) }
        switch rule.action {
        case .quarantine: u8(1)
        case .trash: u8(2)
        case .command(let spec): u8(3); command(spec)
        case .advisory(let kind): u8(4); string(kind.rawValue)
        case .permanentDelete: u8(5)
        case .bootoutAndTrash: u8(6)
        }
        optionalInt(rule.retentionHours)
        i64(rule.effectiveMaxExpectedBytes)
        int(rule.effectiveMaxExpectedItems)
        bool(rule.allowSymlinkTarget)
        strings(rule.excludedNames)
        bool(rule.requiresFullDiskAccess)
        string(rule.ownerInference.rawValue)
    }

    mutating func precondition(_ value: Precondition) {
        string(value.name)
        switch value {
        case .appNotRunning(let ids): u8(1); strings(ids)
        case .processNotRunning(let names): u8(1); strings(names)
        case .manifestPresent(let names): u8(1); strings(names)
        case .olderThan(let days), .projectOlderThan(let days): u8(2); int(days)
        case .owningAppNotRunning, .notOpenByAnyProcess, .notInsideCloudRoot, .ownedByUser, .simulatorIdle,
             .dockerDaemonReachable, .notMounted, .appleSigned, .notSelectedXcode, .uploadedToCloud,
             .notTrackedByGit, .stillOrphaned:
            u8(0)
        }
    }
}
