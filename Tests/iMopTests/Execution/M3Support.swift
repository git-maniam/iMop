import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Shared helpers for the Milestone 3 suites (plan, quarantine, executor, audit log).
///
/// Every mutation in these suites happens strictly inside the per-test `FixtureBuilder` root, through
/// `MutationPolicy.fixtureOnly(root:)`. Nothing touches the real Trash or the real ~/Library.
@MainActor
enum M3 {
    /// A fixed review start; confirmations are dated 3 s later (spec §9.4: Clean is disabled for 2 s).
    static let reviewStart = Date(timeIntervalSince1970: 1_790_000_000)

    static func confirmation(perItem: Set<UUID> = [], irreversible: Bool = false, after seconds: TimeInterval = 3) -> UserConfirmation {
        UserConfirmation(reviewPresentedAt: reviewStart, confirmedAt: reviewStart.addingTimeInterval(seconds),
                         perItemConfirmed: perItem, acknowledgedIrreversible: irreversible)
    }

    enum Policy { case fixture, compiledIn }

    /// Everything one Milestone 3 test needs, sharing one fixture and one set of fakes.
    struct Context {
        let env: FakeEnvironment
        let gate: SafetyGate
        let policy: MutationPolicy
        let quarantine: Quarantine
        let audit: AuditLog
        let trash: FixtureTrash

        var fixture: FixtureBuilder { env.fixture }
        var home: String { env.fixture.home }
        var quarantineRoot: String { home + "/Library/Application Support/iMop/Quarantine" }
        var logDirectory: String { home + "/Library/Logs/iMop" }

        /// Executor over this context. `environment` replaces the default fake environment (e.g. to
        /// inject a gated command runner); `policy` replaces the context's policy.
        func executor(policy: MutationPolicy? = nil, environment: SafeCleanEnvironment? = nil,
                      remover: (any PermanentRemoving)? = nil, trash: (any TrashMoving)? = nil) -> Executor {
            let policy = policy ?? self.policy
            let environment = environment ?? env.environment
            // The real removefile primitive, gated by the same (fixture) policy as the Executor.
            let remover = remover ?? RemovefileRemover(mutationPolicy: policy, environment: environment)
            return Executor(environment: environment, gate: gate, quarantine: quarantine, auditLog: audit,
                            trash: trash ?? self.trash, remover: remover, mutationPolicy: policy)
        }

        func planBuilder(settings: PlanSettings = PlanSettings()) -> PlanBuilder {
            PlanBuilder(environment: env.environment, gate: gate, settings: settings)
        }
    }

    static func withContext(policy: Policy = .fixture, _ body: (Context) async throws -> Void) async throws {
        try await M1.withEnv { env in
            let gate = env.makeGate()
            let mutationPolicy: MutationPolicy = policy == .fixture ? .fixtureOnly(root: env.fixture.root) : .compiledIn
            if policy == .fixture {
                try TestSuite.assertTrue(mutationPolicy.isEnabled, "fixture policy must be enabled for \(env.fixture.root)")
            }
            let quarantine = Quarantine(environment: env.environment, gate: gate, mutationPolicy: mutationPolicy)
            let audit = AuditLog(environment: env.environment, exportWaivedSystemRoots: [env.fixture.root])
            let trashDir = try env.fixture.dir("FakeTrash", base: .root)
            let context = Context(env: env, gate: gate, policy: mutationPolicy, quarantine: quarantine, audit: audit,
                                  trash: FixtureTrash(directory: trashDir, fixtureRoot: env.fixture.root))
            try await body(context)
        }
    }

    // MARK: Fixture items

    /// Creates `Library/Caches/<name>/payload.bin` (with `contents` when given). Returns the folder path.
    @discardableResult
    static func cacheItem(_ env: FakeEnvironment, _ name: String, bytes: Int = 4_096, contents: Data? = nil) throws -> String {
        if let contents {
            try env.fixture.file("Library/Caches/\(name)/payload.bin", contents: contents)
        } else {
            try env.fixture.file("Library/Caches/\(name)/payload.bin", bytes: bytes)
        }
        return env.fixture.path("Library/Caches/\(name)")
    }

    static func target(_ env: FakeEnvironment, rule: Rule, path: String, bytes: Int64 = 4_096,
                       owner: String? = nil) -> ScanTarget {
        env.scanTarget(ruleID: rule.id, path: path, allocatedBytes: bytes, owningBundleID: owner)
    }

    /// A command item target (no path checks; its path is informational).
    static func commandTarget(rule: Rule, path: String, argument: String? = nil, bytes: Int64 = 1_000) -> ScanTarget {
        ScanTarget(ruleID: rule.id, kind: .commandItem(argument: argument), path: path,
                   displayName: argument ?? rule.id, identity: nil, allocatedBytes: bytes, reclaimableBytes: bytes,
                   itemCount: 1, lastUsed: nil)
    }

    /// One of the Swift-pinned Milestone 4 vendor-command rules (`RuleTargetMatcher.commandRuleShapes`:
    /// exact tool, arguments, tier and inspector) with exactly its pinned required preconditions. Since
    /// Milestone 4 SafetyGate accepts command items only for these rules.
    static func commandRule(_ id: String = "homebrew.cleanup", timeoutSeconds: Int? = nil) -> Rule {
        guard let shape = RuleTargetMatcher.commandRuleShapes[id] else { fatalError("\(id) is not a pinned command rule") }
        let spec = CommandSpec(tool: shape.tool, arguments: shape.arguments, timeoutSeconds: timeoutSeconds,
                               idempotentSafe: shape.tier == .green)
        return Rule(id: id, category: .developer, tier: shape.tier, title: "Test command \(id)", explanation: "test",
                    whatYouLose: "nothing", howItRegenerates: "re-downloaded", discovery: .inspector(shape.inspector),
                    allowRoots: [], minDepthBelowRoot: 1, preconditions: shape.requiredPreconditions, action: .command(spec))
    }

    /// Fake absolute executable path for `tool` (FakeCommandRunner / GatedCommandRunner).
    static func fakeExecutable(_ tool: String) -> String { "/opt/fake/" + tool }

    /// A command rule that is NOT one of the pinned vendor-command rules (refused since Milestone 4).
    static func unpinnedCommandRule(id: String = "test.command", tier: Tier = .yellow, spec: CommandSpec) -> Rule {
        Rule(id: id, category: .developer, tier: tier, title: "Test command \(id)", explanation: "test",
             whatYouLose: "nothing", howItRegenerates: "re-downloaded", discovery: .command(spec),
             allowRoots: [], minDepthBelowRoot: 1, action: .command(spec))
    }

    // MARK: Plans

    static func plan(_ ctx: Context, _ groups: [(Rule, [ScanTarget])], settings: PlanSettings = PlanSettings()) async -> CleanupPlan {
        await ctx.planBuilder(settings: settings).build(from: groups.map { RuleScanResult(rule: $0.0, targets: $0.1, status: .ok) })
    }

    /// Confirms every actionable item (Red items confirmed one by one).
    static func confirmAll(_ plan: CleanupPlan, irreversible: Bool = false, alwaysQuarantine: Bool = true) throws -> ConfirmedPlan {
        let ids = Set(plan.actionableItems.map(\.id))
        let red = Set(plan.actionableItems.filter(\.requiresPerItemConfirmation).map(\.id))
        return try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: ids,
                                         confirmation: confirmation(perItem: red, irreversible: irreversible),
                                         alwaysQuarantine: alwaysQuarantine)
    }

    /// Plans and confirms; fails the test unless every item is actionable at plan time.
    static func confirmedPlan(_ ctx: Context, _ groups: [(Rule, [ScanTarget])], irreversible: Bool = false,
                              alwaysQuarantine: Bool = true) async throws -> ConfirmedPlan {
        let plan = await plan(ctx, groups)
        for item in plan.items where !item.isActionable {
            throw TestError("plan item \(item.target.path) not actionable: \(item.planVerdict)")
        }
        return try confirmAll(plan, irreversible: irreversible, alwaysQuarantine: alwaysQuarantine)
    }

    // MARK: Running

    struct Run {
        let events: [ExecutionEvent]
        let report: ExecutionReport
    }

    static func run(_ executor: Executor, _ plan: ConfirmedPlan) async throws -> Run {
        var events: [ExecutionEvent] = []
        var report: ExecutionReport?
        for await event in await executor.execute(plan) {
            events.append(event)
            if case .finished(let r) = event { report = r }
        }
        guard let report else { throw TestError("execution stream ended without a finished report") }
        return Run(events: events, report: report)
    }

    static func status(_ report: ExecutionReport, _ id: UUID) throws -> ItemStatus {
        guard let outcome = report.outcomes.first(where: { $0.id == id }) else { throw TestError("no outcome for \(id)") }
        return outcome.status
    }

    static func expectSkipped(_ status: ItemStatus, _ expected: SafetyRejection, _ context: String = "",
                              file: StaticString = #file, line: UInt = #line) throws {
        guard case .skipped(let actual) = status, actual == expected else {
            throw TestError("Expected .skipped(\(expected)) but got \(status). \(context) (\(file):\(line))")
        }
    }

    static func expectPreconditionSkipped(_ status: ItemStatus, name: String, _ context: String = "",
                                          file: StaticString = #file, line: UInt = #line) throws {
        guard case .skipped(.preconditionFailed(let actual, _)) = status, actual == name else {
            throw TestError("Expected .skipped(preconditionFailed(\(name))) but got \(status). \(context) (\(file):\(line))")
        }
    }

    // MARK: Inspection

    static func exists(_ path: String) -> Bool {
        var st = Darwin.stat()
        return Darwin.lstat(path, &st) == 0
    }

    static func lstatInfo(_ path: String) -> Darwin.stat? {
        var st = Darwin.stat()
        return Darwin.lstat(path, &st) == 0 ? st : nil
    }

    static func permissions(_ path: String) -> Int? {
        guard let st = lstatInfo(path) else { return nil }
        return Int(st.st_mode & 0o7777)
    }

    static func inode(_ path: String) -> UInt64? {
        lstatInfo(path).map { UInt64($0.st_ino) }
    }

    /// Children of `path`, or [] when it does not exist.
    static func children(_ path: String) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []).sorted()
    }

    /// Every audit event in the fixture's log folder, file by file in name order.
    static func auditEvents(_ ctx: Context) throws -> [AuditEvent] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var events: [AuditEvent] = []
        for name in children(ctx.logDirectory) where name.hasSuffix(".jsonl") {
            guard let text = try? String(contentsOfFile: ctx.logDirectory + "/" + name, encoding: .utf8) else {
                throw TestError("cannot read audit file \(name)")
            }
            for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
                events.append(try decoder.decode(AuditEvent.self, from: Data(line.utf8)))
            }
        }
        return events
    }

    /// Raw text of every audit file.
    static func auditText(_ ctx: Context) -> String {
        children(ctx.logDirectory).compactMap { try? String(contentsOfFile: ctx.logDirectory + "/" + $0, encoding: .utf8) }
            .joined()
    }

    /// A copy of `env.environment` with some services replaced.
    static func environment(_ env: FakeEnvironment, commands: (any CommandRunning)? = nil,
                            fileSystem: (any FileSystemProbe)? = nil) -> SafeCleanEnvironment {
        SafeCleanEnvironment(
            homeDirectory: URL(fileURLWithPath: env.fixture.home, isDirectory: true),
            fileSystem: fileSystem ?? env.fileSystem, processes: env.processes, runningApplications: env.runningApplications,
            applications: env.applications, volumes: env.volumes, commands: commands ?? env.commands,
            clock: env.clock, effectiveUserID: env.effectiveUserID, userID: env.userID,
            codeSignatures: env.codeSignatures)
    }

    /// Writes a session manifest by hand (crash-reconciliation tests). Mirrors Quarantine's on-disk format.
    static func writeManifest(sessionDir: String, sessionID: UUID, createdAt: Date, entries: [QuarantineEntry]) throws {
        struct Manifest: Codable {
            var formatVersion: Int
            var sessionID: UUID
            var createdAt: Date
            var entries: [QuarantineEntry]
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(Manifest(formatVersion: 1, sessionID: sessionID, createdAt: createdAt, entries: entries))
        try data.write(to: URL(fileURLWithPath: sessionDir + "/manifest.json"), options: .atomic)
        _ = chmod(sessionDir + "/manifest.json", 0o600)
    }

    static func readManifestEntries(sessionDir: String) throws -> [QuarantineEntry] {
        struct Manifest: Codable { var entries: [QuarantineEntry] }
        guard let data = FileManager.default.contents(atPath: sessionDir + "/manifest.json") else {
            throw TestError("no manifest in \(sessionDir)")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(Manifest.self, from: data).entries
    }

    static func wholeSeconds(_ date: Date) -> Date {
        Date(timeIntervalSince1970: date.timeIntervalSince1970.rounded(.down))
    }
}

// MARK: - Fakes

/// Test-only `TrashMoving`: renames the item into a folder inside the fixture root. A real
/// `trashItem` would touch the real ~/.Trash, which tests must never do.
struct FixtureTrash: TrashMoving {
    let directory: String
    let fixtureRoot: String

    func moveToTrash(path: String, expectedIdentity: FileIdentity) throws -> String {
        try moveToTrash(path: path)
    }

    func moveToTrash(path: String) throws -> String {
        guard path.hasPrefix(fixtureRoot + "/"), !path.contains("/../") else {
            throw TestError("FixtureTrash refuses \(path) outside the fixture root")
        }
        let destination = directory + "/" + UUID().uuidString + "-" + (path as NSString).lastPathComponent
        guard Darwin.rename(path, destination) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return destination
    }
}

/// A `PermanentRemoving` that refuses everything (proves an item never reached the remover).
struct RefusingRemover: PermanentRemoving {
    func removePermanently(path: String) throws {
        throw TestError("RefusingRemover must never be called (\(path))")
    }

    func removePermanently(path: String, expectedIdentity: FileIdentity) throws {
        throw TestError("RefusingRemover must never be called (\(path))")
    }
}

/// A command runner whose `run` blocks until the test releases it, so a test can act while an
/// item is in progress (cancellation, concurrent runs).
final class GatedCommandRunner: CommandRunning, @unchecked Sendable {
    private let lock = NSLock()
    private var _started = 0
    private var _released = false
    private let result: CommandResult
    private let executables: [String: String]

    init(executables: [String: String], result: CommandResult = CommandResult(exitCode: 0, stdout: "ok", stderr: "")) {
        self.executables = executables
        self.result = result
    }

    var startedCount: Int { lock.lock(); defer { lock.unlock() }; return _started }

    func release() { lock.lock(); _released = true; lock.unlock() }

    private func markStarted() { lock.lock(); _started += 1; lock.unlock() }

    private var isReleased: Bool { lock.lock(); defer { lock.unlock() }; return _released }

    func resolveExecutable(_ tool: String) -> String? { executables[tool] }

    func run(executable: String, arguments: [String], timeout: TimeInterval, purpose: CommandPurpose) async -> CommandResult {
        markStarted()
        var waited = 0
        while !isReleased && waited < 10_000 {
            try? await Task.sleep(nanoseconds: 1_000_000)
            waited += 1
        }
        return result
    }

    /// Waits (bounded) until `run` has been entered `count` times.
    func waitUntilStarted(_ count: Int = 1) async throws {
        var waited = 0
        while startedCount < count {
            guard waited < 5_000 else { throw TestError("gated command never started") }
            try await Task.sleep(nanoseconds: 1_000_000)
            waited += 1
        }
    }
}
