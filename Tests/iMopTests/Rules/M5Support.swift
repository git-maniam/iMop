import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Shared helpers for the Milestone 5 suites (Yellow rules, Xcode / project / editor / media / AI
/// inspectors). Every fixture lives under an `iMopTests-*` temp tree; nothing outside it is touched,
/// no command really runs (git answers come from `FakeCommandRunner`).
@MainActor
enum M5 {
    nonisolated static let xcodeBundleID = "com.apple.dt.Xcode"
    nonisolated static let gitPath = "/usr/bin/git"
    nonisolated static let gitUntrackedStderr = "error: pathspec 'node_modules' did not match any file(s) known to git\nDid you forget to 'git add'?\n"

    /// Fake git + developer tools (review M5): `/usr/bin/git` is only run when `xcode-select -p` names a
    /// developer directory holding `usr/bin/git`, so tests provide a fixture developer directory.
    /// `git: nil` leaves git unresolvable. Responses set before are kept.
    static func useGit(_ env: FakeEnvironment, git: String? = gitPath, developerTools: Bool = true) throws {
        let f = env.fixture
        let developer = "DeveloperTools/Contents/Developer"
        if !FileManager.default.fileExists(atPath: f.path(developer + "/usr/bin/git", base: .root)) {
            try f.file(developer + "/usr/bin/git", bytes: 16, base: .root)
        }
        var executables = env.commands.executables
        executables["git"] = git
        executables["xcode-select"] = "/usr/bin/xcode-select"
        env.commands.executables = executables
        env.commands.setResponse(developerTools
                                 ? CommandResult(exitCode: 0, stdout: f.path(developer, base: .root) + "\n", stderr: "")
                                 : CommandResult(exitCode: 2, stdout: "", stderr: "xcode-select: error: unable to get active developer directory"),
                                 for: ["-p"])
    }

    /// The source-tree Rules.json, loaded against `env`.
    static func catalog(_ env: FakeEnvironment) throws -> RuleCatalog {
        RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
    }

    static func rule(_ env: FakeEnvironment, _ id: String) throws -> Rule {
        guard let rule = try catalog(env).rule(id: id) else { throw TestError("missing bundled rule \(id)") }
        return rule
    }

    /// Scanner over the source catalog with the fixture waiver (like the M2 suites).
    static func scanner(_ env: FakeEnvironment, catalog: RuleCatalog? = nil,
                        inspectors: [any Inspector] = SafeCleanScanner.defaultInspectors) throws -> SafeCleanScanner {
        SafeCleanScanner(environment: env.environment, catalog: try catalog ?? M5.catalog(env), inspectors: inspectors,
                         hasFullDiskAccess: true, waivedSystemRoots: [env.fixture.root])
    }

    /// Scans `ids` and returns the results keyed by rule id.
    static func scan(_ env: FakeEnvironment, _ ids: Set<String>) async throws -> [String: RuleScanResult] {
        let s = try scanner(env)
        let results = await s.scan(ruleIDs: ids)
        return Dictionary(uniqueKeysWithValues: results.map { ($0.rule.id, $0) })
    }

    /// Runs one inspector directly for a bundled rule.
    static func discover(_ inspector: any Inspector, _ env: FakeEnvironment, _ ruleID: String) async throws -> InspectorOutput {
        await inspector.discover(rule: try rule(env, ruleID), environment: env.environment)
    }

    nonisolated static func relative(_ path: String, _ f: FixtureBuilder) -> String {
        path.hasPrefix(f.home + "/") ? String(path.dropFirst(f.home.count + 1)) : path
    }

    nonisolated static func paths(_ output: InspectorOutput, _ f: FixtureBuilder) -> Set<String> {
        Set(output.candidates.map { relative($0.path, f) })
    }

    nonisolated static func paths(_ result: RuleScanResult?, _ f: FixtureBuilder) -> Set<String> {
        Set(result?.targets.map { relative($0.path, f) } ?? [])
    }

    /// Builds a plan from scan results with the fixture-waived gate.
    static func plan(_ env: FakeEnvironment, _ results: [RuleScanResult]) async -> CleanupPlan {
        await PlanBuilder(environment: env.environment, gate: env.makeGate(), settings: PlanSettings()).build(from: results)
    }

    /// Evaluates one precondition with the fixture-waived evaluator.
    static func evaluate(_ env: FakeEnvironment, _ precondition: Precondition, path: String, rule: Rule) async -> PreconditionResult {
        let evaluator = PreconditionEvaluator(environment: env.environment, ageThresholdOverrides: [:],
                                              waivedSystemRoots: [env.fixture.root])
        return await evaluator.evaluate(precondition, target: env.scanTarget(ruleID: rule.id, path: path), rule: rule)
    }

    nonisolated static func unwrap<T>(_ value: T?, file: StaticString = #file, line: UInt = #line) throws -> T {
        guard let value else { throw TestError("unexpected nil (\(file):\(line))") }
        return value
    }

    /// Runs `body` inside a task that is already cancelled.
    static func cancelled<T: Sendable>(_ body: @escaping @Sendable () async -> T) async -> T {
        await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await body()
        }.value
    }

    nonisolated static func plistData(_ object: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
    }

    nonisolated static func jsonData(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted])
    }

    /// Sets the mtime of `rel` and of every entry directly inside it (so `lastUsed` is that old).
    static func age(_ f: FixtureBuilder, _ rel: String, days: Int, clock: any iMopCore.Clock) throws {
        let absolute = f.path(rel)
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: absolute, isDirectory: &isDirectory), isDirectory.boolValue {
            for child in (try? FileManager.default.contentsOfDirectory(atPath: absolute)) ?? [] {
                try f.setModificationDate(rel + "/" + child, daysAgo: days, clock: clock)
            }
        }
        try f.setModificationDate(rel, daysAgo: days, clock: clock)
    }

    /// The plan item for `rel` (fixture-home relative), or a failure.
    nonisolated static func item(_ plan: CleanupPlan, _ rel: String, _ f: FixtureBuilder) throws -> PlanItem {
        guard let item = plan.items.first(where: { relative($0.target.path, f) == rel }) else {
            throw TestError("no plan item for \(rel); items: \(plan.items.map { relative($0.target.path, f) })")
        }
        return item
    }

    /// Name of the first failing precondition of a plan item (nil when all passed).
    nonisolated static func failedPrecondition(_ item: PlanItem) -> String? {
        item.preconditions.first { !$0.passed }?.name
    }
}
