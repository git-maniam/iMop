import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Regression tests for the adversarial review of Milestone 2 (one group per finding).
struct M2ReviewRegressionTests {
    // MARK: Helpers

    static func value<T>(_ optional: T?, _ context: String = "", file: StaticString = #file, line: UInt = #line) throws -> T {
        guard let optional else { throw TestError("unexpected nil \(context) (\(file):\(line))") }
        return optional
    }

    static func bundledCatalog(_ env: FakeEnvironment) throws -> RuleCatalog {
        RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
    }

    static func bundledRule(_ env: FakeEnvironment, _ id: String) throws -> Rule {
        try value(try bundledCatalog(env).rule(id: id), id)
    }

    /// The bundled rule `id` as a JSON object (to derive modified copies).
    static func bundledRuleJSON(_ id: String) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: try M2.sourceRulesData()) as? [String: Any]
        guard let rules = object?["rules"] as? [[String: Any]], let rule = rules.first(where: { $0["id"] as? String == id }) else {
            throw TestError("bundled rule \(id) not found")
        }
        return rule
    }

    static func load(_ rules: [[String: Any]], _ env: FakeEnvironment) throws -> RuleCatalog {
        RuleCatalog.load(data: try M2.catalogData(rules), environment: env.environment)
    }

    static func validate(_ env: FakeEnvironment, _ rule: Rule, _ rel: String, owner: String? = nil,
                         phase: ValidationPhase = .execute) async -> SafetyVerdict {
        await env.makeGate().validate(target: env.scanTarget(ruleID: rule.id, path: rel, owningBundleID: owner),
                                      rule: rule, phase: phase)
    }

    static func expectShapeRejected(_ verdict: SafetyVerdict, _ context: String) throws {
        guard case .rejected(.doesNotMatchRule) = verdict else {
            throw TestError("expected .doesNotMatchRule, got \(verdict) — \(context)")
        }
    }

    static func relative(_ path: String, _ f: FixtureBuilder) -> String {
        path.hasPrefix(f.home + "/") ? String(path.dropFirst(f.home.count + 1)) : path
    }

    /// Milestone 6: by default the fixture-rooted inspectors (`M6.fixtureInspectors`), so no scan reads
    /// the real /Applications or /Library.
    static func scanner(_ env: FakeEnvironment, catalog: RuleCatalog, inspectors: [any Inspector]? = nil,
                        fda: Bool = true) -> SafeCleanScanner {
        SafeCleanScanner(environment: env.environment, catalog: catalog,
                         inspectors: inspectors ?? (try? M6.fixtureInspectors(env.fixture)) ?? SafeCleanScanner.defaultInspectors,
                         hasFullDiskAccess: fda, waivedSystemRoots: [env.fixture.root])
    }

    @MainActor
    static func runAll() async {
        print("\n🛡️  Running Milestone 2 Review Regression Tests...")
        await shapeTests()
        await auditLogTests()
        await nonHomeExceptionTests()
        await commandAllowListTests()
        await protectedDescendantTests()
        await overlapCacheTests()
        await bundleDescentTests()
        await sizerTests()
    }

    // MARK: Finding 1 — SafetyGate re-checks the rule's target shape

    @MainActor
    static func shapeTests() async {
        await TestSuite.run("M2 review 1: gate rejects non-cache folders under inspector/exact-name allow-roots") {
            try await M1.withEnv { env in
                let f = env.fixture
                let support = "Library/Application Support"
                for rel in ["Slack/Local Storage", "Slack/Cache", "Google/Chrome/Default/Login Data", "Google/Chrome/Default/Cache",
                            "Vivaldi/Default/Login Data", "Code/User", "Code/Cache", "Cursor/User"] {
                    try f.file("\(support)/\(rel)/data.bin", bytes: 10)
                }
                try f.file("Library/Containers/com.foo.App/Data/Documents/MyNovel/Chapters/one.txt", bytes: 10)
                try f.file("Library/Containers/com.foo.App/Data/Library/Caches/WebKit/x", bytes: 10)

                let electron = try bundledRule(env, "apps.electronCaches")
                let chromium = try bundledRule(env, "browser.chromium.cache")
                let containers = try bundledRule(env, "apps.containerCaches")
                let vscode = try bundledRule(env, "vscode.caches")
                let cursor = try bundledRule(env, "cursor.caches")
                let slack = "com.tinyspeck.slackmacgap", chrome = "com.google.Chrome"

                try expectShapeRejected(await validate(env, electron, "\(support)/Slack/Local Storage", owner: slack), "Slack Local Storage")
                try expectShapeRejected(await validate(env, electron, "\(support)/Google/Chrome", owner: chrome), "whole Chrome user data")
                try expectShapeRejected(await validate(env, electron, "\(support)/Slack/Cache", owner: chrome), "wrong owner")
                try expectShapeRejected(await validate(env, electron, "\(support)/Slack/Cache"), "no owner")
                try expectShapeRejected(await validate(env, chromium, "\(support)/Google/Chrome/Default", owner: chrome), "whole profile")
                try expectShapeRejected(await validate(env, chromium, "\(support)/Google/Chrome/Default/Login Data", owner: chrome), "Login Data")
                try expectShapeRejected(await validate(env, chromium, "\(support)/Vivaldi/Default/Login Data", owner: "com.vivaldi.Vivaldi"), "Vivaldi Login Data")
                try expectShapeRejected(await validate(env, containers, "Library/Containers/com.foo.App/Data/Documents/MyNovel/Chapters",
                                                       owner: "com.foo.App"), "container Documents")
                try expectShapeRejected(await validate(env, vscode, "\(support)/Code/User"), "Code/User")
                try expectShapeRejected(await validate(env, cursor, "\(support)/Cursor/User"), "Cursor/User")

                // Controls: the real cache folders are still allowed.
                try M1.expectAllowed(await validate(env, electron, "\(support)/Slack/Cache", owner: slack), "Slack Cache")
                try M1.expectAllowed(await validate(env, chromium, "\(support)/Google/Chrome/Default/Cache", owner: chrome), "Chrome Cache")
                try M1.expectAllowed(await validate(env, containers, "Library/Containers/com.foo.App/Data/Library/Caches/WebKit",
                                                    owner: "com.foo.App"), "container cache")
                try M1.expectAllowed(await validate(env, vscode, "\(support)/Code/Cache"), "Code/Cache")
            }
        }

        await TestSuite.run("M2 review 1: protected-ancestor rules have pinned inspectors and minimum depths") {
            try await M1.withEnv { env in
                var bad: [[String: Any]] = []
                for (id, depth) in [("apps.containerCaches", 1), ("apps.containerCaches", 4), ("apps.electronCaches", 1),
                                    ("browser.chromium.cache", 2)] {
                    var rule = try bundledRuleJSON(id)
                    rule["minDepthBelowRoot"] = depth
                    rule["id"] = id
                    bad.append(rule)
                }
                for (index, rule) in bad.enumerated() {
                    let catalog = try load([rule], env)
                    try TestSuite.assertEqual(catalog.rules.count, 0, "case \(index): \(rule["id"] ?? "")")
                }
                var swapped = try bundledRuleJSON("apps.containerCaches")
                swapped["discovery"] = ["inspector": "electronCaches"]
                try TestSuite.assertEqual(try load([swapped], env).rules.count, 0, "inspector swap")
                // Controls: the bundled versions are valid.
                for id in ["apps.containerCaches", "apps.electronCaches", "browser.chromium.cache"] {
                    try TestSuite.assertEqual(try load([try bundledRuleJSON(id)], env).rules.map(\.id), [id])
                }
            }
        }

        await TestSuite.run("M2 review 1: matcher fails closed for inspectors without a shape and for command discovery") {
            try await M1.withEnv { env in
                let home = CanonicalPath(validatedPath: env.fixture.home)
                let matcher = RuleTargetMatcher(homeForms: [home])
                let target = home.appending("Library").appending("Developer").appending("Xcode").appending("DerivedData").appending("X")
                let inspectorRule = M1.rule(id: "test.dd", discovery: .inspector(.xcodeDerivedData))
                try TestSuite.assertTrue(matcher.mismatch(target, rule: inspectorRule, owningBundleID: "com.apple.dt.Xcode") != nil)
                let commandRule = M1.rule(id: "test.cmd", discovery: .command(CommandSpec(tool: "brew", arguments: ["cleanup", "--prune=all", "-n"])))
                try TestSuite.assertTrue(matcher.mismatch(target, rule: commandRule, owningBundleID: nil) != nil)
            }
        }
    }

    // MARK: Finding 2 — iMop's audit log folder

    @MainActor
    static func auditLogTests() async {
        await TestSuite.run("M2 review 2: logs.user can never reach ~/Library/Logs/iMop or its other excluded names") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Library/Logs/iMop/audit-2026-08.jsonl", bytes: 100)
                try f.file("Library/Logs/DiagnosticReports/a.ips", bytes: 100)
                try f.file("Library/Logs/JetBrains/idea.log", bytes: 100)
                try f.file("Library/Logs/Other.log", bytes: 100)
                for rel in ["Library/Logs/iMop/audit-2026-08.jsonl", "Library/Logs/iMop", "Library/Logs/DiagnosticReports/a.ips",
                            "Library/Logs/DiagnosticReports", "Library/Logs/JetBrains", "Library/Logs/Other.log"] {
                    try f.setModificationDate(rel, daysAgo: 30, clock: env.clock)
                }
                let rule = try bundledRule(env, "logs.user")
                for rel in ["Library/Logs/iMop", "Library/Logs/iMop/audit-2026-08.jsonl"] {
                    try M1.expectDenyListed(await validate(env, rule, rel), "~/Library/Logs/iMop", rel)
                }
                try expectShapeRejected(await validate(env, rule, "Library/Logs/DiagnosticReports"), "excluded DiagnosticReports")
                try expectShapeRejected(await validate(env, rule, "Library/Logs/JetBrains"), "excluded JetBrains")
                try expectShapeRejected(await validate(env, rule, "Library/Logs/DiagnosticReports/a.ips"), "too deep for the glob")
                try M1.expectAllowed(await validate(env, rule, "Library/Logs/Other.log"), "control")
            }
        }

        await TestSuite.run("M2 review 2: only logs.user may use ~/Library/Logs as a root, and only while it excludes iMop") {
            try await M1.withEnv { env in
                var noExclusion = try bundledRuleJSON("logs.user")
                noExclusion["excludedNames"] = ["DiagnosticReports"]
                try TestSuite.assertEqual(try load([noExclusion], env).rules.count, 0, "logs.user without iMop exclusion")
                var other = try bundledRuleJSON("logs.user")
                other["id"] = "other.logs"
                try TestSuite.assertEqual(try load([other], env).rules.count, 0, "another id with ~/Library/Logs")
            }
        }
    }

    // MARK: Finding 3 — non-home exceptions are fully pinned

    @MainActor
    static func nonHomeExceptionTests() async {
        await TestSuite.run("M2 review 3: non-home exception ids validate only with their pinned shape") {
            try await M1.withEnv { env in
                func rule(_ id: String, _ tier: String, _ action: Any, _ globs: [String], _ roots: [String],
                          _ preconditions: [Any] = []) -> [String: Any] {
                    M2.ruleJSON(id, overrides: ["tier": tier, "action": action, "discovery": ["glob": globs],
                                                "allowRoots": roots, "preconditions": preconditions])
                }
                let notRunning: [String: Any] = ["appNotRunning": ["com.apple.InstallAssistant.*"]]
                let bad: [[String: Any]] = [
                    rule("installers.macOS", "yellow", "trash", ["/Applications/*.app"], ["/Applications"]),
                    rule("installers.macOS", "yellow", "trash", ["/Applications/*.app"], ["/Applications"], ["appleSigned", notRunning]),
                    rule("installers.macOS", "yellow", "trash", ["/Applications/Install macOS *.app"], ["/Applications"], ["appleSigned"]),
                    rule("installers.macOS", "red", "trash", ["/Applications/Install macOS *.app"], ["/Applications"], ["appleSigned", notRunning]),
                    rule("xcode.extraInstalls", "green", "quarantine", ["/Applications/*"], ["/Applications"]),
                    rule("xcode.extraInstalls", "red", "trash", ["/Applications/*.app"], ["/Applications"]),
                    rule("system.coreDumps", "green", "quarantine", ["/cores/*"], ["/cores"]),
                    rule("system.coreDumps", "yellow", "trash", ["/cores/core.*"], ["/cores"], ["ownedByUser", ["olderThan": 1]]),
                ]
                for (index, json) in bad.enumerated() {
                    let catalog = try load([json], env)
                    try TestSuite.assertEqual(catalog.rules.count, 0, "case \(index) (\(json["id"] ?? "")) must be disabled")
                }
                // Milestone 6: the reviewed shape is the macOSInstallers inspector (a glob is refused).
                var good = rule("installers.macOS", "yellow", "trash", ["/Applications/Install macOS *.app"], ["/Applications"],
                                ["appleSigned", notRunning])
                try TestSuite.assertEqual(try load([good], env).rules.count, 0, "the glob form is no longer the reviewed shape")
                good["discovery"] = ["inspector": "macOSInstallers"]
                var wrongTier = good
                wrongTier["tier"] = "green"
                var missingPrecondition = good
                missingPrecondition["preconditions"] = ["appleSigned"]
                for (index, json) in [wrongTier, missingPrecondition].enumerated() {
                    try TestSuite.assertEqual(try load([json], env).rules.count, 0, "inspector case \(index) must be disabled")
                }
                try TestSuite.assertEqual(try load([good], env).rules.map(\.id), ["installers.macOS"],
                                          "\(try load([good], env).disabled)")
            }
        }
    }

    // MARK: Finding 4 — commands are allow-listed

    @MainActor
    static func commandAllowListTests() async {
        await TestSuite.run("M2 review 4: wrapper tools, arbitrary xcrun tools and destructive subcommands are rejected") {
            try await M1.withEnv { env in
                func commandRule(_ id: String, tier: String = "green", _ tool: String, _ arguments: [String],
                                 dryRun: [String]? = nil) -> [String: Any] {
                    var spec: [String: Any] = ["tool": tool, "arguments": arguments, "idempotentSafe": true]
                    if let dryRun { spec["dryRunArguments"] = dryRun }
                    return M2.ruleJSON(id, overrides: ["tier": tier, "action": ["command": spec]])
                }
                let bad: [[String: Any]] = [
                    commandRule("c.nohup", "nohup", ["/bin/rm", "-rf", "{ITEM}"]),
                    commandRule("c.arch", "arch", ["-arm64", "/bin/zsh", "-e", "x"]),
                    commandRule("c.caffeinate", "caffeinate", ["-i", "/bin/rm", "-rf", "{ITEM}"]),
                    commandRule("c.nice", "nice", ["brew", "cleanup", "--prune=all"]),
                    commandRule("c.time", "time", ["brew", "cleanup", "--prune=all"]),
                    commandRule("c.xcrunPerl", "xcrun", ["perl", "-e", "system q(x)"]),
                    commandRule("c.dockerVolumePrune", tier: "yellow", "docker", ["volume", "prune", "-a", "-f"]),
                    commandRule("c.greenUnusedImages", "docker", ["image", "prune", "-a", "-f"]),
                    commandRule("c.extraArg", "brew", ["cleanup", "--prune=all", "--force"]),
                    commandRule("c.embeddedItem", tier: "yellow", "xcrun", ["simctl", "delete", "x{ITEM}"]),
                    commandRule("c.badDryRun", "brew", ["cleanup", "--prune=all"], dryRun: ["cleanup", "--prune=all"]),
                    commandRule("c.brewAutoremove", "brew", ["autoremove"]),
                ]
                for json in bad {
                    let catalog = try load([json], env)
                    try TestSuite.assertEqual(catalog.rules.count, 0, "\(json["id"] ?? "") must be disabled")
                }
                var discovery = M2.ruleJSON("c.discoveryDestructive", overrides: ["tier": "yellow"])
                discovery["discovery"] = ["command": ["tool": "docker", "arguments": ["image", "prune", "-f"], "idempotentSafe": true]]
                try TestSuite.assertEqual(try load([discovery], env).rules.count, 0, "discovery command must be read-only")

                let good: [[String: Any]] = [
                    commandRule("c.simctl", "xcrun", ["simctl", "delete", "unavailable"], dryRun: ["simctl", "list", "devices", "unavailable", "-j"]),
                    commandRule("c.brew", "brew", ["cleanup", "--prune=all"], dryRun: ["cleanup", "--prune=all", "-n"]),
                    commandRule("c.yellowUnusedImages", tier: "yellow", "docker", ["image", "prune", "-a", "-f"]),
                    commandRule("c.runtime", tier: "yellow", "xcrun", ["simctl", "runtime", "delete", "{ITEM}"]),
                ]
                let catalog = try load(good, env)
                try TestSuite.assertEqual(Set(catalog.rules.map(\.id)), ["c.simctl", "c.brew", "c.yellowUnusedImages", "c.runtime"],
                                          "\(catalog.disabled)")
            }
        }
    }

    // MARK: Finding 5 — protected items below a target

    @MainActor
    static func protectedDescendantTests() async {
        await TestSuite.run("M2 review 5: a target containing .git / .photoslibrary / .sparsebundle is never offered or allowed") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Library/Caches/pip/http/proj/.git/HEAD", bytes: 10)
                try f.file("Library/Caches/CocoaPods/Pods/My.photoslibrary/database/Photos.sqlite", bytes: 10)
                try f.file("Library/Caches/CocoaPods/Clean/data.bin", bytes: 10)
                try f.file("Library/Logs/Stuff/Backup.sparsebundle/Info.plist", bytes: 10)
                try f.setModificationDate("Library/Logs/Stuff/Backup.sparsebundle/Info.plist", daysAgo: 30, clock: env.clock)
                try f.setModificationDate("Library/Logs/Stuff/Backup.sparsebundle", daysAgo: 30, clock: env.clock)
                try f.setModificationDate("Library/Logs/Stuff", daysAgo: 30, clock: env.clock)

                let estimate = try value(SizeCalculator(environment: env.environment).measure(path: f.path("Library/Caches/pip/http")))
                try TestSuite.assertEqual(estimate.protectedDescendantEntry, ".git")

                let catalog = try bundledCatalog(env)
                let results = await scanner(env, catalog: catalog).scan(ruleIDs: ["pip.cache", "cocoapods.cache", "logs.user"])
                let found = Set(results.flatMap(\.targets).map { relative($0.path, f) })
                try TestSuite.assertEqual(found, ["Library/Caches/CocoaPods/Clean"], "only the clean folder is offered")

                let gate = env.makeGate()
                for (id, rel, entry) in [("pip.cache", "Library/Caches/pip/http", "contains .git"),
                                         ("cocoapods.cache", "Library/Caches/CocoaPods/Pods", "contains .photoslibrary"),
                                         ("logs.user", "Library/Logs/Stuff", "contains .sparsebundle")] {
                    let rule = try value(catalog.rule(id: id))
                    for phase in [ValidationPhase.plan, .execute] {
                        try M1.expectDenyListed(await gate.validate(target: env.scanTarget(ruleID: id, path: rel), rule: rule, phase: phase),
                                                entry, rel)
                    }
                }
                // The tree can change after the scan: a .git appearing later is caught at execute time.
                let clean = try value(catalog.rule(id: "cocoapods.cache"))
                let target = env.scanTarget(ruleID: clean.id, path: "Library/Caches/CocoaPods/Clean")
                try M1.expectAllowed(await gate.validate(target: target, rule: clean, phase: .plan), "clean at plan time")
                try f.file("Library/Caches/CocoaPods/Clean/repo/.git/config", bytes: 10)
                try M1.expectDenyListed(await gate.validate(target: target, rule: clean, phase: .execute), "contains .git", "after change")
            }
        }
    }

    // MARK: Finding 6 — overlap across cached subset scans; cancellation

    final class TaskHolder: @unchecked Sendable {
        private let lock = NSLock()
        private var task: Task<[RuleScanResult], Never>?
        func set(_ task: Task<[RuleScanResult], Never>) { lock.lock(); self.task = task; lock.unlock() }
        func cancel() { lock.lock(); let t = task; lock.unlock(); t?.cancel() }
    }

    /// Cancels the surrounding scan after the other rules have had time to finish.
    struct CancellingInspector: Inspector {
        let holder: TaskHolder
        // Milestone 6: every pinned inspector id has a real implementation; electronCaches is an
        // unpinned id the test rule may use.
        var id: InspectorID { .electronCaches }
        func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
            try? await Task.sleep(nanoseconds: 300_000_000)
            holder.cancel()
            return InspectorOutput(candidates: [], status: .ok)
        }
    }

    @MainActor
    static func overlapCacheTests() async {
        await TestSuite.run("M2 review 6: two subset scans in sequence never leave overlapping targets in the session cache") {
            try await M1.withEnv { env in
                let f = env.fixture
                env.applications.applicationURLs = ["com.example.Sparkly": [URL(fileURLWithPath: "/Applications/Sparkly.app")]]
                try f.file("Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle/u.zip", bytes: 1_000)
                try f.file("Library/Caches/com.example.Sparkly/db", bytes: 100)
                let scanner = scanner(env, catalog: try bundledCatalog(env))

                let first = await scanner.scan(ruleIDs: ["apps.userCaches", "apps.sparkleUpdates"])
                try TestSuite.assertEqual(first.flatMap(\.targets).map { relative($0.path, f) },
                                          ["Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle"])
                let second = await scanner.scan(ruleIDs: ["apps.userCaches"])
                try TestSuite.assertEqual(second.flatMap(\.targets).count, 0,
                                          "the userCaches ancestor overlaps the cached Sparkle target: \(second.flatMap(\.targets).map(\.path))")
                let cached = try value(await scanner.cachedResults())
                let paths = cached.flatMap(\.targets).compactMap { target -> CanonicalPath? in
                    guard case .success(let p) = PathCanonicalizer(environment: env.environment).lexical(target.path) else { return nil }
                    return p
                }
                for (i, a) in paths.enumerated() {
                    for (j, b) in paths.enumerated() where i != j {
                        try TestSuite.assertFalse(a.isInsideOrEqual(b), "\(a) overlaps \(b)")
                    }
                }
                try TestSuite.assertEqual(paths.map { relative($0.path, f) }, ["Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle"])
            }
        }

        await TestSuite.run("M2 review 6: a scan cancelled midway returns no targets for any rule and is not cached") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Library/Caches/pip/http/payload.bin", bytes: 1_000)
                let pip = try bundledRule(env, "pip.cache")
                let slow = M1.rule(id: "test.slowInspector", discovery: .inspector(.electronCaches))
                let catalog = RuleCatalog(validating: [pip, slow], environment: env.environment)
                try TestSuite.assertEqual(catalog.rules.count, 2, "\(catalog.disabled)")
                let holder = TaskHolder()
                let scanner = scanner(env, catalog: catalog, inspectors: [CancellingInspector(holder: holder)])
                let task = Task { await scanner.scan() }
                holder.set(task)
                let results = await task.value
                try TestSuite.assertEqual(results.count, 2)
                for result in results {
                    try TestSuite.assertEqual(result.targets.count, 0, result.rule.id)
                    try TestSuite.assertEqual(result.status, .failed("Scan cancelled"), result.rule.id)
                }
                try TestSuite.assertTrue(await scanner.cachedResults() == nil, "a cancelled scan is never cached")
            }
        }
    }

    // MARK: Finding 7 — never descend into packages

    @MainActor
    static func bundleDescentTests() async {
        await TestSuite.run("M2 review 7: glob expansion and inspectors never offer items inside (or that are) bundles") {
            try await M1.withEnv { env in
                let f = env.fixture
                env.applications.applicationURLs = ["com.foo.Sandboxed": [URL(fileURLWithPath: "/Applications/Sandboxed.app")]]
                try f.file("Library/Caches/Evil.app/org.sparkle-project.Sparkle/u.zip", bytes: 100)
                try f.file("Library/Caches/Firefox/Profiles/Thing.bundle/cache2/x", bytes: 100)
                try f.file("Library/Caches/Firefox/Profiles/abcd.default/cache2/x", bytes: 100)
                try f.file("Library/Containers/com.foo.Sandboxed/Data/Library/Caches/Plug.bundle/x", bytes: 100)
                try f.file("Library/Containers/com.foo.Sandboxed/Data/Library/Caches/WebKit/x", bytes: 100)

                let expander = GlobExpander(environment: env.environment)
                let sparkle = try value(GlobPattern("{HOME}/Library/Caches/*/org.sparkle-project.Sparkle"))
                try TestSuite.assertEqual(expander.expand(sparkle), [], "never descends into Evil.app")

                let results = await scanner(env, catalog: try bundledCatalog(env))
                    .scan(ruleIDs: ["apps.sparkleUpdates", "browser.firefox.cache", "apps.containerCaches"])
                let found = Set(results.flatMap(\.targets).map { relative($0.path, f) })
                try TestSuite.assertEqual(found, ["Library/Caches/Firefox/Profiles/abcd.default/cache2",
                                                  "Library/Containers/com.foo.Sandboxed/Data/Library/Caches/WebKit"])
            }
        }
    }

    // MARK: Findings 9, 10, 11 — SizeCalculator

    /// Runs `body` with the soft RLIMIT_NOFILE lowered to `limit`, always restoring it.
    static func withDescriptorLimit<T>(_ limit: rlim_t, _ body: () throws -> T) throws -> T {
        var saved = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &saved) == 0 else { throw TestError("getrlimit failed") }
        var lowered = saved
        lowered.rlim_cur = min(limit, saved.rlim_max)
        guard setrlimit(RLIMIT_NOFILE, &lowered) == 0 else { throw TestError("setrlimit failed: \(errno)") }
        defer { _ = setrlimit(RLIMIT_NOFILE, &saved) }
        return try body()
    }

    static func runTool(_ path: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw TestError("\(path) \(arguments) exited \(process.terminationStatus)") }
    }

    @MainActor
    static func sizerTests() async {
        await TestSuite.run("M2 review 9: a deep tree is measured completely with RLIMIT_NOFILE lowered to 64") {
            try await M1.withEnv { env in
                let f = env.fixture
                // 200 levels; each level holds dirs a and b with one file each; the chain continues
                // alternately through a and b, so returning to closed frames forces re-opens.
                var rel = "deep"
                for level in 0..<200 {
                    try f.file(rel + "/a/f.bin", bytes: 100)
                    try f.file(rel + "/b/f.bin", bytes: 100)
                    rel += level % 2 == 0 ? "/a" : "/b"
                }
                let root = f.path("deep")
                let truth = M2.treeBlocksBytes(root)
                let estimate = try withDescriptorLimit(64) { SizeCalculator(environment: env.environment).measure(path: root) }
                let measured = try value(estimate)
                try TestSuite.assertTrue(measured.complete, "estimate must be complete: \(measured)")
                try TestSuite.assertEqual(measured.allocatedBytes, truth)
                try TestSuite.assertEqual(measured.itemCount, 200 * 4, "dirs a, b and one file in each per level")
            }
        }

        await TestSuite.run("M2 review 10: a never-cloned compressed file is reclaimable; a clone of it is not") {
            try await M1.withEnv { env in
                let f = env.fixture
                let source = try f.file("cmp/source.txt", contents: Data(String(repeating: "abcdefghij", count: 400_000).utf8))
                let compressed = f.path("cmp/compressed.txt")
                try runTool("/usr/bin/ditto", ["--hfsCompression", source, compressed])
                var st = Darwin.stat()
                guard Darwin.lstat(compressed, &st) == 0, st.st_flags & UInt32(UF_COMPRESSED) != 0 else {
                    throw TestError("ditto did not produce a compressed file (flags \(st.st_flags))")
                }
                let sizer = SizeCalculator(environment: env.environment)
                let single = try value(sizer.measure(path: compressed))
                try TestSuite.assertTrue(single.allocatedBytes > 0, "\(single)")
                try TestSuite.assertEqual(single.reclaimableBytes, single.allocatedBytes, "never cloned: deleting it frees its blocks")

                let clone = f.path("cmp/clone.txt")
                guard Darwin.clonefile(compressed, clone, 0) == 0 else { throw TestError("clonefile failed: \(errno)") }
                let cloned = try value(sizer.measure(path: clone))
                try TestSuite.assertEqual(cloned.reclaimableBytes, 0, "a clone shares its blocks: \(cloned)")
            }
        }

        await TestSuite.run("M2 review 11: measure(path:) refuses non-normal paths and never follows a symlink at any level") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("real/sub/big.bin", bytes: 200_000)
                let link = try f.symlink("lnk", to: f.path("real"))
                let sizer = SizeCalculator(environment: env.environment)
                let real = f.path("real")
                try TestSuite.assertTrue(sizer.measure(path: real) != nil, "control")
                for bad in [link + "/", link + "/.", link + "/sub", real + "/", real + "/.", real + "//sub",
                            real + "/sub/..", "/", "", "relative/path"] {
                    try TestSuite.assertTrue(sizer.measure(path: bad) == nil, "must be refused: \(bad)")
                }
                let linkItself = try value(sizer.measure(path: link))
                try TestSuite.assertEqual(linkItself.itemCount, 1)
                try TestSuite.assertEqual(linkItself.allocatedBytes, 0)
            }
        }
    }
}
