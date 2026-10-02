import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §3.1 / §7.2: the read-only SafeClean Scanner over a realistic fixture home.
/// (Named SafeCleanScannerTests so it does not clash with the v1.0 `ScannerTests` suite.)
struct SafeCleanScannerTests {
    /// Installed apps registered with the fake LaunchServices.
    static let installedApps: [String: [URL]] = [
        "com.foo.App": [URL(fileURLWithPath: "/Applications/Foo.app")],
        "com.foo.Sandboxed": [URL(fileURLWithPath: "/Applications/Sandboxed.app")],
        "com.tinyspeck.slackmacgap": [URL(fileURLWithPath: "/Applications/Slack.app")],
        "com.google.Chrome": [URL(fileURLWithPath: "/Applications/Google Chrome.app")],
        // Apple apps are never offered by apps.userCaches, even when "installed".
        "com.apple.akd": [URL(fileURLWithPath: "/System/Library/PrivateFrameworks/AuthKit.framework/akd")],
    ]

    /// Rule id → fixture-home-relative paths the scan must return (exactly).
    static let expected: [String: Set<String>] = [
        "xcode.previews": ["Library/Developer/Xcode/UserData/Previews/Simulator Devices"],
        "xcode.docCache": ["Library/Developer/Xcode/DocumentationCache/v1"],
        "simulator.caches": ["Library/Developer/CoreSimulator/Caches/dyld"],
        "spm.cache": ["Library/Caches/org.swift.swiftpm/repositories"],
        "carthage.cache": ["Library/Caches/org.carthage.CarthageKit/dependencies"],
        "cocoapods.cache": ["Library/Caches/CocoaPods/Pods"],
        "pip.cache": ["Library/Caches/pip/http"],
        "poetry.cache": ["Library/Caches/pypoetry/cache/repositories", "Library/Caches/pypoetry/artifacts/ab"],
        "cargo.registrySrc": [".cargo/registry/src/index.crates.io-6f17d22bba15001f"],
        "vscode.caches": ["Library/Application Support/Code/Cache", "Library/Application Support/Code/CachedData",
                          "Library/Application Support/Code/logs"],
        "cursor.caches": ["Library/Application Support/Cursor/GPUCache"],
        "jetbrains.logs": ["Library/Logs/JetBrains/IntelliJIdea2024.1"],
        "apps.sparkleUpdates": ["Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle"],
        "apps.squirrelShipIt": ["Library/Caches/com.example.Electrony.ShipIt"],
        "apps.savedState": ["Library/Saved Application State/com.example.Editor.savedState"],
        "browser.firefox.cache": ["Library/Caches/Firefox/Profiles/abcd.default-release/cache2"],
        "browser.safari.cache": ["Library/Caches/com.apple.Safari/WebKitCache"],
        "mail.downloads": ["Library/Containers/com.apple.mail/Data/Library/Mail Downloads/1A2B"],
        "logs.user": ["Library/Logs/SomeApp.log", "Library/Logs/Homebrew"],
        "logs.diagnosticReports": ["Library/Logs/DiagnosticReports/App_2026-09-01.ips"],
        "ios.firmware": ["Library/iTunes/iPhone Software Updates/iPhone_17.ipsw", "Library/iTunes/iPad Software Updates/iPad_17.ipsw"],
        "apps.userCaches": ["Library/Caches/com.foo.App"],
        "apps.containerCaches": ["Library/Containers/com.foo.Sandboxed/Data/Library/Caches/WebKit"],
        "apps.electronCaches": ["Library/Application Support/Slack/Cache", "Library/Application Support/Slack/Code Cache",
                                "Library/Application Support/Slack/GPUCache"],
        "browser.chromium.cache": ["Library/Application Support/Google/Chrome/Default/Cache",
                                   "Library/Application Support/Google/Chrome/Default/Code Cache",
                                   "Library/Application Support/Google/Chrome/Default/GPUCache",
                                   "Library/Application Support/Google/Chrome/Profile 1/Cache",
                                   "Library/Caches/Google/Chrome/Default/Cache"],
        // Milestone 5 (Yellow): the poetry virtualenv that was a Green decoy is now offered by its own
        // Yellow rule (never preselected; preconditions olderThan(60) etc. checked at plan time).
        "poetry.virtualenvs": ["Library/Caches/pypoetry/virtualenvs/proj-py3.12"],
    ]

    /// Milestone 5: forbidden components a specific Yellow rule is allowed to contain.
    static let yellowAllowedComponents: [String: Set<String>] = [
        "poetry.virtualenvs": ["virtualenvs"],
        "browser.chromium.serviceWorkerCache": ["service worker"],
    ]

    static let expectedOwners: [String: String] = [
        "Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle": "com.example.Sparkly",
        "Library/Caches/com.example.Electrony.ShipIt": "com.example.Electrony",
        "Library/Saved Application State/com.example.Editor.savedState": "com.example.Editor",
        "Library/Caches/com.foo.App": "com.foo.App",
        "Library/Containers/com.foo.Sandboxed/Data/Library/Caches/WebKit": "com.foo.Sandboxed",
        "Library/Application Support/Slack/Cache": "com.tinyspeck.slackmacgap",
        "Library/Application Support/Slack/Code Cache": "com.tinyspeck.slackmacgap",
        "Library/Application Support/Slack/GPUCache": "com.tinyspeck.slackmacgap",
        "Library/Application Support/Google/Chrome/Default/Cache": "com.google.Chrome",
        "Library/Application Support/Google/Chrome/Default/Code Cache": "com.google.Chrome",
        "Library/Application Support/Google/Chrome/Default/GPUCache": "com.google.Chrome",
        "Library/Application Support/Google/Chrome/Profile 1/Cache": "com.google.Chrome",
        "Library/Caches/Google/Chrome/Default/Cache": "com.google.Chrome",
    ]

    /// Milestone 6 adds the OrphanDetector (it reads Containers / Group Containers), the Trash and the
    /// iOS backups advisory.
    static let fullDiskAccessRules: Set<String> = ["browser.safari.cache", "mail.downloads", "apps.containerCaches",
                                                   "leftovers.appData", "trash.empty", "advisory.iosBackups"]

    /// Milestone 6: rules that need a developer tool no fixture provides here (xcode-select, tmutil)
    /// report unavailable instead of offering anything.
    static let unavailableWithoutTools: Set<String> = ["xcode.extraInstalls", "advisory.timeMachineSnapshots"]

    /// Milestone 6: advisory targets are explanation-only: kind .advisory, nothing reclaimable.
    @MainActor
    static func checkAdvisory(_ result: RuleScanResult) throws {
        for target in result.targets {
            try TestSuite.assertEqual(target.kind, .advisory, result.rule.id)
            try TestSuite.assertEqual(target.reclaimableBytes, 0, result.rule.id)
            try TestSuite.assertTrue(target.identity == nil, result.rule.id)
        }
    }

    /// Never offered by any Green rule: browser/Electron storage that is not cache.
    static let forbiddenComponents: Set<String> = ["local storage", "indexeddb", "service worker", "cookies",
                                                   "session storage", "user", "virtualenvs", "guest profile"]

    /// Builds the realistic junk fixture (plus decoys that must NOT be found).
    static func buildFixture(_ f: FixtureBuilder) throws {
        for (_, paths) in expected {
            for rel in paths where !rel.hasSuffix(".ipsw") && !rel.hasSuffix(".log") && !rel.hasSuffix(".ips") {
                try f.file(rel + "/payload.bin", bytes: 12_000)
            }
        }
        try f.file("Library/iTunes/iPhone Software Updates/iPhone_17.ipsw", bytes: 50_000)
        try f.file("Library/iTunes/iPad Software Updates/iPad_17.ipsw", bytes: 40_000)
        try f.file("Library/Logs/SomeApp.log", bytes: 2_000)
        try f.file("Library/Logs/DiagnosticReports/App_2026-09-01.ips", bytes: 3_000)
        try f.file("Library/Caches/com.example.Sparkly/other.db", bytes: 100)

        // Decoys.
        try f.file("Library/iTunes/iPhone Software Updates/readme.txt", bytes: 10)
        try f.file("Library/Caches/pypoetry/virtualenvs/proj-py3.12/bin/python", bytes: 100)
        try f.file("Library/Application Support/Code/User/settings.json", bytes: 100)
        try f.file("Library/Application Support/Code/Backups/workspace.json", bytes: 100)
        try f.file("Library/Logs/iMop/imop.log", bytes: 100)
        try f.file("Library/Caches/com.notinstalled.App/data.bin", bytes: 100)
        try f.file("Library/Caches/com.apple.akd/data.bin", bytes: 100)
        try f.file("Library/Containers/com.notinstalled.Box/Data/Library/Caches/x/data.bin", bytes: 100)
        try f.file("Library/Containers/com.apple.Notes/Data/Library/Caches/x/data.bin", bytes: 100)
        try f.file("Library/Application Support/discord/Cache/data.bin", bytes: 100) // Discord not installed
        for name in ["Local Storage", "IndexedDB", "Service Worker", "Session Storage"] {
            try f.file("Library/Application Support/Slack/\(name)/data.bin", bytes: 100)
            try f.file("Library/Application Support/Google/Chrome/Default/\(name)/data.bin", bytes: 100)
        }
        try f.file("Library/Application Support/Google/Chrome/Default/Cookies", bytes: 100)
        try f.file("Library/Application Support/Google/Chrome/Guest Profile/Cache/data.bin", bytes: 100)
        try f.file("Library/Application Support/Google/Chrome/Default/Code Cache/js/index", bytes: 100)
        // Deny-listed candidate (protected extension) and symlinked candidates.
        try f.file("Library/Caches/CocoaPods/Old.photoslibrary/database/Photos.sqlite", bytes: 100)
        try f.file("outside/big.bin", bytes: 1 << 20, base: .root)
        try f.symlink("Library/Caches/CocoaPods/linked", to: f.path("outside", base: .root))
        try f.symlink("Library/Caches/pip/linked-wheels", to: f.path("outside", base: .root))
        try f.symlink("Library/Application Support/Slack/DawnCache", to: f.path("outside", base: .root))
    }

    @MainActor
    static func makeScanner(_ env: FakeEnvironment, fda: Bool = true, catalog: RuleCatalog? = nil) throws -> SafeCleanScanner {
        let catalog = try catalog ?? RuleCatalog.load(data: M2.sourceRulesData(), environment: env.environment)
        return SafeCleanScanner(environment: env.environment, catalog: catalog,
                                inspectors: try M6.fixtureInspectors(env.fixture), hasFullDiskAccess: fda,
                                waivedSystemRoots: [env.fixture.root])
    }

    @MainActor
    static func withScanEnv(_ body: (FakeEnvironment) async throws -> Void) async throws {
        try await M1.withEnv { env in
            env.applications.applicationURLs = installedApps
            try buildFixture(env.fixture)
            try await body(env)
        }
    }

    static func relative(_ path: String, _ f: FixtureBuilder) -> String {
        path.hasPrefix(f.home + "/") ? String(path.dropFirst(f.home.count + 1)) : path
    }

    static func byRule(_ results: [RuleScanResult]) -> [String: RuleScanResult] {
        Dictionary(uniqueKeysWithValues: results.map { ($0.rule.id, $0) })
    }

    @MainActor
    static func runAll() async {
        print("\n🔎 Running SafeClean Scanner Tests (spec §3.1, §7.2)...")

        await TestSuite.run("Scanner: a realistic fixture home yields exactly the expected targets for every Green rule") {
            try await withScanEnv { env in
                let f = env.fixture
                let results = try await makeScanner(env).scan()
                try TestSuite.assertEqual(Set(results.map(\.rule.id)), M2.expectedBundledRuleIDs)
                for result in results {
                    if M2.m4CommandRuleIDs.contains(result.rule.id) {
                        // No vendor tool resolves in this fixture: command rules offer nothing.
                        try TestSuite.assertEqual(result.targets.count, 0, result.rule.id)
                        continue
                    }
                    if result.rule.usesProjectRoots || unavailableWithoutTools.contains(result.rule.id) {
                        // Milestone 5: no project roots are configured by default → unavailable, nothing offered.
                        guard case .unavailable = result.status else { throw TestError("\(result.rule.id): \(result.status)") }
                        try TestSuite.assertEqual(result.targets.count, 0, result.rule.id)
                        continue
                    }
                    try TestSuite.assertEqual(result.status, .ok, result.rule.id)
                    if result.rule.tier == .advisory {
                        try checkAdvisory(result)
                        continue
                    }
                    let found = Set(result.targets.map { relative($0.path, f) })
                    try TestSuite.assertEqual(found, expected[result.rule.id] ?? [], result.rule.id)
                    try TestSuite.assertEqual(found.count, result.targets.count, "\(result.rule.id): duplicates")
                }
            }
        }

        await TestSuite.run("Scanner: targets carry rule id, kind, identity, owner, sizes and lastUsed") {
            try await withScanEnv { env in
                let f = env.fixture
                let results = try await makeScanner(env).scan()
                var seen = 0
                for result in results where result.rule.tier != .advisory {
                    for target in result.targets {
                        seen += 1
                        let rel = relative(target.path, f)
                        try TestSuite.assertEqual(target.ruleID, result.rule.id, rel)
                        try TestSuite.assertEqual(target.kind, .filesystem, rel)
                        guard let stat = env.fileSystem.lstat(target.path) else { throw TestError("lstat \(rel)") }
                        try TestSuite.assertEqual(target.identity, stat.identity, rel)
                        try TestSuite.assertTrue(target.allocatedBytes > 0, "\(rel): \(target.allocatedBytes)")
                        try TestSuite.assertTrue(target.reclaimableBytes > 0 && target.reclaimableBytes <= target.allocatedBytes, rel)
                        try TestSuite.assertEqual(target.allocatedBytes, M2.treeBlocksBytes(target.path), rel)
                        try TestSuite.assertTrue(target.itemCount >= 1, rel)
                        try TestSuite.assertTrue(target.lastUsed != nil, rel)
                        try TestSuite.assertFalse(target.displayName.isEmpty, rel)
                        try TestSuite.assertEqual(target.owningBundleID, expectedOwners[rel], rel)
                    }
                }
                try TestSuite.assertEqual(seen, expected.values.reduce(0) { $0 + $1.count })
            }
        }

        await TestSuite.run("Scanner: lastUsed is the newest mtime of the target and its immediate children") {
            try await withScanEnv { env in
                let f = env.fixture
                try f.file("Library/Caches/pip/http/fresh.bin", bytes: 10)
                try f.file("Library/Caches/pip/http/deep/deeper/newest.bin", bytes: 10)
                try f.setModificationDate("Library/Caches/pip/http/payload.bin", daysAgo: 20, clock: env.clock)
                try f.setModificationDate("Library/Caches/pip/http/fresh.bin", daysAgo: 3, clock: env.clock)
                try f.setModificationDate("Library/Caches/pip/http/deep", daysAgo: 30, clock: env.clock)
                try f.setModificationDate("Library/Caches/pip/http", daysAgo: 40, clock: env.clock)
                // The single-file target uses its own mtime.
                try f.setModificationDate("Library/Logs/SomeApp.log", daysAgo: 9, clock: env.clock)

                let results = byRule(try await makeScanner(env).scan(ruleIDs: ["pip.cache", "logs.user"]))
                guard let pip = results["pip.cache"]?.targets.first else { throw TestError("no pip target") }
                let expectedPip = env.clock.now.addingTimeInterval(-3 * 86_400)
                try TestSuite.assertTrue(abs((pip.lastUsed ?? .distantPast).timeIntervalSince(expectedPip)) < 2,
                                         "lastUsed \(String(describing: pip.lastUsed)) expected \(expectedPip)")
                guard let log = results["logs.user"]?.targets.first(where: { $0.path.hasSuffix("SomeApp.log") }) else {
                    throw TestError("no log target")
                }
                let expectedLog = env.clock.now.addingTimeInterval(-9 * 86_400)
                try TestSuite.assertTrue(abs((log.lastUsed ?? .distantPast).timeIntervalSince(expectedLog)) < 2)
            }
        }

        await TestSuite.run("Scanner: deny-listed and symlinked candidates are skipped; nothing outside the home is sized") {
            try await withScanEnv { env in
                let f = env.fixture
                let results = try await makeScanner(env).scan()
                for result in results where result.rule.tier == .advisory { try checkAdvisory(result) }
                let all = results.filter { $0.rule.tier != .advisory }.flatMap(\.targets)
                for target in all {
                    let rel = relative(target.path, f)
                    try TestSuite.assertTrue(target.path.hasPrefix(f.home + "/"), target.path)
                    try TestSuite.assertFalse(rel.lowercased().contains("photoslibrary"), rel)
                    try TestSuite.assertFalse(rel.hasSuffix("linked") || rel.hasSuffix("linked-wheels") || rel.hasSuffix("DawnCache"), rel)
                    let components = Set(rel.split(separator: "/").map { $0.lowercased() })
                    let forbidden = forbiddenComponents.subtracting(yellowAllowedComponents[target.ruleID] ?? [])
                    try TestSuite.assertTrue(components.isDisjoint(with: forbidden), "\(target.ruleID): \(rel)")
                }
                // The 1 MiB file behind the symlinks is never counted.
                let pip = byRule(results)["pip.cache"]?.allocatedBytes ?? 0
                try TestSuite.assertTrue(pip < 1 << 20, "\(pip)")
            }
        }

        await TestSuite.run("Scanner: a symlinked candidate is skipped even when it is the only match") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("outside/x/data.bin", bytes: 100, base: .root)
                try f.symlink("Library/Caches/CocoaPods/Pods", to: f.path("outside/x", base: .root))
                try f.symlink("Library/Logs/JetBrains", to: f.path("outside", base: .root))
                let results = byRule(try await makeScanner(env).scan(ruleIDs: ["cocoapods.cache", "jetbrains.logs", "logs.user"]))
                try TestSuite.assertEqual(results["cocoapods.cache"]?.targets.count, 0)
                try TestSuite.assertEqual(results["jetbrains.logs"]?.targets.count, 0)
                try TestSuite.assertEqual(results["logs.user"]?.targets.count, 0)
            }
        }

        await TestSuite.run("Scanner: without the fixture waiver the deny-listed temp home yields nothing") {
            try await withScanEnv { env in
                let catalog = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                let scanner = SafeCleanScanner(environment: env.environment, catalog: catalog,
                                               inspectors: try M6.fixtureInspectors(env.fixture), hasFullDiskAccess: true)
                let results = await scanner.scan()
                // Milestone 6: explanation-only advisory items (never actionable) may still be listed.
                for result in results where result.rule.tier == .advisory { try checkAdvisory(result) }
                try TestSuite.assertEqual(results.filter { $0.rule.tier != .advisory }.flatMap(\.targets).count, 0,
                                          "/private/var/folders is deny-listed")
            }
        }

        await TestSuite.run("Scanner: Full Disk Access rules are locked without FDA; the others still scan") {
            try await withScanEnv { env in
                let results = try await makeScanner(env, fda: false).scan()
                for result in results {
                    if fullDiskAccessRules.contains(result.rule.id) {
                        try TestSuite.assertEqual(result.status, .lockedNeedsFullDiskAccess, result.rule.id)
                        try TestSuite.assertEqual(result.targets.count, 0, result.rule.id)
                    } else if M2.m4CommandRuleIDs.contains(result.rule.id) {
                        // Milestone 4: a command rule whose tool does not resolve fails closed
                        // (.unavailable, no targets); none needs Full Disk Access.
                        try TestSuite.assertTrue(result.status != .lockedNeedsFullDiskAccess, result.rule.id)
                        try TestSuite.assertEqual(result.targets.count, 0, result.rule.id)
                    } else if result.rule.usesProjectRoots || unavailableWithoutTools.contains(result.rule.id) {
                        // Milestone 5: no project roots configured → unavailable (never FDA-locked).
                        guard case .unavailable = result.status else { throw TestError("\(result.rule.id): \(result.status)") }
                        try TestSuite.assertEqual(result.targets.count, 0, result.rule.id)
                    } else if result.rule.tier == .advisory {
                        try TestSuite.assertEqual(result.status, .ok, result.rule.id)
                        try checkAdvisory(result)
                    } else {
                        try TestSuite.assertEqual(result.status, .ok, result.rule.id)
                        try TestSuite.assertEqual(result.targets.count, expected[result.rule.id]?.count ?? 0, result.rule.id)
                    }
                }
                // Locked rules never even looked at their folders.
                let listed = env.fileSystem.recordedCalls.filter { $0.0 == .contentsOfDirectory }.map(\.1)
                // (The Sparkle glob `Caches/*/org.sparkle-project.Sparkle` may list com.apple.Safari itself, never below it.)
                try TestSuite.assertFalse(listed.contains { $0.contains("com.apple.Safari/") || $0.contains("Mail Downloads") || $0.contains("Library/Containers") },
                                          "\(listed.filter { $0.contains("Containers") || $0.contains("Safari") })")
            }
        }

        await TestSuite.run("Scanner: overlap — equal tier drops the ancestor (userCaches folder vs its Sparkle child)") {
            try await withScanEnv { env in
                let f = env.fixture
                env.applications.applicationURLs = installedApps.merging(["com.example.Sparkly": [URL(fileURLWithPath: "/Applications/Sparkly.app")]]) { a, _ in a }
                let results = byRule(try await makeScanner(env).scan(ruleIDs: ["apps.userCaches", "apps.sparkleUpdates"]))
                try TestSuite.assertEqual(Set(results["apps.userCaches"]?.targets.map { relative($0.path, f) } ?? []), ["Library/Caches/com.foo.App"])
                try TestSuite.assertEqual(Set(results["apps.sparkleUpdates"]?.targets.map { relative($0.path, f) } ?? []),
                                          ["Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle"])
            }
        }

        await TestSuite.run("Scanner: overlap — the less cautious tier is dropped; equal paths keep one target") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Library/Caches/com.overlap.test/inner/data.bin", bytes: 100)
                try f.file("Library/Caches/com.rev.test/inner/data.bin", bytes: 100)
                try f.file("Library/Caches/com.same.test/inner/data.bin", bytes: 100)
                let rules = [
                    M1.rule(id: "test.greenChild", allowRoots: ["{HOME}/Library/Caches/com.overlap.test"],
                            discovery: .glob(["{HOME}/Library/Caches/com.overlap.test/*"])),
                    M1.rule(id: "test.yellowParent", tier: .yellow, action: .trash,
                            discovery: .glob(["{HOME}/Library/Caches/com.overlap.*"])),
                    M1.rule(id: "test.greenParent", discovery: .glob(["{HOME}/Library/Caches/com.rev.*"])),
                    M1.rule(id: "test.yellowChild", tier: .yellow, allowRoots: ["{HOME}/Library/Caches/com.rev.test"], action: .trash,
                            discovery: .glob(["{HOME}/Library/Caches/com.rev.test/*"])),
                    M1.rule(id: "test.dupA", allowRoots: ["{HOME}/Library/Caches/com.same.test"],
                            discovery: .glob(["{HOME}/Library/Caches/com.same.test/*"])),
                    M1.rule(id: "test.dupB", allowRoots: ["{HOME}/Library/Caches/com.same.test"],
                            discovery: .glob(["{HOME}/Library/Caches/com.same.test/*"])),
                ]
                let catalog = RuleCatalog(validating: rules, environment: env.environment)
                try TestSuite.assertEqual(catalog.disabled, [])
                let results = byRule(try await makeScanner(env, catalog: catalog).scan())
                func paths(_ id: String) -> Set<String> { Set(results[id]?.targets.map { relative($0.path, f) } ?? []) }
                try TestSuite.assertEqual(paths("test.yellowParent"), ["Library/Caches/com.overlap.test"])
                try TestSuite.assertEqual(paths("test.greenChild"), [], "green child inside a yellow target is dropped")
                try TestSuite.assertEqual(paths("test.yellowChild"), ["Library/Caches/com.rev.test/inner"])
                try TestSuite.assertEqual(paths("test.greenParent"), [], "green ancestor of a yellow target is dropped")
                try TestSuite.assertEqual(paths("test.dupA").count + paths("test.dupB").count, 1, "equal paths keep exactly one")
                try TestSuite.assertEqual(paths("test.dupA"), ["Library/Caches/com.same.test/inner"])
            }
        }

        await TestSuite.run("Scanner: appUserCaches only offers installed non-Apple apps; lookup failure offers nothing") {
            try await withScanEnv { env in
                let f = env.fixture
                var results = byRule(try await makeScanner(env).scan(ruleIDs: ["apps.userCaches"]))
                try TestSuite.assertEqual(Set(results["apps.userCaches"]?.targets.map { relative($0.path, f) } ?? []), ["Library/Caches/com.foo.App"])
                env.applications.failing = true
                results = byRule(try await makeScanner(env).scan(ruleIDs: ["apps.userCaches", "apps.electronCaches", "browser.chromium.cache"]))
                for id in ["apps.userCaches", "apps.electronCaches", "browser.chromium.cache"] {
                    try TestSuite.assertEqual(results[id]?.targets.count, 0, id)
                }
            }
        }

        await TestSuite.run("Scanner: a declined Containers listing reports unavailable instead of crashing") {
            try await withScanEnv { env in
                // Both spellings of the home (`homePath` is the standardized /var/… form).
                env.fileSystem.fail(.contentsOfDirectory, path: env.fixture.path("Library/Containers"))
                env.fileSystem.fail(.contentsOfDirectory, path: env.environment.homePath + "/Library/Containers")
                let results = byRule(try await makeScanner(env).scan(ruleIDs: ["apps.containerCaches"]))
                try TestSuite.assertEqual(results["apps.containerCaches"]?.status, .unavailable("Access was declined"))
                try TestSuite.assertEqual(results["apps.containerCaches"]?.targets.count, 0)
            }
        }

        await TestSuite.run("Scanner: unimplemented inspectors and command rules report unavailable") {
            try await M1.withEnv { env in
                // Milestone 6: every pinned inspector id is implemented; an unpinned id whose inspector
                // is not registered stands in for "unimplemented".
                let rules = [
                    M1.rule(id: "test.inspector", discovery: .inspector(.electronCaches)),
                    M1.rule(id: "test.command", tier: .yellow,
                            action: .command(CommandSpec(tool: "brew", arguments: ["cleanup", "--prune=all"], idempotentSafe: true)),
                            discovery: .command(CommandSpec(tool: "brew", arguments: ["cleanup", "--prune=all", "-n"], idempotentSafe: true))),
                ]
                let catalog = RuleCatalog(validating: rules, environment: env.environment)
                try TestSuite.assertEqual(catalog.rules.count, 2, "\(catalog.disabled)")
                let inspectors = try M6.fixtureInspectors(env.fixture).filter { $0.id != .electronCaches }
                let scanner = SafeCleanScanner(environment: env.environment, catalog: catalog, inspectors: inspectors,
                                               hasFullDiskAccess: true, waivedSystemRoots: [env.fixture.root])
                let results = byRule(await scanner.scan())
                for id in ["test.inspector", "test.command"] {
                    try TestSuite.assertEqual(results[id]?.status, .unavailable("Available in a later milestone"), id)
                    try TestSuite.assertEqual(results[id]?.targets.count, 0, id)
                }
                try TestSuite.assertTrue(env.commands.invocations.isEmpty, "the scanner never runs commands")
            }
        }

        await TestSuite.run("Scanner: honours ruleIDs, reports progress per rule and caches the session result in memory") {
            try await withScanEnv { env in
                final class Events: @unchecked Sendable {
                    let lock = NSLock(); var items: [ScanProgressEvent] = []
                    func add(_ e: ScanProgressEvent) { lock.lock(); items.append(e); lock.unlock() }
                    var all: [ScanProgressEvent] { lock.lock(); defer { lock.unlock() }; return items }
                }
                let events = Events()
                let scanner = try makeScanner(env)
                try TestSuite.assertTrue(await scanner.cachedResults() == nil)
                let results = await scanner.scan(ruleIDs: ["pip.cache", "logs.user"]) { events.add($0) }
                try TestSuite.assertEqual(results.map(\.rule.id).sorted(), ["logs.user", "pip.cache"])
                let finished = events.all.filter(\.finished)
                try TestSuite.assertEqual(Set(finished.map(\.ruleID)), ["pip.cache", "logs.user"])
                try TestSuite.assertEqual(finished.first { $0.ruleID == "logs.user" }?.targetsFound, 2)
                try TestSuite.assertEqual(finished.first { $0.ruleID == "pip.cache" }?.category, .developer)
                try TestSuite.assertTrue((finished.first { $0.ruleID == "pip.cache" }?.bytesFound ?? 0) > 0)
                let cached = await scanner.cachedResults()
                try TestSuite.assertEqual(cached?.map(\.rule.id).sorted(), ["logs.user", "pip.cache"])
            }
        }

        await TestSuite.run("Scanner: cancellation yields no targets and is not cached") {
            try await withScanEnv { env in
                let scanner = try makeScanner(env)
                let task = Task.detached { () -> [RuleScanResult] in
                    withUnsafeCurrentTask { $0?.cancel() }
                    return await scanner.scan()
                }
                let results = await task.value
                try TestSuite.assertEqual(results.flatMap(\.targets).count, 0)
                for result in results {
                    if case .failed = result.status { continue }
                    throw TestError("\(result.rule.id): expected .failed after cancellation, got \(result.status)")
                }
                try TestSuite.assertTrue(await scanner.cachedResults() == nil)
            }
        }

        await TestSuite.run("Scanner: scanning is read-only (fixture tree is unchanged)") {
            try await withScanEnv { env in
                func snapshot() -> [String: Date] {
                    var out: [String: Date] = [:]
                    let root = env.fixture.root
                    guard let walker = FileManager.default.enumerator(atPath: root) else { return out }
                    while let rel = walker.nextObject() as? String {
                        var st = Darwin.stat()
                        if Darwin.lstat(root + "/" + rel, &st) == 0 {
                            out[rel] = Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec))
                        }
                    }
                    return out
                }
                // (Built first: the fixture-rooted M6 inspectors create their fixture folders.)
                let scanner = try makeScanner(env)
                let before = snapshot()
                _ = await scanner.scan()
                try TestSuite.assertEqual(snapshot(), before)
                let methods = Set(env.fileSystem.recordedCalls.map(\.0))
                try TestSuite.assertFalse(methods.contains(.readFile), "\(methods)")
            }
        }
    }
}
