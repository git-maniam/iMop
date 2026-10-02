import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Milestone 5 (spec §6.2, §6.3, §6.6–§6.8): VS Code old extensions, JetBrains caches, unknown-owner
/// caches, Chromium service-worker caches, Lightroom previews, AI model caches, Adobe media cache and
/// the remaining Yellow glob rules.
struct OtherYellowInspectorTests {
    static let extensions = ".vscode/extensions"
    static let jetbrains = "Library/Caches/JetBrains"

    @MainActor
    static func runAll() async {
        print("\n🧩 Running Milestone 5 editor / app / media / AI inspector tests (spec §6.2–§6.8)...")
        await vscodeTests()
        await jetbrainsTests()
        await unknownOwnerTests()
        await serviceWorkerTests()
        await lightroomTests()
        await globRuleTests()
    }

    // MARK: VS Code

    /// One `extensions.json` entry in VS Code's format.
    static func entry(_ id: String, _ version: String, home: String, relative: Bool = true, fsPath: Bool = true) -> [String: Any] {
        var e: [String: Any] = ["identifier": ["id": id, "uuid": "00000000-0000-0000-0000-000000000000"], "version": version,
                                "metadata": ["installedTimestamp": 1_700_000_000_000]]
        let folder = "\(id)-\(version)"
        if fsPath { e["location"] = ["$mid": 1, "fsPath": home + "/.vscode/extensions/" + folder, "scheme": "file"] }
        if relative { e["relativeLocation"] = folder }
        return e
    }

    @MainActor
    static func vscodeTests() async {
        await TestSuite.run("VSCode: an old version is offered only when a newer one exists AND extensions.json no longer references it") {
            try await M1.withEnv { env in
                let f = env.fixture
                let folders = ["ms-python.python-2024.2.1", "ms-python.python-2024.4.0",
                               "golang.go-0.40.0", "golang.go-0.41.0",
                               "ms-vscode.cpptools-1.20.5-darwin-arm64", "ms-vscode.cpptools-1.21.0-darwin-x64",
                               "esbenp.prettier-vscode-10.1.0",
                               "a.b-1.0.0", "a.b-1.1.0", "a.b-2.0.0", "a.b-1.10.0",
                               "not-an-extension", "x.y-1.0", "x.y-2.0.0"]
                for folder in folders { try f.file(extensions + "/" + folder + "/package.json", bytes: 200) }
                try f.file(extensions + "/.obsolete", contents: Data("{}".utf8))
                try f.symlink(extensions + "/a.b-0.9.0", to: f.path("elsewhere", base: .root))
                let manifest: [[String: Any]] = [
                    entry("ms-python.python", "2024.4.0", home: f.home),
                    entry("golang.go", "0.41.0", home: f.home), entry("golang.go", "0.40.0", home: f.home, fsPath: false),
                    entry("ms-vscode.cpptools", "1.21.0", home: f.home),
                    entry("esbenp.prettier-vscode", "10.1.0", home: f.home),
                    entry("a.b", "2.0.0", home: f.home, relative: false),
                    entry("a.b", "1.1.0", home: f.home, relative: false, fsPath: false),
                    entry("x.y", "2.0.0", home: f.home),
                ]
                try f.file(extensions + "/extensions.json", contents: try M5.jsonData(manifest))

                let expected: Set<String> = [extensions + "/ms-python.python-2024.2.1", extensions + "/a.b-1.0.0", extensions + "/a.b-1.10.0"]
                let out = try await M5.discover(VSCodeExtensionsInspector(), env, "vscode.oldExtensions")
                try TestSuite.assertEqual(out.status, .ok)
                try TestSuite.assertEqual(M5.paths(out, f), expected)
                try TestSuite.assertTrue(out.candidates.allSatisfy { $0.owningBundleID == "com.microsoft.VSCode" })
                let results = try await M5.scan(env, ["vscode.oldExtensions"])
                try TestSuite.assertEqual(M5.paths(results["vscode.oldExtensions"], f), expected)

                // VS Code running blocks; never preselected.
                var plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { $0.isActionable && !$0.selectedByDefault }, "\(plan.items.map(\.preconditions))")
                env.runningApplications.ids = ["com.microsoft.VSCode"]
                plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.isActionable && M5.failedPrecondition($0) == "appNotRunning" })

                // Folder-name parsing.
                let parsed = try M5.unwrap(VSCodeExtensionsInspector.parseFolderName("ms-vscode.cpptools-1.20.5-darwin-arm64"))
                try TestSuite.assertEqual(parsed.id, "ms-vscode.cpptools")
                try TestSuite.assertEqual(parsed.version, [1, 20, 5])
                try TestSuite.assertEqual(parsed.target, "darwin-arm64")
                for bad in ["not-an-extension", "x.y-1.0", ".obsolete", "noversion.ext", "a.b-1.0.0.0"] {
                    try TestSuite.assertNil(VSCodeExtensionsInspector.parseFolderName(bad), bad)
                }
            }
        }

        await TestSuite.run("VSCode: a missing, unparsable or not-understood extensions.json offers nothing") {
            try await M1.withEnv { env in
                let f = env.fixture
                for folder in ["ms-python.python-2024.2.1", "ms-python.python-2024.4.0"] {
                    try f.file(extensions + "/" + folder + "/package.json", bytes: 200)
                }
                @MainActor func offered() async throws -> Int {
                    let out = try await M5.discover(VSCodeExtensionsInspector(), env, "vscode.oldExtensions")
                    try TestSuite.assertEqual(out.status, .ok)
                    return out.candidates.count
                }
                try TestSuite.assertEqual(try await offered(), 0, "missing")
                let manifestPath = extensions + "/extensions.json"
                for bad in [Data("not json".utf8), Data("{\"a\": 1}".utf8), try M5.jsonData([["foo": 1]]),
                            try M5.jsonData([entry("ms-python.python", "2024.4.0", home: f.home), "string entry"])] {
                    try f.file(manifestPath, contents: bad)
                    try TestSuite.assertEqual(try await offered(), 0, String(decoding: bad, as: UTF8.self))
                }
                // A symlinked extensions.json is never read.
                try f.file("real.json", contents: try M5.jsonData([entry("ms-python.python", "2024.4.0", home: f.home)]), base: .root)
                try FileManager.default.removeItem(atPath: f.path(manifestPath))
                try f.symlink(manifestPath, to: f.path("real.json", base: .root))
                try TestSuite.assertEqual(try await offered(), 0, "symlinked manifest")
                // Sanity: a real one works.
                try FileManager.default.removeItem(atPath: f.path(manifestPath))
                try f.file(manifestPath, contents: try M5.jsonData([entry("ms-python.python", "2024.4.0", home: f.home)]))
                try TestSuite.assertEqual(try await offered(), 1)
            }
        }
    }

    // MARK: JetBrains

    /// A fake installed JetBrains app inside the fixture root (`version` nil = no Info.plist).
    @MainActor
    static func app(_ f: FixtureBuilder, _ name: String, version: String?) throws -> URL {
        let rel = "Applications/\(name).app"
        try f.dir(rel + "/Contents/MacOS", base: .root)
        if let version {
            try f.file(rel + "/Contents/Info.plist", contents: try M5.plistData(["CFBundleShortVersionString": version]), base: .root)
        }
        return URL(fileURLWithPath: f.path(rel, base: .root))
    }

    @MainActor
    static func jetbrainsTests() async {
        await TestSuite.run("JetBrains: a cache is orphaned only for a KNOWN product with no installed app of that major.minor; unknown → current; failed lookups → current") {
            try await M1.withEnv { env in
                let f = env.fixture
                for name in ["IntelliJIdea2024.1", "IntelliJIdea2024.3", "PyCharm2023.2", "WebStorm2024.2", "Foo2024.2",
                             "Toolbox", "GoLand2024.1.2", "log"] {
                    try f.file(jetbrains + "/" + name + "/caches/data.bin", bytes: 1_000)
                }
                let idea = try app(f, "IntelliJ IDEA", version: "2024.3.1")
                let webstorm = try app(f, "WebStorm", version: nil) // unreadable version
                env.applications.applicationURLs = ["com.jetbrains.intellij": [idea], "com.jetbrains.WebStorm": [webstorm]]

                @MainActor func split() async throws -> (orphaned: Set<String>, current: Set<String>) {
                    let o = try await M5.discover(JetBrainsCachesInspector(), env, "jetbrains.caches.orphanedVersion")
                    let c = try await M5.discover(JetBrainsCachesInspector(), env, "jetbrains.caches.current")
                    try TestSuite.assertEqual(o.status, .ok)
                    try TestSuite.assertEqual(c.status, .ok)
                    let strip = { (s: Set<String>) in Set(s.map { String($0.dropFirst(jetbrains.count + 1)) }) }
                    return (strip(M5.paths(o, f)), strip(M5.paths(c, f)))
                }
                var r = try await split()
                // Review M5: no PyCharm found at all → CURRENT (it may be installed but unregistered).
                try TestSuite.assertEqual(r.orphaned, ["IntelliJIdea2024.1"])
                try TestSuite.assertEqual(r.current, ["IntelliJIdea2024.3", "PyCharm2023.2", "WebStorm2024.2", "Foo2024.2"])
                let o = try await M5.discover(JetBrainsCachesInspector(), env, "jetbrains.caches.orphanedVersion")
                try TestSuite.assertEqual(Set(o.candidates.compactMap(\.owningBundleID)), ["com.jetbrains.intellij"])

                // Spotlight can reveal MORE installed copies (PyCharm 2023.2 elsewhere) → current, never fewer.
                let pycharm = try app(f, "PyCharm", version: "2023.2.5")
                env.applications.spotlightPaths = ["com.jetbrains.pycharm": [pycharm.path]]
                r = try await split()
                try TestSuite.assertEqual(r.orphaned, ["IntelliJIdea2024.1"])
                env.applications.spotlightFailing = true
                r = try await split()
                try TestSuite.assertEqual(r.orphaned, ["IntelliJIdea2024.1"], "a failed Spotlight query only removes extra copies")
                env.applications.spotlightFailing = false
                env.applications.spotlightPaths = [:]

                // LaunchServices fails → nothing is orphaned; every parsable folder is current.
                env.applications.failing = true
                r = try await split()
                try TestSuite.assertEqual(r.orphaned, [])
                try TestSuite.assertEqual(r.current, ["IntelliJIdea2024.1", "IntelliJIdea2024.3", "PyCharm2023.2", "WebStorm2024.2", "Foo2024.2"])
                env.applications.failing = false

                // Through the Scanner: Green orphaned (preselected when allowed), Yellow current (never); any JetBrains IDE running blocks.
                let ids: Set<String> = ["jetbrains.caches.orphanedVersion", "jetbrains.caches.current"]
                let results = try await M5.scan(env, ids)
                try TestSuite.assertEqual(Set(M5.paths(results["jetbrains.caches.orphanedVersion"], f).map { String($0.dropFirst(jetbrains.count + 1)) }),
                                          ["IntelliJIdea2024.1"])
                try TestSuite.assertEqual(Set(M5.paths(results["jetbrains.caches.current"], f).map { String($0.dropFirst(jetbrains.count + 1)) }),
                                          ["IntelliJIdea2024.3", "PyCharm2023.2", "WebStorm2024.2", "Foo2024.2"])
                var plan = await M5.plan(env, Array(results.values))
                for item in plan.items {
                    try TestSuite.assertTrue(item.isActionable, "\(item.target.path): \(item.preconditions.filter { !$0.passed })")
                    try TestSuite.assertEqual(item.selectedByDefault, item.rule.tier == .green, item.target.path)
                }
                env.runningApplications.ids = ["com.jetbrains.goland"]
                plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.isActionable && !$0.selectedByDefault })

                // The matcher refuses an "orphaned" target without its known product owner.
                let home = CanonicalPath(validatedPath: f.home)
                let matcher = RuleTargetMatcher(homeForms: [home])
                let orphanRule = try M5.rule(env, "jetbrains.caches.orphanedVersion")
                let foo = home.appending("Library").appending("Caches").appending("JetBrains").appending("Foo2024.2")
                try TestSuite.assertTrue(matcher.mismatch(foo, rule: orphanRule, owningBundleID: nil) != nil)
                try TestSuite.assertTrue(matcher.mismatch(foo, rule: orphanRule, owningBundleID: "com.jetbrains.foo") != nil)
                try TestSuite.assertNil(matcher.mismatch(foo, rule: try M5.rule(env, "jetbrains.caches.current"), owningBundleID: nil))
                let ideaPath = home.appending("Library").appending("Caches").appending("JetBrains").appending("IntelliJIdea2024.1")
                try TestSuite.assertNil(matcher.mismatch(ideaPath, rule: orphanRule, owningBundleID: "com.jetbrains.intellij"))
                try TestSuite.assertTrue(matcher.mismatch(ideaPath, rule: orphanRule, owningBundleID: "com.jetbrains.pycharm") != nil)
            }
        }

        await TestSuite.run("JetBrains: folder-name parsing and the product table") {
            let p = try M5.unwrap(JetBrainsCachesInspector.parseFolderName("IntelliJIdea2024.1"))
            try TestSuite.assertEqual(p.product, "IntelliJIdea")
            try TestSuite.assertEqual(p.version, [2024, 1])
            for bad in ["Toolbox", "GoLand2024.1.2", "2024.1", "Idea-2024.1", "PyCharm2024", "PyCharm2024."] {
                try TestSuite.assertNil(JetBrainsCachesInspector.parseFolderName(bad), bad)
            }
            try TestSuite.assertEqual(JetBrainsCachesInspector.bundleID(forProduct: "AndroidStudio"), "com.google.android.studio")
            try TestSuite.assertEqual(JetBrainsCachesInspector.bundleID(forProduct: "IdeaIC"), "com.jetbrains.intellij.ce")
            try TestSuite.assertNil(JetBrainsCachesInspector.bundleID(forProduct: "Fleet"))
            try TestSuite.assertEqual(JetBrainsCachesInspector.productBundleIDs.count, 12)
        }
    }

    // MARK: apps.userCaches.unknownOwner

    @MainActor
    static func unknownOwnerTests() async {
        await TestSuite.run("UnknownOwner: offers only unresolvable, non-Apple, non-reserved Library/Caches folders; a failed lookup offers nothing") {
            try await M1.withEnv { env in
                let f = env.fixture
                env.applications.applicationURLs = ["com.foo.App": [URL(fileURLWithPath: "/Applications/Foo.app")]]
                let offeredNames = ["com.gone.Tool", "SomeOldTool"]
                let keptNames = ["com.foo.App", "com.foo.App.helper", "com.apple.akd", "com.apple.Safari", "Homebrew", "pip", "CocoaPods",
                                 "org.swift.swiftpm", "org.carthage.CarthageKit", "pypoetry", "ms-playwright", "JetBrains", "Firefox",
                                 "Google", "Microsoft Edge", "BraveSoftware", "Vivaldi", "Arc", "Yarn", "com.example.Electrony.ShipIt",
                                 ".hidden", "Adobe", "iMop"]
                for name in offeredNames + keptNames { try f.file("Library/Caches/\(name)/data.bin", bytes: 500) }
                // A not-installed app holding a Sparkle download: owned by apps.sparkleUpdates' glob → never unknown-owner.
                try f.file("Library/Caches/com.example.Sparkly/org.sparkle-project.Sparkle/u.zip", bytes: 500)
                try f.file("Library/Caches/loose-file.db", bytes: 500)
                try f.file("elsewhere/x", bytes: 1, base: .root)
                try f.symlink("Library/Caches/com.linked.App", to: f.path("elsewhere", base: .root))

                let out = try await M5.discover(UnknownOwnerCachesInspector(catalog: try M5.catalog(env)), env, "apps.userCaches.unknownOwner")
                try TestSuite.assertEqual(out.status, .ok)
                try TestSuite.assertEqual(M5.paths(out, f), Set(offeredNames.map { "Library/Caches/" + $0 }))
                try TestSuite.assertTrue(out.candidates.allSatisfy { $0.owningBundleID == nil })

                let results = try await M5.scan(env, ["apps.userCaches.unknownOwner"])
                try TestSuite.assertEqual(M5.paths(results["apps.userCaches.unknownOwner"], f), Set(offeredNames.map { "Library/Caches/" + $0 }))
                // olderThan(30): fresh folders are blocked; never preselected.
                let plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.selectedByDefault && M5.failedPrecondition($0) == "olderThan" })

                env.applications.failing = true
                let failed = try await M5.discover(UnknownOwnerCachesInspector(catalog: try M5.catalog(env)), env, "apps.userCaches.unknownOwner")
                try TestSuite.assertEqual(M5.paths(failed, f), [], "a failed app lookup withholds every folder")
                // A folder named like a bundle (".App" suffix) is never offered.
                env.applications.failing = false
                try f.file("Library/Caches/com.gone.App/data.bin", bytes: 10)
                let bundleLike = try await M5.discover(UnknownOwnerCachesInspector(catalog: try M5.catalog(env)), env, "apps.userCaches.unknownOwner")
                try TestSuite.assertFalse(M5.paths(bundleLike, f).contains("Library/Caches/com.gone.App"))
                // Without a catalog the inspector refuses.
                let empty = RuleCatalog(validating: [], environment: env.environment)
                let none = try await M5.discover(UnknownOwnerCachesInspector(catalog: empty), env, "apps.userCaches.unknownOwner")
                guard case .unavailable = none.status else { throw TestError("\(none.status)") }
            }
        }

        await TestSuite.run("UnknownOwner: never swallows a Green target — the realistic fixture keeps every Green target with the Yellow rule scanned too") {
            try await SafeCleanScannerTests.withScanEnv { env in
                let f = env.fixture
                try f.file("Library/Caches/com.notinstalled.Widget/data.bin", bytes: 1_000)
                let results = try M5.scanner(env)
                let all = await results.scan()
                let byID = Dictionary(uniqueKeysWithValues: all.map { ($0.rule.id, $0) })
                for (id, paths) in SafeCleanScannerTests.expected {
                    try TestSuite.assertEqual(M5.paths(byID[id], f), paths, id)
                }
                let unknown = M5.paths(byID["apps.userCaches.unknownOwner"], f)
                try TestSuite.assertEqual(unknown, ["Library/Caches/com.notinstalled.Widget"])
                // No unknown-owner target is an ancestor of (or equal to) any other rule's target.
                let others = all.filter { $0.rule.id != "apps.userCaches.unknownOwner" }.flatMap(\.targets).map { M5.relative($0.path, f) }
                for u in unknown {
                    try TestSuite.assertFalse(others.contains { $0 == u || $0.hasPrefix(u + "/") }, u)
                }
                // A catalog whose other rule targets a Library/Caches child that is not reserved disables the Yellow rule.
                let bundled = try M5.catalog(env).rules
                let extra = M1.rule(id: "test.newToolCache", allowRoots: ["{HOME}/Library/Caches/com.newtool.cache"],
                                    discovery: .glob(["{HOME}/Library/Caches/com.newtool.cache/*"]))
                let catalog = RuleCatalog(validating: bundled + [extra], environment: env.environment)
                try TestSuite.assertTrue(catalog.disabled.contains { $0.ruleID == "apps.userCaches.unknownOwner" }, "\(catalog.disabled)")
            }
        }
    }

    // MARK: Chromium service workers

    @MainActor
    static func serviceWorkerTests() async {
        await TestSuite.run("ChromiumServiceWorker: only <profile>/Service Worker/CacheStorage of installed browsers; never Database / ScriptCache / other profiles") {
            try await M1.withEnv { env in
                let f = env.fixture
                env.applications.applicationURLs = ["com.google.Chrome": [URL(fileURLWithPath: "/Applications/Google Chrome.app")],
                                                    "com.brave.Browser": [URL(fileURLWithPath: "/Applications/Brave Browser.app")]]
                let chrome = "Library/Application Support/Google/Chrome/"
                let brave = "Library/Application Support/BraveSoftware/Brave-Browser/"
                for profile in ["Default", "Profile 1", "Guest Profile", "System Profile"] {
                    for sub in ["CacheStorage", "Database", "ScriptCache"] {
                        try f.file(chrome + profile + "/Service Worker/" + sub + "/data", bytes: 300)
                    }
                }
                try f.file(brave + "Default/Service Worker/CacheStorage/data", bytes: 300)
                try f.file("Library/Application Support/Microsoft Edge/Default/Service Worker/CacheStorage/data", bytes: 300) // not installed
                try f.file(chrome + "Profile 2/Service Worker/x", bytes: 1)
                try f.symlink(chrome + "Profile 2/Service Worker/CacheStorage", to: f.path("elsewhere", base: .root))

                let expected: Set<String> = [chrome + "Default/Service Worker/CacheStorage", chrome + "Profile 1/Service Worker/CacheStorage",
                                             brave + "Default/Service Worker/CacheStorage"]
                let out = try await M5.discover(ChromiumServiceWorkerInspector(), env, "browser.chromium.serviceWorkerCache")
                try TestSuite.assertEqual(M5.paths(out, f), expected)
                let results = try await M5.scan(env, ["browser.chromium.serviceWorkerCache", "browser.chromium.cache"])
                try TestSuite.assertEqual(M5.paths(results["browser.chromium.serviceWorkerCache"], f), expected)
                try TestSuite.assertTrue(M5.paths(results["browser.chromium.cache"], f).allSatisfy { !$0.contains("Service Worker") })
                // The browser running blocks its own items only.
                env.runningApplications.ids = ["com.google.Chrome"]
                let plan = await M5.plan(env, [try M5.unwrap(results["browser.chromium.serviceWorkerCache"])])
                for item in plan.items {
                    let isChrome = item.target.owningBundleID == "com.google.Chrome"
                    try TestSuite.assertEqual(item.isActionable, !isChrome, "\(item.target.path): \(item.preconditions.filter { !$0.passed })")
                    try TestSuite.assertFalse(item.selectedByDefault)
                }
                env.applications.failing = true
                let none = try await M5.discover(ChromiumServiceWorkerInspector(), env, "browser.chromium.serviceWorkerCache")
                try TestSuite.assertTrue(none.candidates.isEmpty)
            }
        }
    }

    // MARK: Lightroom

    @MainActor
    static func lightroomTests() async {
        await TestSuite.run("Lightroom: only '<catalog> Previews.lrdata' beside a Spotlight-reported .lrcat — never Smart Previews, never the .lrcat; Spotlight nil → unavailable") {
            try await M1.withEnv { env in
                let f = env.fixture
                let dir = "LightroomCatalogs/"
                try f.file(dir + "Main.lrcat", bytes: 4_000)
                try f.file(dir + "Main Previews.lrdata/root/a.lrprev", bytes: 3_000)
                try f.file(dir + "Main Smart Previews.lrdata/x.dng", bytes: 3_000)
                try f.file(dir + "Main Helper.lrdata/helper.db", bytes: 100)
                // A catalog named "Trip Smart": its previews folder cannot be told from Smart Previews → refused.
                try f.file(dir + "Trip Smart.lrcat", bytes: 100)
                try f.file(dir + "Trip Smart Previews.lrdata/x", bytes: 100)
                // Catalog without previews; previews without catalog; deny-listed location; outside home.
                try f.file(dir + "Lonely.lrcat", bytes: 100)
                try f.file(dir + "Orphan Previews.lrdata/x", bytes: 100)
                try f.file("Pictures/Lightroom/Pics.lrcat", bytes: 100)
                try f.file("Pictures/Lightroom/Pics Previews.lrdata/x", bytes: 100)
                try f.file("outside/Out.lrcat", bytes: 100, base: .root)
                try f.file("outside/Out Previews.lrdata/x", bytes: 100, base: .root)
                // A catalog reached through a symlinked folder.
                try f.symlink("LinkedCatalogs", to: f.path(dir))
                // A catalog that is a directory, not a file.
                try f.dir(dir + "Dir.lrcat")
                try f.file(dir + "Dir Previews.lrdata/x", bytes: 100)

                env.spotlight.results = ["lrcat": [f.path(dir + "Main.lrcat"), f.path(dir + "Trip Smart.lrcat"), f.path(dir + "Lonely.lrcat"),
                                                   f.path(dir + "Ghost.lrcat"), f.path("Pictures/Lightroom/Pics.lrcat"),
                                                   f.path("outside/Out.lrcat", base: .root), f.path("LinkedCatalogs/Main.lrcat"),
                                                   f.path(dir + "Dir.lrcat"), "relative/Main.lrcat", f.path(dir + "../" + dir + "Main.lrcat")]]
                let out = try await M5.discover(LightroomPreviewsInspector(), env, "lightroom.previews")
                try TestSuite.assertEqual(out.status, .ok)
                try TestSuite.assertEqual(M5.paths(out, f), [dir + "Main Previews.lrdata"])
                try TestSuite.assertEqual(out.candidates.first?.owningBundleID, "com.adobe.LightroomClassicCC7")
                try TestSuite.assertEqual(env.spotlight.queries.first?.0, "lrcat")
                try TestSuite.assertEqual(env.spotlight.queries.first?.1 ?? [], [env.environment.homePath])

                try TestSuite.assertTrue(LightroomPreviewsInspector.isPreviewsFolderName("Main Previews.lrdata"))
                for bad in ["Main Smart Previews.lrdata", "Smart Previews.lrdata", " Previews.lrdata", "Main.lrcat", "Main Previews.lrdata.bak", "Main Helper.lrdata"] {
                    try TestSuite.assertFalse(LightroomPreviewsInspector.isPreviewsFolderName(bad), bad)
                }

                // Scanner + plan: Yellow, never preselected; Lightroom running blocks.
                let results = try await M5.scan(env, ["lightroom.previews"])
                try TestSuite.assertEqual(M5.paths(results["lightroom.previews"], f), [dir + "Main Previews.lrdata"])
                var plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.selectedByDefault })
                env.runningApplications.ids = ["com.adobe.LightroomClassicCC7"]
                plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.isActionable })
                // The gate never accepts the .lrcat or the Smart Previews under this rule.
                let rule = try M5.rule(env, "lightroom.previews")
                env.runningApplications.ids = []
                for rel in [dir + "Main.lrcat", dir + "Main Smart Previews.lrdata"] {
                    let verdict = await env.makeGate().validate(target: env.scanTarget(ruleID: rule.id, path: rel, owningBundleID: "com.adobe.LightroomClassicCC7"),
                                                                rule: rule, phase: .plan)
                    guard case .rejected = verdict else { throw TestError("\(rel) must be rejected: \(verdict)") }
                }

                env.spotlight.failing = true
                let failed = try await M5.discover(LightroomPreviewsInspector(), env, "lightroom.previews")
                guard case .unavailable = failed.status else { throw TestError("\(failed.status)") }
                let scanned = try await M5.scan(env, ["lightroom.previews"])
                guard case .unavailable = scanned["lightroom.previews"]?.status else { throw TestError("scanner must report unavailable") }
            }
        }
    }

    // MARK: Glob-based Yellow rules (AI models, Adobe, package tools)

    @MainActor
    static func globRuleTests() async {
        await TestSuite.run("Yellow glob rules: Hugging Face, LM Studio, Adobe media cache and package-tool caches match exactly their folders") {
            try await M1.withEnv { env in
                let f = env.fixture
                let hub = ".cache/huggingface/hub/"
                let adobe = "Library/Application Support/Adobe/Common/"
                let files: [String] = [
                    hub + "models--bert-base-uncased/blobs/a", hub + "datasets--squad/blobs/b", hub + "version.txt", hub + ".locks/models--x/l",
                    hub + "spaces--demo/x",
                    ".lmstudio/models/lmstudio-community/Meta-Llama-3-8B-GGUF/model.gguf", ".lmstudio/models/README.md",
                    ".lmstudio/conversations/c.json",
                    adobe + "Media Cache Files/clip.cfa", adobe + "Media Cache/db/x", adobe + "Peak Files/p.pek",
                    "Library/Caches/pypoetry/virtualenvs/proj-abc-py3.12/bin/python",
                    ".cargo/registry/cache/index.crates.io-6f17d22bba15001f/serde-1.0.crate",
                    ".gradle/caches/8.5/x", ".m2/repository/org/x.jar",
                    "Library/Caches/ms-playwright/chromium-1105/x", ".cache/puppeteer/chrome/x",
                    "Library/Android/sdk/system-images/android-34/google_apis/arm64-v8a/system.img",
                ]
                for file in files { try f.file(file, bytes: 2_000) }
                let expected: [String: Set<String>] = [
                    "ai.huggingface": [hub + "models--bert-base-uncased", hub + "datasets--squad"],
                    "ai.lmstudio": [".lmstudio/models/lmstudio-community/Meta-Llama-3-8B-GGUF"],
                    "adobe.mediaCache": [adobe + "Media Cache Files/clip.cfa", adobe + "Media Cache/db"],
                    "poetry.virtualenvs": ["Library/Caches/pypoetry/virtualenvs/proj-abc-py3.12"],
                    "cargo.registryCache": [".cargo/registry/cache/index.crates.io-6f17d22bba15001f"],
                    "gradle.caches": [".gradle/caches/8.5"],
                    "maven.repo": [".m2/repository/org"],
                    "playwright.browsers": ["Library/Caches/ms-playwright/chromium-1105"],
                    "puppeteer.browsers": [".cache/puppeteer/chrome"],
                    "android.systemImages": ["Library/Android/sdk/system-images/android-34/google_apis/arm64-v8a"],
                ]
                let results = try await M5.scan(env, Set(expected.keys))
                for (id, paths) in expected {
                    try TestSuite.assertEqual(results[id]?.status, .ok, id)
                    try TestSuite.assertEqual(M5.paths(results[id], f), paths, id)
                    try TestSuite.assertEqual(results[id]?.rule.tier, .yellow, id)
                    // Model name / size / last used are shown for every item.
                    for target in results[id]?.targets ?? [] {
                        try TestSuite.assertFalse(target.displayName.isEmpty, id)
                        try TestSuite.assertTrue(target.allocatedBytes > 0, id)
                        try TestSuite.assertTrue(target.lastUsed != nil, id)
                    }
                }
                // Preconditions: Python running blocks Hugging Face; an Adobe app blocks the media cache; java blocks Gradle and Maven.
                env.processes.names = ["launchd", "python3", "java"]
                env.runningApplications.ids = ["com.adobe.PremierePro.24"]
                let plan = await M5.plan(env, Array(results.values))
                for item in plan.items {
                    try TestSuite.assertFalse(item.selectedByDefault, item.rule.id)
                    if ["ai.huggingface", "adobe.mediaCache", "gradle.caches", "maven.repo"].contains(item.rule.id) {
                        try TestSuite.assertFalse(item.isActionable, item.rule.id)
                    }
                }
                env.processes.names = ["launchd"]
                env.runningApplications.ids = []
                let free = await M5.plan(env, Array(results.values))
                for item in free.items where ["ai.huggingface", "adobe.mediaCache", "gradle.caches", "maven.repo", "ai.lmstudio", "cargo.registryCache"].contains(item.rule.id) {
                    try TestSuite.assertTrue(item.isActionable, "\(item.rule.id): \(item.preconditions.filter { !$0.passed })")
                    try TestSuite.assertFalse(item.selectedByDefault, item.rule.id)
                }
            }
        }
    }
}
