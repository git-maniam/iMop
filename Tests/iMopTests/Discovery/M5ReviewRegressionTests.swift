import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Regression tests for the adversarial review of Milestone 5 (git case-insensitivity, gate-side
/// re-proof of project-artifact identity, other version-control systems, JetBrains EAP channels,
/// VS Code profiles, DerivedData on unmounted volumes, plain-named Apple caches, Lightroom catalog
/// pairing, developer-tools shim). Every fixture lives in an `iMopTests-*` temp tree; git answers
/// come from `FakeCommandRunner`.
struct M5ReviewRegressionTests {
    static let root = "Projects"

    @MainActor
    static func runAll() async {
        print("\n🧩 Running Milestone 5 review regression tests...")
        await gitCaseTests()
        await gateIdentityTests()
        await otherVCSTests()
        await developerToolsTests()
        await jetbrainsChannelTests()
        await vscodeProfileTests()
        await derivedDataMountTests()
        await unknownOwnerAppleTests()
        await lightroomPairingTests()
    }

    // MARK: Helpers

    /// Sets the mtime of `rel` and everything below it (no symlinks in these fixtures).
    @MainActor
    static func ageTree(_ env: FakeEnvironment, _ rel: String, days: Int = 200) throws {
        let f = env.fixture
        let absolute = f.path(rel)
        let children = FileManager.default.subpaths(atPath: absolute) ?? []
        for child in children { try f.setModificationDate(rel + "/" + child, daysAgo: days, clock: env.clock) }
        try f.setModificationDate(rel, daysAgo: days, clock: env.clock)
    }

    @MainActor
    static func project(_ f: FixtureBuilder, _ rel: String, files: [String] = [], dirs: [String] = []) throws {
        try ProjectScannerTests.project(f, rel, files: files, dirs: dirs)
    }

    static func rule(_ base: Rule, preconditions: [Precondition]) -> Rule {
        Rule(id: base.id, version: base.version, category: base.category, tier: base.tier, title: base.title,
             explanation: base.explanation, whatYouLose: base.whatYouLose, howItRegenerates: base.howItRegenerates,
             discovery: base.discovery, allowRoots: base.allowRoots, minDepthBelowRoot: base.minDepthBelowRoot,
             preconditions: preconditions, action: base.action, retentionHours: base.retentionHours,
             maxExpectedBytes: base.maxExpectedBytes, maxExpectedItems: base.maxExpectedItems,
             allowSymlinkTarget: base.allowSymlinkTarget, excludedNames: base.excludedNames,
             requiresFullDiskAccess: base.requiresFullDiskAccess, ownerInference: base.ownerInference)
    }

    /// Execute-phase gate verdict for `rel` under `rule`.
    @MainActor
    static func verdict(_ env: FakeEnvironment, _ rule: Rule, _ rel: String, owner: String? = nil) async -> SafetyVerdict {
        await env.makeGate().validateWithDetails(target: env.scanTarget(ruleID: rule.id, path: rel, owningBundleID: owner),
                                                 rule: rule, phase: .execute).verdict
    }

    @MainActor static func assertNotNil<T>(_ value: T?, _ message: String = "", file: StaticString = #file, line: UInt = #line) throws {
        try TestSuite.assertTrue(value != nil, "expected a value \(message)", file: file, line: line)
    }

    static func isShapeRejection(_ verdict: SafetyVerdict) -> Bool {
        if case .rejected(.doesNotMatchRule) = verdict { return true }
        return false
    }

    // MARK: 1. git --icase-pathspecs

    @MainActor
    static func gitCaseTests() async {
        await TestSuite.run("Review M5: the git probe matches pathspecs case-insensitively (--icase-pathspecs), and only that exact probe is allow-listed") {
            try await M1.withEnv { env in
                let f = env.fixture
                ProjectScannerTests.useRoots(env)
                try project(f, root + "/app", files: ["build.gradle", ".git/HEAD", ".git/index"], dirs: ["build/classes", ".git/objects"])
                let args = CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(root + "/app"), artifactName: "build")
                try TestSuite.assertEqual(Array(args.prefix(2)), ["--no-optional-locks", "--icase-pathspecs"])
                try TestSuite.assertTrue(args.firstIndex(of: "--icase-pathspecs")! < args.firstIndex(of: "ls-files")!)
                try TestSuite.assertTrue(CommandAllowList.matches(tool: "git", arguments: args, purpose: .readOnly))
                try TestSuite.assertNil(CommandAllowList.forbiddenInvocationReason(tool: "git", arguments: args, purpose: .readOnly))
                // The old case-sensitive form is no longer allow-listed.
                let caseSensitive = args.filter { $0 != "--icase-pathspecs" }
                try TestSuite.assertFalse(CommandAllowList.matches(tool: "git", arguments: caseSensitive, purpose: .readOnly))
                try TestSuite.assertFalse(CommandAllowList.gitProbeAllowed(
                    arguments: caseSensitive, projectRoots: ProjectRoots.resolve(environment: env.environment, waivedSystemRoots: [f.root])))

                // The evaluator runs exactly the icase probe; git listing `Build/ci.sh` (exit 0) → tracked.
                try M5.useGit(env)
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "Build/ci.sh\n", stderr: ""), for: args)
                let rule = try M5.rule(env, "project.gradleBuild")
                let result = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/app/build"), rule: rule)
                try TestSuite.assertFalse(result.passed)
                let gitRun = try M5.unwrap(env.commands.invocations.last { $0.executable == M5.gitPath })
                try TestSuite.assertEqual(gitRun.arguments, args)
                try TestSuite.assertEqual(gitRun.purpose, .readOnly)
            }
        }
    }

    // MARK: 2/8/10/11. SafetyGate re-proves project-artifact identity

    @MainActor
    static func gateIdentityTests() async {
        await TestSuite.run("Review M5: SafetyGate re-proves marker, depth, monorepo layout and manifest pairing of project artifacts at execute time") {
            try await M1.withEnv { env in
                let f = env.fixture
                ProjectScannerTests.useRoots(env)
                let p = root + "/"
                try project(f, p + "rustok", files: ["Cargo.toml", "target/CACHEDIR.TAG"], dirs: ["target/debug"])
                try project(f, p + "rustnomark", files: ["Cargo.toml"], dirs: ["target/src"])
                try project(f, p + "rustbadtag", files: ["Cargo.toml"], dirs: ["target/src"])
                try f.file(p + "rustbadtag/target/CACHEDIR.TAG", contents: Data("not a cache tag\n".utf8))
                try project(f, p + "pyok", files: ["requirements.txt", "venv/pyvenv.cfg"], dirs: ["venv/lib"])
                try project(f, p + "pynocfg", files: ["requirements.txt"], dirs: ["venv/mydata"])
                try project(f, p + "mono", files: [".git/HEAD"])
                try project(f, p + "mono/pkg", files: ["package-lock.json"], dirs: ["node_modules/x"])
                let deep = (1...9).map { "d\($0)" }.joined(separator: "/")
                try project(f, p + deep, files: ["package-lock.json"], dirs: ["node_modules/x"])
                try project(f, p + "notgradle", files: ["package.json"], dirs: ["build/important"])
                try project(f, p + "gradleok", files: ["build.gradle"], dirs: ["build/classes"])
                try ageTree(env, root)

                let rust = try M5.rule(env, "project.rustTarget")
                let venv = try M5.rule(env, "project.pythonVenv")
                let node = try M5.rule(env, "project.nodeModules")
                let gradle = try M5.rule(env, "project.gradleBuild")

                // Baselines the scanner offers are allowed.
                for (r, rel) in [(rust, p + "rustok/target"), (venv, p + "pyok/venv"), (gradle, p + "gradleok/build")] {
                    let v = await verdict(env, r, rel)
                    try TestSuite.assertTrue(v.isAllowed, "\(rel): \(v)")
                }
                try TestSuite.assertEqual(try await ProjectScannerTests.discovered(env, "project.rustTarget"), [p + "rustok/target"])

                // Everything the scanner refuses, the gate refuses too.
                let refused: [(Rule, String, String)] = [
                    (rust, p + "rustnomark/target", "no CACHEDIR.TAG / .rustc_info.json"),
                    (rust, p + "rustbadtag/target", "CACHEDIR.TAG without the signature"),
                    (venv, p + "pynocfg/venv", "no pyvenv.cfg"),
                    (node, p + "mono/pkg/node_modules", "monorepo member without its own .git"),
                    (node, p + deep + "/node_modules", "deeper than 8 below the project root"),
                    (gradle, p + "notgradle/build", "no build.gradle beside it"),
                ]
                for (r, rel, label) in refused {
                    let v = await verdict(env, r, rel)
                    try TestSuite.assertTrue(isShapeRejection(v), "\(label): \(v)")
                    try assertNotNil(ProjectArtifactsInspector.identityProblem(
                        target: CanonicalPath(validatedPath: f.path(rel)), ruleID: r.id, environment: env.environment,
                        waivedSystemRoots: [f.root]), label)
                }

                // The marker table the matcher declares is the scanner's.
                for kind in ProjectArtifactsInspector.artifactKinds {
                    try TestSuite.assertEqual(RuleTargetMatcher.projectArtifactSpecs[kind.ruleID]?.markersInside, kind.requiredInsideAnyOf, kind.ruleID)
                }

                // A rule built in code without manifestPresent never acts, even with build.gradle beside it.
                let bare = rule(gradle, preconditions: [.projectOlderThan(days: 90), .notTrackedByGit, .processNotRunning(["java", "gradle"])])
                try assertNotNil(RuleTargetMatcher.pinnedInspectorRuleMismatch(bare, inspector: .projectArtifacts))
                let bareVerdict = await verdict(env, bare, p + "gradleok/build")
                try TestSuite.assertTrue(isShapeRejection(bareVerdict), "\(bareVerdict)")
                // …and an unreviewed manifest name is refused as well.
                let foreign = rule(gradle, preconditions: gradle.preconditions + [.manifestPresent(["package.json"])])
                try assertNotNil(RuleTargetMatcher.pinnedInspectorRuleMismatch(foreign, inspector: .projectArtifacts))
                try TestSuite.assertNil(RuleTargetMatcher.pinnedInspectorRuleMismatch(gradle, inspector: .projectArtifacts))
            }
        }
    }

    // MARK: 3. Other version-control systems

    @MainActor
    static func otherVCSTests() async {
        await TestSuite.run("Review M5: a checkout of another VCS (.hg, .svn, .jj, …) is treated as tracked — never proposed, never allowed, no tool run") {
            try await M1.withEnv { env in
                let f = env.fixture
                ProjectScannerTests.useRoots(env)
                let p = root + "/"
                try project(f, p + "hgapp", files: ["Podfile.lock", ".hg/requires"], dirs: ["Pods/Alamofire"])
                try project(f, p + "svnwc", files: [".svn/wc.db"])
                try project(f, p + "svnwc/ios", files: ["Podfile.lock"], dirs: ["Pods/X"])
                try project(f, p + "fossil", files: ["Podfile.lock", ".fslckout"], dirs: ["Pods/Y"])
                try project(f, p + "plain", files: ["Podfile.lock"], dirs: ["Pods/Z"])
                try ageTree(env, root)
                try M5.useGit(env)

                let pods = try M5.rule(env, "project.pods")
                try TestSuite.assertEqual(try await ProjectScannerTests.discovered(env, "project.pods"), [p + "plain/Pods"])
                for rel in [p + "hgapp/Pods", p + "svnwc/ios/Pods", p + "fossil/Pods"] {
                    let before = env.commands.invocations.count
                    let result = await M5.evaluate(env, .notTrackedByGit, path: f.path(rel), rule: pods)
                    try TestSuite.assertFalse(result.passed, rel)
                    try TestSuite.assertEqual(env.commands.invocations.count, before, "no command for \(rel)")
                    let v = await verdict(env, pods, rel)
                    try TestSuite.assertFalse(v.isAllowed, "\(rel): \(v)")
                }
                let plain = await verdict(env, pods, p + "plain/Pods")
                try TestSuite.assertTrue(plain.isAllowed, "\(plain)")
                for marker in [".hg", ".svn", ".jj", ".sl", ".fslckout", "_FOSSIL_", ".bzr"] {
                    try TestSuite.assertTrue(PreconditionEvaluator.isOtherVersionControlMarker(marker), marker)
                }
                try TestSuite.assertFalse(PreconditionEvaluator.isOtherVersionControlMarker(".git"))
            }
        }
    }

    // MARK: 12. Developer tools shim

    @MainActor
    static func developerToolsTests() async {
        await TestSuite.run("Review M5: /usr/bin/git is never run unless xcode-select names a developer dir holding usr/bin/git (no install dialog)") {
            try await M1.withEnv { env in
                let f = env.fixture
                ProjectScannerTests.useRoots(env)
                try project(f, root + "/repo", files: ["package-lock.json", ".git/HEAD"], dirs: ["node_modules"])
                let rule = try M5.rule(env, "project.nodeModules")
                let args = CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(root + "/repo"), artifactName: "node_modules")
                let untracked = CommandResult(exitCode: 1, stdout: "", stderr: M5.gitUntrackedStderr)
                @MainActor func gitRuns() -> Int { env.commands.invocations.filter { $0.executable == M5.gitPath }.count }

                // No developer tools: xcode-select fails → tracked, git never run.
                try M5.useGit(env, developerTools: false)
                env.commands.setResponse(untracked, for: args)
                var result = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/repo/node_modules"), rule: rule)
                try TestSuite.assertFalse(result.passed)
                try TestSuite.assertEqual(gitRuns(), 0)
                // xcode-select unresolvable → tracked.
                env.commands.executables = ["git": M5.gitPath]
                result = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/repo/node_modules"), rule: rule)
                try TestSuite.assertFalse(result.passed)
                try TestSuite.assertEqual(gitRuns(), 0)
                // A developer dir without usr/bin/git → tracked.
                try f.dir("EmptyDeveloper", base: .root)
                env.commands.executables = ["git": M5.gitPath, "xcode-select": "/usr/bin/xcode-select"]
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: f.path("EmptyDeveloper", base: .root) + "\n", stderr: ""), for: ["-p"])
                result = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/repo/node_modules"), rule: rule)
                try TestSuite.assertFalse(result.passed)
                try TestSuite.assertEqual(gitRuns(), 0)
                // With developer tools git is asked (read-only) and its answer counts.
                try M5.useGit(env)
                result = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/repo/node_modules"), rule: rule)
                try TestSuite.assertTrue(result.passed, result.detail)
                try TestSuite.assertEqual(gitRuns(), 1)
                try TestSuite.assertTrue(env.commands.invocations.allSatisfy { $0.purpose == .readOnly })
            }
        }
    }

    // MARK: 4/9. JetBrains EAP channels

    @MainActor
    static func jetbrainsChannelTests() async {
        await TestSuite.run("Review M5: JetBrains caches of an EAP-only version are CURRENT; no app of the product found → CURRENT, never Green") {
            try await M1.withEnv { env in
                let f = env.fixture
                let jb = "Library/Caches/JetBrains"
                for name in ["IntelliJIdea2024.1", "IntelliJIdea2024.2", "IntelliJIdea2023.3"] {
                    try f.file(jb + "/" + name + "/LocalHistory/changes.storageData", bytes: 100)
                }
                let release = try OtherYellowInspectorTests.app(f, "IntelliJ IDEA", version: "2024.1.4")
                let eap = try OtherYellowInspectorTests.app(f, "IntelliJ IDEA 2024.2 EAP", version: "2024.2 EAP")
                @MainActor func names(_ ruleID: String) async throws -> Set<String> {
                    let out = try await M5.discover(JetBrainsCachesInspector(), env, ruleID)
                    try TestSuite.assertEqual(out.status, .ok)
                    return Set(M5.paths(out, f).map { String($0.dropFirst(jb.count + 1)) })
                }
                // Only the EAP installed: nothing is orphaned (2024.1 / 2023.3 might belong to an unseen release).
                env.applications.applicationURLs = ["com.jetbrains.intellij-EAP": [eap]]
                try TestSuite.assertEqual(try await names(JetBrainsCachesInspector.orphanedRuleID), ["IntelliJIdea2024.1", "IntelliJIdea2023.3"])
                // Release 2024.1 + EAP 2024.2: only 2023.3 is orphaned.
                env.applications.applicationURLs = ["com.jetbrains.intellij": [release], "com.jetbrains.intellij-EAP": [eap]]
                try TestSuite.assertEqual(try await names(JetBrainsCachesInspector.orphanedRuleID), ["IntelliJIdea2023.3"])
                try TestSuite.assertEqual(try await names(JetBrainsCachesInspector.currentRuleID), ["IntelliJIdea2024.1", "IntelliJIdea2024.2"])
                // Nothing of the product found at all → every folder current.
                env.applications.applicationURLs = [:]
                try TestSuite.assertEqual(try await names(JetBrainsCachesInspector.orphanedRuleID), [])
                try TestSuite.assertEqual(try await names(JetBrainsCachesInspector.currentRuleID),
                                          ["IntelliJIdea2024.1", "IntelliJIdea2024.2", "IntelliJIdea2023.3"])
                try TestSuite.assertTrue(JetBrainsCachesInspector.bundleIDFamily("com.jetbrains.intellij").contains("com.jetbrains.intellij-EAP"))
            }
        }
    }

    // MARK: 5. VS Code profiles

    @MainActor
    static func vscodeProfileTests() async {
        await TestSuite.run("Review M5: a version referenced by any VS Code profile's extensions.json is never offered; an unreadable profile list offers nothing") {
            try await M1.withEnv { env in
                let f = env.fixture
                let ext = ".vscode/extensions"
                let profiles = "Library/Application Support/Code/User/profiles"
                for folder in ["foo.bar-1.0.0", "foo.bar-2.0.0", "baz.qux-1.0.0", "baz.qux-1.1.0"] {
                    try f.file(ext + "/" + folder + "/package.json", bytes: 10)
                }
                let main = [OtherYellowInspectorTests.entry("foo.bar", "2.0.0", home: f.home),
                            OtherYellowInspectorTests.entry("baz.qux", "1.1.0", home: f.home)]
                try f.file(ext + "/extensions.json", contents: try M5.jsonData(main))
                @MainActor func offered() async throws -> (Set<String>, InspectorOutput) {
                    let out = try await M5.discover(VSCodeExtensionsInspector(), env, "vscode.oldExtensions")
                    return (Set(M5.paths(out, f).map { String($0.dropFirst(ext.count + 1)) }), out)
                }
                // No profiles folder: both old versions offered.
                try TestSuite.assertEqual(try await offered().0, ["foo.bar-1.0.0", "baz.qux-1.0.0"])
                // A profile uses foo.bar 1.0.0 → kept.
                try f.file(profiles + "/-6a1b2c3d/extensions.json",
                           contents: try M5.jsonData([OtherYellowInspectorTests.entry("foo.bar", "1.0.0", home: f.home)]))
                try f.file(profiles + "/.DS_Store", bytes: 4)
                try TestSuite.assertEqual(try await offered().0, ["baz.qux-1.0.0"])
                // A profile without (or with an unparsable) extensions.json → nothing offered.
                try f.dir(profiles + "/7f00aa11")
                var (names, out) = try await offered()
                try TestSuite.assertEqual(names, [])
                guard case .unavailable = out.status else { throw TestError("expected unavailable, got \(out.status)") }
                try f.file(profiles + "/7f00aa11/extensions.json", contents: Data("{not json".utf8))
                (names, _) = try await offered()
                try TestSuite.assertEqual(names, [])
                try f.file(profiles + "/7f00aa11/extensions.json", contents: try M5.jsonData([[String: Any]]()))
                (names, _) = try await offered()
                try TestSuite.assertEqual(names, ["baz.qux-1.0.0"])
                // An unlistable profiles folder → nothing offered.
                env.fileSystem.fail(.contentsOfDirectory, path: f.path(profiles))
                (names, _) = try await offered()
                try TestSuite.assertEqual(names, [])
            }
        }
    }

    // MARK: 6. DerivedData on an unmounted / mounted volume

    @MainActor
    static func derivedDataMountTests() async {
        await TestSuite.run("Review M5: DerivedData of a project behind an empty mount point, a mount point or a mount area is ACTIVE, never orphaned") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.dir("mnt/server", base: .root) // an unmounted sshfs / macFUSE mount point: empty
                try f.file("work/Other/readme.txt", bytes: 1, base: .root)
                try f.dir("vol/disk/Other", base: .root)
                env.fileSystem.overrideStat(f.path("vol/disk", base: .root), device: 9_999)
                try XcodeInspectorTests.derived(f, "Unmounted-abc", plist: ["WorkspacePath": f.path("mnt/server/Proj/App.xcodeproj", base: .root)])
                try XcodeInspectorTests.derived(f, "Gone-abc", plist: ["WorkspacePath": f.path("work/Gone/App.xcodeproj", base: .root)])
                try XcodeInspectorTests.derived(f, "MountPoint-abc", plist: ["WorkspacePath": f.path("vol/disk/Proj/App.xcodeproj", base: .root)])
                try XcodeInspectorTests.derived(f, "Net-abc", plist: ["WorkspacePath": "/net/server/Proj/App.xcodeproj"])
                try XcodeInspectorTests.derived(f, "Network-abc", plist: ["WorkspacePath": "/Network/Servers/s/Proj/App.xcodeproj"])
                try XcodeInspectorTests.derived(f, "SysVol-abc", plist: ["WorkspacePath": "/System/Volumes/Data/x/App.xcodeproj"])
                let orphaned = try await M5.discover(XcodeDerivedDataInspector(), env, "xcode.derivedData.orphaned")
                try TestSuite.assertEqual(M5.paths(orphaned, f), [XcodeInspectorTests.derivedData + "/Gone-abc"])
                let active = try await M5.discover(XcodeDerivedDataInspector(), env, "xcode.derivedData.active")
                for name in ["Unmounted-abc", "MountPoint-abc", "Net-abc", "Network-abc", "SysVol-abc"] {
                    try TestSuite.assertTrue(M5.paths(active, f).contains(XcodeInspectorTests.derivedData + "/" + name), name)
                }
            }
        }
    }

    // MARK: 7. Plain-named Apple caches

    @MainActor
    static func unknownOwnerAppleTests() async {
        await TestSuite.run("Review M5: plain-named Apple caches (CloudKit, GeoServices, …) and folders holding com.apple.* data are never 'unknown owner'") {
            try await M1.withEnv { env in
                let f = env.fixture
                let apple = ["CloudKit", "GeoServices", "PassKit", "FamilyCircle", "familycircled", "GameKit", "SiriTTS"]
                for name in apple + ["SomeOldTool"] { try f.file("Library/Caches/\(name)/data.bin", bytes: 100) }
                try f.file("Library/Caches/HiddenApple/com.apple.something/db", bytes: 100)
                let out = try await M5.discover(UnknownOwnerCachesInspector(catalog: try M5.catalog(env)), env, "apps.userCaches.unknownOwner")
                try TestSuite.assertEqual(out.status, .ok)
                try TestSuite.assertEqual(M5.paths(out, f), ["Library/Caches/SomeOldTool"])

                let rule = try M5.rule(env, "apps.userCaches.unknownOwner")
                let home = CanonicalPath(validatedPath: f.home)
                let matcher = RuleTargetMatcher(homeForms: [home])
                for name in apple {
                    let path = home.appending("Library").appending("Caches").appending(name)
                    try assertNotNil(matcher.mismatch(path, rule: rule, owningBundleID: nil), name)
                }
                // The gate re-lists the folder: com.apple.* inside → rejected.
                let v = await verdict(env, rule, "Library/Caches/HiddenApple")
                try TestSuite.assertTrue(isShapeRejection(v), "\(v)")
            }
        }
    }

    // MARK: 8. Lightroom exact catalog pairing

    @MainActor
    static func lightroomPairingTests() async {
        await TestSuite.run("Review M5: SafetyGate accepts '<X> Previews.lrdata' only beside the exact catalog '<X>.lrcat'") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Photos/Bar.lrcat", bytes: 100)
                try f.file("Photos/Foo Previews.lrdata/root-pixels.db", bytes: 100)
                try f.file("Photos/Bar Previews.lrdata/root-pixels.db", bytes: 100)
                try f.dir("Photos/Dir.lrcat") // a directory, not a catalog file
                try f.file("Photos/Dir Previews.lrdata/root-pixels.db", bytes: 100)
                func problem(_ rel: String) -> String? {
                    LightroomPreviewsInspector.identityProblem(target: CanonicalPath(validatedPath: f.path(rel)), fileSystem: env.fileSystem)
                }
                try TestSuite.assertNil(problem("Photos/Bar Previews.lrdata"))
                try assertNotNil(problem("Photos/Foo Previews.lrdata"))
                try assertNotNil(problem("Photos/Dir Previews.lrdata"))
                let rule = try M5.rule(env, "lightroom.previews")
                let v = await verdict(env, rule, "Photos/Foo Previews.lrdata", owner: LightroomPreviewsInspector.lightroomBundleID)
                try TestSuite.assertTrue(isShapeRejection(v), "\(v)")
                let ok = await verdict(env, rule, "Photos/Bar Previews.lrdata", owner: LightroomPreviewsInspector.lightroomBundleID)
                try TestSuite.assertFalse(isShapeRejection(ok), "\(ok)")
            }
        }
    }
}
