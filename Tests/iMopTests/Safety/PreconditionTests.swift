import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §3.6 precondition evaluators with fake process lists, apps and commands.
/// Every predicate must fail closed (error / nil / timeout → false).
struct PreconditionTests {
    static let appCache = "Library/Caches/com.example.app"

    @MainActor
    static func eval(_ env: FakeEnvironment, _ precondition: Precondition, _ target: ScanTarget,
                     rule: Rule? = nil, overrides: [String: Int] = [:]) async -> PreconditionResult {
        let r = rule ?? M1.rule(id: target.ruleID)
        return await env.makePreconditionEvaluator(ageThresholdOverrides: overrides).evaluate(precondition, target: target, rule: r)
    }

    @MainActor
    static func target(_ env: FakeEnvironment, _ rel: String = appCache, owner: String? = nil) throws -> ScanTarget {
        if env.fileSystem.lstat(env.fixture.path(rel)) == nil { try env.fixture.dir(rel) }
        return env.scanTarget(ruleID: "test.caches", path: rel, owningBundleID: owner)
    }

    static func plist(_ imagePaths: [String]) -> String {
        let entries = imagePaths.map { "<dict><key>image-path</key><string>\($0)</string></dict>" }.joined()
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>images</key><array>\(entries)</array></dict></plist>
        """
    }

    static func simctlJSON(_ states: [String]) -> String {
        let devices = states.enumerated().map { "{\"udid\":\"U\($0.offset)\",\"state\":\"\($0.element)\",\"name\":\"iPhone\"}" }
        return "{\"devices\":{\"com.apple.CoreSimulator.SimRuntime.iOS-18-0\":[\(devices.joined(separator: ","))]}}"
    }

    @MainActor
    static func runAll() async {
        print("\n🔒 Running Precondition Tests (spec §3.6)...")

        // MARK: appNotRunning

        await TestSuite.run("Precondition appNotRunning: running/not running, case-insensitive, trailing wildcard, error → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                env.runningApplications.ids = ["com.apple.finder", "com.apple.dt.Xcode", "com.adobe.Photoshop"]
                try TestSuite.assertFalse(await eval(env, .appNotRunning(["com.apple.dt.Xcode"]), t).passed)
                try TestSuite.assertFalse(await eval(env, .appNotRunning(["COM.APPLE.DT.XCODE"]), t).passed, "case-insensitive")
                try TestSuite.assertFalse(await eval(env, .appNotRunning(["com.adobe.*"]), t).passed, "wildcard")
                try TestSuite.assertFalse(await eval(env, .appNotRunning(["com.example.none", "com.apple.dt.Xcode"]), t).passed, "any of list")
                try TestSuite.assertTrue(await eval(env, .appNotRunning(["com.google.Chrome", "com.microsoft.*"]), t).passed)
                try TestSuite.assertTrue(await eval(env, .appNotRunning(["com.apple.dt"]), t).passed, "no implicit prefix match")
                try TestSuite.assertFalse(await eval(env, .appNotRunning([]), t).passed, "empty list fails closed")
                try TestSuite.assertFalse(await eval(env, .appNotRunning(["com.*.x*"]), t).passed, "malformed pattern fails closed")
                env.runningApplications.failing = true
                let r = await eval(env, .appNotRunning(["com.google.Chrome"]), t)
                try TestSuite.assertFalse(r.passed, "error → false")
                try TestSuite.assertEqual(r.name, "appNotRunning")
            }
        }

        // MARK: owningAppNotRunning

        await TestSuite.run("Precondition owningAppNotRunning: nil owner → false; running → false; error → false") {
            try await M1.withEnv { env in
                env.runningApplications.ids = ["com.apple.finder", "com.example.app"]
                try TestSuite.assertFalse(await eval(env, .owningAppNotRunning, try target(env, owner: nil)).passed, "nil owner")
                try TestSuite.assertFalse(await eval(env, .owningAppNotRunning, try target(env, owner: "  ")).passed, "blank owner")
                try TestSuite.assertFalse(await eval(env, .owningAppNotRunning, try target(env, owner: "com.example.app")).passed, "running")
                try TestSuite.assertFalse(await eval(env, .owningAppNotRunning, try target(env, owner: "COM.EXAMPLE.APP")).passed, "running, case")
                try TestSuite.assertTrue(await eval(env, .owningAppNotRunning, try target(env, owner: "com.example.other")).passed, "not running")
                try TestSuite.assertTrue(await eval(env, .owningAppNotRunning, try target(env, owner: "com.example.*")).passed,
                                         "owner IDs are never wildcards")
                env.runningApplications.failing = true
                try TestSuite.assertFalse(await eval(env, .owningAppNotRunning, try target(env, owner: "com.example.other")).passed, "error")
            }
        }

        // MARK: processNotRunning

        await TestSuite.run("Precondition processNotRunning: exact, truncated proc_name, error → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                env.processes.names = ["launchd", "node", "com.apple.dt.SK"]   // 15 chars: truncated proc_name
                try TestSuite.assertFalse(await eval(env, .processNotRunning(["node"]), t).passed)
                try TestSuite.assertFalse(await eval(env, .processNotRunning(["npm", "node"]), t).passed)
                try TestSuite.assertFalse(await eval(env, .processNotRunning(["com.apple.dt.SKAgent"]), t).passed, "truncation prefix")
                try TestSuite.assertTrue(await eval(env, .processNotRunning(["gradle", "xcodebuild"]), t).passed)
                try TestSuite.assertTrue(await eval(env, .processNotRunning(["nodemon"]), t).passed, "short names need exact match")
                try TestSuite.assertFalse(await eval(env, .processNotRunning([]), t).passed, "empty list")
                env.processes.failing = true
                try TestSuite.assertFalse(await eval(env, .processNotRunning(["gradle"]), t).passed, "error → false")
            }
        }

        // MARK: notOpenByAnyProcess

        await TestSuite.run("Precondition notOpenByAnyProcess: open file below target → false; error → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                let base = env.fixture.path(appCache)
                try TestSuite.assertTrue(await eval(env, .notOpenByAnyProcess, t).passed)
                env.processes.openFiles = [base + "Evil/file": [7]]
                try TestSuite.assertTrue(await eval(env, .notOpenByAnyProcess, t).passed, "sibling prefix is not inside")
                env.processes.openFiles = [base + "/db/Cache.db": [77]]
                try TestSuite.assertFalse(await eval(env, .notOpenByAnyProcess, t).passed)
                env.processes.openFiles = [:]
                env.processes.failing = true
                try TestSuite.assertFalse(await eval(env, .notOpenByAnyProcess, t).passed, "error → false")
            }
        }

        // MARK: olderThan

        await TestSuite.run("Precondition olderThan: uses max(mtime target, mtime children) via lstat") {
            try await M1.withEnv { env in
                let fx = env.fixture
                try fx.file(appCache + "/old.bin", bytes: 1)
                try fx.file(appCache + "/fresh.bin", bytes: 1)
                try fx.setModificationDate(appCache + "/old.bin", daysAgo: 90, clock: env.clock)
                try fx.setModificationDate(appCache + "/fresh.bin", daysAgo: 5, clock: env.clock)
                try fx.setModificationDate(appCache, daysAgo: 90, clock: env.clock)
                let t = env.scanTarget(ruleID: "test.caches", path: appCache)
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t).passed, "fresh child keeps it in use")
                try TestSuite.assertTrue(await eval(env, .olderThan(days: 3), t).passed)
                try fx.setModificationDate(appCache + "/fresh.bin", daysAgo: 60, clock: env.clock)
                try fx.setModificationDate(appCache, daysAgo: 90, clock: env.clock)
                try TestSuite.assertTrue(await eval(env, .olderThan(days: 30), t).passed, "all old")
                // Directory itself fresh (child added/removed recently) → not old.
                try fx.setModificationDate(appCache, daysAgo: 1, clock: env.clock)
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t).passed, "fresh directory mtime")
                // Clock moves forward → old again.
                env.clock.advance(days: 40)
                try TestSuite.assertTrue(await eval(env, .olderThan(days: 30), t).passed, "uses env.clock")
            }
        }

        await TestSuite.run("Precondition olderThan: missing target, unreadable listing, negative days → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                try env.fixture.setModificationDate(appCache, daysAgo: 100, clock: env.clock)
                try TestSuite.assertTrue(await eval(env, .olderThan(days: 30), t).passed)
                try TestSuite.assertFalse(await eval(env, .olderThan(days: -1), t).passed, "negative days")
                env.fileSystem.fail(.contentsOfDirectory, path: env.fixture.path(appCache))
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t).passed, "listing error")
                env.fileSystem.clearOverrides()
                env.fileSystem.fail(.lstat, path: env.fixture.path(appCache))
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t).passed, "lstat error")
                let gone = ScanTarget(ruleID: "test.caches", path: env.fixture.path("Library/Caches/gone"), displayName: "g",
                                      identity: nil, allocatedBytes: 0, reclaimableBytes: 0, itemCount: 0, lastUsed: nil)
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 0), gone).passed, "missing target")
            }
        }

        await TestSuite.run("Precondition olderThan: ageThresholdOverrides can only RAISE the threshold") {
            try await M1.withEnv { env in
                let t = try target(env)
                try env.fixture.setModificationDate(appCache, daysAgo: 20, clock: env.clock)
                let rule = M1.rule(id: t.ruleID, preconditions: [.olderThan(days: 30)])
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t, rule: rule, overrides: [rule.id: 10]).passed,
                                          "lowering to 10 days is ignored")
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t, rule: rule, overrides: [rule.id: -5]).passed)
                try env.fixture.setModificationDate(appCache, daysAgo: 45, clock: env.clock)
                try TestSuite.assertTrue(await eval(env, .olderThan(days: 30), t, rule: rule).passed)
                try TestSuite.assertFalse(await eval(env, .olderThan(days: 30), t, rule: rule, overrides: [rule.id: 60]).passed,
                                          "raising to 60 days applies")
                try TestSuite.assertTrue(await eval(env, .olderThan(days: 30), t, rule: rule, overrides: ["other.rule": 60]).passed,
                                         "override for another rule does not apply")
            }
        }

        // MARK: manifestPresent

        await TestSuite.run("Precondition manifestPresent: exact names and single '*' wildcards beside the artifact") {
            try await M1.withEnv { env in
                let fx = env.fixture
                try fx.dir("Projects/web/node_modules/x")
                let t = env.scanTarget(ruleID: "test.caches", path: "Projects/web/node_modules")
                try TestSuite.assertFalse(await eval(env, .manifestPresent(["package-lock.json", "yarn.lock"]), t).passed, "none yet")
                try fx.file("Projects/web/next.config.mjs", bytes: 1)
                try TestSuite.assertTrue(await eval(env, .manifestPresent(["next.config.*"]), t).passed)
                try TestSuite.assertFalse(await eval(env, .manifestPresent(["requirements*.txt"]), t).passed)
                try fx.file("Projects/web/requirements-dev.txt", bytes: 1)
                try TestSuite.assertTrue(await eval(env, .manifestPresent(["requirements*.txt"]), t).passed)
                try fx.file("Projects/web/package-lock.json", bytes: 1)
                try TestSuite.assertTrue(await eval(env, .manifestPresent(["package-lock.json"]), t).passed)
                try TestSuite.assertFalse(await eval(env, .manifestPresent(["a*b*c"]), t).passed, "two wildcards never match")
                try TestSuite.assertFalse(await eval(env, .manifestPresent([]), t).passed)
            }
        }

        await TestSuite.run("Precondition manifestPresent: directories / symlinks are not manifests; listing error → false") {
            try await M1.withEnv { env in
                let fx = env.fixture
                try fx.dir("Projects/rs/target/debug")
                try fx.dir("Projects/rs/Cargo.lock")                 // a directory, not a manifest
                try fx.file("elsewhere/Cargo.lock", bytes: 1, base: .root)
                try fx.symlink("Projects/rs/Cargo.toml", to: fx.path("elsewhere/Cargo.lock", base: .root))
                let t = env.scanTarget(ruleID: "test.caches", path: "Projects/rs/target")
                try TestSuite.assertFalse(await eval(env, .manifestPresent(["Cargo.lock", "Cargo.toml"]), t).passed)
                try fx.file("Projects/rs/Cargo.lock.real", bytes: 1)
                try TestSuite.assertTrue(await eval(env, .manifestPresent(["Cargo.lock.*"]), t).passed)
                env.fileSystem.fail(.contentsOfDirectory, path: fx.path("Projects/rs"))
                try TestSuite.assertFalse(await eval(env, .manifestPresent(["Cargo.lock.*"]), t).passed, "error → false")
            }
        }

        // MARK: notInsideCloudRoot

        await TestSuite.run("Precondition notInsideCloudRoot: cloud roots, ubiquitous, File Provider xattrs, errors → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                let path = env.fixture.path(appCache)
                try TestSuite.assertTrue(await eval(env, .notInsideCloudRoot, t).passed, "plain local cache")
                let icloud = try target(env, "Library/Mobile Documents/com~apple~CloudDocs/file")
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, icloud).passed, "iCloud Drive")
                let dropbox = try target(env, "Library/CloudStorage/Dropbox/x")
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, dropbox).passed, "CloudStorage")
                let caseVariant = try target(env, "library/CLOUDSTORAGE/Dropbox/y")
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, caseVariant).passed, "case variant")
                env.fileSystem.setUbiquitous(true, for: path)
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, t).passed, "ubiquitous")
                env.fileSystem.setUbiquitous(nil, for: path)
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, t).passed, "ubiquity unknown")
                env.fileSystem.clearOverrides()
                env.fileSystem.setExtendedAttributes(["com.apple.fileprovider.dir#N"], for: path)
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, t).passed, "fileprovider xattr")
                env.fileSystem.setExtendedAttributes(["com.apple.file-provider-domain-id"], for: path)
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, t).passed, "file-provider-domain-id xattr")
                env.fileSystem.clearOverrides()
                env.fileSystem.fail(.extendedAttributeNames, path: path)
                try TestSuite.assertFalse(await eval(env, .notInsideCloudRoot, t).passed, "xattr error → false")
            }
        }

        // MARK: ownedByUser

        await TestSuite.run("Precondition ownedByUser: uid mismatch / lstat error → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                try TestSuite.assertTrue(await eval(env, .ownedByUser, t).passed)
                env.fileSystem.overrideStat(env.fixture.path(appCache), uid: M1.otherUID)
                try TestSuite.assertFalse(await eval(env, .ownedByUser, t).passed)
                env.fileSystem.clearOverrides()
                env.userID = M1.otherUID
                try TestSuite.assertFalse(await eval(env, .ownedByUser, t).passed, "env.userID differs")
                env.userID = getuid()
                env.fileSystem.fail(.lstat)
                try TestSuite.assertFalse(await eval(env, .ownedByUser, t).passed, "error → false")
            }
        }

        // MARK: simulatorIdle

        await TestSuite.run("Precondition simulatorIdle: Booted device → false; Simulator.app running → false; errors → false") {
            try await M1.withEnv { env in
                let t = try target(env)
                let args = ["simctl", "list", "devices", "-j"]
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "xcrun not resolvable")
                env.commands.executables = ["xcrun": "/usr/bin/xcrun"]
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "command failed (default exit 1)")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: simctlJSON(["Shutdown", "Booted"]), stderr: ""), for: args)
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "Booted device")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: simctlJSON(["Shutdown", "Shutdown"]), stderr: ""), for: args)
                try TestSuite.assertTrue(await eval(env, .simulatorIdle, t).passed, "all shut down")
                let last = env.commands.invocations.last
                try TestSuite.assertEqual(last?.executable, "/usr/bin/xcrun")
                try TestSuite.assertEqual(last?.arguments, args)
                try TestSuite.assertEqual(last?.timeout, 30)
                env.runningApplications.ids = ["com.apple.finder", "com.apple.iphonesimulator"]
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "Simulator.app running")
                env.runningApplications.ids = ["com.apple.finder"]
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "not json", stderr: ""), for: args)
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "malformed JSON")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: simctlJSON(["Shutdown"]), stderr: "", timedOut: true), for: args)
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "timeout")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: simctlJSON(["Shutdown"]), stderr: ""), for: args)
                env.runningApplications.failing = true
                try TestSuite.assertFalse(await eval(env, .simulatorIdle, t).passed, "running apps unavailable")
            }
        }

        // MARK: dockerDaemonReachable

        await TestSuite.run("Precondition dockerDaemonReachable: exit 0 within 5 s only") {
            try await M1.withEnv { env in
                let t = try target(env)
                try TestSuite.assertFalse(await eval(env, .dockerDaemonReachable, t).passed, "docker missing")
                env.commands.executables = ["docker": "/usr/local/bin/docker"]
                try TestSuite.assertFalse(await eval(env, .dockerDaemonReachable, t).passed, "exit 1")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "Server: ...", stderr: ""), for: ["info"])
                try TestSuite.assertTrue(await eval(env, .dockerDaemonReachable, t).passed)
                try TestSuite.assertEqual(env.commands.invocations.last?.timeout, 5)
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: "", timedOut: true), for: ["info"])
                try TestSuite.assertFalse(await eval(env, .dockerDaemonReachable, t).passed, "timeout")
            }
        }

        // MARK: notMounted

        await TestSuite.run("Precondition notMounted: image-path list from hdiutil info -plist") {
            try await M1.withEnv { env in
                let dmgRel = "Downloads/Installer.dmg"
                let dmg = try env.fixture.file(dmgRel, bytes: 16)
                let t = env.scanTarget(ruleID: "test.caches", path: dmgRel)
                let args = ["info", "-plist"]
                try TestSuite.assertFalse(await eval(env, .notMounted, t).passed, "hdiutil missing")
                env.commands.executables = ["hdiutil": "/usr/bin/hdiutil"]
                try TestSuite.assertFalse(await eval(env, .notMounted, t).passed, "command failed")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: plist([dmg]), stderr: ""), for: args)
                try TestSuite.assertFalse(await eval(env, .notMounted, t).passed, "mounted")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: plist([dmg.uppercased()]), stderr: ""), for: args)
                try TestSuite.assertFalse(await eval(env, .notMounted, t).passed, "mounted (case variant)")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: plist(["/Users/Shared/Other.dmg"]), stderr: ""), for: args)
                try TestSuite.assertTrue(await eval(env, .notMounted, t).passed, "another image")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: plist([]), stderr: ""), for: args)
                try TestSuite.assertTrue(await eval(env, .notMounted, t).passed, "nothing mounted")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "<plist><dict/></plist>", stderr: ""), for: args)
                try TestSuite.assertFalse(await eval(env, .notMounted, t).passed, "malformed plist")
            }
        }

        // MARK: appleSigned

        await TestSuite.run("Precondition appleSigned: true only when verifier says true; nil → false") {
            try await M1.withEnv { env in
                let t = try target(env, "Applications/Install macOS.app")
                let path = env.fixture.path("Applications/Install macOS.app")
                try TestSuite.assertFalse(await eval(env, .appleSigned, t).passed, "default nil")
                env.codeSignatures.set(true, for: path)
                try TestSuite.assertTrue(await eval(env, .appleSigned, t).passed)
                env.codeSignatures.set(false, for: path)
                try TestSuite.assertFalse(await eval(env, .appleSigned, t).passed)
                // The environment's default verifier can never vouch.
                try TestSuite.assertNil(UnavailableCodeSignatureVerifier().isAppleSigned(path: path))
            }
        }

        // MARK: notSelectedXcode

        await TestSuite.run("Precondition notSelectedXcode: xcode-select -p inside the bundle → false; errors → false") {
            try await M1.withEnv { env in
                let rel = "Applications/Xcode-15.app"
                let t = try target(env, rel)
                let bundle = env.fixture.path(rel)
                try TestSuite.assertFalse(await eval(env, .notSelectedXcode, t).passed, "tool missing")
                env.commands.executables = ["xcode-select": "/usr/bin/xcode-select"]
                try TestSuite.assertFalse(await eval(env, .notSelectedXcode, t).passed, "command failed")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: bundle + "/Contents/Developer\n", stderr: ""), for: ["-p"])
                try TestSuite.assertFalse(await eval(env, .notSelectedXcode, t).passed, "selected")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "/Applications/Xcode.app/Contents/Developer\n", stderr: ""), for: ["-p"])
                try TestSuite.assertTrue(await eval(env, .notSelectedXcode, t).passed, "another Xcode")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: ""), for: ["-p"])
                try TestSuite.assertFalse(await eval(env, .notSelectedXcode, t).passed, "empty output")
            }
        }

        // MARK: uploadedToCloud

        await TestSuite.run("Precondition uploadedToCloud: always false in v1") {
            try await M1.withEnv { env in
                let t = try target(env)
                env.fileSystem.setUbiquitous(true, for: env.fixture.path(appCache))
                try TestSuite.assertFalse(await eval(env, .uploadedToCloud, t).passed)
            }
        }

        // MARK: evaluateAll, live placeholders

        await TestSuite.run("Precondition evaluateAll: declared first, then implicit ownedByUser + notInsideCloudRoot") {
            try await M1.withEnv { env in
                let t = try target(env)
                let rule = M1.rule(id: t.ruleID, preconditions: [.processNotRunning(["node"]), .ownedByUser])
                let results = await env.makePreconditionEvaluator().evaluateAll(rule: rule, target: t)
                try TestSuite.assertEqual(results.map(\.name), ["processNotRunning", "ownedByUser", "notInsideCloudRoot"])
                try TestSuite.assertTrue(results.allSatisfy(\.passed), "\(results)")
                let cmdRule = M1.rule(id: "test.cmd", action: .command(CommandSpec(tool: "docker", arguments: ["volume", "rm", "{ITEM}"])))
                let cmd = env.scanTarget(ruleID: cmdRule.id, path: "volume", kind: .commandItem(argument: "v1"), captureIdentity: false)
                try TestSuite.assertTrue(await env.makePreconditionEvaluator().evaluateAll(rule: cmdRule, target: cmd).isEmpty,
                                         "no implicit filesystem predicates for command items")
            }
        }

        await TestSuite.run("Precondition: Milestone-1 DisabledCommandRunner makes every command predicate fail closed") {
            try await M1.withEnv { env in
                let t = try target(env)
                let base = env.environment
                let disabled = SafeCleanEnvironment(
                    homeDirectory: base.homeDirectory, fileSystem: base.fileSystem, processes: base.processes,
                    runningApplications: base.runningApplications, applications: base.applications, volumes: base.volumes,
                    commands: DisabledCommandRunner(), clock: base.clock, effectiveUserID: base.effectiveUserID,
                    userID: base.userID)
                let evaluator = PreconditionEvaluator(environment: disabled)
                let rule = M1.rule(id: t.ruleID)
                for p in [Precondition.simulatorIdle, .dockerDaemonReachable, .notMounted, .notSelectedXcode, .appleSigned] {
                    try TestSuite.assertFalse(await evaluator.evaluate(p, target: t, rule: rule).passed, p.name)
                }
                try TestSuite.assertNil(DisabledCommandRunner().resolveExecutable("xcrun"))
                let result = await DisabledCommandRunner().run(executable: "/usr/bin/true", arguments: [], timeout: 1)
                try TestSuite.assertFalse(result.succeeded)
            }
        }

        await TestSuite.run("LiveEnvironment.make: real uid/euid, Milestone-1 placeholders") {
            let live = LiveEnvironment.make()
            try TestSuite.assertEqual(live.effectiveUserID, geteuid())
            try TestSuite.assertEqual(live.userID, getuid())
            try TestSuite.assertNil(live.commands.resolveExecutable("xcrun"))
            try TestSuite.assertTrue(live.commands is DisabledCommandRunner)
        }
    }
}
