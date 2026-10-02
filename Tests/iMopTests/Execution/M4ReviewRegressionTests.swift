import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Regression tests for the Milestone 4 adversarial review: CommandRunner trust model (PATH,
/// `#!` interpreters, every directory and symlink hop, launching the verified file), process
/// lifetime (fd release, process-group kill, cancellation), UTF-8-safe truncation, and the vendor
/// inspectors (AVD .ini folder, bun / CocoaPods cache location, pinned preconditions, honest,
/// non-overlapping estimates).
///
/// Every executable run here is a FAKE `#!/bin/sh` script created inside the fixture (tests only)
/// or a symlink to it; no real vendor tool is ever run.
struct M4ReviewRegressionTests {
    typealias Ctx = CommandRunnerTests.Context

    static func ro(_ tool: String, _ arguments: [String]) -> CommandAllowList.Entry {
        CommandAllowList.Entry(tool, arguments, purpose: .readOnly)
    }

    static func act(_ tool: String, _ arguments: [String]) -> CommandAllowList.Entry {
        CommandAllowList.Entry(tool, arguments, purpose: .action)
    }

    /// Writes an executable file with exactly `contents` (no `#!/bin/sh` prefix added).
    @discardableResult
    static func rawScript(_ path: String, _ contents: String, mode: mode_t = 0o755) throws -> String {
        guard FileManager.default.createFile(atPath: path, contents: Data(contents.utf8)) else { throw TestError("create \(path)") }
        guard chmod(path, mode) == 0 else { throw TestError("chmod \(path)") }
        return path
    }

    static func directory(_ ctx: Ctx, _ rel: String, mode: mode_t) throws -> String {
        let path = try ctx.fixture.dir(rel, base: .root)
        guard chmod(path, mode) == 0 else { throw TestError("chmod \(path)") }
        return path
    }

    static func openFileDescriptorCount() -> Int {
        var count = 0
        for fd in 0..<Int32(getdtablesize()) where fcntl(fd, F_GETFD) != -1 { count += 1 }
        return count
    }

    /// `true` once `pid` no longer exists (polls: a killed, reparented process may linger briefly).
    static func processGone(_ pid: pid_t, within seconds: TimeInterval = 3) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if kill(pid, 0) == -1 && errno == ESRCH { return true }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return kill(pid, 0) == -1 && errno == ESRCH
    }

    @MainActor
    static func runAll() async {
        print("\n🧯 Running Milestone 4 Review Regression Tests...")
        await runnerTrustTests()
        await runnerLifetimeTests()
        await inspectorTests()
    }

    // MARK: - CommandRunner trust model

    @MainActor
    static func runnerTrustTests() async {
        await TestSuite.run("M4 review #1: PATH lists only search directories that pass the directory checks (+ /usr/bin, /bin); env never picks a program from a 0775 directory") {
            try await CommandRunnerTests.withContext { ctx in
                let loose = try directory(ctx, "loosebin", mode: 0o775)
                defer { chmod(loose, 0o755) }
                let marker = ctx.fixture.path("untrusted-node-ran")
                try rawScript(loose + "/node", "#!/bin/sh\n/usr/bin/touch \"\(marker)\"\n")
                let npm = try rawScript(ctx.bin + "/npm", "#!/usr/bin/env node\nconsole.log('x')\n")
                let envdump = try ctx.link("envdump", to: "/usr/bin/env")
                let runner = ctx.runner(entries: [ro("npm", ["config", "get", "cache"]), ro("envdump", [])],
                                        directories: [.init(path: ctx.bin), .init(path: loose)],
                                        roots: [ctx.bin, loose, "/usr/bin"])
                try TestSuite.assertNil(runner.resolveExecutable("node"), "a tool in a 0775 directory")
                try TestSuite.assertNil(runner.resolveExecutable("npm"), "#!/usr/bin/env node with node only in an untrusted directory")
                let refused = await runner.run(executable: npm, arguments: ["config", "get", "cache"], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(refused.exitCode, -1)
                try TestSuite.assertFalse(FileManager.default.fileExists(atPath: marker), "the untrusted interpreter ran")
                // The child's PATH leaves the 0775 directory out and ends with the SIP system directories.
                let env = await runner.run(executable: envdump, arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(env.exitCode, 0, env.stderr)
                let path = env.stdout.split(separator: "\n").first { $0.hasPrefix("PATH=") }.map { String($0.dropFirst(5)) }
                try TestSuite.assertEqual(path, ctx.bin + ":/usr/bin:/bin")
                // Control: `#!/usr/bin/env NAME` whose NAME is a trusted script on PATH runs.
                try ctx.script("goodinterp", #"echo "via goodinterp $1""#)
                let tool = try rawScript(ctx.bin + "/viaenv", "#!/usr/bin/env goodinterp\n")
                let good = ctx.runner(entries: [ro("viaenv", [])])
                try TestSuite.assertEqual(good.resolveExecutable("viaenv"), tool)
                let ran = await good.run(executable: tool, arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(ran.exitCode, 0, ran.stderr)
                try TestSuite.assertTrue(ran.stdout.hasPrefix("via goodinterp "), ran.stdout)
            }
        }

        await TestSuite.run("M4 review #2: a #! interpreter must pass the same trust checks (world-writable, outside the roots, relative, env options, over-long line → refused)") {
            try await CommandRunnerTests.withContext { ctx in
                let ww = try directory(ctx, "ww", mode: 0o777)
                defer { chmod(ww, 0o755) }
                let marker = ctx.fixture.path("interp-ran")
                _ = try rawScript(ww + "/interp", "#!/bin/sh\n/usr/bin/touch \"\(marker)\"\n")
                _ = try rawScript(ctx.outside + "/interp", "#!/bin/sh\n/usr/bin/touch \"\(marker)\"\n")
                _ = try rawScript(ctx.bin + "/looseinterp", "#!/bin/sh\n/usr/bin/touch \"\(marker)\"\n", mode: 0o777)
                let cases: [(String, String)] = [
                    ("wwinterp", "#!\(ww)/interp\n"),
                    ("outsideinterp", "#!\(ctx.outside)/interp\n"),
                    ("writableinterp", "#!\(ctx.bin)/looseinterp\n"),
                    ("relinterp", "#!interp\n"),
                    ("envoptions", "#!/usr/bin/env -S sh -c true\n"),
                    ("envtwo", "#!/usr/bin/env sh extra\n"),
                    ("envmissing", "#!/usr/bin/env imop-no-such-tool\n"),
                    ("nonewline", "#!/bin/sh " + String(repeating: "x", count: 600)),
                ]
                var entries: [CommandAllowList.Entry] = []
                for (name, contents) in cases {
                    try rawScript(ctx.bin + "/" + name, contents)
                    entries.append(ro(name, []))
                }
                let runner = ctx.runner(entries: entries)
                for (name, _) in cases {
                    try TestSuite.assertNil(runner.resolveExecutable(name), name)
                    let result = await runner.run(executable: ctx.bin + "/" + name, arguments: [], timeout: 10, purpose: .readOnly)
                    try TestSuite.assertEqual(result.exitCode, -1, name)
                }
                try TestSuite.assertFalse(FileManager.default.fileExists(atPath: marker), "an untrusted interpreter ran")
                // Controls: the SIP shell and `env sh` (found in /bin) are fine.
                try rawScript(ctx.bin + "/sipshell", "#!/bin/sh\necho ok\n")
                try rawScript(ctx.bin + "/envsh", "#!/usr/bin/env sh\necho ok\n")
                let good = ctx.runner(entries: [ro("sipshell", []), ro("envsh", [])])
                for name in ["sipshell", "envsh"] {
                    let result = await good.run(executable: ctx.bin + "/" + name, arguments: [], timeout: 10, purpose: .readOnly)
                    try TestSuite.assertEqual(result.stdout, "ok\n", "\(name): \(result.stderr)")
                }
            }
        }

        await TestSuite.run("M4 review #3: every ancestor and symlink hop is checked, and the verified real file (not the link) is launched") {
            try await CommandRunnerTests.withContext { ctx in
                // A search directory whose PARENT is world-writable.
                let ww = try directory(ctx, "ww", mode: 0o755)
                let nested = try directory(ctx, "ww/trusted", mode: 0o755)
                try ctx.script("nestedtool", "exit 0", in: nested)
                let nestedRunner = ctx.runner(entries: [], directories: [.init(path: nested)], roots: [nested])
                try TestSuite.assertTrue(nestedRunner.resolveExecutable("nestedtool") != nil, "control: safe ancestors")
                chmod(ww, 0o777)
                defer { chmod(ww, 0o755) }
                try TestSuite.assertNil(nestedRunner.resolveExecutable("nestedtool"), "parent of the search directory is 0777")
                try TestSuite.assertTrue(nestedRunner.sanitizedPathDirectories() == CommandRunner.systemDirectories,
                                         "an unsafe search directory is never on PATH: \(nestedRunner.sanitizedPathDirectories())")

                // An intermediate hop living in a world-writable directory: T/uv → ww/hop → T/realuv.
                let real = try ctx.script("realuv", "exit 0")
                _ = try FileManager.default.createSymbolicLink(atPath: ww + "/hop", withDestinationPath: real)
                _ = try ctx.link("uv", to: ww + "/hop")
                try TestSuite.assertNil(ctx.runner(entries: []).resolveExecutable("uv"), "a hop inside a 0777 directory")

                // The launched file is the resolved one: $0 is the real path, not the search-directory link.
                let realDir = try directory(ctx, "realdir", mode: 0o755)
                let target = try ctx.script("printself", #"printf '%s' "$0""#, in: realDir)
                let link = try ctx.link("printself", to: target)
                let runner = ctx.runner(entries: [ro("printself", [])], roots: [ctx.bin, realDir])
                try TestSuite.assertEqual(runner.resolveExecutable("printself"), link)
                let result = await runner.run(executable: link, arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(result.exitCode, 0, result.stderr)
                try TestSuite.assertEqual(FixtureBuilder.realpath(result.stdout), FixtureBuilder.realpath(target))
                try TestSuite.assertFalse(result.stdout.hasPrefix(ctx.bin), result.stdout)
            }
        }
    }

    // MARK: - CommandRunner lifetime

    @MainActor
    static func runnerLifetimeTests() async {
        await TestSuite.run("M4 review #9: a finished command releases its pipe descriptors at once (no fd per run held until the timeout)") {
            try await CommandRunnerTests.withContext { ctx in
                let quick = try ctx.script("quick", "echo hi; echo err >&2")
                let runner = ctx.runner(entries: [ro("quick", [])])
                // Warm-up (dispatch and Foundation open a few descriptors once).
                _ = await runner.run(executable: quick, arguments: [], timeout: 600, purpose: .readOnly)
                try? await Task.sleep(nanoseconds: 200_000_000)
                let baseline = openFileDescriptorCount()
                for _ in 0..<40 {
                    let result = await runner.run(executable: quick, arguments: [], timeout: 600, purpose: .readOnly)
                    try TestSuite.assertEqual(result.stdout, "hi\n")
                    try TestSuite.assertEqual(result.stderr, "err\n")
                }
                var after = openFileDescriptorCount()
                let deadline = Date().addingTimeInterval(3)
                while after > baseline + 2 && Date() < deadline {
                    try? await Task.sleep(nanoseconds: 100_000_000)
                    after = openFileDescriptorCount()
                }
                try TestSuite.assertTrue(after <= baseline + 2, "open fds grew from \(baseline) to \(after) after 40 runs")
            }
        }

        await TestSuite.run("M4 review #10: on timeout the whole process group is killed (a TERM-ignoring grandchild too) before the result is delivered") {
            try await CommandRunnerTests.withContext { ctx in
                let pidFile = ctx.fixture.path("grandchild.pid")
                let spawner = try ctx.script("spawner", """
                /bin/sh -c 'trap "" TERM; echo $$ > "\(pidFile)"; exec /bin/sleep 120' &
                exec /bin/sleep 120
                """)
                let runner = ctx.runner(entries: [ro("spawner", [])], grace: 1)
                let started = Date()
                let result = await runner.run(executable: spawner, arguments: [], timeout: 1, purpose: .readOnly)
                let elapsed = Date().timeIntervalSince(started)
                try TestSuite.assertTrue(result.timedOut, result.stderr)
                try TestSuite.assertTrue(elapsed < 10, "\(elapsed) s")
                guard let text = try? String(contentsOfFile: pidFile, encoding: .utf8),
                      let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 else {
                    throw TestError("no grandchild pid")
                }
                let gone = await processGone(pid)
                if !gone { kill(pid, SIGKILL) }
                try TestSuite.assertTrue(gone, "the TERM-ignoring grandchild \(pid) survived the timeout")
            }
        }

        await TestSuite.run("M4 review #11: a cancelled task stops a read-only probe promptly (\"cancelled\"); an action is never interrupted") {
            try await CommandRunnerTests.withContext { ctx in
                let pidFile = ctx.fixture.path("probe.pid")
                let slow = try ctx.script("slowprobe", "echo $$ > \"\(pidFile)\"\nexec /bin/sleep 60")
                let work = try ctx.script("slowaction", "/bin/sleep 1\necho done")
                let runner = ctx.runner(entries: [ro("slowprobe", []), act("slowaction", [])], grace: 1)
                let started = Date()
                let probe = Task { await runner.run(executable: slow, arguments: [], timeout: 30, purpose: .readOnly) }
                // Cancel once the probe is certainly running.
                let readyBy = Date().addingTimeInterval(10)
                while !FileManager.default.fileExists(atPath: pidFile) && Date() < readyBy {
                    try? await Task.sleep(nanoseconds: 20_000_000)
                }
                try? await Task.sleep(nanoseconds: 100_000_000)
                let cancelledAt = Date()
                probe.cancel()
                let result = await probe.value
                let elapsed = Date().timeIntervalSince(cancelledAt)
                _ = started
                try TestSuite.assertEqual(result.exitCode, -1)
                try TestSuite.assertEqual(result.stderr, CommandRunner.cancelledMessage)
                try TestSuite.assertFalse(result.timedOut)
                try TestSuite.assertTrue(elapsed < 6, "cancellation took \(elapsed) s")
                let pidText = (try? String(contentsOfFile: pidFile, encoding: .utf8)) ?? ""
                if let pid = pid_t(pidText.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 {
                    let gone = await processGone(pid)
                    if !gone { kill(pid, SIGKILL) }
                    try TestSuite.assertTrue(gone, "the cancelled probe \(pid) is still running")
                } else {
                    throw TestError("no pid in \(pidText.debugDescription)")
                }
                // Already cancelled before the call: the probe never starts.
                let early = Task {
                    withUnsafeCurrentTask { $0?.cancel() }
                    return await runner.run(executable: slow, arguments: [], timeout: 30, purpose: .readOnly)
                }
                try TestSuite.assertEqual(await early.value.stderr, CommandRunner.cancelledMessage)

                let action = Task { await runner.run(executable: work, arguments: [], timeout: 30, purpose: .action) }
                try? await Task.sleep(nanoseconds: 200_000_000)
                action.cancel()
                let finished = await action.value
                try TestSuite.assertEqual(finished.exitCode, 0, finished.stderr)
                try TestSuite.assertEqual(finished.stdout, "done\n")
            }
        }

        await TestSuite.run("M4 review #12: truncation never splits a UTF-8 sequence (no U+FFFD), and counts the dropped bytes") {
            try await CommandRunnerTests.withContext { ctx in
                let limit = CommandRunner.outputLimit
                let path = try ctx.script("multibyte", """
                /usr/bin/head -c \(limit - 1) /dev/zero | /usr/bin/tr '\\000' a
                printf '\\303\\251bbbbbbbbbb'
                """)
                let runner = ctx.runner(entries: [ro("multibyte", [])])
                let result = await runner.run(executable: path, arguments: [], timeout: 30, purpose: .readOnly)
                try TestSuite.assertEqual(result.exitCode, 0, result.stderr)
                try TestSuite.assertFalse(result.stdout.contains("\u{FFFD}"), "a split sequence was decoded as U+FFFD")
                try TestSuite.assertEqual(result.stdout, String(repeating: "a", count: limit - 1) + "\n[truncated 12 bytes]")
                // A sequence that fits whole is kept.
                let fits = try ctx.script("fits", """
                /usr/bin/head -c \(limit - 2) /dev/zero | /usr/bin/tr '\\000' a
                printf '\\303\\251bb'
                """)
                let kept = await ctx.runner(entries: [ro("fits", [])]).run(executable: fits, arguments: [], timeout: 30, purpose: .readOnly)
                try TestSuite.assertEqual(kept.stdout, String(repeating: "a", count: limit - 2) + "é\n[truncated 2 bytes]")
            }
        }
    }

    // MARK: - Inspectors

    static func ok(_ stdout: String) -> CommandResult { CommandResult(exitCode: 0, stdout: stdout, stderr: "") }

    @MainActor
    static func inspectorTests() async {
        await TestSuite.run("M4 review #4: an AVD is actionable only when its .ini names exactly its own folder") {
            try await M1.withEnv { env in
                try CommandInspectorTests.installEverything(env)
                let f = env.fixture
                let name = "Pixel_7_API_34"
                let ini = ".android/avd/\(name).ini"
                try f.file("Documents/notes.txt", bytes: 100)
                try f.file("Projects/repo/.git/HEAD", bytes: 10)
                try f.file(".android/avd/Other.avd/userdata.img", bytes: 100)
                _ = try f.symlink("Library/avdlink", to: f.path(".android/avd/\(name).avd"))
                @MainActor func scanWith(_ contents: String) async throws -> [TargetKind] {
                    try FileManager.default.removeItem(atPath: f.path(ini))
                    try f.file(ini, contents: Data(contents.utf8))
                    let r = try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["android.avd"]), "android.avd")
                    try TestSuite.assertEqual(r.status, .ok)
                    return r.targets.map(\.kind)
                }
                let own = "path=\(f.home)/.android/avd/\(name).avd\npath.rel=avd/\(name).avd\n"
                try TestSuite.assertEqual(try await scanWith(own), [.commandItem(argument: name)], "control")
                try TestSuite.assertEqual(try await scanWith("path.rel=avd/\(name).avd\n"), [.commandItem(argument: name)], "path.rel only")
                let hostile = [
                    "path=\(f.home)/Documents\n",
                    "path=\(f.home)/Projects/repo\n",
                    "path=\(f.home)/.android/avd/Other.avd\n",
                    "path=\(f.home)/.android/avd/\(name).avd\npath.rel=avd/Other.avd\n",
                    "path=\(f.home)/.android/avd/\(name).avd\npath=\(f.home)/Documents\n",
                    "path=\(f.home)/Library/avdlink\n",
                    "path=relative/\(name).avd\n",
                    "path=/Volumes/External/\(name).avd\n",
                    "path.rel=../Documents\n",
                    "target=android-34\n",
                    "",
                ]
                for contents in hostile {
                    let kinds = try await scanWith(contents)
                    try TestSuite.assertEqual(kinds, [.advisory], contents.debugDescription)
                }
            }
        }

        await TestSuite.run("M4 review #5: bun sizes the folder `bun pm cache` reports; CocoaPods with a custom cache_root is unavailable; pod sizes <cache>/Pods") {
            try await M1.withEnv { env in
                try CommandInspectorTests.installEverything(env)
                let f = env.fixture
                // bun's config points the cache at a project with a .git: the folder is checked and withheld.
                try f.file("Projects/shared/.git/HEAD", bytes: 10)
                try f.file("Projects/shared/pkg/index.js", bytes: 1_000)
                env.commands.setResponse(ok(f.path("Projects/shared") + "\n"), for: ["pm", "cache"])
                let bun = try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["bun.cache"]), "bun.cache")
                try TestSuite.assertEqual(bun.targets.count, 0, "a cache folder containing .git was offered")
                try TestSuite.assertTrue(env.commands.invocations.contains { $0.arguments == ["pm", "cache"] && $0.purpose == .readOnly })
                // A custom, harmless location is the one sized (never the default folder).
                try f.file("Library/Caches/bun-custom/x/index.js", bytes: 5_000)
                env.commands.setResponse(ok(f.path("Library/Caches/bun-custom") + "\n"), for: ["pm", "cache"])
                let custom = try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["bun.cache"]), "bun.cache")
                try TestSuite.assertEqual(custom.targets.map(\.path), [f.path("Library/Caches/bun-custom")])
                try TestSuite.assertEqual(custom.targets.first?.allocatedBytes, M2.treeBlocksBytes(f.path("Library/Caches/bun-custom")))
                env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: "x"), for: ["pm", "cache"])
                try CommandInspectorTests.expectUnavailable(try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["bun.cache"]), "bun.cache"))

                // CocoaPods: the default <cache_root>/Pods is sized…
                let pods = try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["cocoapods.cache.command"]), "cocoapods.cache.command")
                try TestSuite.assertEqual(pods.targets.map(\.path), [f.path("Library/Caches/CocoaPods/Pods")])
                // …a config.yaml without cache_root changes nothing…
                try f.file(".cocoapods/config.yaml", contents: Data("---\nnew_version_message: false\n".utf8))
                let plain = try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["cocoapods.cache.command"]), "cocoapods.cache.command")
                try TestSuite.assertEqual(plain.targets.count, 1)
                // …but a custom cache_root makes the command rule unavailable.
                try FileManager.default.removeItem(atPath: f.path(".cocoapods/config.yaml"))
                try f.file(".cocoapods/config.yaml", contents: Data("---\ncache_root: \(f.home)/Projects\n".utf8))
                try CommandInspectorTests.expectUnavailable(try CommandInspectorTests.result(
                    try await CommandInspectorTests.scan(env, ["cocoapods.cache.command"]), "cocoapods.cache.command"), "cache_root")
            }
        }

        await TestSuite.run("M4 review #6: a pinned command rule that drops its spec §6 preconditions offers nothing (catalog, matcher, inspector, gate)") {
            try await M1.withEnv { env in
                try CommandInspectorTests.installEverything(env)
                for id in ["npm.cache", "go.modCache", "android.avd", "flutter.pubCache", "homebrew.cleanup", "docker.volumes",
                           "simulator.devices.stale"] {
                    var json = try M2ReviewRegressionTests.bundledRuleJSON(id)
                    json["preconditions"] = [Any]()
                    try TestSuite.assertEqual(try M2ReviewRegressionTests.load([json], env).rules.count, 0, "\(id): catalog accepted it")
                    let bundled = try M2ReviewRegressionTests.bundledRule(env, id)
                    let stripped = Rule(id: bundled.id, category: bundled.category, tier: bundled.tier, title: bundled.title,
                                        explanation: bundled.explanation, whatYouLose: bundled.whatYouLose,
                                        howItRegenerates: bundled.howItRegenerates, discovery: bundled.discovery,
                                        allowRoots: bundled.allowRoots, minDepthBelowRoot: bundled.minDepthBelowRoot,
                                        preconditions: [], action: bundled.action)
                    try TestSuite.assertTrue(RuleTargetMatcher.commandRuleMismatch(stripped) != nil, id)
                    try TestSuite.assertNil(RuleTargetMatcher.commandRuleMismatch(bundled), "\(id): bundled rule")
                }
                // npm.cache with only `processNotRunning(npm)` (node dropped) is refused too.
                let npm = try M2ReviewRegressionTests.bundledRule(env, "npm.cache")
                let partial = Rule(id: npm.id, category: npm.category, tier: npm.tier, title: npm.title, explanation: npm.explanation,
                                   whatYouLose: npm.whatYouLose, howItRegenerates: npm.howItRegenerates, discovery: npm.discovery,
                                   allowRoots: npm.allowRoots, minDepthBelowRoot: npm.minDepthBelowRoot,
                                   preconditions: [.processNotRunning(["npm"])], action: npm.action)
                try TestSuite.assertTrue(RuleTargetMatcher.commandRuleMismatch(partial) != nil)
                let output = await PackageManagerCachesInspector().discover(rule: partial, environment: env.environment)
                try TestSuite.assertEqual(output.candidates.count, 0)
                try TestSuite.assertEqual(RuleCatalog(validating: [partial], environment: env.environment).rules.count, 0)
                let target = M3.commandTarget(rule: partial, path: env.fixture.home + "/.npm/_cacache")
                guard case .rejected(.doesNotMatchRule) = await env.makeGate().validate(target: target, rule: partial, phase: .plan) else {
                    throw TestError("the gate accepted a rule without its pinned preconditions")
                }
            }
        }

        await TestSuite.run("M4 review #7/#8: estimates are honest and never overlap (dangling = unique sizes; unused images exclude them; pnpm/uv prune count 0)") {
            try await M1.withEnv { env in
                try CommandInspectorTests.installEverything(env)
                // Two dangling images of 1.2 GB that share a base layer: only their unique 100 MB each is freed.
                env.commands.setResponse(ok("""
                Images space usage:

                REPOSITORY   TAG       IMAGE ID       CREATED        SIZE      SHARED SIZE   UNIQUE SIZE   CONTAINERS
                node         20        77aa88bb99cc   4 months ago   1.1GB     1.1GB         0B            1
                <none>       <none>    9a8b7c6d5e4f   2 months ago   1.2GB     1.1GB         100MB         0
                <none>       <none>    0f1e2d3c4b5a   2 months ago   1.2GB     1.1GB         100MB         0
                <none>       <none>    1b2c3d4e5f60   3 days ago     900MB     0B            900MB         1

                Local Volumes space usage:

                VOLUME NAME   LINKS     SIZE
                old_pgdata    0         1.85GB

                """), for: DockerClient.systemDFVerboseArguments)
                let results = try await CommandInspectorTests.scan(env, ["docker.danglingImages", "docker.unusedImages", "pnpm.store",
                                                                        "uv.cache.prune", "uv.cache.clean"])
                let dangling = try CommandInspectorTests.result(results, "docker.danglingImages")
                try TestSuite.assertEqual(dangling.targets.first?.reclaimableBytes, 200_000_000, "unique sizes of container-less dangling images")
                let unused = try CommandInspectorTests.result(results, "docker.unusedImages")
                try TestSuite.assertEqual(unused.targets.first?.reclaimableBytes, 11_630_000_000 - 200_000_000)
                let dockerTotal = (dangling.targets.first?.reclaimableBytes ?? 0) + (unused.targets.first?.reclaimableBytes ?? 0)
                try TestSuite.assertTrue(dockerTotal <= 11_630_000_000, "both Docker image rules together claim \(dockerTotal) bytes")

                // Malformed image table → dangling unavailable (never a guess).
                env.commands.setResponse(ok("Images space usage:\n\nREPOSITORY TAG\n"), for: DockerClient.systemDFVerboseArguments)
                try CommandInspectorTests.expectUnavailable(try CommandInspectorTests.result(
                    try await CommandInspectorTests.scan(env, ["docker.danglingImages"]), "docker.danglingImages"), "malformed")

                // Partial-free commands: size shown as allocated ("up to"), never counted as reclaimable.
                for id in ["pnpm.store", "uv.cache.prune"] {
                    let target = try CommandInspectorTests.result(results, id).targets.first
                    try TestSuite.assertTrue((target?.allocatedBytes ?? 0) > 0, id)
                    try TestSuite.assertEqual(target?.reclaimableBytes, 0, id)
                    try TestSuite.assertTrue(target?.notes.contains { $0.hasPrefix("Up to ") } == true, "\(id): \(target?.notes ?? [])")
                }
                let clean = try CommandInspectorTests.result(results, "uv.cache.clean").targets.first
                try TestSuite.assertTrue((clean?.reclaimableBytes ?? 0) > 0)
                try TestSuite.assertEqual(clean?.reclaimableBytes, clean?.allocatedBytes)
            }
        }
    }
}
