import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §5.3 / §12.2 (Milestone 4): `CommandRunner` — trusted executable resolution, exact
/// allow-listed invocations per purpose, no shell, sanitized environment, `/dev/null` stdin,
/// 64 KB output capture without pipe deadlock and hard timeouts.
///
/// Every executable run here is a FAKE created inside the fixture: a `#!/bin/sh` script (tests
/// only — never in Sources) or a symlink to a harmless system tool (`env`, `cat`, `pwd`). No real
/// vendor tool is ever run, and the production runner is only ever given invocations it refuses
/// before resolving anything.
struct CommandRunnerTests {
    /// A fixture with one trusted `bin` directory (0755) and a runner limited to it.
    final class Context: Sendable {
        let fixture: FixtureBuilder
        let bin: String
        let outside: String

        init() throws {
            fixture = try FixtureBuilder()
            bin = try fixture.dir("trusted/bin", base: .root)
            outside = try fixture.dir("outside", base: .root)
            chmod(fixture.path("trusted", base: .root), 0o755)
            chmod(bin, 0o755)
            chmod(outside, 0o755)
        }

        /// Writes an executable script (mode `mode`) into `directory`.
        @discardableResult
        func script(_ name: String, _ body: String, in directory: String? = nil, mode: mode_t = 0o755) throws -> String {
            let path = (directory ?? bin) + "/" + name
            guard FileManager.default.createFile(atPath: path, contents: Data(("#!/bin/sh\n" + body + "\n").utf8)) else {
                throw TestError("could not create \(path)")
            }
            guard chmod(path, mode) == 0 else { throw TestError("chmod \(path)") }
            return path
        }

        func link(_ name: String, to destination: String, in directory: String? = nil) throws -> String {
            let path = (directory ?? bin) + "/" + name
            try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: destination)
            return path
        }

        func runner(entries: [CommandAllowList.Entry], directories: [CommandRunner.SearchDirectory]? = nil,
                    roots: [String]? = nil, grace: TimeInterval = 1, userID: uid_t = getuid()) -> CommandRunner {
            CommandRunner(homeDirectory: URL(fileURLWithPath: fixture.home, isDirectory: true),
                          searchDirectories: directories ?? [CommandRunner.SearchDirectory(path: bin)],
                          trustedRoots: roots ?? [bin], allowList: CommandAllowList(entries: entries),
                          terminationGrace: grace, userID: userID)
        }

        func cleanup() {
            // Restore owner write permission everywhere so the fixture can be removed.
            for dir in [bin, outside, fixture.path("trusted", base: .root)] { chmod(dir, 0o755) }
            fixture.cleanup()
        }
    }

    @MainActor
    static func withContext(_ body: (Context) async throws -> Void) async throws {
        let ctx = try Context()
        defer { ctx.cleanup() }
        try await body(ctx)
    }

    static func ro(_ tool: String, _ arguments: [String]) -> CommandAllowList.Entry {
        CommandAllowList.Entry(tool, arguments, purpose: .readOnly)
    }

    static func act(_ tool: String, _ arguments: [String], item: CommandItemKind? = nil) -> CommandAllowList.Entry {
        CommandAllowList.Entry(tool, arguments, purpose: .action, itemKind: item)
    }

    @MainActor
    static func runAll() async {
        print("\n🧰 Running CommandRunner Tests (spec §5.3, §12.2)...")

        // MARK: Resolution

        await TestSuite.run("CommandRunner: a script in a trusted directory resolves to its absolute path") {
            try await withContext { ctx in
                let path = try ctx.script("goodtool", "exit 0")
                try TestSuite.assertEqual(ctx.runner(entries: []).resolveExecutable("goodtool"), path)
                try TestSuite.assertNil(ctx.runner(entries: []).resolveExecutable("missingtool"))
            }
        }

        await TestSuite.run("CommandRunner: untrusted locations are rejected (outside the list, /tmp, the fixture, relative, '/' and '-' names)") {
            try await withContext { ctx in
                try ctx.script("strayTool", "exit 0", in: ctx.outside)
                let runner = ctx.runner(entries: [ro("strayTool", [])])
                try TestSuite.assertNil(runner.resolveExecutable("strayTool"), "a directory that is not in the trusted list")
                // Running it by absolute path anyway is refused (it is not what resolution returns).
                let stray = await runner.run(executable: ctx.outside + "/strayTool", arguments: [], timeout: 5, purpose: .readOnly)
                try TestSuite.assertEqual(stray.exitCode, -1)
                try TestSuite.assertTrue(stray.stderr.contains("trusted"), stray.stderr)
                let tmp = await runner.run(executable: "/tmp/strayTool", arguments: [], timeout: 5, purpose: .readOnly)
                try TestSuite.assertEqual(tmp.exitCode, -1)
                // The production search list never includes /tmp or the fixture.
                let production = CommandRunner.standardSearchDirectories(home: ctx.fixture.home).map(\.path)
                let home = ctx.fixture.home
                try TestSuite.assertEqual(production, ["/usr/bin", "/opt/homebrew/bin", "/usr/local/bin", home + "/.cargo/bin",
                                                       home + "/go/bin", home + "/.bun/bin", home + "/.local/bin"])
                try TestSuite.assertEqual(CommandRunner.standardSearchDirectories(home: "/Users/u").first?.allowedTools,
                                          ["xcrun", "xcode-select", "hdiutil", "tmutil", "pkgutil", "launchctl", "git"])

                try ctx.script("goodtool", "exit 0")
                let good = ctx.runner(entries: [])
                for name in ["./goodtool", "bin/goodtool", "../bin/goodtool", "/goodtool", ctx.bin + "/goodtool", "-goodtool",
                             "--goodtool", "", ".goodtool", "good tool", "goodtool;", "good\u{0}tool", "gооdtool" /* Cyrillic о */] {
                    try TestSuite.assertNil(good.resolveExecutable(name), "resolved \(name.debugDescription)")
                }
                let relative = await good.run(executable: "goodtool", arguments: [], timeout: 5, purpose: .readOnly)
                try TestSuite.assertEqual(relative.exitCode, -1)
                try TestSuite.assertTrue(relative.stderr.contains("absolute"), relative.stderr)
            }
        }

        await TestSuite.run("CommandRunner: a symlink in a trusted directory is accepted only when its real path is inside a trusted root") {
            try await withContext { ctx in
                let target = try ctx.script("realtool", "exit 0", in: ctx.outside)
                _ = try ctx.link("linkedtool", to: target)
                try TestSuite.assertNil(ctx.runner(entries: []).resolveExecutable("linkedtool"), "real path outside the trusted roots")
                let widened = ctx.runner(entries: [], roots: [ctx.bin, ctx.outside])
                try TestSuite.assertEqual(widened.resolveExecutable("linkedtool"), ctx.bin + "/linkedtool")
                _ = try ctx.link("dangling", to: ctx.outside + "/nothing-here")
                try TestSuite.assertNil(widened.resolveExecutable("dangling"))
                _ = try ctx.link("tmplink", to: "/tmp")
                try TestSuite.assertNil(widened.resolveExecutable("tmplink"), "a directory is not an executable")
            }
        }

        await TestSuite.run("CommandRunner: world/group-writable file, group/world-writable directory, not executable, another owner → nil") {
            try await withContext { ctx in
                try ctx.script("worldw", "exit 0", mode: 0o757)
                try ctx.script("groupw", "exit 0", mode: 0o775)
                try ctx.script("noexec", "exit 0", mode: 0o644)
                try ctx.script("fine", "exit 0", mode: 0o755)
                let runner = ctx.runner(entries: [])
                try TestSuite.assertNil(runner.resolveExecutable("worldw"), "world-writable file")
                try TestSuite.assertNil(runner.resolveExecutable("groupw"), "group-writable file")
                try TestSuite.assertNil(runner.resolveExecutable("noexec"), "not executable")
                try TestSuite.assertEqual(runner.resolveExecutable("fine"), ctx.bin + "/fine")
                // Owned by another user: files owned by the real uid count as someone else's.
                try TestSuite.assertNil(ctx.runner(entries: [], userID: getuid() &+ 1).resolveExecutable("fine"), "another owner")

                // A group- or world-writable directory makes everything in it untrusted.
                for mode: mode_t in [0o775, 0o757, 0o777] {
                    guard chmod(ctx.bin, mode) == 0 else { throw TestError("chmod bin") }
                    try TestSuite.assertNil(runner.resolveExecutable("fine"), "directory mode \(String(mode, radix: 8))")
                }
                chmod(ctx.bin, 0o755)
                try TestSuite.assertEqual(runner.resolveExecutable("fine"), ctx.bin + "/fine")
                // A symlink whose real file lives in a writable directory is rejected too.
                let loose = try ctx.fixture.dir("loose", base: .root)
                chmod(loose, 0o777)
                defer { chmod(loose, 0o755) }
                let realFile = try ctx.script("hidden", "exit 0", in: loose)
                _ = try ctx.link("viaLoose", to: realFile)
                try TestSuite.assertNil(ctx.runner(entries: [], roots: [ctx.bin, loose]).resolveExecutable("viaLoose"))
            }
        }

        await TestSuite.run("CommandRunner: the first directory holding the tool decides — an untrusted copy is never bypassed") {
            try await withContext { ctx in
                let second = try ctx.fixture.dir("second", base: .root)
                chmod(second, 0o755)
                try ctx.script("shadow", "exit 0", mode: 0o777)
                try ctx.script("shadow", "exit 0", in: second)
                let runner = ctx.runner(entries: [], directories: [.init(path: ctx.bin), .init(path: second)], roots: [ctx.bin, second])
                try TestSuite.assertNil(runner.resolveExecutable("shadow"))
                // A per-directory tool allow-list (like /usr/bin's) is honoured.
                try ctx.script("onlyhere", "exit 0", in: second)
                let limited = ctx.runner(entries: [], directories: [.init(path: second, allowedTools: ["other"])], roots: [second])
                try TestSuite.assertNil(limited.resolveExecutable("onlyhere"))
            }
        }

        // MARK: Running

        await TestSuite.run("CommandRunner: the script receives EXACTLY the argument array — no shell interpretation") {
            try await withContext { ctx in
                let path = try ctx.script("argdump", #"for a in "$@"; do printf '<%s>\n' "$a"; done"#)
                let arguments = ["; rm -rf ~", "$(touch pwned)", "`touch pwned2`", "a b  c", "*", "~", "$HOME", "|", "&&", "'\"",
                                 "--", "> out.txt", "ü 名前"]
                let runner = ctx.runner(entries: [ro("argdump", arguments)])
                let result = await runner.run(executable: path, arguments: arguments, timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(result.exitCode, 0, result.stderr)
                try TestSuite.assertFalse(result.timedOut)
                try TestSuite.assertEqual(result.stdout, arguments.map { "<\($0)>\n" }.joined())
                for name in ["pwned", "pwned2", "out.txt"] {
                    try TestSuite.assertFalse(FileManager.default.fileExists(atPath: ctx.fixture.path(name)), name)
                }
                // A non-zero exit code is reported as is.
                let failing = try ctx.script("exit3", "echo oops >&2; exit 3")
                let failed = await ctx.runner(entries: [ro("exit3", [])]).run(executable: failing, arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(failed.exitCode, 3)
                try TestSuite.assertEqual(failed.stderr, "oops\n")
                try TestSuite.assertFalse(failed.succeeded)
            }
        }

        await TestSuite.run("CommandRunner: sanitized environment — only PATH (trusted dirs), HOME, USER, LANG; cwd = HOME; stdin = /dev/null") {
            try await withContext { ctx in
                let second = try ctx.fixture.dir("second", base: .root)
                chmod(second, 0o755)
                let envdump = try ctx.link("envdump", to: "/usr/bin/env")
                let catin = try ctx.link("catin", to: "/bin/cat")
                let pwdtool = try ctx.link("pwdtool", to: "/bin/pwd")
                let runner = ctx.runner(entries: [ro("envdump", []), ro("catin", []), ro("pwdtool", ["-P"])],
                                        directories: [.init(path: ctx.bin), .init(path: second)],
                                        roots: [ctx.bin, second, "/usr/bin", "/bin"])
                setenv("IMOP_SECRET_TEST_VAR", "leak", 1)
                defer { unsetenv("IMOP_SECRET_TEST_VAR") }
                let result = await runner.run(executable: envdump, arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(result.exitCode, 0, result.stderr)
                var variables: [String: String] = [:]
                for line in result.stdout.split(separator: "\n") {
                    let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                    variables[String(parts[0])] = parts.count > 1 ? String(parts[1]) : ""
                }
                try TestSuite.assertTrue(Set(variables.keys).isSubset(of: ["PATH", "HOME", "USER", "LANG"]), "\(variables.keys.sorted())")
                // Trusted search directories, then the SIP-protected /usr/bin and /bin (review M4).
                try TestSuite.assertEqual(variables["PATH"], ctx.bin + ":" + second + ":/usr/bin:/bin")
                // HOME may be spelled /var/… or /private/var/…; it is the fixture home either way.
                try TestSuite.assertEqual(variables["HOME"].flatMap(FixtureBuilder.realpath), ctx.fixture.home)
                try TestSuite.assertNil(variables["IMOP_SECRET_TEST_VAR"])
                // The production search order is exactly the trusted search directories.
                let production = CommandRunner.standardSearchDirectories(home: "/Users/u").map(\.path).joined(separator: ":")
                try TestSuite.assertEqual(production, "/usr/bin:/opt/homebrew/bin:/usr/local/bin:/Users/u/.cargo/bin:/Users/u/go/bin:/Users/u/.bun/bin:/Users/u/.local/bin")

                // stdin is /dev/null: `cat` sees EOF at once (an inherited stdin would block until the timeout).
                let started = Date()
                let cat = await runner.run(executable: catin, arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(cat.exitCode, 0)
                try TestSuite.assertEqual(cat.stdout, "")
                try TestSuite.assertFalse(cat.timedOut)
                try TestSuite.assertTrue(Date().timeIntervalSince(started) < 5, "cat waited for input")

                let pwd = await runner.run(executable: pwdtool, arguments: ["-P"], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(pwd.stdout.trimmingCharacters(in: .newlines), ctx.fixture.home)
            }
        }

        await TestSuite.run("CommandRunner: 1 MB on stdout AND stderr is drained without deadlock and truncated at 64 KB each") {
            try await withContext { ctx in
                // stderr is written completely BEFORE stdout: reading the streams one after the other
                // would deadlock once the stderr pipe buffer is full.
                let path = try ctx.script("chatty", "/usr/bin/yes e | /usr/bin/head -c 1048576 >&2\n/usr/bin/yes o | /usr/bin/head -c 1048576\nexit 0")
                let runner = ctx.runner(entries: [ro("chatty", [])])
                let started = Date()
                let result = await runner.run(executable: path, arguments: [], timeout: 60, purpose: .readOnly)
                try TestSuite.assertEqual(result.exitCode, 0, String(result.stderr.suffix(200)))
                try TestSuite.assertFalse(result.timedOut)
                try TestSuite.assertTrue(Date().timeIntervalSince(started) < 30, "took too long")
                let limit = CommandRunner.outputLimit
                let dropped = 1_048_576 - limit
                try TestSuite.assertEqual(result.stdout, String(repeating: "o\n", count: limit / 2) + "\n[truncated \(dropped) bytes]")
                try TestSuite.assertEqual(result.stderr, String(repeating: "e\n", count: limit / 2) + "\n[truncated \(dropped) bytes]")
            }
        }

        await TestSuite.run("CommandRunner: hard timeout — SIGTERM, then SIGKILL after the grace; the child is gone; marked timedOut") {
            try await withContext { ctx in
                let sleeper = try ctx.script("sleeper", "echo $$\nexec /bin/sleep 30")
                // Ignores SIGTERM, so only the SIGKILL after the grace period ends it.
                let stubborn = try ctx.script("stubborn", "trap '' TERM\necho $$\nwhile :; do /bin/sleep 1; done")
                let runner = ctx.runner(entries: [ro("sleeper", []), ro("stubborn", [])], grace: 1)
                for path in [sleeper, stubborn] {
                    let started = Date()
                    let result = await runner.run(executable: path, arguments: [], timeout: 1, purpose: .readOnly)
                    let elapsed = Date().timeIntervalSince(started)
                    try TestSuite.assertTrue(result.timedOut, path)
                    try TestSuite.assertFalse(result.succeeded)
                    try TestSuite.assertTrue(result.stderr.contains("timed out"), result.stderr)
                    try TestSuite.assertTrue(elapsed >= 1 && elapsed < 10, "\(path): \(elapsed) s")
                    guard let pid = pid_t(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 else {
                        throw TestError("no pid in \(result.stdout.debugDescription)")
                    }
                    try TestSuite.assertEqual(kill(pid, 0), -1, "\(path): process \(pid) still running")
                }
                // A non-positive or non-finite timeout means the 10-minute default, never "no timeout".
                let quick = try ctx.script("quick", "exit 0")
                let r = ctx.runner(entries: [ro("quick", [])])
                for timeout in [0, -5, TimeInterval.infinity, TimeInterval.nan] {
                    try TestSuite.assertEqual(await r.run(executable: quick, arguments: [], timeout: timeout, purpose: .readOnly).exitCode, 0)
                }
                try TestSuite.assertEqual(CommandRunner.maximumTimeout, 1800)
            }
        }

        await TestSuite.run("CommandRunner: concurrent runs each get their own output") {
            try await withContext { ctx in
                let path = try ctx.script("echoer", #"printf '%s' "$1""#)
                let ids = (0..<8).map { "run\($0)" }
                let runner = ctx.runner(entries: ids.map { ro("echoer", [$0]) })
                let results = await withTaskGroup(of: (String, CommandResult).self) { group in
                    for id in ids {
                        group.addTask { (id, await runner.run(executable: path, arguments: [id], timeout: 20, purpose: .readOnly)) }
                    }
                    var all: [(String, CommandResult)] = []
                    for await item in group { all.append(item) }
                    return all
                }
                try TestSuite.assertEqual(results.count, 8)
                for (id, result) in results { try TestSuite.assertEqual(result.stdout, id) }
            }
        }

        // MARK: Purpose enforcement

        await TestSuite.run("CommandRunner: a non-allow-listed invocation is refused for both purposes and never starts") {
            try await withContext { ctx in
                let marker = ctx.fixture.path("ran")
                let path = try ctx.script("marker", "/usr/bin/touch \"$HOME/ran\"")
                let runner = ctx.runner(entries: [ro("marker", ["query"]), act("marker", ["clean"])])
                let refused: [([String], CommandPurpose)] = [
                    (["clean"], .readOnly), (["query"], .action), (["other"], .readOnly), (["other"], .action),
                    (["query", "--extra"], .readOnly), ([], .action), (["clean", "clean"], .action),
                ]
                for (arguments, purpose) in refused {
                    let result = await runner.run(executable: path, arguments: arguments, timeout: 5, purpose: purpose)
                    try TestSuite.assertEqual(result.exitCode, -1, "\(arguments) \(purpose)")
                    try TestSuite.assertEqual(result.stderr, CommandRunner.notAllowedMessage)
                }
                // The purpose-less form is read-only: an action entry is refused through it.
                let legacy = await runner.run(executable: path, arguments: ["clean"], timeout: 5)
                try TestSuite.assertEqual(legacy.stderr, CommandRunner.notAllowedMessage)
                try TestSuite.assertFalse(FileManager.default.fileExists(atPath: marker), "a refused invocation ran")
                // The exact entries run.
                try TestSuite.assertEqual(await runner.run(executable: path, arguments: ["clean"], timeout: 5, purpose: .action).exitCode, 0)
                try TestSuite.assertTrue(FileManager.default.fileExists(atPath: marker))
            }
        }

        await TestSuite.run("CommandRunner: always-forbidden invocations are refused even if a table lists them") {
            try await withContext { ctx in
                let path = try ctx.script("sh", "exit 0")
                let tool = try ctx.script("vendor", "exit 0")
                let bad: [[String]] = [["system", "prune", "-a"], ["volume", "prune", "--volumes"], ["autoremove"], ["-c", "x"],
                                       ["sudo", "x"], ["rm", "-rf", "x"], ["rm", "-r", "x"], ["--no-preserve-root"], ["bad\u{1}"],
                                       ["sh"], ["zsh"]]
                let runner = ctx.runner(entries: [ro("sh", [])] + bad.flatMap { [ro("vendor", $0), act("vendor", $0)] })
                try TestSuite.assertEqual(await runner.run(executable: path, arguments: [], timeout: 5, purpose: .readOnly).stderr,
                                          CommandRunner.notAllowedMessage, "a shell is never a tool")
                for arguments in bad {
                    for purpose in [CommandPurpose.readOnly, .action] {
                        let result = await runner.run(executable: tool, arguments: arguments, timeout: 5, purpose: purpose)
                        try TestSuite.assertEqual(result.stderr, CommandRunner.notAllowedMessage, "\(arguments) \(purpose)")
                    }
                }
                // Action arguments never carry a path.
                let pathy = ctx.runner(entries: [act("vendor", ["clean", "/Users/x"]), act("vendor", ["{ITEM}"], item: .ollamaModelName)])
                try TestSuite.assertEqual(await pathy.run(executable: tool, arguments: ["clean", "/Users/x"], timeout: 5, purpose: .action).stderr,
                                          CommandRunner.notAllowedMessage)
                try TestSuite.assertEqual(await pathy.run(executable: tool, arguments: ["library/llama3"], timeout: 5, purpose: .action).exitCode, 0)
            }
        }

        await TestSuite.run("CommandRunner: the production runner refuses destructive or unlisted invocations before resolving anything") {
            try await withContext { ctx in
                // SAFETY: every invocation below is refused by the allow-list check, which runs BEFORE
                // resolution; nothing on this machine is started.
                let runner = CommandRunner(homeDirectory: URL(fileURLWithPath: ctx.fixture.home, isDirectory: true))
                let refused: [(String, [String], CommandPurpose)] = [
                    ("/usr/bin/xcrun", ["simctl", "delete", "all"], .action),
                    ("/usr/bin/xcrun", ["simctl", "delete", "unavailable"], .readOnly),
                    ("/usr/bin/xcrun", ["simctl", "erase", "all"], .action),
                    ("/usr/bin/xcrun", ["simctl", "delete", "-rf"], .action),
                    ("/usr/local/bin/docker", ["system", "prune", "--volumes", "-f"], .action),
                    ("/usr/local/bin/docker", ["system", "prune", "-f"], .action),
                    ("/usr/local/bin/docker", ["volume", "prune", "-f"], .action),
                    ("/usr/local/bin/docker", ["volume", "rm", "--force"], .action),
                    ("/usr/local/bin/docker", ["volume", "rm", "a", "b"], .action),
                    ("/opt/homebrew/bin/brew", ["autoremove"], .action),
                    ("/opt/homebrew/bin/brew", ["cleanup", "--prune=all"], .readOnly),
                    ("/opt/homebrew/bin/ollama", ["rm", "../models"], .action),
                    ("/bin/sh", ["-c", "true"], .readOnly),
                    ("/bin/zsh", ["-c", "true"], .action),
                    ("/usr/bin/sudo", ["true"], .action),
                    ("/bin/rm", ["-rf", "/tmp/x"], .action),
                ]
                for (executable, arguments, purpose) in refused {
                    let result = await runner.run(executable: executable, arguments: arguments, timeout: 5, purpose: purpose)
                    try TestSuite.assertEqual(result.exitCode, -1, "\(executable) \(arguments)")
                    try TestSuite.assertEqual(result.stderr, CommandRunner.notAllowedMessage, "\(executable) \(arguments)")
                }
            }
        }

        // MARK: {ITEM} validators

        await TestSuite.run("CommandItemKind: every {ITEM} validator rejects option injection, paths, spaces, empty and look-alikes") {
            let hostile = ["-rf", "--all", "-", "--", "../x", "./x", "/x", "x/../y", "a b", " a", "a ", "", "a\nb", "a\u{0}b", "a;b",
                           "$(id)", "`id`", "a|b", "a&b", "*", "~", "\u{2212}rf", "\u{2010}x", "\u{FF0D}x",
                           "ａｂｃ" /* fullwidth */, "аbc" /* Cyrillic а */, "e\u{301}", String(repeating: "a", count: 300)]
            for kind in CommandItemKind.allCases {
                for value in hostile {
                    try TestSuite.assertFalse(kind.accepts(value), "\(kind) accepted \(value.debugDescription)")
                }
                try TestSuite.assertEqual(kind.allowsSlash, kind == .ollamaModelName)
            }
            let udid = "A47CD2C9-0C68-4140-A0B1-925934040AD2"
            let valid: [CommandItemKind: [String]] = [
                .simulatorDeviceUDID: [udid],
                .simulatorRuntimeIdentifier: ["com.apple.CoreSimulator.SimRuntime.iOS-17-0", "com.apple.CoreSimulator.SimRuntime.xrOS-2-0", udid],
                .dockerVolumeName: ["pgdata", "old_pgdata", "my.vol-1", String(repeating: "f", count: 64)],
                .ollamaModelName: ["llama3.2:latest", "llama3", "library/llama3:8b", "hf.co/org/model:Q4_K_M", "qwen2.5-coder:7b"],
                .androidAVDName: ["Pixel_7_API_34", "Nexus5X", "my.avd-1"],
            ]
            let invalid: [CommandItemKind: [String]] = [
                .simulatorDeviceUDID: [udid.lowercased(), "all", "booted", "unavailable", udid + "0", String(udid.dropLast())],
                .simulatorRuntimeIdentifier: ["com.apple.CoreSimulator.SimRuntime.", "com.apple.CoreSimulator.SimRuntime.iOS 17", "all",
                                              "com.apple.CoreSimulator.SimRuntime.iOS/17", "iOS-17-0"],
                .dockerVolumeName: ["_x", ".x", "x/y", String(repeating: "f", count: 256)],
                .ollamaModelName: ["Llama3", "a//b", "a/./b", "a/../b", "/a", "a/", "a:", "a:b:c", ":tag", "a:tag/x"],
                .androidAVDName: ["_x", ".x", "x/y", "x:y"],
            ]
            for (kind, values) in valid {
                for value in values { try TestSuite.assertTrue(kind.accepts(value), "\(kind) rejected \(value)") }
            }
            for (kind, values) in invalid {
                for value in values { try TestSuite.assertFalse(kind.accepts(value), "\(kind) accepted \(value)") }
            }
        }

        await TestSuite.run("CommandAllowList: {ITEM} entries match only validated values; the Red command is pinned to docker.volumes") {
            let table = CommandAllowList.standard
            let udid = "A47CD2C9-0C68-4140-A0B1-925934040AD2"
            let allowed: [(String, [String])] = [
                ("xcrun", ["simctl", "delete", udid]), ("xcrun", ["simctl", "delete", "unavailable"]),
                ("xcrun", ["simctl", "runtime", "delete", udid]), ("docker", ["volume", "rm", "pgdata"]),
                ("ollama", ["rm", "library/llama3:latest"]), ("avdmanager", ["delete", "avd", "-n", "Pixel_7"]),
                ("bun", ["pm", "cache", "rm"]), ("brew", ["cleanup", "--prune=all"]), ("docker", ["image", "prune", "-a", "-f"]),
            ]
            for (tool, arguments) in allowed {
                try TestSuite.assertTrue(table.matches(tool: tool, arguments: arguments, purpose: .action), "\(tool) \(arguments)")
                try TestSuite.assertFalse(table.matches(tool: tool, arguments: arguments, purpose: .readOnly), "\(tool) \(arguments) read-only")
            }
            let refused: [(String, [String])] = [
                ("xcrun", ["simctl", "delete", "all"]), ("xcrun", ["simctl", "delete", "booted"]), ("xcrun", ["simctl", "delete", "-rf"]),
                ("xcrun", ["simctl", "delete", udid, udid]), ("xcrun", ["simctl", "runtime", "delete", "all"]),
                ("docker", ["volume", "rm", "-f"]), ("docker", ["volume", "rm", "--all"]), ("docker", ["volume", "rm", "a b"]),
                ("docker", ["volume", "rm", "../x"]), ("docker", ["volume", "prune", "-f"]), ("docker", ["system", "prune", "--volumes"]),
                ("ollama", ["rm", "../x"]), ("ollama", ["rm", "-h"]), ("avdmanager", ["delete", "avd", "-n", "-x"]),
                ("brew", ["autoremove"]), ("brew", ["cleanup"]), ("rm", ["-rf", "x"]), ("bun", ["pm", "cache", "rm", "-g"]),
                ("npm", ["cache", "clean"]), ("sh", ["-c", "x"]),
            ]
            for (tool, arguments) in refused {
                try TestSuite.assertFalse(table.matches(tool: tool, arguments: arguments, purpose: .action), "\(tool) \(arguments)")
            }
            // Milestone 6: the second Red action entry is the pinned launchctl bootout (not usable by rules).
            let redEntries = table.actionEntries.filter { $0.minimumTier == .red }
            try TestSuite.assertEqual(redEntries.count, 2)
            let bootout = redEntries.filter { $0.tool == "launchctl" }
            try TestSuite.assertEqual(bootout.count, 1)
            try TestSuite.assertFalse(bootout[0].usableByRules)
            try TestSuite.assertEqual(bootout[0].ruleIDs, ["leftovers.launchAgents"])
            guard let red = redEntries.first(where: { $0.tool == "docker" }) else { throw TestError("no Red docker entry") }
            try TestSuite.assertEqual(red.arguments, ["volume", "rm", CommandSpec.itemToken])
            try TestSuite.assertTrue(red.permits(ruleID: "docker.volumes", tier: .red))
            try TestSuite.assertFalse(red.permits(ruleID: "docker.other", tier: .red))
            try TestSuite.assertFalse(red.permits(ruleID: "docker.volumes", tier: .yellow))
            // Timeouts: 10 minutes everywhere except simctl runtime delete (30 minutes).
            for entry in table.entries {
                let expected = entry.arguments == ["simctl", "runtime", "delete", CommandSpec.itemToken] ? 1800 : 600
                try TestSuite.assertEqual(entry.maximumTimeoutSeconds, expected, "\(entry.tool) \(entry.arguments)")
            }
            // Precondition probes are allowed for the runner but no rule may name them.
            try TestSuite.assertTrue(table.matches(tool: "xcode-select", arguments: ["-p"], purpose: .readOnly))
            try TestSuite.assertFalse(RuleCatalog.allowedReadOnlyCommands.contains { $0.tool == "xcode-select" || $0.tool == "hdiutil" })
        }
    }
}
