import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Settings → "Trust Homebrew tools" (opt-in, OFF by default; SAFETY.md › Command trust).
///
/// A Homebrew-like tree is built inside the fixture: a prefix whose folders are group-writable
/// (0775) and owned by the test user with the test user's OWN primary group, which the tests inject
/// as the "admin" group id (the test user cannot `chgrp admin`). Every executable is a fixture
/// `#!/bin/sh` script; no real vendor tool is ever run.
struct HomebrewTrustTests {
    static let ownGroup: gid_t = getgid()

    final class Context: Sendable {
        let fixture: FixtureBuilder
        /// The injected Homebrew prefix (0775, like /opt/homebrew).
        let prefix: String
        /// `<prefix>/bin` (0775), holding a symlink into the Cellar.
        let bin: String
        /// `<prefix>/Cellar/hbtool/1.0/bin` (every folder 0775) with the real script.
        let cellarBin: String
        /// A strict (0755) trusted folder outside the prefix.
        let strictBin: String
        /// A group-writable folder outside the prefix.
        let outsideBin: String
        /// `<root>/hb-evil/bin`: a look-alike of the prefix (`hb` vs `hb-evil`), group-writable.
        let lookalikeBin: String

        init() throws {
            fixture = try FixtureBuilder()
            prefix = try fixture.dir("hb", base: .root)
            bin = try fixture.dir("hb/bin", base: .root)
            cellarBin = try fixture.dir("hb/Cellar/hbtool/1.0/bin", base: .root)
            strictBin = try fixture.dir("strict/bin", base: .root)
            outsideBin = try fixture.dir("outside/bin", base: .root)
            lookalikeBin = try fixture.dir("hb-evil/bin", base: .root)
            for dir in [prefix, bin, fixture.path("hb/Cellar", base: .root), fixture.path("hb/Cellar/hbtool", base: .root),
                        fixture.path("hb/Cellar/hbtool/1.0", base: .root), cellarBin, outsideBin, lookalikeBin] {
                try Self.setOwnGroup(dir, mode: 0o775)
            }
            for dir in [fixture.path("strict", base: .root), strictBin, fixture.path("outside", base: .root),
                        fixture.path("hb-evil", base: .root)] {
                try Self.setOwnGroup(dir, mode: 0o755)
            }
            let real = try script("hbtool", "echo hb-ok", in: cellarBin)
            _ = real
            try FileManager.default.createSymbolicLink(atPath: bin + "/hbtool", withDestinationPath: "../Cellar/hbtool/1.0/bin/hbtool")
        }

        static func setOwnGroup(_ path: String, mode: mode_t) throws {
            guard chown(path, getuid(), HomebrewTrustTests.ownGroup) == 0 else { throw TestError("chown \(path)") }
            guard chmod(path, mode) == 0 else { throw TestError("chmod \(path)") }
        }

        @discardableResult
        func script(_ name: String, _ body: String, in directory: String, mode: mode_t = 0o755,
                    shebang: String = "#!/bin/sh") throws -> String {
            let path = directory + "/" + name
            guard FileManager.default.createFile(atPath: path, contents: Data((shebang + "\n" + body + "\n").utf8)) else {
                throw TestError("could not create \(path)")
            }
            guard chmod(path, mode) == 0 else { throw TestError("chmod \(path)") }
            return path
        }

        func runner(on: Bool, directories: [String]? = nil, roots: [String]? = nil, prefixes: [String]? = nil,
                    adminGroupID: gid_t? = HomebrewTrustTests.ownGroup, userID: uid_t = getuid(),
                    entries: [CommandAllowList.Entry] = []) -> CommandRunner {
            CommandRunner(homeDirectory: URL(fileURLWithPath: fixture.home, isDirectory: true),
                          searchDirectories: (directories ?? [bin]).map { CommandRunner.SearchDirectory(path: $0) },
                          trustedRoots: roots ?? [prefix, strictBin],
                          allowList: CommandAllowList(entries: entries),
                          terminationGrace: 1, userID: userID,
                          policy: CommandTrustPolicy(trustsHomebrewAdminWritableDirectories: on),
                          homebrewPrefixes: prefixes ?? [prefix], adminGroupID: adminGroupID)
        }

        func cleanup() {
            for dir in [prefix, bin, cellarBin, strictBin, outsideBin, lookalikeBin] { chmod(dir, 0o755) }
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

    static func isTrustReason(_ reason: String?) -> Bool {
        reason.map(CommandTrustPolicy.isHomebrewTrustRequiredMessage) ?? false
    }

    @MainActor
    static func runAll() async {
        print("\n🍺 Running Homebrew Trust Tests (Settings → Trust Homebrew tools)...")

        await TestSuite.run("Homebrew trust: OFF (default) → an admin-group-writable Homebrew folder is refused with the specific reason") {
            try await withContext { ctx in
                let off = ctx.runner(on: false)
                try TestSuite.assertNil(off.resolveExecutable("hbtool"))
                let reason = off.unavailableReason(for: "hbtool")
                try TestSuite.assertTrue(isTrustReason(reason), reason ?? "nil")
                try TestSuite.assertEqual(reason, "hbtool is in \(ctx.bin), a folder other accounts can change. "
                                          + "Turn on “Trust Homebrew tools” in Settings to allow it.")
                // A missing tool has no such reason (callers keep "not installed").
                try TestSuite.assertNil(off.unavailableReason(for: "nosuchtool"))
                // The default policy is strict and the setting defaults to OFF.
                try TestSuite.assertEqual(CommandTrustPolicy.strict, CommandTrustPolicy())
                try TestSuite.assertFalse(CommandTrustPolicy(settings: .default).trustsHomebrewAdminWritableDirectories)
                // Running it anyway is refused before anything starts.
                let refused = await ctx.runner(on: false, entries: [ro("hbtool", ["--version"])])
                    .run(executable: ctx.bin + "/hbtool", arguments: ["--version"], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(refused.exitCode, -1)
                try TestSuite.assertTrue(refused.stderr.contains("trusted"), refused.stderr)
            }
        }

        await TestSuite.run("Homebrew trust: ON → accepted when the folders are owned by the user, group == admin gid, not world-writable, inside the prefix") {
            try await withContext { ctx in
                let on = ctx.runner(on: true, entries: [ro("hbtool", ["--version"])])
                try TestSuite.assertEqual(on.resolveExecutable("hbtool"), ctx.bin + "/hbtool")
                try TestSuite.assertNil(on.unavailableReason(for: "hbtool"))
                let result = await on.run(executable: ctx.bin + "/hbtool", arguments: ["--version"], timeout: 10, purpose: .readOnly)
                try TestSuite.assertTrue(result.succeeded, "\(result)")
                try TestSuite.assertEqual(result.stdout, "hb-ok\n")
                // Allow-listing is unchanged: an unlisted invocation is still refused.
                let unlisted = await on.run(executable: ctx.bin + "/hbtool", arguments: ["cleanup"], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(unlisted.exitCode, -1)
                try TestSuite.assertEqual(unlisted.stderr, CommandRunner.notAllowedMessage)
                // `applying` turns the relaxation on and off on an existing runner.
                let off = ctx.runner(on: false)
                try TestSuite.assertEqual(off.applying(CommandTrustPolicy(trustsHomebrewAdminWritableDirectories: true))
                    .resolveExecutable("hbtool"), ctx.bin + "/hbtool")
                try TestSuite.assertNil(on.applying(.strict).resolveExecutable("hbtool"))
            }
        }

        await TestSuite.run("Homebrew trust: ON but a world-writable folder (0777, also with the sticky bit) → refused") {
            try await withContext { ctx in
                for mode: mode_t in [0o777, 0o1777, 0o757] {
                    chmod(ctx.cellarBin, mode)
                    try TestSuite.assertNil(ctx.runner(on: true).resolveExecutable("hbtool"), "mode \(String(mode, radix: 8))")
                    try TestSuite.assertNil(ctx.runner(on: false).unavailableReason(for: "hbtool"), "no trust hint for \(String(mode, radix: 8))")
                }
                chmod(ctx.cellarBin, 0o775)
                chmod(ctx.bin, 0o777)
                try TestSuite.assertNil(ctx.runner(on: true).resolveExecutable("hbtool"), "world-writable bin")
            }
        }

        await TestSuite.run("Homebrew trust: ON but the folder's group is not the admin group → refused") {
            try await withContext { ctx in
                let other = HomebrewTrustTests.ownGroup &+ 4242
                try TestSuite.assertNil(ctx.runner(on: true, adminGroupID: other).resolveExecutable("hbtool"))
                try TestSuite.assertNil(ctx.runner(on: false, adminGroupID: other).unavailableReason(for: "hbtool"))
            }
        }

        await TestSuite.run("Homebrew trust: ON but the folders belong to another account (simulated uid) → refused") {
            try await withContext { ctx in
                let other = getuid() &+ 4242
                try TestSuite.assertNil(ctx.runner(on: true, userID: other).resolveExecutable("hbtool"))
                // The folder check alone: the prefix bin is not put on PATH for that "user".
                try TestSuite.assertFalse(ctx.runner(on: true, userID: other).sanitizedPathDirectories().contains(ctx.bin))
                try TestSuite.assertTrue(ctx.runner(on: true).sanitizedPathDirectories().contains(ctx.bin))
            }
        }

        await TestSuite.run("Homebrew trust: ON but the group-writable folder is outside the Homebrew prefixes (also a look-alike name) → refused") {
            try await withContext { ctx in
                try ctx.script("strayhb", "echo stray", in: ctx.outsideBin)
                let outside = ctx.runner(on: true, directories: [ctx.outsideBin], roots: [ctx.prefix, ctx.outsideBin])
                try TestSuite.assertNil(outside.resolveExecutable("strayhb"))
                try TestSuite.assertNil(ctx.runner(on: false, directories: [ctx.outsideBin], roots: [ctx.prefix, ctx.outsideBin])
                    .unavailableReason(for: "strayhb"))
                try ctx.script("evilhb", "echo evil", in: ctx.lookalikeBin)
                let lookalike = ctx.runner(on: true, directories: [ctx.lookalikeBin],
                                           roots: [ctx.prefix, ctx.fixture.path("hb-evil", base: .root)])
                try TestSuite.assertNil(lookalike.resolveExecutable("evilhb"), "prefix containment is component-wise")
                // No prefixes at all (e.g. a runner built without them) → never relaxed.
                try TestSuite.assertNil(ctx.runner(on: true, prefixes: []).resolveExecutable("hbtool"))
                // The production prefix list is exactly the documented one.
                try TestSuite.assertEqual(CommandTrustPolicy.appleSiliconHomebrewPrefixes, ["/opt/homebrew"])
                try TestSuite.assertEqual(CommandTrustPolicy.intelHomebrewPrefixes,
                                          ["/usr/local/Homebrew", "/usr/local/Cellar", "/usr/local/opt", "/usr/local/lib",
                                           "/usr/local/bin", "/usr/local/share", "/usr/local/Caskroom"])
                try TestSuite.assertFalse(CommandTrustPolicy.standardHomebrewPrefixes.contains("/usr/local"))
            }
        }

        await TestSuite.run("Homebrew trust: ON but the FILE itself is group-writable → refused (files are never relaxed)") {
            try await withContext { ctx in
                chmod(ctx.cellarBin + "/hbtool", 0o775)
                try TestSuite.assertNil(ctx.runner(on: true).resolveExecutable("hbtool"))
                try ctx.script("groupfile", "exit 0", in: ctx.bin, mode: 0o775)
                try TestSuite.assertNil(ctx.runner(on: true).resolveExecutable("groupfile"))
                try TestSuite.assertNil(ctx.runner(on: false).unavailableReason(for: "groupfile"))
            }
        }

        await TestSuite.run("Homebrew trust: a #! interpreter in an admin-writable Homebrew folder — refused OFF, accepted ON (direct and via /usr/bin/env)") {
            try await withContext { ctx in
                try ctx.script("hbinterp", "exec /bin/sh \"$@\"", in: ctx.cellarBin)
                try FileManager.default.createSymbolicLink(atPath: ctx.bin + "/hbinterp", withDestinationPath: "../Cellar/hbtool/1.0/bin/hbinterp")
                try ctx.script("direct", "echo direct", in: ctx.strictBin, shebang: "#!" + ctx.bin + "/hbinterp")
                try ctx.script("viaenv", "echo viaenv", in: ctx.strictBin, shebang: "#!/usr/bin/env hbinterp")
                let dirs = [ctx.strictBin, ctx.bin]
                for tool in ["direct", "viaenv"] {
                    try TestSuite.assertNil(ctx.runner(on: false, directories: dirs).resolveExecutable(tool), "\(tool) OFF")
                    try TestSuite.assertEqual(ctx.runner(on: true, directories: dirs).resolveExecutable(tool), ctx.strictBin + "/" + tool, "\(tool) ON")
                    let reason = ctx.runner(on: false, directories: dirs).unavailableReason(for: tool)
                    try TestSuite.assertTrue(isTrustReason(reason), "\(tool): \(reason ?? "nil")")
                }
                // ON but the admin lookup failed → refused.
                try TestSuite.assertNil(ctx.runner(on: true, directories: dirs, adminGroupID: nil).resolveExecutable("direct"))
            }
        }

        await TestSuite.run("Homebrew trust: the child's PATH includes the prefix bin only when ON and it passes") {
            try await withContext { ctx in
                let dirs = [ctx.strictBin, ctx.bin, ctx.outsideBin]
                let off = ctx.runner(on: false, directories: dirs).sanitizedPathDirectories()
                try TestSuite.assertEqual(off, [ctx.strictBin, "/usr/bin", "/bin"])
                let on = ctx.runner(on: true, directories: dirs).sanitizedPathDirectories()
                try TestSuite.assertEqual(on, [ctx.strictBin, ctx.bin, "/usr/bin", "/bin"], "the group-writable non-prefix folder stays out")
                chmod(ctx.bin, 0o777)
                try TestSuite.assertEqual(ctx.runner(on: true, directories: dirs).sanitizedPathDirectories(), [ctx.strictBin, "/usr/bin", "/bin"])
            }
        }

        await TestSuite.run("Homebrew trust: admin group lookup failure → relaxation disabled (and no trust hint)") {
            try await withContext { ctx in
                try TestSuite.assertNil(ctx.runner(on: true, adminGroupID: nil).resolveExecutable("hbtool"))
                try TestSuite.assertNil(ctx.runner(on: false, adminGroupID: nil).unavailableReason(for: "hbtool"))
                try TestSuite.assertFalse(ctx.runner(on: true, adminGroupID: nil).sanitizedPathDirectories().contains(ctx.bin))
            }
        }

        await TestSuite.run("Homebrew trust: the environment's runner follows its settings (with(scanSettings:) and init)") {
            try await withContext { ctx in
                try await M1.withEnv { env in
                    func environment(_ settings: ScanSettings, runner: CommandRunner) -> SafeCleanEnvironment {
                        SafeCleanEnvironment(homeDirectory: URL(fileURLWithPath: env.fixture.home, isDirectory: true),
                                             fileSystem: env.fileSystem, processes: env.processes,
                                             runningApplications: env.runningApplications, applications: env.applications,
                                             volumes: env.volumes, commands: runner, clock: env.clock,
                                             effectiveUserID: env.effectiveUserID, userID: env.userID, scanSettings: settings)
                    }
                    var on = ScanSettings.default
                    on.trustHomebrewAdminWritableDirectories = true
                    // A runner built ON is turned OFF by default settings, and vice versa.
                    let fromOn = environment(.default, runner: ctx.runner(on: true))
                    try TestSuite.assertNil(fromOn.commands.resolveExecutable("hbtool"))
                    try TestSuite.assertTrue(isTrustReason(fromOn.commands.unavailableReason(for: "hbtool")))
                    let enabled = fromOn.with(scanSettings: on)
                    try TestSuite.assertEqual(enabled.commands.resolveExecutable("hbtool"), ctx.bin + "/hbtool")
                    try TestSuite.assertNil(enabled.with(scanSettings: .default).commands.resolveExecutable("hbtool"))
                    try TestSuite.assertEqual(environment(on, runner: ctx.runner(on: false)).commands.resolveExecutable("hbtool"),
                                              ctx.bin + "/hbtool")
                }
            }
        }

        await TestSuite.run("Homebrew trust: inspectors report the specific reason when a tool is refused only because of the setting") {
            try await M1.withEnv { env in
                try CommandInspectorTests.installEverything(env)
                let reasons = ["npm", "brew", "pod", "docker", "ollama"].map {
                    ($0, CommandTrustPolicy.homebrewTrustRequiredMessage(tool: $0, folder: "/opt/homebrew/bin"))
                }
                var executables = env.commands.executables
                for (tool, _) in reasons { executables[tool] = nil }
                env.commands.executables = executables
                env.commands.unavailableReasons = Dictionary(uniqueKeysWithValues: reasons)
                env.processes.names = ["launchd", "ollama"]
                let results = try await CommandInspectorTests.scan(env, ["npm.cache", "homebrew.cleanup", "cocoapods.cache.command",
                                                                         "docker.danglingImages", "ai.ollama"])
                for (id, tool) in [("npm.cache", "npm"), ("homebrew.cleanup", "brew"), ("cocoapods.cache.command", "pod"),
                                   ("docker.danglingImages", "docker"), ("ai.ollama", "ollama")] {
                    let result = try CommandInspectorTests.result(results, id)
                    guard case .unavailable(let why) = result.status else {
                        throw TestError("\(id): expected unavailable, got \(result.status)")
                    }
                    try TestSuite.assertTrue(isTrustReason(why) && why.hasPrefix(tool + " is in"), "\(id): \(why)")
                }
                // Without a specific reason the generic message stays.
                env.commands.unavailableReasons = [:]
                let generic = try CommandInspectorTests.result(try await CommandInspectorTests.scan(env, ["npm.cache"]), "npm.cache")
                try TestSuite.assertEqual(generic.status, .unavailable("npm is not installed in a trusted location"))
            }
        }

        // MARK: Settings

        await TestSuite.run("Homebrew trust setting: default OFF; a missing or garbage value decodes to OFF; ON round-trips") {
            try TestSuite.assertFalse(ScanSettings.default.trustHomebrewAdminWritableDirectories)
            try TestSuite.assertFalse(ScanSettings().trustHomebrewAdminWritableDirectories)
            let decoder = JSONDecoder()
            let missing = try decoder.decode(ScanSettings.self, from: Data(#"{"alwaysQuarantine":true}"#.utf8))
            try TestSuite.assertFalse(missing.trustHomebrewAdminWritableDirectories)
            for garbage in [#""yes""#, "1", "null", "{}", "[true]"] {
                let data = Data(#"{"alwaysQuarantine":true,"trustHomebrewAdminWritableDirectories":"#.utf8) + Data(garbage.utf8) + Data("}".utf8)
                let decoded = try decoder.decode(ScanSettings.self, from: data)
                try TestSuite.assertFalse(decoded.trustHomebrewAdminWritableDirectories, "Codable: \(garbage)")
                let store = SettingsStore.inMemory(rawData: data)
                let loaded = store.load()
                try TestSuite.assertFalse(loaded.trustHomebrewAdminWritableDirectories, "store: \(garbage)")
                try TestSuite.assertTrue(loaded.alwaysQuarantine, "other fields are kept: \(garbage)")
                if garbage != "null" {
                    try TestSuite.assertTrue(store.lastLoadUnreadableFields.contains("Trust Homebrew tools"), "\(garbage): \(store.lastLoadUnreadableFields)")
                }
            }
            let store = SettingsStore.inMemory(rawData: Data(#"{"projectRoots":["~/code"]}"#.utf8))
            try TestSuite.assertFalse(store.load().trustHomebrewAdminWritableDirectories)
            try TestSuite.assertFalse(store.lastLoadFellBackToDefaults, "absence is not an error")
            var on = ScanSettings.default
            on.trustHomebrewAdminWritableDirectories = true
            try TestSuite.assertTrue(store.save(on))
            try TestSuite.assertTrue(store.load().trustHomebrewAdminWritableDirectories)
            try TestSuite.assertTrue(try decoder.decode(ScanSettings.self, from: JSONEncoder().encode(on)).trustHomebrewAdminWritableDirectories)
            try TestSuite.assertTrue(CommandTrustPolicy(settings: on).trustsHomebrewAdminWritableDirectories)
        }

        // MARK: AppState

        await TestSuite.run("AppState: a plan built with Trust Homebrew tools OFF is refused after turning it ON; the change is audited") {
            try await AppStateTests.withContext { ctx in
                let state = try await AppStateTests.scanned(ctx)
                try TestSuite.assertFalse(state.settings.trustHomebrewAdminWritableDirectories, "OFF by default")
                state.beginReview()
                try TestSuite.assertTrue(state.showReview)
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                state.setTrustHomebrewTools(true, disclosedAccounts: ["otheradmin"])
                try TestSuite.assertTrue(state.settings.trustHomebrewAdminWritableDirectories)
                try TestSuite.assertTrue(ctx.store.load().trustHomebrewAdminWritableDirectories, "persisted")
                try TestSuite.assertTrue(state.planIsOutdated)
                try AppStateTests.expectThrows(AppStateError.planOutdated) {
                    try state.confirmAndClean(acknowledgedIrreversible: true)
                }
                try TestSuite.assertEqual(state.phase, .scanned, "nothing ran")
                // A new scan builds the plan under the new setting.
                try await AppStateTests.scan(state)
                try TestSuite.assertFalse(state.planIsOutdated)
                // Turning it off again (no confirmation needed) outdates the plan again.
                state.setTrustHomebrewTools(false, disclosedAccounts: nil)
                try TestSuite.assertFalse(ctx.store.load().trustHomebrewAdminWritableDirectories)
                try TestSuite.assertTrue(state.planIsOutdated)
                await state.waitUntilIdle()

                let exportDir = try ctx.fixture.dir("Export", base: .root)
                let destination = URL(fileURLWithPath: exportDir + "/imop-audit.jsonl")
                try await state.exportAuditLog(to: destination)
                let log = try String(contentsOf: destination, encoding: .utf8)
                let lines = log.split(separator: "\n").filter { $0.contains(AppState.trustHomebrewAuditAction) }
                try TestSuite.assertEqual(lines.count, 2, log)
                try TestSuite.assertTrue(lines[0].contains("\"enabled\"") && lines[0].contains("otheradmin"), String(lines[0]))
                try TestSuite.assertTrue(lines[1].contains("\"disabled\"") && lines[1].contains("could not be determined"), String(lines[1]))
            }
        }

        // MARK: Disclosure

        await TestSuite.run("AdminGroupMembers: members + primary-group accounts, de-duplicated and sorted, without the user and root; nil when unknown") {
            let gid: gid_t = 80
            func source(group: (gid: gid_t, members: [String])?, accounts: [(name: String, primaryGroupID: gid_t)]?,
                        me: String?) -> AdminGroupMembers.Source {
                AdminGroupMembers.Source(adminGroup: { group }, accounts: { accounts }, currentUserName: { me })
            }
            let accounts: [(name: String, primaryGroupID: gid_t)] = [("bob", gid), ("me", gid), ("carol", 20), ("root", 0), ("alice", gid)]
            try TestSuite.assertEqual(AdminGroupMembers.members(from: source(group: (gid, ["root", "me", "alice", "dave"]), accounts: accounts, me: "me")),
                                      ["alice", "bob", "dave"])
            try TestSuite.assertEqual(AdminGroupMembers.members(from: source(group: (gid, ["root", "me"]), accounts: [], me: "me")), [])
            try TestSuite.assertNil(AdminGroupMembers.members(from: source(group: nil, accounts: accounts, me: "me")))
            try TestSuite.assertNil(AdminGroupMembers.members(from: source(group: (gid, []), accounts: nil, me: "me")))
            // The user's own name unknown: nothing but root is removed (over-disclosing is the safe side).
            try TestSuite.assertEqual(AdminGroupMembers.members(from: source(group: (gid, ["root", "me"]), accounts: [], me: nil)), ["me"])
            // The live lookup (read-only) never lists root or the current user.
            if let live = AdminGroupMembers.current() {
                try TestSuite.assertFalse(live.contains("root"))
                if let me = getpwuid(getuid())?.pointee.pw_name.map({ String(cString: $0) }) {
                    try TestSuite.assertFalse(live.contains(me))
                }
            }
        }
    }
}
