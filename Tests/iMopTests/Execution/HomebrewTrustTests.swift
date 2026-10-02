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

        /// `prefix` as `secureResolve` reaches it (`/var/folders` → `/private/var/folders`).
        var physicalPrefix: String {
            guard let resolved = realpath(prefix, nil) else { return prefix }
            defer { free(resolved) }
            return String(cString: resolved)
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
                    // Review: the message names the Homebrew folder that needs the setting (the
                    // interpreter's, physical path), not the tool's own strict folder.
                    try TestSuite.assertEqual(reason, CommandTrustPolicy.homebrewTrustRequiredMessage(tool: tool, uses: ctx.physicalPrefix),
                                              "\(tool)")
                    try TestSuite.assertFalse(reason?.contains(ctx.strictBin) ?? true, "\(tool): \(reason ?? "nil")")
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
                AdminGroupMembers.Source(adminGroup: { group }, accounts: { accounts }, currentUserName: { me },
                                         directoryRecord: { .init(groupID: gid, nestedGroups: [], memberUUIDs: []) },
                                         accountName: { _ in nil })
            }
            let accounts: [(name: String, primaryGroupID: gid_t)] = [("bob", gid), ("me", gid), ("carol", 20), ("root", 0), ("alice", gid)]
            try TestSuite.assertEqual(AdminGroupMembers.members(from: source(group: (gid, ["root", "me", "alice", "dave"]), accounts: accounts, me: "me")),
                                      ["alice", "bob", "dave"])
            try TestSuite.assertEqual(AdminGroupMembers.members(from: source(group: (gid, ["root", "me"]), accounts: [], me: "me")), [])
            try TestSuite.assertNil(AdminGroupMembers.members(from: source(group: nil, accounts: accounts, me: "me")))
            try TestSuite.assertNil(AdminGroupMembers.members(from: source(group: (gid, []), accounts: nil, me: "me")))
            // The user's own name unknown: nothing but root is removed (over-disclosing is the safe side).
            try TestSuite.assertEqual(AdminGroupMembers.members(from: source(group: (gid, ["root", "me"]), accounts: [], me: nil)), ["me"])
            // Review: what `getgrnam` does not show. Member UUIDs are added by name; a nested group, a
            // UUID that is not a user account, an unreadable record or another group id → unknown (nil).
            let users = ["AAAA0000-0000-0000-0000-000000000001": "erin", "AAAA0000-0000-0000-0000-000000000002": "me"]
            func directory(_ record: AdminGroupMembers.DirectoryRecord?) -> AdminGroupMembers.Source {
                AdminGroupMembers.Source(adminGroup: { (gid, ["root", "alice"]) }, accounts: { [("bob", gid)] },
                                         currentUserName: { "me" }, directoryRecord: { record }, accountName: { users[$0] })
            }
            try TestSuite.assertEqual(AdminGroupMembers.members(from: directory(.init(groupID: gid, nestedGroups: [],
                                                                                        memberUUIDs: Array(users.keys)))),
                                      ["alice", "bob", "erin"])
            try TestSuite.assertNil(AdminGroupMembers.members(from: directory(.init(groupID: gid,
                                                                                   nestedGroups: ["ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000999"],
                                                                                   memberUUIDs: []))), "nested group")
            try TestSuite.assertNil(AdminGroupMembers.members(from: directory(.init(groupID: gid, nestedGroups: [],
                                                                                   memberUUIDs: ["BBBB0000-0000-0000-0000-000000000009"]))),
                                    "unknown member UUID")
            try TestSuite.assertNil(AdminGroupMembers.members(from: directory(nil)), "unreadable record")
            try TestSuite.assertNil(AdminGroupMembers.members(from: directory(.init(groupID: gid &+ 1, nestedGroups: [], memberUUIDs: []))),
                                    "other group id")
            try TestSuite.assertNil(AdminGroupMembers.members(from: directory(.init(groupID: nil, nestedGroups: [], memberUUIDs: []))),
                                    "no group id")
            // The live lookup (read-only) never lists root or the current user.
            if let live = AdminGroupMembers.current() {
                try TestSuite.assertFalse(live.contains("root"))
                if let me = getpwuid(getuid())?.pointee.pw_name.map({ String(cString: $0) }) {
                    try TestSuite.assertFalse(live.contains(me))
                }
            }
        }

        // MARK: Review regressions

        await TestSuite.run("Command trust (review): an extended ACL that lets others write refuses a 0755 folder or file, ON or OFF; DENY entries are fine") {
            try await withContext { ctx in
                let aclBin = try ctx.fixture.dir("aclbin", base: .root)
                try Context.setOwnGroup(aclBin, mode: 0o755)
                try ctx.script("acltool", "echo acl", in: aclBin)
                defer { try? clearACL(aclBin + "/acltool"); try? clearACL(aclBin) }
                let dirs = [aclBin]
                let roots = [aclBin]
                func strict() -> CommandRunner { ctx.runner(on: false, directories: dirs, roots: roots) }
                func relaxed() -> CommandRunner { ctx.runner(on: true, directories: dirs, roots: roots, prefixes: [ctx.prefix, aclBin]) }
                try TestSuite.assertEqual(strict().resolveExecutable("acltool"), aclBin + "/acltool")
                try TestSuite.assertTrue(strict().sanitizedPathDirectories().contains(aclBin))
                // A DENY entry (like the home folder's `everyone deny delete`) changes nothing.
                try setACL(aclBin, allow: false, [ACL_DELETE])
                try TestSuite.assertEqual(strict().resolveExecutable("acltool"), aclBin + "/acltool", "deny entry")
                // `everyone allow add_file,delete_child` on the folder → refused and not on PATH.
                try setACL(aclBin, allow: true, [ACL_ADD_FILE, ACL_DELETE_CHILD])
                try TestSuite.assertNil(strict().resolveExecutable("acltool"))
                try TestSuite.assertFalse(strict().sanitizedPathDirectories().contains(aclBin))
                try TestSuite.assertNil(relaxed().resolveExecutable("acltool"), "the Homebrew relaxation never covers an ACL")
                try TestSuite.assertNil(strict().unavailableReason(for: "acltool"))
                try clearACL(aclBin)
                try TestSuite.assertEqual(strict().resolveExecutable("acltool"), aclBin + "/acltool")
                // `everyone allow write` on the file → refused.
                try setACL(aclBin + "/acltool", allow: true, [ACL_WRITE_DATA, ACL_APPEND_DATA])
                try TestSuite.assertNil(strict().resolveExecutable("acltool"))
                let refused = await ctx.runner(on: false, directories: dirs, roots: roots, entries: [ro("acltool", [])])
                    .run(executable: aclBin + "/acltool", arguments: [], timeout: 10, purpose: .readOnly)
                try TestSuite.assertEqual(refused.exitCode, -1)
                try clearACL(aclBin + "/acltool")
                // Only `writesecurity` (could grant itself anything) is refused too.
                try setACL(aclBin + "/acltool", allow: true, [ACL_WRITE_SECURITY])
                try TestSuite.assertNil(strict().resolveExecutable("acltool"))
                try clearACL(aclBin + "/acltool")
                try TestSuite.assertEqual(strict().resolveExecutable("acltool"), aclBin + "/acltool")
            }
        }

        await TestSuite.run("Homebrew trust (review): assigning env.scanSettings re-applies the trust policy to the runner") {
            try await withContext { ctx in
                try await M1.withEnv { env in
                    var on = ScanSettings.default
                    on.trustHomebrewAdminWritableDirectories = true
                    var environment = SafeCleanEnvironment(homeDirectory: URL(fileURLWithPath: env.fixture.home, isDirectory: true),
                                                           fileSystem: env.fileSystem, processes: env.processes,
                                                           runningApplications: env.runningApplications, applications: env.applications,
                                                           volumes: env.volumes, commands: ctx.runner(on: false), clock: env.clock,
                                                           effectiveUserID: env.effectiveUserID, userID: env.userID, scanSettings: on)
                    try TestSuite.assertEqual(environment.commands.resolveExecutable("hbtool"), ctx.bin + "/hbtool")
                    environment.scanSettings = .default
                    try TestSuite.assertNil(environment.commands.resolveExecutable("hbtool"), "OFF after assigning default settings")
                    try TestSuite.assertFalse(environment.commandTrustPolicy.relaxesHomebrewDirectories)
                    environment.scanSettings = on
                    try TestSuite.assertEqual(environment.commands.resolveExecutable("hbtool"), ctx.bin + "/hbtool", "ON again")
                }
            }
        }

        await TestSuite.run("Homebrew trust (review): a revoked switch turns the relaxation off for runners already handed out; ON never revives it") {
            try await withContext { ctx in
                try await M1.withEnv { env in
                    var on = ScanSettings.default
                    on.trustHomebrewAdminWritableDirectories = true
                    let revocation = CommandTrustRevocation()
                    let environment = SafeCleanEnvironment(homeDirectory: URL(fileURLWithPath: env.fixture.home, isDirectory: true),
                                                           fileSystem: env.fileSystem, processes: env.processes,
                                                           runningApplications: env.runningApplications, applications: env.applications,
                                                           volumes: env.volumes, commands: ctx.runner(on: false), clock: env.clock,
                                                           effectiveUserID: env.effectiveUserID, userID: env.userID, scanSettings: on)
                        .with(commandTrustRevocation: revocation)
                    let captured = environment.commands
                    try TestSuite.assertEqual(captured.resolveExecutable("hbtool"), ctx.bin + "/hbtool")
                    revocation.revoke()
                    try TestSuite.assertNil(captured.resolveExecutable("hbtool"), "the captured runner tightens live")
                    try TestSuite.assertFalse(captured.unavailableReason(for: "hbtool") == nil, "and explains why")
                    let refused = await captured.run(executable: ctx.bin + "/hbtool", arguments: ["--version"], timeout: 10, purpose: .readOnly)
                    try TestSuite.assertEqual(refused.exitCode, -1)
                    // A revoked switch stays revoked.
                    try TestSuite.assertTrue(revocation.isRevoked)
                    try TestSuite.assertNil(environment.with(scanSettings: on).commands.resolveExecutable("hbtool"))
                }
            }
        }

        await TestSuite.run("AppState (review): turning Trust Homebrew tools OFF withdraws it from environments already handed out; turnOff audits off-main") {
            try await AppStateTests.withContext { ctx in
                let state = try await AppStateTests.scanned(ctx)
                try TestSuite.assertFalse(state.currentCommandTrustPolicy.relaxesHomebrewDirectories)
                state.setTrustHomebrewTools(true, disclosedAccounts: [])
                let duringRun = state.currentCommandTrustPolicy
                try TestSuite.assertTrue(duringRun.relaxesHomebrewDirectories)
                state.turnOffTrustHomebrewTools()
                try TestSuite.assertFalse(state.settings.trustHomebrewAdminWritableDirectories)
                try TestSuite.assertFalse(duringRun.relaxesHomebrewDirectories, "a running scan/cleanup loses the relaxation at once")
                try TestSuite.assertFalse(state.currentCommandTrustPolicy.relaxesHomebrewDirectories)
                state.setTrustHomebrewTools(true, disclosedAccounts: ["x"])
                try TestSuite.assertFalse(duringRun.relaxesHomebrewDirectories, "turning it ON again never revives an old run")
                try TestSuite.assertTrue(state.currentCommandTrustPolicy.relaxesHomebrewDirectories)
                state.turnOffTrustHomebrewTools()
                state.turnOffTrustHomebrewTools() // no-op when already OFF
                await state.waitUntilIdle()
                let exportDir = try ctx.fixture.dir("Export", base: .root)
                let destination = URL(fileURLWithPath: exportDir + "/imop-audit.jsonl")
                try await state.exportAuditLog(to: destination)
                let lines = try String(contentsOf: destination, encoding: .utf8).split(separator: "\n")
                    .filter { $0.contains(AppState.trustHomebrewAuditAction) }
                try TestSuite.assertEqual(lines.count, 4, "\(lines)")
                try TestSuite.assertTrue(lines[1].contains("\"disabled\"") && lines[1].contains("Other accounts in the admin group"), String(lines[1]))
                try TestSuite.assertTrue(lines[3].contains("\"disabled\""), String(lines[3]))
                // The disclosure is computed off the main actor and never lists root.
                let disclosure = await state.loadHomebrewTrustDisclosure()
                try TestSuite.assertFalse(disclosure?.contains("root") ?? false)
            }
        }
    }
}

/// Sets one `everyone allow|deny <permissions>` extended ACL entry on a FIXTURE path (replacing any).
private func setACL(_ path: String, allow: Bool, _ permissions: [acl_perm_t]) throws {
    var acl: acl_t? = acl_init(1)
    guard acl != nil else { throw TestError("acl_init") }
    defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
    var entry: acl_entry_t?
    guard acl_create_entry(&acl, &entry) == 0, let entry else { throw TestError("acl_create_entry") }
    guard acl_set_tag_type(entry, allow ? ACL_EXTENDED_ALLOW : ACL_EXTENDED_DENY) == 0 else { throw TestError("acl_set_tag_type") }
    // The well-known "everyone" group.
    guard let everyone = UUID(uuidString: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C") else { throw TestError("uuid") }
    var guid = guid_t(g_guid: everyone.uuid)
    guard acl_set_qualifier(entry, &guid) == 0 else { throw TestError("acl_set_qualifier") }
    var permset: acl_permset_t?
    guard acl_get_permset(entry, &permset) == 0, let permset else { throw TestError("acl_get_permset") }
    for permission in permissions { guard acl_add_perm(permset, permission) == 0 else { throw TestError("acl_add_perm") } }
    guard acl_set_permset(entry, permset) == 0 else { throw TestError("acl_set_permset") }
    guard acl_set_link_np(path, ACL_TYPE_EXTENDED, acl) == 0 else { throw TestError("acl_set_link_np \(path): \(errno)") }
}

/// Removes every extended ACL entry from a FIXTURE path.
private func clearACL(_ path: String) throws {
    guard let acl = acl_init(0) else { throw TestError("acl_init") }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    guard acl_set_link_np(path, ACL_TYPE_EXTENDED, acl) == 0 else { throw TestError("clear acl \(path): \(errno)") }
}
