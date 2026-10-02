import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §6.9 / §13 M6: orphaned per-user LaunchAgents (`leftovers.launchAgents`, Red,
/// `launchctl bootout gui/<uid> <plist>` then Trash). launchctl never really runs (FakeCommandRunner)
/// and the plist only ever moves into the fixture Trash.
@MainActor
enum LaunchAgentTests {
    static let label = "com.acme.updater"
    static let plistRel = "Library/LaunchAgents/com.acme.updater.plist"

    /// `<root>/opt/acme` exists (and is not empty), `<root>/opt/acme/bin/updater` does not (provably missing).
    static func missingProgram(_ f: FixtureBuilder) throws -> String {
        try f.file("opt/acme/README", bytes: 10, base: .root)
        return f.path("opt/acme/bin/updater", base: .root)
    }

    static func writeAgent(_ f: FixtureBuilder, _ rel: String, _ plist: [String: Any]) throws {
        try f.file(rel, contents: try M5.plistData(plist))
    }

    static func writeAgent(_ f: FixtureBuilder, _ plist: [String: Any]) throws {
        try writeAgent(f, plistRel, plist)
    }

    static func discover(_ env: FakeEnvironment) async throws -> InspectorOutput {
        await OrphanedLaunchAgentsInspector().discover(rule: try M5.rule(env, "leftovers.launchAgents"), environment: env.environment)
    }

    static func offered(_ env: FakeEnvironment) async throws -> Set<String> {
        let output = try await discover(env)
        try TestSuite.assertEqual(output.status, .ok)
        return Set(output.candidates.map { OrphanDetectorTests.relative($0.path, env) })
    }

    /// Scan → plan → confirm (per item + irreversible acknowledgement) the one orphaned agent.
    static func confirmedAgent(_ ctx: M3.Context) async throws -> (ConfirmedPlan, PlanItem) {
        let results = try await M5.scanner(ctx.env).scan(ruleIDs: ["leftovers.launchAgents"])
        let plan = await ctx.planBuilder().build(from: results)
        let item = try M5.item(plan, plistRel, ctx.env.fixture)
        try TestSuite.assertTrue(item.isActionable, "\(item.planVerdict) \(item.preconditions)")
        return (try M3.confirmAll(plan, irreversible: true), item)
    }

    static func bootoutArguments(_ env: FakeEnvironment, _ item: PlanItem) -> [String] {
        ["bootout", "gui/\(env.userID)", item.target.path]
    }

    static func runAll() async {
        print("\n🚀 Running LaunchAgent Tests (spec §6.9, §13 M6)...")

        await TestSuite.run("LaunchAgents: a missing Program / ProgramArguments[0] is offered with label and missing binary in the notes") {
            try await M1.withEnv { env in
                let f = env.fixture
                let missing = try missingProgram(f)
                try writeAgent(f, ["Label": label, "ProgramArguments": [missing, "--daemon"]])
                try writeAgent(f, "Library/LaunchAgents/com.acme.helper.plist", ["Label": "com.acme.helper", "Program": missing + "-helper"])
                let output = try await discover(env)
                try TestSuite.assertEqual(output.status, .ok)
                try TestSuite.assertEqual(Set(output.candidates.map { OrphanDetectorTests.relative($0.path, env) }),
                                          [plistRel, "Library/LaunchAgents/com.acme.helper.plist"])
                let agent = try M5.unwrap(output.candidates.first { $0.path.hasSuffix("com.acme.updater.plist") })
                try TestSuite.assertEqual(agent.displayName, label)
                try TestSuite.assertTrue(agent.notes.contains("Label: \(label)"), "\(agent.notes)")
                try TestSuite.assertTrue(agent.notes.contains("Missing program: \(missing)"), "\(agent.notes)")
                try TestSuite.assertTrue(env.commands.invocations.isEmpty, "discovery never runs launchctl")
            }
        }

        await TestSuite.run("LaunchAgents: an existing binary, an unprovable one or a relative program is not offered") {
            try await M1.withEnv { env in
                let f = env.fixture
                let existing = try f.file("opt/acme/bin/present", bytes: 10, base: .root)
                try writeAgent(f, ["Label": label, "ProgramArguments": [existing]])
                try writeAgent(f, "Library/LaunchAgents/com.acme.volume.plist", ["Label": "com.acme.volume", "Program": "/Volumes/Gone/acme"])
                // An EMPTY parent folder (an unmounted mount point looks like that) proves nothing.
                try f.dir("opt/empty", base: .root)
                try writeAgent(f, "Library/LaunchAgents/com.acme.empty.plist",
                               ["Label": "com.acme.empty", "Program": f.path("opt/empty/bin/x", base: .root)])
                try writeAgent(f, "Library/LaunchAgents/com.acme.relative.plist", ["Label": "com.acme.relative", "ProgramArguments": ["acme"]])
                try writeAgent(f, "Library/LaunchAgents/com.acme.bundle.plist",
                               ["Label": "com.acme.bundle", "BundleProgram": "Contents/MacOS/x", "Program": f.path("nope/x", base: .root)])
                try TestSuite.assertEqual(try await offered(env), [])
                // A dangling symlink at the program path counts as existing.
                try f.symlink("opt/acme/bin/link", to: f.path("nowhere/x", base: .root), base: .root)
                try writeAgent(f, ["Label": label, "Program": f.path("opt/acme/bin/link", base: .root)])
                try TestSuite.assertEqual(try await offered(env), [])
            }
        }

        await TestSuite.run("LaunchAgents: com.apple.* agents and unparsable / label-less plists are never offered") {
            try await M1.withEnv { env in
                let f = env.fixture
                let missing = try missingProgram(f)
                try writeAgent(f, "Library/LaunchAgents/com.apple.foo.plist", ["Label": "com.apple.foo", "Program": missing])
                try writeAgent(f, "Library/LaunchAgents/com.acme.applelabel.plist", ["Label": "com.apple.sneaky", "Program": missing])
                try f.file("Library/LaunchAgents/com.acme.garbage.plist", contents: Data("not a plist <<<".utf8))
                try writeAgent(f, "Library/LaunchAgents/com.acme.nolabel.plist", ["Program": missing])
                try writeAgent(f, "Library/LaunchAgents/com.acme.badargs.plist", ["Label": "com.acme.badargs", "ProgramArguments": [42]])
                try f.file("Library/LaunchAgents/com.acme.text.txt", bytes: 10)
                try TestSuite.assertEqual(try await offered(env), [])
                // Review M6: a symlinked plist cannot be read (readers never follow links) but launchd may
                // load it, so a duplicate Label cannot be ruled out → nothing offered, and the scan says so.
                try f.symlink("Library/LaunchAgents/com.acme.link.plist", to: f.path("Library/LaunchAgents/com.acme.nolabel.plist"))
                let linked = try await discover(env)
                try TestSuite.assertEqual(linked.candidates.count, 0)
                guard case .unavailable = linked.status else { throw TestError("expected unavailable, got \(linked.status)") }
                try TestSuite.assertEqual(OrphanedLaunchAgentsInspector.parseAgent(["Label": "x", "Program": "relative"]), nil)
                try TestSuite.assertEqual(OrphanedLaunchAgentsInspector.parseAgent(["Label": "com.x.y", "Program": "/a/../b"]), nil)
                try TestSuite.assertEqual(OrphanedLaunchAgentsInspector.parseAgent(["Label": "com.x.y", "Program": "/opt/x"])?.program, "/opt/x")
            }
        }

        await TestSuite.run("LaunchAgents: Red plan item — per-item confirmation AND the irreversible acknowledgement are required") {
            try await M3.withContext { ctx in
                try writeAgent(ctx.fixture, ["Label": label, "Program": try missingProgram(ctx.fixture)])
                let results = try await M5.scanner(ctx.env).scan(ruleIDs: ["leftovers.launchAgents"])
                let plan = await ctx.planBuilder().build(from: results)
                let item = try M5.item(plan, plistRel, ctx.fixture)
                try TestSuite.assertTrue(item.isActionable, "\(item.planVerdict)")
                try TestSuite.assertEqual(item.action, .bootoutAndTrash)
                try TestSuite.assertEqual(item.effectiveTier, .red)
                try TestSuite.assertFalse(item.selectedByDefault)
                try TestSuite.assertFalse(item.isRestorable)
                for (perItem, irreversible, expected) in [(Set<UUID>(), true, ConfirmationError.missingPerItemConfirmation(item.id)),
                                                         ([item.id], false, .irreversibleNotAcknowledged)] {
                    do {
                        _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id],
                                                      confirmation: M3.confirmation(perItem: perItem, irreversible: irreversible),
                                                      alwaysQuarantine: true)
                        throw TestError("confirmed without \(expected)")
                    } catch let error as ConfirmationError {
                        try TestSuite.assertEqual(error, expected)
                    }
                }
            }
        }

        await TestSuite.run("LaunchAgents: the Executor runs exactly /bin/launchctl bootout gui/<uid> <plist> (.action), then trashes into the fixture Trash") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try writeAgent(ctx.fixture, ["Label": label, "Program": try missingProgram(ctx.fixture)])
                M6.useLaunchctl(env)
                let (confirmed, item) = try await confirmedAgent(ctx)
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: ""), for: bootoutArguments(env, item))
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .trashed(let result) = try M3.status(run.report, item.id) else {
                    throw TestError("expected trashed, got \(try M3.status(run.report, item.id))")
                }
                try TestSuite.assertTrue(result.hasPrefix(ctx.trash.directory + "/"), result)
                try TestSuite.assertFalse(M3.exists(ctx.fixture.path(plistRel)))
                try TestSuite.assertEqual(env.commands.invocations,
                                          [FakeCommandRunner.Invocation(executable: M6.launchctlPath, arguments: bootoutArguments(env, item),
                                                                        timeout: 30, purpose: .action)])
                try TestSuite.assertEqual(bootoutArguments(env, item),
                                          CommandAllowList.launchAgentBootoutArguments(userID: env.userID, plistPath: item.target.path))
                try TestSuite.assertTrue(item.target.path.hasSuffix("/Library/LaunchAgents/com.acme.updater.plist"))
            }
        }

        await TestSuite.run("LaunchAgents: launchd's \"not loaded\" / \"No such process\" answer counts as success") {
            for result in [CommandResult(exitCode: 3, stdout: "", stderr: "Boot-out failed: 3: No such process"),
                           CommandResult(exitCode: 113, stdout: "", stderr: "Could not find specified service")] {
                try await M3.withContext { ctx in
                    let env = ctx.env
                    try writeAgent(ctx.fixture, ["Label": label, "Program": try missingProgram(ctx.fixture)])
                    M6.useLaunchctl(env)
                    let (confirmed, item) = try await confirmedAgent(ctx)
                    env.commands.setResponse(result, for: bootoutArguments(env, item))
                    let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                    guard case .trashed = try M3.status(run.report, item.id) else {
                        throw TestError("\(result.exitCode): expected trashed, got \(try M3.status(run.report, item.id))")
                    }
                    try TestSuite.assertEqual(M3.children(ctx.trash.directory).count, 1)
                }
            }
        }

        await TestSuite.run("LaunchAgents: any other bootout failure (or a timeout, or exit 3 without the message) → failed, nothing trashed") {
            for result in [CommandResult(exitCode: 5, stdout: "", stderr: "Boot-out failed: 5: Input/output error"),
                           CommandResult(exitCode: 3, stdout: "", stderr: "something else"),
                           CommandResult(exitCode: 1, stdout: "", stderr: "", timedOut: true)] {
                try await M3.withContext { ctx in
                    let env = ctx.env
                    try writeAgent(ctx.fixture, ["Label": label, "Program": try missingProgram(ctx.fixture)])
                    M6.useLaunchctl(env)
                    let (confirmed, item) = try await confirmedAgent(ctx)
                    env.commands.setResponse(result, for: bootoutArguments(env, item))
                    let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                    guard case .failed = try M3.status(run.report, item.id) else {
                        throw TestError("expected failed, got \(try M3.status(run.report, item.id))")
                    }
                    try TestSuite.assertTrue(M3.exists(ctx.fixture.path(plistRel)))
                    try TestSuite.assertEqual(M3.children(ctx.trash.directory), [])
                }
            }
        }

        await TestSuite.run("LaunchAgents: launchctl not at /bin/launchctl, or the program back before execute → launchctl never runs") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try writeAgent(ctx.fixture, ["Label": label, "Program": try missingProgram(ctx.fixture)])
                env.commands.executables["launchctl"] = "/usr/local/bin/launchctl"
                let (confirmed, item) = try await confirmedAgent(ctx)
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .failed = try M3.status(run.report, item.id) else { throw TestError("\(try M3.status(run.report, item.id))") }
                try TestSuite.assertTrue(env.commands.invocations.isEmpty)
                try TestSuite.assertTrue(M3.exists(ctx.fixture.path(plistRel)))
            }
            try await M3.withContext { ctx in
                let env = ctx.env
                let missing = try missingProgram(ctx.fixture)
                try writeAgent(ctx.fixture, ["Label": label, "Program": missing])
                M6.useLaunchctl(env)
                let (confirmed, item) = try await confirmedAgent(ctx)
                try ctx.fixture.file("opt/acme/bin/updater", bytes: 10, base: .root)
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .skipped = try M3.status(run.report, item.id) else { throw TestError("\(try M3.status(run.report, item.id))") }
                try TestSuite.assertTrue(env.commands.invocations.isEmpty)
                try TestSuite.assertTrue(M3.exists(ctx.fixture.path(plistRel)))
            }
        }

        await TestSuite.run("LaunchAgents review M6: another plist declaring the same Label (user or /Library/LaunchAgents) → never offered; refused again at execute") {
            for (rel, base) in [("Library/LaunchAgents/com.acme.updater-current.plist", FixtureBuilder.Base.home),
                                ("System/Library-LaunchAgents/com.acme.updater.plist", .root)] {
                try await M1.withEnv { env in
                    let f = env.fixture
                    try writeAgent(f, ["Label": label, "Program": try missingProgram(f)])
                    try TestSuite.assertEqual(try await offered(env), [plistRel])
                    try f.file("opt/acme/bin/current", bytes: 10, base: .root)
                    try f.file(rel, contents: try M5.plistData(["Label": label.uppercased(), "Program": f.path("opt/acme/bin/current", base: .root)]),
                               base: base)
                    try TestSuite.assertEqual(try await offered(env), [], rel)
                }
            }
            // Duplicate created between plan and execute → skipped, launchctl never runs.
            try await M3.withContext { ctx in
                let env = ctx.env
                try writeAgent(ctx.fixture, ["Label": label, "Program": try missingProgram(ctx.fixture)])
                M6.useLaunchctl(env)
                let (confirmed, item) = try await confirmedAgent(ctx)
                try ctx.fixture.file("System/Library-LaunchAgents/com.acme.updater.plist",
                                     contents: try M5.plistData(["Label": label, "Program": "/usr/bin/true"]), base: .root)
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: ""), for: bootoutArguments(env, item))
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .skipped = try M3.status(run.report, item.id) else { throw TestError("\(try M3.status(run.report, item.id))") }
                try TestSuite.assertTrue(env.commands.invocations.isEmpty)
                try TestSuite.assertTrue(M3.exists(ctx.fixture.path(plistRel)))
            }
            // An unreadable system agent folder → nothing offered.
            try await M1.withEnv { env in
                let f = env.fixture
                try writeAgent(f, ["Label": label, "Program": try missingProgram(f)])
                try f.dir("System/Library-LaunchAgents", base: .root)
                env.fileSystem.fail(.contentsOfDirectory, path: f.path("System/Library-LaunchAgents", base: .root))
                let output = try await discover(env)
                try TestSuite.assertEqual(output.candidates.count, 0)
                guard case .unavailable = output.status else { throw TestError("expected unavailable, got \(output.status)") }
            }
        }

        await TestSuite.run("LaunchAgents review M6: the confirmed Label is pinned as the owner; a plist rewritten in place with another Label is refused") {
            try await M3.withContext { ctx in
                let env = ctx.env
                let missing = try missingProgram(ctx.fixture)
                try writeAgent(ctx.fixture, ["Label": label, "Program": missing])
                M6.useLaunchctl(env)
                let (confirmed, item) = try await confirmedAgent(ctx)
                try TestSuite.assertEqual(item.target.owningBundleID, label)
                // Same inode (written through an open descriptor), another Label.
                let path = ctx.fixture.path(plistRel)
                let before = try M5.unwrap(env.fileSystem.lstat(path)).identity
                let handle = try FileHandle(forUpdating: URL(fileURLWithPath: path))
                try handle.truncate(atOffset: 0)
                try handle.write(contentsOf: try M5.plistData(["Label": "com.other.job", "Program": missing]))
                try handle.close()
                try TestSuite.assertEqual(try M5.unwrap(env.fileSystem.lstat(path)).identity, before)
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: ""), for: bootoutArguments(env, item))
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .skipped = try M3.status(run.report, item.id) else { throw TestError("\(try M3.status(run.report, item.id))") }
                try TestSuite.assertTrue(env.commands.invocations.isEmpty, "\(env.commands.invocations)")
                try TestSuite.assertTrue(M3.exists(path))
            }
            // The matcher requires the owner, and the gate requires it to be the plist's Label.
            try await M1.withEnv { env in
                let f = env.fixture
                try writeAgent(f, ["Label": label, "Program": try missingProgram(f)])
                let rule = try M5.rule(env, "leftovers.launchAgents")
                for (owner, allowed) in [(nil, false), ("com.other.job", false), (label, true)] as [(String?, Bool)] {
                    let verdict = await env.makeGate().validate(target: env.scanTarget(ruleID: rule.id, path: plistRel, owningBundleID: owner),
                                                                rule: rule, phase: .plan)
                    try TestSuite.assertEqual(verdict.isAllowed, allowed, "\(owner ?? "nil"): \(verdict)")
                }
            }
        }

        await TestSuite.run("M6 tools: pkgutil / tmutil / launchctl resolve ONLY from their exact system path; pkgutil --pkgs is read-only") {
            try TestSuite.assertEqual(CommandRunner.systemToolPaths,
                                      ["pkgutil": "/usr/sbin/pkgutil", "tmutil": "/usr/bin/tmutil", "launchctl": "/bin/launchctl"])
            try await CommandRunnerTests.withContext { ctx in
                // Fake tools (fixture scripts); nothing real is run.
                let pkgutil = try ctx.script("pkgutil", "echo com.apple.pkg.Core; echo com.acme.widget")
                _ = try ctx.script("pkgutil", "echo decoy", in: ctx.outside)
                func runner(_ exact: [String: String]) -> CommandRunner {
                    CommandRunner(homeDirectory: URL(fileURLWithPath: ctx.fixture.home, isDirectory: true),
                                  searchDirectories: [CommandRunner.SearchDirectory(path: ctx.outside)],
                                  trustedRoots: [ctx.outside, ctx.bin], allowList: .standard, exactToolPaths: exact)
                }
                let exact = runner(["pkgutil": pkgutil])
                try TestSuite.assertEqual(exact.resolveExecutable("pkgutil"), pkgutil, "the exact path wins over every search directory")
                try TestSuite.assertEqual(runner(["pkgutil": ctx.bin + "/missing"]).resolveExecutable("pkgutil"), nil,
                                          "a missing exact tool never falls back to a search directory")
                let link = try ctx.link("pkgutil-link", to: pkgutil)
                try TestSuite.assertEqual(runner(["pkgutil": link]).resolveExecutable("pkgutil"), nil, "a symlink is not the exact file")
                let listing = await exact.run(executable: pkgutil, arguments: ["--pkgs"], timeout: 10, purpose: .readOnly)
                try TestSuite.assertTrue(listing.succeeded, "\(listing)")
                try TestSuite.assertTrue(listing.stdout.contains("com.acme.widget"))
                for (arguments, purpose) in [(["--forget", "com.acme.widget"], CommandPurpose.readOnly), (["--pkgs"], .action),
                                             (["--pkg-info", "com.acme.widget"], .readOnly)] {
                    let refused = await exact.run(executable: pkgutil, arguments: arguments, timeout: 10, purpose: purpose)
                    try TestSuite.assertFalse(refused.succeeded, "\(arguments) \(purpose)")
                }
            }
        }

        await TestSuite.run("LaunchAgents: {UID} / {PLIST} validators refuse other users, paths outside LaunchAgents and com.apple.*") {
            try await M1.withEnv { env in
                let home = env.fixture.home
                let uid = env.userID
                let good = home + "/Library/LaunchAgents/com.acme.updater.plist"
                func allowed(_ arguments: [String], userID: UInt32 = uid) -> Bool {
                    CommandAllowList.launchAgentBootoutAllowed(arguments: arguments, userID: userID, homeDirectories: [home])
                }
                try TestSuite.assertTrue(allowed(["bootout", "gui/\(uid)", good]))
                try TestSuite.assertFalse(allowed(["bootout", "gui/\(M1.otherUID)", good]), "another user's domain")
                try TestSuite.assertFalse(allowed(["bootout", "gui/\(uid)", good], userID: M1.otherUID))
                try TestSuite.assertFalse(allowed(["bootout", "system", good]))
                try TestSuite.assertFalse(allowed(["bootout", "user/\(uid)", good]))
                for bad in ["/Library/LaunchAgents/com.acme.updater.plist", "/Library/LaunchDaemons/com.acme.updater.plist",
                            home + "/Library/LaunchAgents/com.apple.foo.plist", home + "/Library/LaunchAgents/COM.APPLE.foo.plist",
                            home + "/Library/LaunchAgents/sub/com.acme.updater.plist", home + "/Library/LaunchAgents/../x.plist",
                            home + "/Library/LaunchAgents/com.acme.updater", home + "/Library/LaunchAgents",
                            "/Users/someoneelse/Library/LaunchAgents/com.acme.updater.plist", "com.acme.updater.plist"] {
                    try TestSuite.assertFalse(allowed(["bootout", "gui/\(uid)", bad]), bad)
                }
                try TestSuite.assertFalse(allowed(["bootstrap", "gui/\(uid)", good]))
                try TestSuite.assertFalse(allowed(["bootout", "gui/\(uid)", good, "extra"]))
                // The static table: only the action shape; launchctl is never a read-only or rule-usable tool.
                let table = CommandAllowList.standard
                try TestSuite.assertTrue(table.matches(tool: "launchctl", arguments: ["bootout", "gui/\(uid)", good], purpose: .action))
                try TestSuite.assertFalse(table.matches(tool: "launchctl", arguments: ["bootout", "gui/\(uid)", good], purpose: .readOnly))
                try TestSuite.assertFalse(table.matches(tool: "launchctl", arguments: ["unload", good], purpose: .action))
                try TestSuite.assertFalse(table.matches(tool: "launchctl", arguments: ["bootout", "system/com.acme"], purpose: .action))
                let entry = try M5.unwrap(table.entry(tool: "launchctl", arguments: ["bootout", "gui/\(uid)", good], purpose: .action))
                try TestSuite.assertFalse(entry.permits(ruleID: "leftovers.launchAgents", tier: .red), "never usable by a rule's command action")
            }
        }
    }
}
