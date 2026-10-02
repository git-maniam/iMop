import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §6.9 / §12.2 / §13 M6: the OrphanDetector (`leftovers.appData`, Red). A fully orphaned fixture
/// identifier is offered (Red, never preselected, per-item confirmation); then EACH of the eight
/// conditions is broken on its own and must block it (fail closed).
@MainActor
enum OrphanDetectorTests {
    static let identifier = "com.acme.widget"
    static let supportRel = "Library/Application Support/com.acme.widget"
    static let otherAppRel = "System/Applications-root/Other.app"

    /// A fully orphaned `com.acme.widget` (Application Support, 40 days old) with a believable system:
    /// pkgutil lists Apple receipts only, one unrelated installed app whose signature can be read,
    /// nothing related running, LaunchServices and Spotlight find nothing, no drive missing.
    static func setUp(_ env: FakeEnvironment) throws {
        let f = env.fixture
        M6.usePkgutil(env)
        env.codeSignatures.defaultSigningInfo = .init(teamID: "QQQQQ11111", appGroups: ["group.com.other.app"])
        try M6.appBundle(f, otherAppRel, bundleID: "com.other.app", base: .root)
        try f.file(supportRel + "/data.db", bytes: 2_000)
        try M6.ageTree(f, supportRel, days: 40, clock: env.clock)
    }

    static func orphanFolder(_ env: FakeEnvironment, _ rel: String, days: Int = 40) throws {
        try env.fixture.file(rel + "/data.bin", bytes: 500)
        try M6.ageTree(env.fixture, rel, days: days, clock: env.clock)
    }

    static func discover(_ env: FakeEnvironment) async throws -> InspectorOutput {
        let inspector = try M6.orphanInspector(env.fixture, catalog: try M5.catalog(env))
        return await inspector.discover(rule: try M5.rule(env, "leftovers.appData"), environment: env.environment)
    }

    static func offered(_ env: FakeEnvironment) async throws -> Set<String> {
        let output = try await discover(env)
        try TestSuite.assertEqual(output.status, .ok)
        return Set(output.candidates.map { relative($0.path, env) })
    }

    /// Fixture-home-relative form of an inspector path (either spelling of the home).
    nonisolated static func relative(_ path: String, _ env: FakeEnvironment) -> String {
        for home in [env.fixture.home, env.environment.homePath] where path.hasPrefix(home + "/") {
            return String(path.dropFirst(home.count + 1))
        }
        return path
    }

    /// The first blocking condition for `<location>/<name>` (via the evaluator, as the inspector uses it).
    static func block(_ env: FakeEnvironment, _ location: OrphanLocation, _ name: String) async throws -> OrphanBlock? {
        let evaluator = try M6.orphanEvaluator(env, catalog: try M5.catalog(env))
        let directory = env.environment.homePath + "/Library/" + location.directoryName
        guard let candidate = OrphanCandidate.make(name: name, location: location, directory: directory) else {
            throw TestError("no candidate for \(name)")
        }
        return await evaluator.evaluate(candidate)
    }

    /// The baseline is offered, then `breakIt` alone blocks it with `condition`.
    static func expectBlocked(_ condition: OrphanCondition, location: OrphanLocation = .applicationSupport,
                              name: String = identifier, rel: String = supportRel,
                              file: StaticString = #file, line: UInt = #line,
                              _ breakIt: (FakeEnvironment) throws -> Void) async throws {
        try await M1.withEnv { env in
            try setUp(env)
            if rel != supportRel { try orphanFolder(env, rel) }
            try TestSuite.assertTrue(try await offered(env).contains(rel), "baseline must be offered: \(rel)", file: file, line: line)
            try TestSuite.assertEqual(try await block(env, location, name), nil, "baseline", file: file, line: line)
            try breakIt(env)
            let blocked = try await block(env, location, name)
            try TestSuite.assertEqual(blocked?.condition, condition, "\(String(describing: blocked))", file: file, line: line)
            try TestSuite.assertFalse(blocked?.reason.isEmpty ?? true, file: file, line: line)
            try TestSuite.assertFalse(try await offered(env).contains(rel), "\(rel) must no longer be offered", file: file, line: line)
        }
    }

    static func runAll() async {
        print("\n🧹 Running OrphanDetector Tests (spec §6.9, §13 M6)...")
        // MARK: Offered

        await TestSuite.run("Orphans: a fully orphaned identifier is offered in every leftover location (Red, owner = identifier)") {
            try await M1.withEnv { env in
                try setUp(env)
                let f = env.fixture
                try f.file("Library/Preferences/com.acme.widget.plist", bytes: 100)
                try f.setModificationDate("Library/Preferences/com.acme.widget.plist", daysAgo: 40, clock: env.clock)
                try orphanFolder(env, "Library/Containers/com.acme.widget")
                try orphanFolder(env, "Library/Group Containers/group.com.acme.widget")
                try orphanFolder(env, "Library/Group Containers/ABCDE12345.com.acme.widget")
                try orphanFolder(env, "Library/Caches/com.acme.widget")
                try orphanFolder(env, "Library/WebKit/com.acme.widget")
                let output = try await discover(env)
                try TestSuite.assertEqual(output.status, .ok)
                let paths = Set(output.candidates.map { relative($0.path, env) })
                try TestSuite.assertEqual(paths, [supportRel, "Library/Preferences/com.acme.widget.plist",
                                                  "Library/Containers/com.acme.widget",
                                                  "Library/Group Containers/group.com.acme.widget",
                                                  "Library/Group Containers/ABCDE12345.com.acme.widget",
                                                  "Library/Caches/com.acme.widget", "Library/WebKit/com.acme.widget"])
                for candidate in output.candidates {
                    let name = (candidate.path as NSString).lastPathComponent
                    let expectedOwner = name.hasSuffix(".plist") ? String(name.dropLast(6)) : name
                    try TestSuite.assertEqual(candidate.owningBundleID, expectedOwner, candidate.path)
                    try TestSuite.assertFalse(candidate.notes.isEmpty, candidate.path)
                }
                // Read-only: only the read-only pkgutil listing ran.
                try TestSuite.assertEqual(env.commands.invocations.map(\.executable), [M6.pkgutilPath])
                try TestSuite.assertEqual(env.commands.invocations.map(\.arguments), [["--pkgs"]])
                try TestSuite.assertEqual(env.commands.purposes, [.readOnly])
            }
        }

        await TestSuite.run("Orphans: scan → plan → execute — Red, never preselected, per-item confirmation, then moved to the (fixture) Trash") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUp(env)
                let results = try await M5.scanner(env).scan(ruleIDs: ["leftovers.appData"])
                try TestSuite.assertEqual(results.first?.status, .ok)
                try TestSuite.assertEqual(results.flatMap(\.targets).map { relative($0.path, env) }, [supportRel])
                let plan = await ctx.planBuilder().build(from: results)
                let item = try M5.item(plan, supportRel, env.fixture)
                try TestSuite.assertTrue(item.isActionable, "\(item.planVerdict) \(item.preconditions)")
                try TestSuite.assertEqual(item.effectiveTier, .red)
                try TestSuite.assertEqual(item.action, .trash)
                try TestSuite.assertFalse(item.selectedByDefault)
                try TestSuite.assertTrue(item.requiresPerItemConfirmation)
                try TestSuite.assertTrue(Set(item.preconditions.map(\.name)).isSuperset(of:
                    ["owningAppNotRunning", "olderThan", "notOpenByAnyProcess", "stillOrphaned"]), "\(item.preconditions.map(\.name))")
                try TestSuite.assertTrue(item.preconditions.allSatisfy(\.passed))
                do {
                    _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id], confirmation: M3.confirmation(),
                                                  alwaysQuarantine: true)
                    throw TestError("a Red item was confirmed without its per-item confirmation")
                } catch let error as ConfirmationError {
                    try TestSuite.assertEqual(error, .missingPerItemConfirmation(item.id))
                }
                let confirmed = try M3.confirmAll(plan)
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .trashed(let result) = try M3.status(run.report, item.id) else {
                    throw TestError("expected trashed, got \(try M3.status(run.report, item.id))")
                }
                try TestSuite.assertTrue(result.hasPrefix(ctx.trash.directory + "/"), result)
                try TestSuite.assertFalse(M3.exists(env.fixture.path(supportRel)))
            }
        }

        // MARK: Condition 1

        await TestSuite.run("Orphans condition 1: com.apple.* / group.com.apple.* (any case) are never orphaned") {
            try await M1.withEnv { env in
                try setUp(env)
                try orphanFolder(env, "Library/Application Support/com.apple.widget")
                try orphanFolder(env, "Library/Application Support/COM.APPLE.Other")
                try orphanFolder(env, "Library/Group Containers/group.com.apple.notes")
                try orphanFolder(env, "Library/Group Containers/ABCDE12345.com.apple.shared")
                try TestSuite.assertEqual(try await offered(env), [supportRel])
                for (location, name) in [(OrphanLocation.applicationSupport, "com.apple.widget"), (.applicationSupport, "COM.APPLE.Other"),
                                         (.groupContainers, "group.com.apple.notes"), (.groupContainers, "ABCDE12345.com.apple.shared")] {
                    try TestSuite.assertTrue(try await block(env, location, name) != nil, name)
                    let evaluator = try M6.orphanEvaluator(env, catalog: try M5.catalog(env))
                    let candidate = try M5.unwrap(OrphanCandidate.make(
                        name: name, location: location, directory: env.environment.homePath + "/Library/" + location.directoryName))
                    try TestSuite.assertEqual(evaluator.checkNotAppleOrDenied(candidate)?.condition, .notAppleOrDenied, name)
                }
            }
        }

        await TestSuite.run("Orphans condition 1: a deny-listed location (HTTPStorages) is never offered") {
            try await M1.withEnv { env in
                try setUp(env)
                try orphanFolder(env, "Library/HTTPStorages/com.acme.widget")
                try TestSuite.assertEqual(try await offered(env), [supportRel])
                try TestSuite.assertEqual(try await block(env, .httpStorages, identifier)?.condition, .notAppleOrDenied)
                // The deny-listed folder was not even listed.
                let listed = env.fileSystem.recordedCalls.filter { $0.0 == .contentsOfDirectory }.map(\.1)
                try TestSuite.assertFalse(listed.contains { $0.contains("HTTPStorages") }, "\(listed)")
            }
        }

        // MARK: Condition 2

        await TestSuite.run("Orphans condition 2: a LaunchServices hit blocks") {
            try await expectBlocked(.notInstalled) { env in
                env.applications.applicationURLs = [identifier: [URL(fileURLWithPath: "/Volumes/Ext/Widget.app")]]
            }
        }

        await TestSuite.run("Orphans condition 2: a Spotlight hit (any volume) blocks") {
            try await expectBlocked(.notInstalled) { env in
                env.applications.spotlightPaths = ["COM.ACME.WIDGET": ["/Volumes/Ext/Widget.app"]]
            }
        }

        await TestSuite.run("Orphans condition 2: LaunchServices or Spotlight unable to answer (nil) blocks") {
            try await expectBlocked(.notInstalled) { env in env.applications.failing = true }
            try await expectBlocked(.notInstalled) { env in env.applications.spotlightFailing = true }
        }

        await TestSuite.run("Orphans condition 2: the main app of a helper identifier is looked up too") {
            try await expectBlocked(.notInstalled, name: "com.acme.widget.helper",
                                    rel: "Library/Application Support/com.acme.widget.helper") { env in
                env.applications.applicationURLs = [identifier: [URL(fileURLWithPath: "/Applications/Widget.app")]]
            }
        }

        // MARK: Condition 3

        await TestSuite.run("Orphans condition 3: a running app with that bundle id (case-insensitive) blocks") {
            try await expectBlocked(.notRunning) { env in env.runningApplications.ids = ["com.apple.finder", "COM.Acme.Widget"] }
        }

        await TestSuite.run("Orphans condition 3: a running process named like the identifier's last component blocks") {
            try await expectBlocked(.notRunning) { env in env.processes.names = ["launchd", "Widget"] }
        }

        await TestSuite.run("Orphans condition 3: running apps / processes that cannot be listed (nil) block") {
            try await expectBlocked(.notRunning) { env in env.runningApplications.failing = true }
            try await expectBlocked(.notRunning) { env in env.processes.failing = true }
        }

        // MARK: Condition 4

        await TestSuite.run("Orphans condition 4: a package receipt that equals / starts with / contains the identifier (or vice versa) blocks") {
            for receipt in ["com.acme.widget", "com.acme.widget.pkg", "COM.ACME.WIDGET.installer", "com.acme"] {
                try await expectBlocked(.noPackageReceipt) { env in M6.usePkgutil(env, receipts: [receipt]) }
            }
            // The pure matcher, both directions.
            try TestSuite.assertEqual(OrphanEvaluator.packageReceiptBlock(identifier: identifier, packageIDs: ["x.com.acme.widget.y"])?.condition,
                                      .noPackageReceipt)
            try TestSuite.assertEqual(OrphanEvaluator.packageReceiptBlock(identifier: identifier, packageIDs: ["com.apple.pkg.Core"]), nil)
        }

        await TestSuite.run("Orphans condition 4: pkgutil failing, timing out, empty or not at /usr/sbin/pkgutil blocks") {
            try await expectBlocked(.noPackageReceipt) { env in
                M6.usePkgutil(env, result: CommandResult(exitCode: 1, stdout: "", stderr: "error"))
            }
            try await expectBlocked(.noPackageReceipt) { env in
                M6.usePkgutil(env, result: CommandResult(exitCode: 0, stdout: "", stderr: ""))
            }
            try await expectBlocked(.noPackageReceipt) { env in
                M6.usePkgutil(env, result: CommandResult(exitCode: 0, stdout: "com.apple.pkg.X\n[truncated 5 MB]\n", stderr: ""))
            }
            try await expectBlocked(.noPackageReceipt) { env in
                env.commands.executables["pkgutil"] = "/opt/homebrew/bin/pkgutil"
            }
            try await expectBlocked(.noPackageReceipt) { env in
                env.commands.executables["pkgutil"] = nil
            }
        }

        // MARK: Condition 5

        let teamContainer = "Library/Group Containers/ABCDE12345.com.acme.widget"
        let groupContainer = "Library/Group Containers/group.com.acme.widget"

        await TestSuite.run("Orphans condition 5: a Group Container whose Team ID matches an installed app's blocks") {
            try await expectBlocked(.groupContainerUnclaimed, location: .groupContainers, name: "ABCDE12345.com.acme.widget",
                                    rel: teamContainer) { env in
                env.codeSignatures.setSigningInfo(.init(teamID: "ABCDE12345", appGroups: []),
                                                  for: env.fixture.path(otherAppRel, base: .root))
            }
        }

        await TestSuite.run("Orphans condition 5: a group.* container declared in an installed app's application-groups blocks") {
            try await expectBlocked(.groupContainerUnclaimed, location: .groupContainers, name: "group.com.acme.widget",
                                    rel: groupContainer) { env in
                env.codeSignatures.setSigningInfo(.init(teamID: "QQQQQ11111", appGroups: ["group.com.acme.widget"]),
                                                  for: env.fixture.path(otherAppRel, base: .root))
            }
        }

        await TestSuite.run("Orphans condition 5: ANY unreadable signing info means no Group Container is orphaned") {
            try await expectBlocked(.groupContainerUnclaimed, location: .groupContainers, name: "group.com.acme.widget",
                                    rel: groupContainer) { env in
                env.codeSignatures.setSigningInfo(nil, for: env.fixture.path(otherAppRel, base: .root))
            }
            // Also an installed app below one folder level (e.g. /Applications/Setapp-like folders).
            try await expectBlocked(.groupContainerUnclaimed, location: .groupContainers, name: "ABCDE12345.com.acme.widget",
                                    rel: teamContainer) { env in
                let nested = try M6.appBundle(env.fixture, "System/Applications-root/Vendor/Nested.app",
                                              bundleID: "com.vendor.nested", base: .root)
                env.codeSignatures.setSigningInfo(nil, for: nested)
            }
            // Non-group locations do not need signing information.
            try await M1.withEnv { env in
                try setUp(env)
                env.codeSignatures.defaultSigningInfo = nil
                try TestSuite.assertTrue(try await offered(env).contains(supportRel))
            }
        }

        await TestSuite.run("Orphans condition 5: a Group Container name that is neither group.* nor <TEAMID>.* is never orphaned") {
            try await M1.withEnv { env in
                try setUp(env)
                try orphanFolder(env, "Library/Group Containers/com.acme.widget.shared")
                try TestSuite.assertFalse(try await offered(env).contains("Library/Group Containers/com.acme.widget.shared"))
                try TestSuite.assertEqual(try await block(env, .groupContainers, "com.acme.widget.shared")?.condition, .groupContainerUnclaimed)
            }
        }

        // MARK: Condition 6

        await TestSuite.run("Orphans condition 6: known CLI / tool / vendor directories are never orphaned") {
            try await M1.withEnv { env in
                try setUp(env)
                let names = ["com.google.Keystone", "com.microsoft.autoupdate2", "org.mozilla.firefox", "com.docker.helper",
                             "com.jetbrains.toolbox", "org.jupyter.lab", "com.homebrew.bundle"]
                for name in names { try orphanFolder(env, "Library/Application Support/\(name)") }
                try TestSuite.assertEqual(try await offered(env), [supportRel])
                for name in names {
                    try TestSuite.assertEqual(try await block(env, .applicationSupport, name)?.condition, .notKnownTool, name)
                }
            }
        }

        await TestSuite.run("Orphans condition 6: plain folder names and two-label names are never candidates") {
            try await M1.withEnv { env in
                try setUp(env)
                let names = ["AcmeWidget", "acme.widget", "Widget Data", "com..widget", "com.acme.-bad", "com.acme.wid_get"]
                for name in names { try orphanFolder(env, "Library/Application Support/\(name)") }
                try TestSuite.assertEqual(try await offered(env), [supportRel])
                for name in names {
                    try TestSuite.assertEqual(try await block(env, .applicationSupport, name)?.condition, .notKnownTool, name)
                }
                try TestSuite.assertFalse(OrphanEvaluator.isReverseDNSIdentifier("acme.widget"))
                try TestSuite.assertTrue(OrphanEvaluator.isReverseDNSIdentifier("com.acme.widget"))
            }
        }

        await TestSuite.run("Orphans condition 6: a folder another rule of the catalog targets is never orphaned") {
            try await M1.withEnv { env in
                try setUp(env)
                // `{HOME}/Library/Caches/*.ShipIt` belongs to apps.squirrelShipIt.
                try orphanFolder(env, "Library/Caches/com.acme.widget.ShipIt")
                try TestSuite.assertFalse(try await offered(env).contains("Library/Caches/com.acme.widget.ShipIt"))
                try TestSuite.assertEqual(try await block(env, .caches, "com.acme.widget.ShipIt")?.condition, .notKnownTool)
                // Without a catalog, condition 6 always blocks.
                let evaluator = try M6.orphanEvaluator(env, catalog: nil)
                let directory = env.environment.homePath + "/Library/Application Support"
                let candidate = try M5.unwrap(OrphanCandidate.make(name: identifier, location: .applicationSupport, directory: directory))
                try TestSuite.assertEqual(await evaluator.evaluate(candidate)?.condition, .notKnownTool)
            }
        }

        // MARK: Condition 7

        await TestSuite.run("Orphans condition 7: data used within the last 30 days (entry or a child) blocks") {
            try await expectBlocked(.olderThan) { env in
                try env.fixture.setModificationDate(supportRel + "/data.db", daysAgo: 5, clock: env.clock)
            }
            try await expectBlocked(.olderThan) { env in
                try env.fixture.setModificationDate(supportRel, daysAgo: 29, clock: env.clock)
            }
            // A user override may only raise the threshold.
            try await expectBlocked(.olderThan) { env in
                var settings = env.scanSettings
                settings.ageThresholdOverrides = ["leftovers.appData": 60]
                env.scanSettings = settings
            }
            try await M1.withEnv { env in
                try setUp(env)
                var settings = env.scanSettings
                settings.ageThresholdOverrides = ["leftovers.appData": 1]
                env.scanSettings = settings
                try TestSuite.assertTrue(try await offered(env).contains(supportRel), "a lower override is ignored")
            }
        }

        // MARK: Condition 8

        await TestSuite.run("Orphans condition 8: with Setapp apps installed, Setapp identifiers and -setapp editions block") {
            try await expectBlocked(.noMissingAppLocation) { env in
                try M6.appBundle(env.fixture, "System/Applications-root/Setapp/Widget.app",
                                 bundleID: "com.acme.widget-setapp", base: .root)
            }
            // The -setapp edition registered with LaunchServices also blocks (Setapp folder present).
            try await expectBlocked(.noMissingAppLocation) { env in
                try M6.appBundle(env.fixture, "System/Applications-root/Setapp/Other.app", bundleID: "com.other.setapp", base: .root)
                env.applications.applicationURLs = ["com.acme.widget-setapp": [URL(fileURLWithPath: "/Volumes/X/Widget.app")]]
            }
            // An unreadable Setapp app blocks everything.
            try await expectBlocked(.noMissingAppLocation) { env in
                try env.fixture.dir("System/Applications-root/Setapp/Broken.app", base: .root)
            }
        }

        await TestSuite.run("Orphans condition 8: a previously seen volume missing, or none listable → no candidates, .unavailable") {
            for breakIt in [{ (env: FakeEnvironment) in env.volumes.volumes = [] },
                            { (env: FakeEnvironment) in env.volumes.volumes = nil }] {
                try await M1.withEnv { env in
                    try setUp(env)
                    env.volumes.volumes = ["/Volumes/Apps"]
                    var settings = env.scanSettings
                    settings.lastSeenVolumes = [FakeVolumeInspector.defaultUUID(for: "/Volumes/Apps")]
                    env.scanSettings = settings
                    try TestSuite.assertTrue(try await offered(env).contains(supportRel))
                    breakIt(env)
                    let output = try await discover(env)
                    try TestSuite.assertEqual(output.candidates.count, 0)
                    guard case .unavailable(let message) = output.status,
                          message.hasPrefix(OrphanEvaluator.disconnectedVolumeMessage) || message.contains("drives") else {
                        throw TestError("expected unavailable, got \(output.status)")
                    }
                    try TestSuite.assertEqual(try await block(env, .applicationSupport, identifier)?.condition, .noMissingAppLocation)
                }
            }
        }

        await TestSuite.run("Orphans condition 8: lastSeenVolumes (UUIDs) only grows; a failed listing changes nothing; nil = never recorded") {
            try await M1.withEnv { env in
                let apps = FakeVolumeInspector.defaultUUID(for: "/Volumes/Apps")
                let new = FakeVolumeInspector.defaultUUID(for: "/Volumes/New")
                var settings = env.scanSettings
                settings.lastSeenVolumes = [apps]
                env.scanSettings = settings
                env.volumes.volumes = ["/Volumes/New"]
                try TestSuite.assertEqual(OrphanEvaluator.lastSeenVolumesAfterScan(environment: env.environment), [apps, new].sorted())
                try TestSuite.assertEqual(try M5.scanner(env).updatedLastSeenVolumes(), [apps, new].sorted())
                env.volumes.volumes = nil
                try TestSuite.assertEqual(settings.lastSeenVolumesAfterScan(mounted: nil), [apps])
                // Never recorded: the first successful listing records the baseline (even an empty one).
                try TestSuite.assertEqual(ScanSettings.default.lastSeenVolumes, nil)
                try TestSuite.assertEqual(ScanSettings.default.lastSeenVolumesAfterScan(mounted: nil), nil)
                try TestSuite.assertEqual(ScanSettings.default.lastSeenVolumesAfterScan(mounted: []), [])
                // Persisted with the settings; a missing key decodes as "never recorded".
                let decoded = try JSONDecoder().decode(ScanSettings.self, from: try JSONEncoder().encode(settings))
                try TestSuite.assertEqual(decoded.lastSeenVolumes, [apps])
                try TestSuite.assertEqual(try JSONDecoder().decode(ScanSettings.self, from: Data("{}".utf8)).lastSeenVolumes, nil)
                let empty = try JSONDecoder().decode(ScanSettings.self, from: Data(#"{"lastSeenVolumes":[]}"#.utf8))
                try TestSuite.assertEqual(empty.lastSeenVolumes, [])
            }
        }

        // MARK: Review M6 regressions

        await TestSuite.run("Orphans review M6 (E5): drives never recorded (lastSeenVolumes nil, first scan / reset) → nothing offered, .unavailable; the baseline is recorded") {
            try await M1.withEnv { env in
                try setUp(env)
                var settings = env.scanSettings
                settings.lastSeenVolumes = nil
                env.scanSettings = settings
                env.volumes.volumes = []
                let output = try await discover(env)
                try TestSuite.assertEqual(output.candidates.count, 0)
                guard case .unavailable(let message) = output.status, message.hasPrefix(OrphanEvaluator.noVolumeBaselineMessage) else {
                    throw TestError("expected unavailable, got \(output.status)")
                }
                try TestSuite.assertEqual(try await block(env, .applicationSupport, identifier)?.condition, .noMissingAppLocation)
                // The scanner's helper records the baseline; with it the next scan offers again.
                settings.lastSeenVolumes = try M5.scanner(env).updatedLastSeenVolumes()
                try TestSuite.assertEqual(settings.lastSeenVolumes, [])
                env.scanSettings = settings
                try TestSuite.assertTrue(try await offered(env).contains(supportRel))
            }
        }

        await TestSuite.run("Orphans review M6 (E6): volumes are compared by UUID — another drive mounted under the same name, or an unidentifiable one, blocks") {
            try await M1.withEnv { env in
                try setUp(env)
                env.volumes.volumes = ["/Volumes/Untitled"]
                var settings = env.scanSettings
                settings.lastSeenVolumes = ["APPS-DRIVE-UUID"]
                env.scanSettings = settings
                // A different drive at the same mount path.
                env.volumes.setUUID("OTHER-DRIVE-UUID", for: "/Volumes/Untitled")
                let other = try await discover(env)
                try TestSuite.assertEqual(other.candidates.count, 0)
                guard case .unavailable(let message) = other.status, message.hasPrefix(OrphanEvaluator.disconnectedVolumeMessage) else {
                    throw TestError("expected unavailable, got \(other.status)")
                }
                // The right drive (UUID compared case-insensitively) → offered.
                env.volumes.setUUID("apps-drive-uuid", for: "/Volumes/Untitled")
                try TestSuite.assertTrue(try await offered(env).contains(supportRel))
                // A mounted drive whose UUID cannot be read → blocks.
                env.volumes.volumes = ["/Volumes/Untitled", "/Volumes/FAT"]
                env.volumes.setUUID(nil, for: "/Volumes/FAT")
                try TestSuite.assertEqual(try await discover(env).candidates.count, 0)
                try TestSuite.assertEqual(try await block(env, .applicationSupport, identifier)?.condition, .noMissingAppLocation)
            }
        }

        await TestSuite.run("Orphans review M6 (E3): an app bundle physically present carries the identifier → not orphaned even when LaunchServices and Spotlight find nothing") {
            try await expectBlocked(.notInstalled) { env in
                try M6.appBundle(env.fixture, "System/Applications-root/Widget.app", bundleID: "COM.ACME.WIDGET", base: .root)
            }
            // Also on a mounted external drive (<volume>/Applications), and one folder level down.
            try await expectBlocked(.notInstalled) { env in
                try M6.appBundle(env.fixture, "Volumes/Ext/Applications/Suite/Widget.app", bundleID: identifier, base: .root)
            }
            // An enumerated app whose identifier cannot be read → unknown → blocks.
            try await expectBlocked(.notInstalled) { env in
                try env.fixture.dir("System/Applications-root/Broken.app/Contents", base: .root)
            }
        }

        await TestSuite.run("Orphans review M6 (E3): Spotlight that does not index the Mac (built-in apps not found) → unknown → blocks") {
            try await expectBlocked(.notInstalled) { env in env.applications.systemAppsIndexed = false }
        }

        await TestSuite.run("Orphans review M6 (E2): a sibling helper of an installed app of the same developer is not orphaned") {
            let launcher = "Library/Containers/com.vendor.EditorLauncher"
            // The vendor's main app enumerated directly (nothing registered anywhere).
            try await expectBlocked(.notInstalled, location: .containers, name: "com.vendor.EditorLauncher", rel: launcher) { env in
                try M6.appBundle(env.fixture, "System/Applications-root/Editor.app", bundleID: "com.vendor.Editor", base: .root)
            }
            // The vendor's app found by the Spotlight vendor-domain query (anywhere, e.g. ~/Desktop).
            try await expectBlocked(.notInstalled, location: .containers, name: "com.vendor.EditorLauncher", rel: launcher) { env in
                env.applications.spotlightPaths = ["com.vendor.Editor": [env.fixture.path("Desktop/Editor.app")]]
            }
            try await M1.withEnv { env in
                try setUp(env)
                _ = try await offered(env)
                try TestSuite.assertTrue(env.applications.vendorQueries.contains("com.acme"), "\(env.applications.vendorQueries)")
            }
        }

        await TestSuite.run("Orphans review M6 (E1): group / Team-ID containers of an app installed outside the roots (external drive) are not orphaned") {
            for name in ["group.com.vendor.shared", "ABCDE12345.com.vendor.shared"] {
                try await expectBlocked(.notInstalled, location: .groupContainers, name: name, rel: "Library/Group Containers/" + name) { env in
                    let ext = "/Volumes/Ext/Applications/Editor.app"
                    env.applications.applicationURLs = ["com.vendor.editor": [URL(fileURLWithPath: ext)]]
                    env.applications.spotlightPaths = ["com.vendor.editor": [ext]]
                    env.volumes.volumes = ["/Volumes/Ext"]
                    var settings = env.scanSettings
                    settings.lastSeenVolumes = [FakeVolumeInspector.defaultUUID(for: "/Volumes/Ext")]
                    env.scanSettings = settings
                }
            }
            // An app on a mounted volume's Applications folder is enumerated for condition 5 too.
            try await expectBlocked(.groupContainerUnclaimed, location: .groupContainers, name: "ABCDE12345.shared.data",
                                    rel: "Library/Group Containers/ABCDE12345.shared.data") { env in
                let app = try M6.appBundle(env.fixture, "Volumes/Ext/Applications/Tool.app", bundleID: "net.other.tool", base: .root)
                env.codeSignatures.setSigningInfo(.init(teamID: "ABCDE12345", appGroups: []), for: app)
            }
        }

        await TestSuite.run("Orphans review M6: an installed LaunchAgent / LaunchDaemon of the same developer whose program exists blocks; an unreadable one blocks everything") {
            func job(_ env: FakeEnvironment, _ dir: String, _ base: FixtureBuilder.Base, label: String, program: String) throws {
                try env.fixture.file(dir + "/" + label + ".plist", contents: try M5.plistData(["Label": label, "Program": program]), base: base)
            }
            // A user agent of the same vendor with an existing program.
            try await expectBlocked(.notRunning) { env in
                try env.fixture.file("bin/syncd", bytes: 10, base: .root)
                try job(env, "Library/LaunchAgents", .home, label: "com.acme.syncd", program: env.fixture.path("bin/syncd", base: .root))
            }
            // A system daemon related to the identifier.
            try await expectBlocked(.notRunning) { env in
                try env.fixture.file("bin/widgetd", bytes: 10, base: .root)
                try job(env, "System/Library-LaunchDaemons", .root, label: "com.acme.widget.daemon",
                        program: env.fixture.path("bin/widgetd", base: .root))
            }
            // An unreadable plist in a system folder → blocks (and the inspector says so).
            try await M1.withEnv { env in
                try setUp(env)
                try env.fixture.file("System/Library-LaunchAgents/com.other.agent.plist", bytes: 10, base: .root)
                env.fileSystem.fail(.readFile, path: env.fixture.path("System/Library-LaunchAgents/com.other.agent.plist", base: .root))
                let output = try await discover(env)
                try TestSuite.assertEqual(output.candidates.count, 0)
                guard case .unavailable = output.status else { throw TestError("expected unavailable, got \(output.status)") }
                try TestSuite.assertEqual(try await block(env, .applicationSupport, identifier)?.condition, .notRunning)
            }
            // An orphaned agent of the vendor (program missing) does not block its data.
            try await M1.withEnv { env in
                try setUp(env)
                try job(env, "Library/LaunchAgents", .home, label: "com.acme.syncd", program: env.fixture.path("gone/syncd", base: .root))
                try TestSuite.assertTrue(try await offered(env).contains(supportRel))
            }
        }

        // MARK: stillOrphaned at execute

        await TestSuite.run("Orphans: stillOrphaned is re-checked at execute — app installed between plan and execute → skipped, untouched") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUp(env)
                let results = try await M5.scanner(env).scan(ruleIDs: ["leftovers.appData"])
                let plan = await ctx.planBuilder().build(from: results)
                let item = try M5.item(plan, supportRel, env.fixture)
                try TestSuite.assertTrue(item.isActionable, "\(item.planVerdict)")
                let confirmed = try M3.confirmAll(plan)
                env.applications.applicationURLs = [identifier: [URL(fileURLWithPath: "/Applications/Widget.app")]]
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                try M3.expectPreconditionSkipped(try M3.status(run.report, item.id), name: "stillOrphaned")
                try TestSuite.assertTrue(M3.exists(env.fixture.path(supportRel + "/data.db")))
                try TestSuite.assertEqual(M3.children(ctx.trash.directory), [])
            }
        }

        await TestSuite.run("Orphans review M6 (E4): stillOrphaned re-checks app groups / Team IDs and Setapp for the target's location") {
            try await M1.withEnv { env in
                try setUp(env)
                let rel = "Library/Group Containers/group.com.vendor.shared"
                try orphanFolder(env, rel)
                try TestSuite.assertTrue(try await offered(env).contains(rel))
                let path = env.fixture.path(rel)
                try TestSuite.assertTrue(await OrphanEvaluator.preconditionOutcome(owningBundleID: "group.com.vendor.shared", targetPath: path,
                                                                                  environment: env.environment).passed)
                // Installed between plan and execute: an app (another vendor id) declaring the group.
                let app = try M6.appBundle(env.fixture, "System/Applications-root/Editor.app", bundleID: "net.editor.app", base: .root)
                env.codeSignatures.setSigningInfo(.init(teamID: "ABCDE12345", appGroups: ["group.com.vendor.shared"]), for: app)
                let outcome = await OrphanEvaluator.preconditionOutcome(owningBundleID: "group.com.vendor.shared", targetPath: path,
                                                                       environment: env.environment)
                try TestSuite.assertFalse(outcome.passed, outcome.detail)
                // A path whose location cannot be derived, or whose name is not the owner, fails closed.
                try TestSuite.assertFalse(await OrphanEvaluator.preconditionOutcome(owningBundleID: identifier, targetPath: "/tmp/x/com.acme.widget",
                                                                                   environment: env.environment).passed)
                try TestSuite.assertFalse(await OrphanEvaluator.preconditionOutcome(owningBundleID: "com.acme.other",
                                                                                   targetPath: env.fixture.path(supportRel),
                                                                                   environment: env.environment).passed)
            }
            // Setapp installed between plan and execute.
            try await M1.withEnv { env in
                try setUp(env)
                let path = env.fixture.path(supportRel)
                try TestSuite.assertTrue(await OrphanEvaluator.preconditionOutcome(owningBundleID: identifier, targetPath: path,
                                                                                  environment: env.environment).passed)
                try M6.appBundle(env.fixture, "System/Applications-root/Setapp/Widget.app", bundleID: "com.acme.widget-setapp", base: .root)
                try TestSuite.assertFalse(await OrphanEvaluator.preconditionOutcome(owningBundleID: identifier, targetPath: path,
                                                                                   environment: env.environment).passed)
            }
        }

        await TestSuite.run("Orphans: stillOrphaned fails closed at execute (pkgutil failure, running process, missing owner)") {
            try await M1.withEnv { env in
                try setUp(env)
                let rule = try M5.rule(env, "leftovers.appData")
                let evaluator = PreconditionEvaluator(environment: env.environment, ageThresholdOverrides: [:],
                                                      waivedSystemRoots: [env.fixture.root])
                func outcome(_ owner: String?) async -> PreconditionResult {
                    await evaluator.evaluate(.stillOrphaned, target: env.scanTarget(ruleID: rule.id, path: supportRel, owningBundleID: owner),
                                             rule: rule)
                }
                try TestSuite.assertTrue(await outcome(identifier).passed)
                try TestSuite.assertFalse(await outcome(nil).passed)
                try TestSuite.assertFalse(await outcome("AcmeWidget").passed)
                try TestSuite.assertFalse(await outcome("com.apple.widget").passed)
                env.processes.names = ["widget"]
                try TestSuite.assertFalse(await outcome(identifier).passed)
                env.processes.names = ["launchd"]
                M6.usePkgutil(env, result: CommandResult(exitCode: 1, stdout: "", stderr: ""))
                try TestSuite.assertFalse(await outcome(identifier).passed)
            }
        }
    }
}
