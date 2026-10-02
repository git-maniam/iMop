import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §6.4 / §6.7 / §6.10 / §13 M6: Advisory rules explain, they never act. Every advisory rule
/// yields only `.advisory` targets, which are never actionable; failures of the read-only probes
/// (tmutil, Spotlight, volume capacities) make the rule unavailable instead of reporting zero.
@MainActor
enum AdvisoryTests {
    static let dockerRaw = "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"
    static let backupRel = "Library/Application Support/MobileSync/Backup/00008110-001A2B3C4D5E6F70"
    static let snapshotListing = """
        Snapshots for disk /:
        com.apple.TimeMachine.2026-09-30-101010.local
        com.apple.TimeMachine.2026-10-01-111111.local
        """

    /// A fixture with something for every advisory rule.
    static func setUp(_ env: FakeEnvironment) throws {
        let f = env.fixture
        let system = "SystemRoot"
        try f.file(dockerRaw, bytes: 20_000)
        try f.file(".orbstack/data/file", bytes: 100)
        try f.file(".colima/default/disk.img", bytes: 5_000)
        try f.file("Movies/Wedding.fcpbundle/Render Files/r.mov", bytes: 1_000)
        env.spotlight.results = ["fcpbundle": [f.path("Movies/Wedding.fcpbundle")]]
        for rel in ["Library/Application Support/GarageBand/Instrument Library/x.caf", "Library/Audio/Apple Loops/Apple/loop.caf",
                    "Library/Caches/com.apple.x/data", "Library/Logs/system.log", "Library/Developer/CoreSimulator/Volumes/r.dmg",
                    "System/Library/AssetsV2/com_apple_MobileAsset/asset.bin"] {
            try f.file(system + "/" + rel, bytes: 3_000, base: .root)
        }
        env.commands.executables["tmutil"] = M6.tmutilPath
        env.commands.setResponse(CommandResult(exitCode: 0, stdout: snapshotListing, stderr: ""), for: ["listlocalsnapshots", "/"])
        env.volumes.capacity = 80_000_000_000
        env.volumes.importantCapacity = 100_000_000_000
        let info: [String: Any] = ["Device Name": "Ravi’s iPhone", "Product Type": "iPhone15,2", "Product Version": "18.0",
                                   "Last Backup Date": Date(timeIntervalSince1970: 1_790_000_000)]
        try f.file(backupRel + "/Info.plist", contents: try M5.plistData(info))
        try f.file(backupRel + "/Manifest.db", bytes: 4_000)
        try f.dir("Library/Mobile Documents/com~apple~CloudDocs")
    }

    static func scan(_ env: FakeEnvironment, _ ids: Set<String> = M6.advisoryRuleIDs, fda: Bool = true) async throws -> [String: RuleScanResult] {
        let scanner = SafeCleanScanner(environment: env.environment, catalog: try M5.catalog(env),
                                       inspectors: try M6.fixtureInspectors(env.fixture), hasFullDiskAccess: fda,
                                       waivedSystemRoots: [env.fixture.root])
        let results = await scanner.scan(ruleIDs: ids)
        return Dictionary(uniqueKeysWithValues: results.map { ($0.rule.id, $0) })
    }

    static func expectUnavailable(_ result: RuleScanResult?, _ context: String) throws {
        guard let result, case .unavailable = result.status else {
            throw TestError("\(context): expected unavailable, got \(String(describing: result?.status))")
        }
        try TestSuite.assertEqual(result.targets.count, 0, context)
    }

    static func runAll() async {
        print("\n💡 Running Advisory Tests (spec §6.4, §6.7, §6.10, §13 M6)...")

        await TestSuite.run("Advisory: every advisory rule yields only .advisory targets (explanation, nothing reclaimable)") {
            try await M1.withEnv { env in
                try setUp(env)
                let results = try await scan(env)
                try TestSuite.assertEqual(Set(results.keys), M6.advisoryRuleIDs)
                for (id, result) in results {
                    try TestSuite.assertEqual(result.status, .ok, id)
                    try TestSuite.assertFalse(result.targets.isEmpty, "\(id) found nothing")
                    for target in result.targets {
                        try TestSuite.assertEqual(target.kind, .advisory, id)
                        try TestSuite.assertEqual(target.reclaimableBytes, 0, id)
                        try TestSuite.assertTrue(target.identity == nil, id)
                        try TestSuite.assertFalse(target.notes.isEmpty, id)
                        try TestSuite.assertFalse(target.displayName.isEmpty, id)
                    }
                    try TestSuite.assertEqual(result.rule.tier, .advisory, id)
                    try TestSuite.assertEqual(result.rule.allowRoots, [], id)
                    guard case .advisory = result.rule.action else { throw TestError("\(id): \(result.rule.action)") }
                }
                let tm = try M5.unwrap(results["advisory.timeMachineSnapshots"]?.targets.first)
                try TestSuite.assertTrue(tm.notes.contains { $0.hasPrefix("2 local snapshots") }, "\(tm.notes)")
                let purgeable = try M5.unwrap(results["advisory.purgeableSpace"]?.targets.first)
                try TestSuite.assertEqual(purgeable.allocatedBytes, 20_000_000_000)
                let docker = try M5.unwrap(results["docker.diskImage"])
                try TestSuite.assertEqual(Set(docker.targets.map(\.displayName)),
                                          ["Docker Desktop disk image", "OrbStack data", "Colima virtual machines"])
                let raw = try M5.unwrap(docker.targets.first { $0.path.hasSuffix("Docker.raw") })
                try TestSuite.assertEqual(raw.allocatedBytes, M2.blocksBytes(env.fixture.path(dockerRaw)), "measured by SizeCalculator")
                // Review M6: the non-destructive route comes first, and the disk-limit / Purge options are
                // only named together with the plain warning that they delete everything.
                let reclaim = try M5.unwrap(raw.notes.firstIndex { $0.contains("without losing data") })
                let destructive = raw.notes.indices.filter { raw.notes[$0].contains("Purge") || raw.notes[$0].contains("size limit") }
                try TestSuite.assertFalse(destructive.isEmpty, "\(raw.notes)")
                for index in destructive {
                    try TestSuite.assertTrue(index > reclaim, "non-destructive advice first: \(raw.notes)")
                    try TestSuite.assertTrue(raw.notes[index].contains("ALL images, containers and volumes"), raw.notes[index])
                }
                let dockerRule = try M6.rule(env, "docker.diskImage")
                try TestSuite.assertTrue(dockerRule.explanation.contains("without losing data")
                                         && dockerRule.explanation.contains("all images, containers and volumes"), dockerRule.explanation)
                try TestSuite.assertEqual(results["audio.soundLibraries"]?.targets.count, 2)
                try TestSuite.assertEqual(results["advisory.rootOwnedLocations"]?.targets.count, 3)
                // Only the allow-listed read-only tmutil invocation ran.
                try TestSuite.assertEqual(env.commands.invocations.map(\.arguments), [["listlocalsnapshots", "/"]])
                try TestSuite.assertEqual(env.commands.purposes, [.readOnly])
                try TestSuite.assertTrue(CommandAllowList.standard.matches(tool: "tmutil", arguments: ["listlocalsnapshots", "/"], purpose: .readOnly))
                try TestSuite.assertFalse(CommandAllowList.standard.matches(tool: "tmutil", arguments: ["deletelocalsnapshots", "/"], purpose: .action))
                try TestSuite.assertFalse(CommandAllowList.standard.matches(tool: "tmutil", arguments: ["thinlocalsnapshots", "/"], purpose: .readOnly))
            }
        }

        await TestSuite.run("Advisory: advisory items are never actionable (PlanBuilder, ConfirmedPlan, SafetyGate)") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUp(env)
                let results = try await scan(env)
                let plan = await ctx.planBuilder().build(from: Array(results.values))
                try TestSuite.assertFalse(plan.items.isEmpty)
                for item in plan.items {
                    try TestSuite.assertFalse(item.isActionable, "\(item.rule.id) \(item.target.path)")
                    try TestSuite.assertFalse(item.selectedByDefault, item.rule.id)
                    guard case .advisory = item.action else { throw TestError("\(item.rule.id): \(item.action)") }
                }
                try TestSuite.assertEqual(plan.actionableItems.count, 0)
                let first = plan.items[0]
                do {
                    _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [first.id],
                                                  confirmation: M3.confirmation(perItem: [first.id], irreversible: true), alwaysQuarantine: false)
                    throw TestError("an advisory item was confirmed")
                } catch let error as ConfirmationError {
                    try TestSuite.assertEqual(error, .notActionable(first.id))
                }
                for item in plan.items {
                    guard case .rejected = await env.makeGate().validate(target: item.target, rule: item.rule, phase: .execute) else {
                        throw TestError("SafetyGate allowed advisory \(item.rule.id)")
                    }
                }
            }
        }

        await TestSuite.run("Advisory: Docker.raw is never actionable, whatever the target kind or rule") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUp(env)
                let rule = try M6.rule(env, "docker.diskImage")
                let fileTarget = env.scanTarget(ruleID: rule.id, path: dockerRaw)
                var plan = await M3.plan(ctx, [(rule, [fileTarget])])
                try TestSuite.assertFalse(plan.items[0].isActionable)
                try TestSuite.assertEqual(plan.items[0].action, .advisory(.openApp))
                // No bundled rule can reach it either: offered to EVERY rule of the catalog, the file
                // is never an actionable item (allow-roots, target shapes, command kinds, deny-list).
                // (A file rule whose allow-root covers ~/Library/Containers cannot load: it intersects
                // the deny-list — see RuleCatalogTests.)
                for other in try M5.catalog(env).rules {
                    plan = await M3.plan(ctx, [(other, [env.scanTarget(ruleID: other.id, path: dockerRaw)])])
                    try TestSuite.assertFalse(plan.items[0].isActionable, "\(other.id): \(plan.items[0].planVerdict)")
                }
                let broad = M2.ruleJSON("test.docker", overrides: ["allowRoots": ["{HOME}/Library/Containers"],
                                                                    "discovery": ["glob": ["{HOME}/Library/Containers/*/Data/vms/0/data/*"]]])
                try TestSuite.assertEqual(RuleCatalog.load(data: try M2.catalogData([broad]), environment: env.environment).rules.count, 0)
                try TestSuite.assertTrue(M3.exists(env.fixture.path(dockerRaw)))
            }
        }

        await TestSuite.run("Advisory: tmutil failing / missing / garbage, Spotlight failing, capacities unreadable → unavailable (never zero)") {
            try await M1.withEnv { env in
                try setUp(env)
                env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: "error"), for: ["listlocalsnapshots", "/"])
                try expectUnavailable(try await scan(env, ["advisory.timeMachineSnapshots"])["advisory.timeMachineSnapshots"], "tmutil exit 1")
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "Failed to mount: permission denied\n", stderr: ""),
                                         for: ["listlocalsnapshots", "/"])
                try expectUnavailable(try await scan(env, ["advisory.timeMachineSnapshots"])["advisory.timeMachineSnapshots"], "garbage")
                env.commands.executables["tmutil"] = nil
                try expectUnavailable(try await scan(env, ["advisory.timeMachineSnapshots"])["advisory.timeMachineSnapshots"], "no tmutil")
                // No snapshots at all is a real answer: nothing to explain.
                env.commands.executables["tmutil"] = M6.tmutilPath
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "Snapshots for disk /:\n", stderr: ""), for: ["listlocalsnapshots", "/"])
                let none = try await scan(env, ["advisory.timeMachineSnapshots"])["advisory.timeMachineSnapshots"]
                try TestSuite.assertEqual(none?.status, .ok)
                try TestSuite.assertEqual(none?.targets.count, 0)

                env.spotlight.failing = true
                try expectUnavailable(try await scan(env, ["finalcut.generated"])["finalcut.generated"], "spotlight")
                env.volumes.capacity = nil
                env.volumes.importantCapacity = nil
                try expectUnavailable(try await scan(env, ["advisory.purgeableSpace"])["advisory.purgeableSpace"], "capacities")
                // Volumes that cannot be listed pause the OrphanDetector (spec §6.9 condition 8).
                env.volumes.volumes = nil
                try OrphanDetectorTests.setUp(env)
                try expectUnavailable(try await scan(env, ["leftovers.appData"])["leftovers.appData"], "volumes")
                // pkgutil failing offers no leftovers at all (fail closed), but the rule still scans.
                env.volumes.volumes = []
                M6.usePkgutil(env, result: CommandResult(exitCode: 1, stdout: "", stderr: ""))
                let leftovers = try await scan(env, ["leftovers.appData"])["leftovers.appData"]
                try TestSuite.assertEqual(leftovers?.targets.count, 0)
            }
        }

        await TestSuite.run("Advisory: Final Cut Pro libraries are never looked inside; Spotlight hints are re-validated") {
            try await M1.withEnv { env in
                try setUp(env)
                env.spotlight.results = ["fcpbundle": [env.fixture.path("Movies/Wedding.fcpbundle"), "relative.fcpbundle",
                                                       env.fixture.path("Movies/../Movies/Wedding.fcpbundle"), env.fixture.path("Movies/Missing.fcpbundle")]]
                let result = try await scan(env, ["finalcut.generated"])["finalcut.generated"]
                try TestSuite.assertEqual(result?.targets.map(\.displayName), ["Wedding"])
                try TestSuite.assertTrue(result?.targets.first?.notes.contains { $0.contains("Delete Generated Library Files") } == true)
                let insideCalls = env.fileSystem.recordedCalls.filter { $0.1.contains("Wedding.fcpbundle/") }
                try TestSuite.assertTrue(insideCalls.isEmpty, "\(insideCalls.map(\.1))")
            }
        }

        await TestSuite.run("Advisory: iOS backups are read only (device, date, size; Manage in Finder); FDA required") {
            try await M1.withEnv { env in
                try setUp(env)
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
                _ = try M6.fixtureInspectors(env.fixture) // creates its fixture folders before the snapshot
                let before = snapshot()
                let result = try M5.unwrap(try await scan(env, ["advisory.iosBackups"])["advisory.iosBackups"])
                try TestSuite.assertEqual(snapshot(), before)
                try TestSuite.assertEqual(result.targets.count, 1)
                let backup = result.targets[0]
                try TestSuite.assertEqual(backup.displayName, "Backup of Ravi’s iPhone")
                try TestSuite.assertTrue(backup.notes.contains("Device: Ravi’s iPhone."), "\(backup.notes)")
                try TestSuite.assertTrue(backup.notes.contains { $0.hasPrefix("Last backed up") }, "\(backup.notes)")
                try TestSuite.assertTrue(backup.notes.contains { $0.contains("Manage Backups") }, "\(backup.notes)")
                try TestSuite.assertTrue(backup.allocatedBytes > 0)
                try TestSuite.assertEqual(result.rule.action, .advisory(.revealInFinder))
                try TestSuite.assertTrue(result.rule.requiresFullDiskAccess)
                let locked = try await scan(env, ["advisory.iosBackups"], fda: false)["advisory.iosBackups"]
                try TestSuite.assertEqual(locked?.status, .lockedNeedsFullDiskAccess)
                // A refused listing (FDA revoked mid-session) locks too.
                let backups = "Library/Application Support/MobileSync/Backup"
                env.fileSystem.fail(.contentsOfDirectory, path: env.fixture.path(backups))
                env.fileSystem.fail(.contentsOfDirectory, path: env.environment.homePath + "/" + backups)
                let refused = try await scan(env, ["advisory.iosBackups"])["advisory.iosBackups"]
                try TestSuite.assertEqual(refused?.status, .lockedNeedsFullDiskAccess)
            }
        }

        await TestSuite.run("Advisory: the advisory inspector refuses non-advisory rules and unknown ids") {
            try await M1.withEnv { env in
                try setUp(env)
                let inspector = AdvisoryInspector(systemRoot: M6.systemRoot(env.fixture))
                let actionable = try M6.rule(env, "downloads.archives")
                let output = await inspector.discover(rule: actionable, environment: env.environment)
                try TestSuite.assertEqual(output.candidates.count, 0)
                let unknown = Rule(id: "advisory.unknown", category: .system, tier: .advisory, title: "Unknown advisory",
                                   explanation: "test", whatYouLose: "nothing", howItRegenerates: "n/a",
                                   discovery: .inspector(.advisory), allowRoots: [], minDepthBelowRoot: 1,
                                   action: .advisory(.instructions))
                try TestSuite.assertEqual(await inspector.discover(rule: unknown, environment: env.environment).candidates.count, 0)
                try TestSuite.assertEqual(Set(AdvisoryInspector.ruleIDs), M6.advisoryRuleIDs)
                try TestSuite.assertEqual(AdvisoryInspector.storageSettingsDeepLink, "x-apple.systempreferences:com.apple.settings.Storage")
            }
        }
    }
}
