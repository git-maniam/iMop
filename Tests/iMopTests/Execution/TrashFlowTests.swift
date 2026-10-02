import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Test-only `TrashMoving` that records every call (path + expected identity) and then moves the item
/// into the fixture Trash folder. Never the real Trash.
final class RecordingTrash: TrashMoving, @unchecked Sendable {
    struct Call: Sendable, Equatable {
        let path: String
        let expectedIdentity: FileIdentity?
    }

    private let inner: FixtureTrash
    private let lock = NSLock()
    private var _calls: [Call] = []
    /// When set, every call throws this error instead of moving anything.
    private let failure: (any Error & Sendable)?

    init(inner: FixtureTrash, failure: (any Error & Sendable)? = nil) {
        self.inner = inner
        self.failure = failure
    }

    var calls: [Call] { lock.lock(); defer { lock.unlock() }; return _calls }

    func moveToTrash(path: String) throws -> String {
        lock.lock(); _calls.append(Call(path: path, expectedIdentity: nil)); lock.unlock()
        throw TestError("RecordingTrash: the identity-less variant must never be used (\(path))")
    }

    func moveToTrash(path: String, expectedIdentity: FileIdentity) throws -> String {
        lock.lock(); _calls.append(Call(path: path, expectedIdentity: expectedIdentity)); lock.unlock()
        if let failure { throw failure }
        return try inner.moveToTrash(path: path, expectedIdentity: expectedIdentity)
    }
}

/// Spec §6.1 / §6.3 / §6.6 / §8 / §13 M6: the Trash-action rules (xcode.extraInstalls,
/// installers.macOS, jetbrains.config.orphanedVersion, downloads.*, trash.empty, system.coreDumps).
@MainActor
enum TrashFlowTests {
    static let xcodeBundleID = "com.apple.dt.Xcode"
    static let selectedXcodeRel = "Applications/Xcode.app"
    static let extraXcodeRel = "Applications/Xcode-beta.app"
    static let jetbrainsRel = "Library/Application Support/JetBrains/IntelliJIdea2023.1"
    static let archiveRel = "Downloads/old-project.zip"
    static let diskImageRel = "Downloads/OldInstaller.dmg"

    // MARK: Fixture

    /// Two copies of Xcode in `{HOME}/Applications`; `xcode-select -p` names the first.
    static func setUpXcode(_ env: FakeEnvironment, selected: Bool = true) throws {
        let f = env.fixture
        try M6.appBundle(f, selectedXcodeRel, bundleID: xcodeBundleID, version: "16.0")
        try f.dir(selectedXcodeRel + "/Contents/Developer")
        try M6.appBundle(f, extraXcodeRel, bundleID: xcodeBundleID, version: "16.1")
        env.commands.executables["xcode-select"] = "/usr/bin/xcode-select"
        env.commands.setResponse(CommandResult(exitCode: 0, stdout: f.path(selectedXcodeRel) + "/Contents/Developer\n", stderr: ""),
                                 for: ["-p"])
        env.codeSignatures.set(true, for: f.path(extraXcodeRel))
        env.codeSignatures.set(true, for: f.path(selectedXcodeRel))
    }

    /// IntelliJ IDEA 2024.1 installed; settings of 2023.1 left behind.
    static func setUpJetBrains(_ env: FakeEnvironment) throws {
        let f = env.fixture
        try f.file(jetbrainsRel + "/options/keymap.xml", bytes: 300)
        let idea = try M6.appBundle(f, "Apps/IntelliJ IDEA.app", bundleID: "com.jetbrains.intellij", version: "2024.1.4", base: .root)
        env.applications.applicationURLs = ["com.jetbrains.intellij": [URL(fileURLWithPath: idea)]]
    }

    /// `hdiutil info -plist` answering `images` (paths of mounted disk images).
    static func useHdiutil(_ env: FakeEnvironment, mounted: [String] = [], result: CommandResult? = nil) throws {
        env.commands.executables["hdiutil"] = "/usr/bin/hdiutil"
        let plist = String(decoding: try M5.plistData(["images": mounted.map { ["image-path": $0] }]), as: UTF8.self)
        env.commands.setResponse(result ?? CommandResult(exitCode: 0, stdout: plist, stderr: ""), for: ["info", "-plist"])
    }

    static func setUpDownloads(_ env: FakeEnvironment) throws {
        let f = env.fixture
        try f.file(archiveRel, bytes: 4_000)
        try f.file(diskImageRel, bytes: 8_000)
        try f.file("Downloads/fresh.zip", bytes: 100)
        try f.file("Downloads/notes.txt", bytes: 100)
        try f.setModificationDate(archiveRel, daysAgo: 40, clock: env.clock)
        try f.setModificationDate(diskImageRel, daysAgo: 40, clock: env.clock)
        try f.setModificationDate("Downloads/notes.txt", daysAgo: 40, clock: env.clock)
        try useHdiutil(env)
    }

    static func scanAndPlan(_ ctx: M3.Context, _ ids: Set<String>, settings: PlanSettings = PlanSettings()) async throws -> ([RuleScanResult], CleanupPlan) {
        let results = try await M5.scanner(ctx.env).scan(ruleIDs: ids)
        return (results, await ctx.planBuilder(settings: settings).build(from: results))
    }

    static func expectConfirmationError(_ expected: ConfirmationError, _ body: () throws -> ConfirmedPlan,
                                        file: StaticString = #file, line: UInt = #line) throws {
        do {
            _ = try body()
            throw TestError("expected \(expected) (\(file):\(line))")
        } catch let error as ConfirmationError {
            try TestSuite.assertEqual(error, expected, file: file, line: line)
        }
    }

    static func runAll() async {
        print("\n🗑️  Running Trash Flow Tests (spec §6.1, §6.3, §6.6, §8, §13 M6)...")

        await TestSuite.run("TrashFlows: Red Trash items (leftovers, downloads.archives, xcode.extraInstalls, jetbrains.config) need per-item confirmation") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try OrphanDetectorTests.setUp(env)
                try setUpXcode(env)
                try setUpJetBrains(env)
                try setUpDownloads(env)
                let (_, plan) = try await scanAndPlan(ctx, ["leftovers.appData", "downloads.archives", "xcode.extraInstalls",
                                                           "jetbrains.config.orphanedVersion"])
                let rels = [OrphanDetectorTests.supportRel, archiveRel, extraXcodeRel, jetbrainsRel]
                try TestSuite.assertEqual(Set(plan.actionableItems.map { OrphanDetectorTests.relative($0.target.path, env) }), Set(rels))
                // A recent download is listed but blocked (olderThan(30)).
                try TestSuite.assertEqual(M5.failedPrecondition(try M5.item(plan, "Downloads/fresh.zip", env.fixture)), "olderThan")
                for rel in rels {
                    let item = try M5.item(plan, rel, env.fixture)
                    try TestSuite.assertTrue(item.isActionable, "\(rel): \(item.planVerdict)")
                    try TestSuite.assertEqual(item.effectiveTier, .red, rel)
                    try TestSuite.assertEqual(item.action, .trash, rel)
                    try TestSuite.assertTrue(item.requiresPerItemConfirmation, rel)
                    try TestSuite.assertFalse(item.selectedByDefault, rel)
                    try expectConfirmationError(.missingPerItemConfirmation(item.id)) {
                        try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id], confirmation: M3.confirmation(),
                                                  alwaysQuarantine: true)
                    }
                    // Confirming a DIFFERENT item does not count.
                    let other = try M5.item(plan, rels.first { $0 != rel }!, env.fixture)
                    try expectConfirmationError(.missingPerItemConfirmation(item.id)) {
                        try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id, other.id],
                                                  confirmation: M3.confirmation(perItem: [other.id]), alwaysQuarantine: true)
                    }
                    _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id], confirmation: M3.confirmation(perItem: [item.id]),
                                                  alwaysQuarantine: true)
                }
                let jetbrains = try M5.item(plan, jetbrainsRel, env.fixture)
                try TestSuite.assertTrue(jetbrains.target.notes.contains { $0.contains("IDE settings") }, "\(jetbrains.target.notes)")
                try TestSuite.assertTrue(jetbrains.rule.whatYouLose.lowercased().contains("settings"), jetbrains.rule.whatYouLose)
            }
        }

        await TestSuite.run("TrashFlows: Yellow Trash items (downloads.diskImages, installers.macOS) are actionable but never preselected") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUpDownloads(env)
                let (_, plan) = try await scanAndPlan(ctx, ["downloads.diskImages"])
                try TestSuite.assertEqual(plan.items.map { OrphanDetectorTests.relative($0.target.path, env) }, [diskImageRel])
                let item = plan.items[0]
                try TestSuite.assertTrue(item.isActionable, "\(item.planVerdict)")
                try TestSuite.assertEqual(item.effectiveTier, .yellow)
                try TestSuite.assertFalse(item.selectedByDefault)
                try TestSuite.assertFalse(item.requiresPerItemConfirmation)

                // installers.macOS: only Apple's installers, found in the (fixture) Applications folder.
                let apps = M6.applicationsDirectory(env.fixture)
                try M6.appBundle(env.fixture, "System/Applications-root/Install macOS Sequoia.app",
                                 bundleID: "com.apple.InstallAssistant.Sequoia", version: "15.0", base: .root)
                try M6.appBundle(env.fixture, "System/Applications-root/Install macOS Fake.app", bundleID: "com.evil.installer", base: .root)
                try env.fixture.dir("System/Applications-root/Install macOS Broken.app/Contents", base: .root)
                try M6.appBundle(env.fixture, "System/Applications-root/Other.app", bundleID: "com.apple.InstallAssistant.X", base: .root)
                let output = try await M5.discover(MacOSInstallersInspector(applicationsDirectory: apps), env, "installers.macOS")
                try TestSuite.assertEqual(output.status, .ok)
                try TestSuite.assertEqual(output.candidates.map { ($0.path as NSString).lastPathComponent }, ["Install macOS Sequoia.app"])
                try TestSuite.assertEqual(output.candidates[0].owningBundleID, "com.apple.InstallAssistant.Sequoia")
                let rule = try M6.rule(env, "installers.macOS")
                try TestSuite.assertEqual(rule.tier, .yellow)
                try TestSuite.assertEqual(rule.action, .trash)
                try TestSuite.assertTrue(rule.preconditions.contains(.appleSigned))
                let target = env.scanTarget(ruleID: rule.id, path: output.candidates[0].path,
                                            owningBundleID: "com.apple.InstallAssistant.Sequoia")
                let planned = PlanItem.makeForTesting(target: target, rule: rule, effectiveTier: rule.tier, action: .trash, planVerdict: .allowed)
                try TestSuite.assertFalse(planned.selectedByDefault)
                try TestSuite.assertFalse(planned.requiresPerItemConfirmation)
            }
        }

        await TestSuite.run("TrashFlows: the selected Xcode is never offered; xcode-select failure or Command Line Tools → nothing") {
            try await M1.withEnv { env in
                try setUpXcode(env)
                var results = try await M5.scan(env, ["xcode.extraInstalls"])
                try TestSuite.assertEqual(M5.paths(results["xcode.extraInstalls"], env.fixture), [extraXcodeRel])
                let extra = try M5.unwrap(results["xcode.extraInstalls"]?.targets.first)
                try TestSuite.assertEqual(extra.owningBundleID, xcodeBundleID)
                try TestSuite.assertTrue(extra.notes.contains { $0.contains("App Management") }, "\(extra.notes)")

                // Selecting the other copy flips which one is offered.
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: env.fixture.path(extraXcodeRel) + "/Contents/Developer\n", stderr: ""),
                                         for: ["-p"])
                try env.fixture.dir(extraXcodeRel + "/Contents/Developer")
                results = try await M5.scan(env, ["xcode.extraInstalls"])
                try TestSuite.assertEqual(M5.paths(results["xcode.extraInstalls"], env.fixture), [selectedXcodeRel])

                for failing in [CommandResult(exitCode: 2, stdout: "", stderr: "error"),
                                CommandResult(exitCode: 0, stdout: "/Library/Developer/CommandLineTools\n", stderr: ""),
                                CommandResult(exitCode: 0, stdout: "relative/path\n", stderr: ""),
                                CommandResult(exitCode: 0, stdout: "/a\n/b\n", stderr: "")] {
                    env.commands.setResponse(failing, for: ["-p"])
                    results = try await M5.scan(env, ["xcode.extraInstalls"])
                    guard case .unavailable = results["xcode.extraInstalls"]?.status else {
                        throw TestError("\(failing.stdout): \(String(describing: results["xcode.extraInstalls"]?.status))")
                    }
                    try TestSuite.assertEqual(results["xcode.extraInstalls"]?.targets.count, 0)
                }
                env.commands.executables["xcode-select"] = nil
                results = try await M5.scan(env, ["xcode.extraInstalls"])
                try TestSuite.assertEqual(results["xcode.extraInstalls"]?.targets.count, 0)
            }
        }

        await TestSuite.run("TrashFlows: notSelectedXcode and appleSigned are re-checked by the gate (hand-built targets are refused)") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUpXcode(env)
                let rule = try M6.rule(env, "xcode.extraInstalls")
                let selected = env.scanTarget(ruleID: rule.id, path: selectedXcodeRel, owningBundleID: xcodeBundleID)
                var plan = await M3.plan(ctx, [(rule, [selected])])
                try TestSuite.assertEqual(M5.failedPrecondition(plan.items[0]), "notSelectedXcode", "\(plan.items[0].planVerdict)")

                for verdict in [false, nil] as [Bool?] {
                    env.codeSignatures.set(verdict, for: env.fixture.path(extraXcodeRel))
                    let extra = env.scanTarget(ruleID: rule.id, path: extraXcodeRel, owningBundleID: xcodeBundleID)
                    plan = await M3.plan(ctx, [(rule, [extra])])
                    try TestSuite.assertFalse(plan.items[0].isActionable)
                    try TestSuite.assertEqual(M5.failedPrecondition(plan.items[0]), "appleSigned", "\(String(describing: verdict))")
                }
                // Running Xcode blocks too.
                env.codeSignatures.set(true, for: env.fixture.path(extraXcodeRel))
                env.runningApplications.ids = [xcodeBundleID]
                plan = await M3.plan(ctx, [(rule, [env.scanTarget(ruleID: rule.id, path: extraXcodeRel, owningBundleID: xcodeBundleID)])])
                try TestSuite.assertEqual(M5.failedPrecondition(plan.items[0]), "appNotRunning")
            }
        }

        await TestSuite.run("TrashFlows review M6: xcode.extraInstalls / installers.macOS only ever move a bundle whose Info.plist says Xcode / an Apple installer") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUpXcode(env)
                let rule = try M6.rule(env, "xcode.extraInstalls")
                // An Apple-signed app of another kind (Keynote) — neither without an owner nor with Xcode's.
                try M6.appBundle(env.fixture, "Applications/Keynote.app", bundleID: "com.apple.iWork.Keynote")
                env.codeSignatures.set(true, for: env.fixture.path("Applications/Keynote.app"))
                for owner in [nil, xcodeBundleID, "com.apple.iWork.Keynote"] as [String?] {
                    let plan = await M3.plan(ctx, [(rule, [env.scanTarget(ruleID: rule.id, path: "Applications/Keynote.app", owningBundleID: owner)])])
                    try TestSuite.assertFalse(plan.items[0].isActionable, "\(owner ?? "nil"): \(plan.items[0].planVerdict)")
                }
                // The genuine extra Xcode still passes; without its owner it does not.
                var plan = await M3.plan(ctx, [(rule, [env.scanTarget(ruleID: rule.id, path: extraXcodeRel, owningBundleID: xcodeBundleID)])])
                try TestSuite.assertTrue(plan.items[0].isActionable, "\(plan.items[0].planVerdict)")
                plan = await M3.plan(ctx, [(rule, [env.scanTarget(ruleID: rule.id, path: extraXcodeRel, owningBundleID: nil)])])
                try TestSuite.assertFalse(plan.items[0].isActionable)
                // Info.plist rewritten to another app between plan and execute → skipped, untouched.
                plan = await M3.plan(ctx, [(rule, [env.scanTarget(ruleID: rule.id, path: extraXcodeRel, owningBundleID: xcodeBundleID)])])
                let confirmed = try M3.confirmAll(plan)
                try env.fixture.file(extraXcodeRel + "/Contents/Info.plist",
                                     contents: try M5.plistData(["CFBundleIdentifier": "com.apple.iWork.Keynote"]))
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .skipped = try M3.status(run.report, plan.items[0].id) else {
                    throw TestError("\(try M3.status(run.report, plan.items[0].id))")
                }
                try TestSuite.assertTrue(M3.exists(env.fixture.path(extraXcodeRel)))
            }
            // installers.macOS: owner required and re-read.
            try await M1.withEnv { env in
                let problem = { (owner: String?, id: String) throws -> String? in
                    let app = try M6.appBundle(env.fixture, "Install macOS Test.app", bundleID: id, base: .root)
                    return SafetyGate.appBundleIdentityProblem(app, inspector: .macOSInstallers, owner: owner, fileSystem: env.fileSystem)
                }
                try TestSuite.assertEqual(try problem("com.apple.InstallAssistant.macOSSequoia", "com.apple.InstallAssistant.macOSSequoia"), nil)
                try TestSuite.assertTrue(try problem(nil, "com.apple.InstallAssistant.macOSSequoia") != nil)
                try TestSuite.assertTrue(try problem("com.apple.iWork.Keynote", "com.apple.iWork.Keynote") != nil)
                try TestSuite.assertTrue(try problem("com.apple.InstallAssistant.macOSSequoia", "com.apple.InstallAssistant.other") != nil)
            }
        }

        await TestSuite.run("TrashFlows: a mounted disk image (or an unreadable hdiutil answer) is blocked by notMounted") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUpDownloads(env)
                try useHdiutil(env, mounted: [env.fixture.path(diskImageRel)])
                var (_, plan) = try await scanAndPlan(ctx, ["downloads.diskImages", "downloads.archives"])
                try TestSuite.assertEqual(M5.failedPrecondition(try M5.item(plan, diskImageRel, env.fixture)), "notMounted")
                try TestSuite.assertTrue(try M5.item(plan, archiveRel, env.fixture).isActionable)
                try useHdiutil(env, result: CommandResult(exitCode: 1, stdout: "", stderr: "hdiutil: info failed"))
                (_, plan) = try await scanAndPlan(ctx, ["downloads.diskImages"])
                try TestSuite.assertEqual(M5.failedPrecondition(try M5.item(plan, diskImageRel, env.fixture)), "notMounted")
                // Only disk images / installer packages belong to this rule.
                try TestSuite.assertFalse(plan.items.contains { $0.target.path.hasSuffix(".zip") || $0.target.path.hasSuffix(".txt") })
            }
        }

        await TestSuite.run("TrashFlows: trash.empty — blocked while Always quarantine is ON; needs the acknowledgement when OFF") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try env.fixture.file(".Trash/old-report.pdf", bytes: 3_000)
                try env.fixture.file(".Trash/Old Folder/inner.txt", bytes: 3_000)
                var (results, plan) = try await scanAndPlan(ctx, ["trash.empty"])
                try TestSuite.assertEqual(M5.paths(results.first, env.fixture), [".Trash/old-report.pdf", ".Trash/Old Folder"])
                try TestSuite.assertTrue(results.first?.targets.allSatisfy { $0.notes.contains { $0.hasPrefix("Part of Empty Trash: 2 items") } } == true,
                                         "\(results.first?.targets.first?.notes ?? [])")
                for item in plan.items {
                    try TestSuite.assertEqual(item.planVerdict, .rejected(PlanBuilder.alwaysQuarantineRejection))
                    try TestSuite.assertEqual(item.action, .permanentDelete)
                }
                // Review M6: the persisted setting (ON by default) wins over caller flags that are OFF.
                try TestSuite.assertTrue(env.scanSettings.alwaysQuarantine)
                (results, plan) = try await scanAndPlan(ctx, ["trash.empty"], settings: PlanSettings(alwaysQuarantine: false))
                for item in plan.items {
                    try TestSuite.assertEqual(item.planVerdict, .rejected(PlanBuilder.alwaysQuarantineRejection), "env setting ON")
                }
                var settingOff = env.scanSettings
                settingOff.alwaysQuarantine = false
                env.scanSettings = settingOff
                (results, plan) = try await scanAndPlan(ctx, ["trash.empty"], settings: PlanSettings(alwaysQuarantine: false))
                let ids = Set(plan.items.map(\.id))
                try TestSuite.assertTrue(plan.items.allSatisfy(\.isActionable), "\(plan.items.map(\.planVerdict))")
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.selectedByDefault && !$0.isRestorable })
                try expectConfirmationError(.permanentDeleteBlockedByAlwaysQuarantine(plan.items[0].id)) {
                    try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [plan.items[0].id], confirmation: M3.confirmation(irreversible: true),
                                              alwaysQuarantine: true)
                }
                try expectConfirmationError(.irreversibleNotAcknowledged) {
                    try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: ids, confirmation: M3.confirmation(), alwaysQuarantine: false)
                }
                let confirmed = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: ids, confirmation: M3.confirmation(irreversible: true),
                                                          alwaysQuarantine: false)
                let trash = RecordingTrash(inner: ctx.trash)
                let run = try await M3.run(ctx.executor(trash: trash), confirmed)
                for item in plan.items {
                    try TestSuite.assertEqual(try M3.status(run.report, item.id), .permanentlyRemoved, item.target.path)
                }
                try TestSuite.assertEqual(M3.children(env.fixture.path(".Trash")), [])
                try TestSuite.assertEqual(trash.calls, [], "Empty Trash never moves anything to the Trash")
            }
        }

        await TestSuite.run("TrashFlows (review M6): Always quarantine switched ON after confirmation → the Executor deletes nothing") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try env.fixture.file(".Trash/old-report.pdf", bytes: 3_000)
                var off = env.scanSettings
                off.alwaysQuarantine = false
                env.scanSettings = off
                let (_, plan) = try await scanAndPlan(ctx, ["trash.empty"], settings: PlanSettings(alwaysQuarantine: false))
                try TestSuite.assertFalse(plan.items.isEmpty)
                try TestSuite.assertTrue(plan.items.allSatisfy(\.isActionable), "\(plan.items.map(\.planVerdict))")
                let confirmed = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: Set(plan.items.map(\.id)),
                                                          confirmation: M3.confirmation(irreversible: true), alwaysQuarantine: false)
                var on = env.scanSettings
                on.alwaysQuarantine = true
                env.scanSettings = on
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                for item in plan.items {
                    try TestSuite.assertEqual(try M3.status(run.report, item.id), .skipped(PlanBuilder.alwaysQuarantineRejection), item.target.path)
                }
                try TestSuite.assertTrue(M3.exists(env.fixture.path(".Trash/old-report.pdf")))
            }
        }

        await TestSuite.run("TrashFlows: system.coreDumps — permanent delete allow-listed, blocked while Always quarantine is ON, acknowledgement when OFF") {
            try await M1.withEnv { env in
                let rule = try M6.rule(env, "system.coreDumps")
                try TestSuite.assertTrue(RuleCatalog.permanentDeleteAllowList.contains(rule.id))
                try TestSuite.assertEqual(RuleCatalog.permanentDeleteAllowList, ["trash.empty", "system.coreDumps"])
                try TestSuite.assertEqual(rule.action, .permanentDelete)
                try TestSuite.assertEqual(rule.tier, .yellow)
                try TestSuite.assertTrue(rule.preconditions.contains(.ownedByUser))
                try TestSuite.assertTrue(rule.preconditions.contains(.olderThan(days: 1)))
                try env.fixture.file("Library/Caches/core.1234", bytes: 100)
                let target = env.scanTarget(ruleID: rule.id, path: "Library/Caches/core.1234")
                let item = PlanItem.makeForTesting(target: target, rule: rule, effectiveTier: .yellow, action: .permanentDelete,
                                                   planVerdict: .allowed)
                let plan = CleanupPlan.makeForTesting(createdAt: M3.reviewStart, items: [item], alwaysQuarantine: false)
                try expectConfirmationError(.permanentDeleteBlockedByAlwaysQuarantine(item.id)) {
                    try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id], confirmation: M3.confirmation(irreversible: true),
                                              alwaysQuarantine: true)
                }
                let onPlan = CleanupPlan.makeForTesting(createdAt: M3.reviewStart, items: [item], alwaysQuarantine: true)
                try expectConfirmationError(.permanentDeleteBlockedByAlwaysQuarantine(item.id)) {
                    try ConfirmedPlan.confirm(plan: onPlan, selectedItemIDs: [item.id], confirmation: M3.confirmation(irreversible: true),
                                              alwaysQuarantine: false)
                }
                try expectConfirmationError(.irreversibleNotAcknowledged) {
                    try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id], confirmation: M3.confirmation(), alwaysQuarantine: false)
                }
                _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id], confirmation: M3.confirmation(irreversible: true),
                                              alwaysQuarantine: false)
                // The gate never lets the rule act outside /cores (the fixture target is refused).
                let built = await PlanBuilder(environment: env.environment, gate: env.makeGate(),
                                              settings: PlanSettings(alwaysQuarantine: false)).build(from: [RuleScanResult(rule: rule, targets: [target], status: .ok)])
                try TestSuite.assertFalse(built.items[0].isActionable)
            }
        }

        await TestSuite.run("TrashFlows: EPERM / EACCES from trashing an .app bundle maps to the App Management message") {
            for code in [POSIXErrorCode.EPERM, .EACCES] {
                try await M3.withContext { ctx in
                    let env = ctx.env
                    try setUpXcode(env)
                    let (_, plan) = try await scanAndPlan(ctx, ["xcode.extraInstalls"])
                    let item = try M5.item(plan, extraXcodeRel, env.fixture)
                    let confirmed = try M3.confirmAll(plan)
                    let trash = RecordingTrash(inner: ctx.trash, failure: POSIXError(code))
                    let run = try await M3.run(ctx.executor(remover: RefusingRemover(), trash: trash), confirmed)
                    guard case .failed(.permissionDenied, let message) = try M3.status(run.report, item.id) else {
                        throw TestError("\(code): \(try M3.status(run.report, item.id))")
                    }
                    try TestSuite.assertEqual(message, Executor.appManagementPermissionMessage)
                    try TestSuite.assertEqual(message, AppManagementProbe.permissionNeededMessage)
                    try TestSuite.assertTrue(message.contains("App Management"))
                    try TestSuite.assertTrue(M3.exists(env.fixture.path(extraXcodeRel)))
                }
            }
            // A non-app item keeps the ordinary permission message.
            try await M3.withContext { ctx in
                let env = ctx.env
                try setUpDownloads(env)
                let (_, plan) = try await scanAndPlan(ctx, ["downloads.archives"])
                let confirmed = try M3.confirmAll(plan)
                let run = try await M3.run(ctx.executor(trash: RecordingTrash(inner: ctx.trash, failure: POSIXError(.EPERM))), confirmed)
                guard case .failed(.permissionDenied, let message) = run.report.outcomes[0].status else {
                    throw TestError("\(run.report.outcomes[0].status)")
                }
                try TestSuite.assertFalse(message.contains("App Management"), message)
            }
            try TestSuite.assertEqual(AppManagementProbe.failureMessage(movingToTrash: "/Applications/Xcode-beta.app", errno: EPERM),
                                      AppManagementProbe.permissionNeededMessage)
            try TestSuite.assertEqual(AppManagementProbe.failureMessage(movingToTrash: "/Applications/Xcode-beta.app", errno: ENOENT), nil)
            try TestSuite.assertEqual(AppManagementProbe.failureMessage(movingToTrash: "/Users/x/Downloads/a.zip", errno: EPERM), nil)
            try TestSuite.assertEqual(AppManagementProbe.appBundleRuleIDs, ["xcode.extraInstalls", "installers.macOS"])
        }

        await TestSuite.run("TrashFlows: every Trash action goes through the injected TrashMoving with the pinned identity (never the real Trash)") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try OrphanDetectorTests.setUp(env)
                try setUpXcode(env)
                try setUpJetBrains(env)
                try setUpDownloads(env)
                let (_, plan) = try await scanAndPlan(ctx, ["leftovers.appData", "downloads.archives", "downloads.diskImages",
                                                           "xcode.extraInstalls", "jetbrains.config.orphanedVersion"])
                try TestSuite.assertEqual(plan.actionableItems.count, 5, "\(plan.items.map { ($0.target.path, $0.planVerdict) })")
                let confirmed = try M3.confirmAll(plan)
                let trash = RecordingTrash(inner: ctx.trash)
                let run = try await M3.run(ctx.executor(remover: RefusingRemover(), trash: trash), confirmed)
                for item in plan.actionableItems {
                    guard case .trashed(let result) = try M3.status(run.report, item.id) else {
                        throw TestError("\(item.target.path): \(try M3.status(run.report, item.id))")
                    }
                    try TestSuite.assertTrue(result.hasPrefix(ctx.trash.directory + "/"), result)
                    try TestSuite.assertFalse(M3.exists(item.target.path), item.target.path)
                }
                try TestSuite.assertEqual(Set(trash.calls.map(\.path)), Set(plan.actionableItems.map(\.target.path)))
                for call in trash.calls {
                    let item = try M5.unwrap(plan.actionableItems.first { $0.target.path == call.path })
                    try TestSuite.assertTrue(call.expectedIdentity != nil, call.path)
                    try TestSuite.assertEqual(call.expectedIdentity, item.target.identity, call.path)
                }
                try TestSuite.assertEqual(M3.children(ctx.trash.directory).count, 5)
            }
        }
    }
}
