import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Milestone 7: `AppState`, the state the SwiftUI app drives (spec §3.2, §5, §8, §9, §13 M7).
///
/// Every test runs against a `FixtureBuilder` home with `FakeEnvironment`, an in-memory
/// `SettingsStore` (the real preferences are never read or written) and recorded system actions
/// (nothing is opened). AppState always uses `MutationPolicy.compiledIn`, so in this debug build a
/// confirmed cleanup is reported as `mutationDisabled` and the fixture stays untouched.
@MainActor
enum AppStateTests {
    // MARK: Fixture

    struct FixedFDA: FullDiskAccessProbing {
        let state: PermissionState
        func fullDiskAccessState() -> PermissionState { state }
    }

    final class RecordingActions: AppStateSystemActions, @unchecked Sendable {
        private let lock = NSLock()
        private var _opened: [URL] = []
        private var _revealed: [String] = []
        private var _apps: [String] = []

        var opened: [URL] { lock.lock(); defer { lock.unlock() }; return _opened }
        var revealed: [String] { lock.lock(); defer { lock.unlock() }; return _revealed }
        var apps: [String] { lock.lock(); defer { lock.unlock() }; return _apps }

        func open(url: URL) { lock.lock(); _opened.append(url); lock.unlock() }
        func revealInFinder(path: String) { lock.lock(); _revealed.append(path); lock.unlock() }
        func openApp(bundleID: String) -> Bool { lock.lock(); _apps.append(bundleID); lock.unlock(); return false }
    }

    /// Relative fixture paths of the items each test rule finds.
    static let greenRel = "Library/Caches/com.example.media.green/item"
    static let yellowRel = "Library/Caches/com.example.media.yellow/item"
    static let redRel = "Library/Caches/com.example.media.red/item"
    static let appsGreenRel = "Library/Caches/com.example.apps.green/item"

    /// Test catalog: Green / Yellow / Red glob rules in Media, a Green rule in Apps and the bundled
    /// `homebrew.cleanup` command rule (Green, irreversible).
    static func catalog(_ env: FakeEnvironment, includeBrew: Bool, bundledRuleIDs: [String] = []) throws -> RuleCatalog {
        var rules: [[String: Any]] = [
            M2.ruleJSON("media.green", overrides: ["category": "media"]),
            M2.ruleJSON("media.yellow", overrides: ["category": "media", "tier": "yellow"]),
            M2.ruleJSON("media.red", overrides: ["category": "media", "tier": "red", "action": "trash"]),
            M2.ruleJSON("apps.green", overrides: ["category": "apps"]),
        ]
        if includeBrew {
            let source = try JSONSerialization.jsonObject(with: try M2.sourceRulesData()) as? [String: Any]
            guard let all = source?["rules"] as? [[String: Any]],
                  let brew = all.first(where: { $0["id"] as? String == "homebrew.cleanup" }) else {
                throw TestError("homebrew.cleanup not found in Rules.json")
            }
            rules.append(brew)
        }
        if !bundledRuleIDs.isEmpty {
            let source = try JSONSerialization.jsonObject(with: try M2.sourceRulesData()) as? [String: Any]
            let all = source?["rules"] as? [[String: Any]] ?? []
            for id in bundledRuleIDs {
                guard let rule = all.first(where: { $0["id"] as? String == id }) else { throw TestError("\(id) not in Rules.json") }
                rules.append(rule)
            }
        }
        let catalog = RuleCatalog.load(data: try M2.catalogData(rules), environment: env.environment)
        try TestSuite.assertEqual(catalog.disabled, [], "test catalog must load cleanly")
        return catalog
    }

    static func makeFixtureItems(_ env: FakeEnvironment, includeBrew: Bool) throws {
        for rel in [greenRel, yellowRel, redRel, appsGreenRel] {
            try env.fixture.file(rel + "/payload.bin", bytes: 8_192)
        }
        if includeBrew {
            env.commands.executables = ["brew": "/opt/fake/bin/brew"]
            env.commands.setResponse(
                CommandResult(exitCode: 0, stdout: "==> This operation would free approximately 1.5GB of disk space.\n", stderr: ""),
                for: ["cleanup", "--prune=all", "-n"])
            try env.fixture.file("Library/Caches/Homebrew/downloads/wget.tar.gz", bytes: 4_096)
        }
    }

    struct Context {
        let env: FakeEnvironment
        let store: SettingsStore
        let actions: RecordingActions
        let catalog: RuleCatalog
        var inspectorOverrides: [any Inspector] = []
        var fixture: FixtureBuilder { env.fixture }

        @MainActor func makeState() throws -> AppState {
            let overrides = Dictionary(inspectorOverrides.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
            let inspectors = try M6.fixtureInspectors(env.fixture).map { overrides[$0.id] ?? $0 }
            return AppState(environment: env.environment, settingsStore: store, fixture: AppStateFixtureOptions(
                waivedSystemRoots: [env.fixture.root], catalog: catalog, inspectors: inspectors,
                permissionProbes: PermissionProbes(fullDiskAccess: FixedFDA(state: .granted), appManagement: AppManagementProbe()),
                systemActions: actions, runsLaunchMaintenance: true, startsDailyPurgeTimer: false))
        }
    }

    static func withContext(includeBrew: Bool = false, store: SettingsStore? = nil, bundledRuleIDs: [String] = [],
                            inspectorOverrides: [any Inspector] = [],
                            _ body: (Context) async throws -> Void) async throws {
        try await M1.withEnv { env in
            try makeFixtureItems(env, includeBrew: includeBrew)
            let context = Context(env: env, store: store ?? SettingsStore.inMemory(), actions: RecordingActions(),
                                  catalog: try catalog(env, includeBrew: includeBrew, bundledRuleIDs: bundledRuleIDs),
                                  inspectorOverrides: inspectorOverrides)
            try await body(context)
        }
    }

    static func scanned(_ ctx: Context) async throws -> AppState {
        let state = try ctx.makeState()
        await state.waitUntilIdle()
        try await scan(state)
        return state
    }

    static func scan(_ state: AppState) async throws {
        state.startScan()
        try TestSuite.assertEqual(state.phase, .scanning)
        await state.waitUntilIdle()
        try TestSuite.assertEqual(state.phase, .scanned, "scan must finish (lastError: \(state.lastError ?? "-"))")
    }

    static func item(_ state: AppState, _ rel: String, _ f: FixtureBuilder) throws -> PlanItem {
        let path = f.path(rel)
        guard let item = state.plan?.items.first(where: { $0.target.path == path }) else {
            let found = state.plan?.items.map(\.target.path) ?? []
            throw TestError("no plan item for \(rel); plan has \(found); statuses \(state.ruleStatuses)")
        }
        return item
    }

    static func actionableItem(_ state: AppState, _ rel: String, _ f: FixtureBuilder) throws -> PlanItem {
        let found = try item(state, rel, f)
        try TestSuite.assertTrue(found.isActionable, "\(rel) must be actionable: \(found.planVerdict)")
        return found
    }

    static func brewItem(_ state: AppState) throws -> PlanItem {
        guard let item = state.plan?.items.first(where: { $0.rule.id == "homebrew.cleanup" }) else {
            throw TestError("no homebrew.cleanup item; statuses \(state.ruleStatuses)")
        }
        try TestSuite.assertTrue(item.isActionable, "brew item must be actionable: \(item.planVerdict)")
        return item
    }

    static func expectThrows<E: Error & Equatable>(_ expected: E, _ context: String = "", file: StaticString = #file,
                                                   line: UInt = #line, _ body: () throws -> Void) throws {
        do {
            try body()
        } catch let error as E {
            try TestSuite.assertEqual(error, expected, context, file: file, line: line)
            return
        } catch {
            throw TestError("Expected \(expected) but got \(error). \(context) (\(file):\(line))")
        }
        throw TestError("Expected \(expected) but nothing was thrown. \(context) (\(file):\(line))")
    }

    static func treeExists(_ path: String) -> Bool {
        var st = Darwin.stat()
        return lstat(path, &st) == 0
    }

    // MARK: Tests

    static func runAll() async {
        print("\n🖥️  Running AppState Tests (spec §3.2, §9, §13 M7)...")

        await TestSuite.run("AppState: this debug test build is dry-run (IMOP_ALLOW_MUTATION is not compiled in)") {
            try TestSuite.assertFalse(AppState.isMutationEnabledInBuild, "tests must run in a dry-run build")
            try TestSuite.assertEqual(AppState.isMutationEnabledInBuild, MutationPolicy.compiledIn.isEnabled)
        }

        await TestSuite.run("AppState: launch reads permissions and quarantine without touching the fixture; nothing is scanned or selected") {
            try await withContext { ctx in
                let state = try ctx.makeState()
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .idle)
                try TestSuite.assertEqual(state.permissions.fullDiskAccess, .granted)
                try TestSuite.assertEqual(state.permissions.appManagement, .unknown)
                try TestSuite.assertTrue(state.quarantineSessions.isEmpty)
                try TestSuite.assertTrue(state.plan == nil && state.selection.isEmpty)
                try TestSuite.assertTrue(state.ruleStatusesLocked().isEmpty, "Full Disk Access granted: nothing locked")
                try TestSuite.assertEqual(state.settings.alwaysQuarantine, true, "default ON")
                try TestSuite.assertFalse(treeExists(ctx.fixture.home + "/Library/Application Support/iMop/Quarantine"),
                                          "launch must not create the Quarantine")
                try TestSuite.assertEqual(state.quarantineNotice, Quarantine.spaceNotice)
            }
        }

        await TestSuite.run("AppState: after a scan Green actionable items are preselected; Yellow and Red never") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                let green = try actionableItem(state, greenRel, ctx.fixture)
                let appsGreen = try actionableItem(state, appsGreenRel, ctx.fixture)
                let yellow = try actionableItem(state, yellowRel, ctx.fixture)
                let red = try actionableItem(state, redRel, ctx.fixture)
                try TestSuite.assertEqual(red.effectiveTier, .red)
                try TestSuite.assertTrue(state.selection.contains(green.id) && state.selection.contains(appsGreen.id))
                try TestSuite.assertFalse(state.selection.contains(yellow.id), "Yellow is never preselected")
                try TestSuite.assertFalse(state.selection.contains(red.id), "Red is never preselected")
                try TestSuite.assertTrue(state.redConfirmed.isEmpty)
                // Category grouping, ordering and totals.
                let media = state.items(in: .media)
                try TestSuite.assertEqual(Set(media.map(\.id)), [green.id, yellow.id, red.id])
                try TestSuite.assertEqual(state.items(in: .apps).map(\.id), [appsGreen.id])
                let totals = state.totals(for: .media)
                try TestSuite.assertEqual(totals.count, 3)
                try TestSuite.assertEqual(totals.selectedCount, 1)
                try TestSuite.assertEqual(totals.selectedReclaimable, green.target.reclaimableBytes)
                try TestSuite.assertEqual(state.selectedReclaimableBytes,
                                          green.target.reclaimableBytes + appsGreen.target.reclaimableBytes)
                try TestSuite.assertEqual(state.categoryProgress[.media]?.targetsFound, 3)
                try TestSuite.assertEqual(state.categoryProgress[.media]?.finished, true)
                try TestSuite.assertTrue(state.advisoryItems.isEmpty)
                try TestSuite.assertFalse(state.planIsOutdated)
            }
        }

        await TestSuite.run("AppState: a Red item is selected only through its per-item confirmation (confirmRed of the presented item)") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                let red = try actionableItem(state, redRel, ctx.fixture)
                let yellow = try actionableItem(state, yellowRel, ctx.fixture)

                // confirmRed without a dialog is a no-op.
                state.confirmRed(red.id)
                try TestSuite.assertFalse(state.selection.contains(red.id))

                state.requestToggle(red.id)
                try TestSuite.assertFalse(state.selection.contains(red.id), "toggling Red only asks")
                try TestSuite.assertEqual(state.pendingRedConfirmation?.id, red.id)
                // Confirming a different item than the one presented does nothing.
                state.confirmRed(yellow.id)
                try TestSuite.assertFalse(state.selection.contains(yellow.id) || state.selection.contains(red.id))
                try TestSuite.assertEqual(state.pendingRedConfirmation?.id, red.id)
                state.cancelRedConfirmation()
                try TestSuite.assertTrue(state.pendingRedConfirmation == nil)
                try TestSuite.assertFalse(state.selection.contains(red.id))

                state.requestToggle(red.id)
                state.confirmRed(red.id)
                try TestSuite.assertTrue(state.selection.contains(red.id) && state.redConfirmed.contains(red.id))
                try TestSuite.assertTrue(state.pendingRedConfirmation == nil)
                try TestSuite.assertEqual(state.reviewSummary.redItems.map(\.id), [red.id])
                try TestSuite.assertEqual(state.reviewSummary.trashItems.map(\.id), [red.id])

                // Deselecting is direct and drops the confirmation.
                state.requestToggle(red.id)
                try TestSuite.assertFalse(state.selection.contains(red.id) || state.redConfirmed.contains(red.id))

                // Yellow toggles directly.
                state.requestToggle(yellow.id)
                try TestSuite.assertTrue(state.selection.contains(yellow.id))
                state.requestToggle(yellow.id)
                try TestSuite.assertFalse(state.selection.contains(yellow.id))
            }
        }

        await TestSuite.run("AppState: bulk category selection never selects Red (or blocked) items; bulk deselection clears everything") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                let green = try actionableItem(state, greenRel, ctx.fixture)
                let yellow = try actionableItem(state, yellowRel, ctx.fixture)
                let red = try actionableItem(state, redRel, ctx.fixture)
                state.setSelection(category: .media, selected: true)
                try TestSuite.assertTrue(state.selection.isSuperset(of: [green.id, yellow.id]))
                try TestSuite.assertFalse(state.selection.contains(red.id), "bulk select must skip Red")
                try TestSuite.assertTrue(state.pendingRedConfirmation == nil)
                state.requestToggle(red.id)
                state.confirmRed(red.id)
                state.setSelection(category: .media, selected: false)
                try TestSuite.assertTrue(state.selection.isDisjoint(with: [green.id, yellow.id, red.id]))
                try TestSuite.assertTrue(state.redConfirmed.isEmpty)
                // Other categories are untouched.
                try TestSuite.assertTrue(state.selection.contains(try actionableItem(state, appsGreenRel, ctx.fixture).id))
            }
        }

        await TestSuite.run("AppState: Clean before 2 s after the review appeared throws confirmedTooQuickly (FixedClock); a changed selection needs a new review") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                // No review yet.
                try expectThrows(AppStateError.reviewNotPresented) { try state.confirmAndClean(acknowledgedIrreversible: false) }

                state.beginReview()
                try TestSuite.assertTrue(state.showReview)
                try TestSuite.assertEqual(state.reviewPresentedAt, ctx.env.clock.now)
                try expectThrows(ConfirmationError.confirmedTooQuickly, "0 s") { try state.confirmAndClean(acknowledgedIrreversible: false) }
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(1.9)
                try expectThrows(ConfirmationError.confirmedTooQuickly, "1.9 s") { try state.confirmAndClean(acknowledgedIrreversible: false) }
                try TestSuite.assertEqual(state.phase, .scanned, "nothing ran")

                // Changing the selection invalidates the review.
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(5)
                state.requestToggle(try actionableItem(state, yellowRel, ctx.fixture).id)
                try TestSuite.assertFalse(state.showReview)
                try expectThrows(AppStateError.reviewNotPresented) { try state.confirmAndClean(acknowledgedIrreversible: false) }
                state.cancelReview()
                try TestSuite.assertTrue(state.reviewPresentedAt == nil)
            }
        }

        await TestSuite.run("AppState: an irreversible (vendor command) item requires the explicit acknowledgement") {
            try await withContext(includeBrew: true) { ctx in
                let state = try await scanned(ctx)
                let brew = try brewItem(state)
                try TestSuite.assertTrue(state.selection.contains(brew.id), "Green idempotent command is preselected")
                let summary = state.reviewSummary
                try TestSuite.assertEqual(summary.commandItems.map(\.id), [brew.id])
                try TestSuite.assertEqual(summary.irreversibleItems.map(\.id), [brew.id])
                try TestSuite.assertTrue(summary.requiresIrreversibleAcknowledgement)
                try TestSuite.assertFalse(summary.quarantineItems.isEmpty)

                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try expectThrows(ConfirmationError.irreversibleNotAcknowledged) { try state.confirmAndClean(acknowledgedIrreversible: false) }
                try TestSuite.assertEqual(state.phase, .scanned)
                try TestSuite.assertTrue(ctx.env.commands.purposes.allSatisfy { $0 == .readOnly }, "no command was run for real")
                try TestSuite.assertTrue(state.lastError != nil)
            }
        }

        await TestSuite.run("AppState: in this dry-run build a confirmed cleanup reports mutationDisabled and leaves the fixture untouched") {
            try await withContext(includeBrew: true) { ctx in
                let state = try await scanned(ctx)
                let red = try actionableItem(state, redRel, ctx.fixture)
                state.setSelection(category: .media, selected: true)
                state.requestToggle(red.id)
                state.confirmRed(red.id)
                let selected = state.selection
                try TestSuite.assertTrue(selected.count >= 5, "\(selected.count)")

                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                // Spec §3.2 (review M7): the selected Yellow media item needs its category acknowledged.
                try expectThrows(AppStateError.categoryNotAcknowledged(.media)) {
                    try state.confirmAndClean(acknowledgedIrreversible: true)
                }
                try TestSuite.assertEqual(state.phase, .scanned)
                try state.confirmAndClean(acknowledgedIrreversible: true, acknowledgedCategories: [.media])
                try TestSuite.assertEqual(state.phase, .executing)
                try TestSuite.assertFalse(state.showReview)
                await state.waitUntilIdle()

                try TestSuite.assertEqual(state.phase, .finished)
                try TestSuite.assertEqual(state.destination, .results)
                guard let report = state.lastReport else { throw TestError("no report: \(state.lastError ?? "-")") }
                try TestSuite.assertTrue(report.mutationDisabled)
                try TestSuite.assertEqual(Set(report.outcomes.map(\.id)), selected)
                try TestSuite.assertEqual(state.executionTotal, selected.count)
                try TestSuite.assertEqual(state.executionOutcomes.count, selected.count)
                for outcome in report.outcomes {
                    try TestSuite.assertFalse(outcome.status.succeeded, "\(outcome.path): \(outcome.status)")
                }
                try TestSuite.assertTrue(report.outcomes.contains {
                    if case .failed(.mutationDisabled, _) = $0.status { return true } else { return false }
                }, "\(report.outcomes.map(\.status))")
                for rel in [greenRel, yellowRel, redRel, appsGreenRel] {
                    try TestSuite.assertTrue(treeExists(ctx.fixture.path(rel + "/payload.bin")), "\(rel) must be untouched")
                }
                try TestSuite.assertTrue(ctx.env.commands.purposes.allSatisfy { $0 == .readOnly }, "no action command ran")
                try TestSuite.assertTrue(state.quarantineSessions.allSatisfy { $0.entries.isEmpty })
                // The run is over: nothing can be confirmed again from this plan.
                try TestSuite.assertTrue(state.selection.isEmpty)
                state.beginReview()
                try TestSuite.assertFalse(state.showReview)
                try expectThrows(AppStateError.nothingToClean) { try state.confirmAndClean(acknowledgedIrreversible: true) }
                // The run is audited.
                let logs = ctx.fixture.home + "/Library/Logs/iMop"
                try TestSuite.assertTrue(!((try? FileManager.default.contentsOfDirectory(atPath: logs)) ?? []).isEmpty)
            }
        }

        await TestSuite.run("AppState: settings persist through the store; corrupted stored settings fall back to the defaults (Always quarantine ON)") {
            let store = SettingsStore.inMemory()
            try await withContext(store: store) { ctx in
                let first = try ctx.makeState()
                await first.waitUntilIdle()
                var changed = first.settings
                changed.projectRoots = ["~/Projects"]
                changed.alwaysQuarantine = false
                changed.archivesToKeep = 7
                changed.quarantineRetentionOverrideHours = ["media.green": 72]
                first.settings = changed
                first.addExclusion(path: "~/Library/Caches/com.example.keep")
                first.addProjectRoot(path: "~/Developer")
                first.addProjectRoot(path: "~/Developer")

                let second = try ctx.makeState()
                await second.waitUntilIdle()
                try TestSuite.assertEqual(second.settings.projectRoots, ["~/Projects", "~/Developer"])
                try TestSuite.assertEqual(second.settings.alwaysQuarantine, false)
                try TestSuite.assertEqual(second.settings.archivesToKeep, 7)
                try TestSuite.assertEqual(second.settings.userExclusions, ["~/Library/Caches/com.example.keep"])
                try TestSuite.assertEqual(second.settings.quarantineRetentionOverrideHours, ["media.green": 72])
                try TestSuite.assertEqual(store.load(), second.settings)
                second.dropProjectRoot("~/Developer")
                second.dropExclusion("~/Library/Caches/com.example.keep")
                try TestSuite.assertEqual(store.load().projectRoots, ["~/Projects"])
                try TestSuite.assertEqual(store.load().userExclusions, [])

                for garbage in [Data("not json".utf8), Data("{\"alwaysQuarantine\": \"no\"}".utf8), Data([0xFF, 0x00])] {
                    store.rawData = garbage
                    let reset = try ctx.makeState()
                    await reset.waitUntilIdle()
                    try TestSuite.assertEqual(reset.settings, ScanSettings.default)
                    try TestSuite.assertTrue(reset.settings.alwaysQuarantine, "corrupted store → Always quarantine ON")
                    try TestSuite.assertTrue(store.lastLoadFellBackToDefaults)
                    try TestSuite.assertTrue(reset.settingsReviewNotice != nil, "the reset is reported")
                }
                // A missing key decodes to the safe default too.
                store.rawData = Data("{}".utf8)
                try TestSuite.assertTrue(store.load().alwaysQuarantine)
                try TestSuite.assertFalse(store.lastLoadFellBackToDefaults)
                store.rawData = nil
                try TestSuite.assertEqual(store.load(), ScanSettings.default)
            }
        }

        await TestSuite.run("AppState: lastSeenVolumes is recorded (and persisted) after every scan; Forget remembered drives resets it to never-recorded") {
            try await withContext { ctx in
                ctx.env.volumes.volumes = ["/Volumes/External"]
                let state = try ctx.makeState()
                await state.waitUntilIdle()
                try TestSuite.assertTrue(state.settings.lastSeenVolumes == nil, "fresh store: never recorded")
                try await scan(state)
                let expected = [FakeVolumeInspector.defaultUUID(for: "/Volumes/External")]
                try TestSuite.assertEqual(state.settings.lastSeenVolumes, expected)
                try TestSuite.assertEqual(ctx.store.load().lastSeenVolumes, expected)
                try TestSuite.assertFalse(state.planIsOutdated, "recording drives does not invalidate the plan")

                // A disconnected drive stays remembered.
                ctx.env.volumes.volumes = []
                try await scan(state)
                try TestSuite.assertEqual(ctx.store.load().lastSeenVolumes, expected)

                state.forgetRememberedDrives()
                try TestSuite.assertTrue(state.settings.lastSeenVolumes == nil)
                try TestSuite.assertTrue(ctx.store.load().lastSeenVolumes == nil)
            }
        }

        await TestSuite.run("AppState: a new exclusion deselects matching items at once and takes effect on the next scan") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                let green = try actionableItem(state, greenRel, ctx.fixture)
                try TestSuite.assertTrue(state.selection.contains(green.id))
                state.addExclusion(path: "~/Library/Caches/com.example.media.green")
                try TestSuite.assertFalse(state.selection.contains(green.id), "deselected immediately")
                try TestSuite.assertTrue(state.planIsOutdated)
                // The outdated plan cannot be reviewed.
                state.beginReview()
                try TestSuite.assertFalse(state.showReview)
                try TestSuite.assertEqual(state.lastError, AppState.planOutdatedMessage)

                try await scan(state)
                try TestSuite.assertFalse(state.planIsOutdated)
                let excludedPath = ctx.fixture.path(greenRel)
                for item in state.plan?.items ?? [] where item.target.path == excludedPath {
                    try TestSuite.assertFalse(item.isActionable, "excluded item must be blocked: \(item.planVerdict)")
                    try TestSuite.assertFalse(state.selection.contains(item.id))
                    // A blocked item is a no-op for toggling.
                    state.requestToggle(item.id)
                    try TestSuite.assertFalse(state.selection.contains(item.id))
                }
                try TestSuite.assertTrue(state.selection.contains(try actionableItem(state, appsGreenRel, ctx.fixture).id))
            }
        }

        await TestSuite.run("AppState: a plan built under old settings is refused at confirm (planOutdated) and works again after a rescan") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                state.beginReview()
                try TestSuite.assertTrue(state.showReview)
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                for change in 0..<3 {
                    var updated = state.settings
                    switch change {
                    case 0: updated.alwaysQuarantine = false
                    case 1: updated.alwaysQuarantine = true; updated.ageThresholdOverrides = ["media.green": 400]
                    default: updated.ageThresholdOverrides = [:]; updated.quarantineRetentionOverrideHours = ["media.green": 500]
                    }
                    state.settings = updated
                    try TestSuite.assertTrue(state.planIsOutdated, "change \(change)")
                    try expectThrows(AppStateError.planOutdated, "change \(change)") {
                        try state.confirmAndClean(acknowledgedIrreversible: true)
                    }
                }
                try TestSuite.assertEqual(state.phase, .scanned, "nothing ran")
                try await scan(state)
                try TestSuite.assertFalse(state.planIsOutdated)
                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try state.confirmAndClean(acknowledgedIrreversible: false)
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .finished)
                try TestSuite.assertEqual(state.lastReport?.mutationDisabled, true)
                for rel in [greenRel, appsGreenRel] {
                    try TestSuite.assertTrue(treeExists(ctx.fixture.path(rel + "/payload.bin")), "\(rel) must be untouched")
                }
            }
        }

        await TestSuite.run("AppState: cancelling a scan returns to idle with no plan and no selection") {
            try await withContext { ctx in
                let state = try ctx.makeState()
                await state.waitUntilIdle()
                state.startScan()
                state.cancelScan()
                try TestSuite.assertEqual(state.phase, .idle)
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .idle, "a late scan result is ignored")
                try TestSuite.assertTrue(state.plan == nil && state.selection.isEmpty)
            }
        }

        await TestSuite.run("AppState: Full Disk Access not confirmed → rules that need it are listed as locked") {
            try await withContext { ctx in
                let state = AppState(environment: ctx.env.environment, settingsStore: ctx.store, fixture: AppStateFixtureOptions(
                    waivedSystemRoots: [ctx.fixture.root], catalog: nil, inspectors: try M6.fixtureInspectors(ctx.fixture),
                    permissionProbes: PermissionProbes(fullDiskAccess: FixedFDA(state: .denied), appManagement: AppManagementProbe()),
                    systemActions: ctx.actions, runsLaunchMaintenance: true))
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.permissions.fullDiskAccess, .denied)
                let locked = state.ruleStatusesLocked()
                try TestSuite.assertTrue(!locked.isEmpty && locked.allSatisfy(\.requiresFullDiskAccess), "\(locked.map(\.id))")
            }
        }

        await TestSuite.run("AppState: deep links, Reveal in Finder and Open App go through the injected system actions only") {
            try await withContext { ctx in
                let state = try ctx.makeState()
                await state.waitUntilIdle()
                state.openFullDiskAccessSettings()
                state.openAppManagementSettings()
                state.openStorageSettings()
                try TestSuite.assertEqual(ctx.actions.opened.map(\.absoluteString),
                                          [FullDiskAccessProbe.settingsDeepLink, AppManagementProbe.settingsDeepLink,
                                           AppState.storageSettingsDeepLink])
                state.revealInFinder(path: ctx.fixture.path(greenRel))
                state.revealInFinder(path: "relative/path")
                try TestSuite.assertEqual(ctx.actions.revealed, [ctx.fixture.path(greenRel)])
                state.openApp(bundleID: "com.example.missing")
                try TestSuite.assertEqual(ctx.actions.apps, ["com.example.missing"])
                try TestSuite.assertTrue(state.lastError != nil, "a missing app is reported")
                state.clearError()
                try TestSuite.assertTrue(state.lastError == nil)
            }
        }

        await TestSuite.run("AppState: Export Log writes a new file only; an existing destination is refused with a clear error") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try state.confirmAndClean(acknowledgedIrreversible: false)
                await state.waitUntilIdle()
                let exportDir = try ctx.fixture.dir("Export", base: .root)
                let destination = URL(fileURLWithPath: exportDir + "/imop-audit.jsonl")
                try await state.exportAuditLog(to: destination)
                try TestSuite.assertTrue(treeExists(destination.path))
                var refused = false
                do {
                    try await state.exportAuditLog(to: destination)
                } catch let error as AuditLogError {
                    refused = error == .destinationExists
                }
                try TestSuite.assertTrue(refused, "an existing file is never overwritten")
                try TestSuite.assertEqual(state.lastError?.contains("already exists"), true, state.lastError ?? "-")
            }
        }

        await TestSuite.run("AppState: Empty Quarantine Now and restores on an empty Quarantine change nothing and report no error") {
            try await withContext { ctx in
                let state = try ctx.makeState()
                await state.waitUntilIdle()
                state.emptyQuarantineNow()
                await state.waitUntilIdle()
                try TestSuite.assertTrue(state.quarantineSessions.isEmpty)
                try TestSuite.assertTrue(state.lastError == nil, state.lastError ?? "-")
                state.restore(entryID: UUID())
                await state.waitUntilIdle()
                try TestSuite.assertTrue(state.lastError != nil, "restoring an unknown entry is reported")
                for rel in [greenRel, yellowRel, redRel, appsGreenRel] {
                    try TestSuite.assertTrue(treeExists(ctx.fixture.path(rel + "/payload.bin")))
                }
            }
        }

        await TestSuite.run("CategoryDetailViewModel: search matches name, path, rule title and owner; sorts are stable") {
            try await withContext { ctx in
                let state = try await scanned(ctx)
                let media = state.items(in: .media)
                try TestSuite.assertEqual(media.count, 3)
                let byYellow = CategoryDetailViewModel.filterAndSort(media, query: "MEDIA.YELLOW", sort: .sizeDescending)
                try TestSuite.assertEqual(byYellow.map(\.target.path), [ctx.fixture.path(yellowRel)])
                let byTitle = CategoryDetailViewModel.filterAndSort(media, query: "Test media.red", sort: .nameAscending)
                try TestSuite.assertEqual(byTitle.map(\.target.path), [ctx.fixture.path(redRel)])
                try TestSuite.assertEqual(CategoryDetailViewModel.filterAndSort(media, query: "   ", sort: .nameAscending).count, 3)
                try TestSuite.assertTrue(CategoryDetailViewModel.filterAndSort(media, query: "nothing-matches", sort: .sizeAscending).isEmpty)
                // Equal sizes and names: ties broken by path.
                let sorted = CategoryDetailViewModel.filterAndSort(media, query: "", sort: .nameAscending)
                try TestSuite.assertEqual(sorted.map(\.target.path), media.map(\.target.path).sorted())
                let model = CategoryDetailViewModel()
                model.searchText = "green"
                try TestSuite.assertEqual(model.filteredAndSortedItems(from: media).map(\.target.path), [ctx.fixture.path(greenRel)])
            }
        }
    }
}
