import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Regression tests for the Milestone 7 adversarial review (exclusions during a run, Yellow
/// "what you lose" acknowledgement, the grouped "Empty Trash" choice, unavailable rules, rules whose
/// access was declined, field-by-field settings recovery).
@MainActor
enum M7ReviewRegressionTests {
    typealias T = AppStateTests

    /// An inspector that reports "Access was declined" and counts how often it was asked.
    final class DecliningInspector: Inspector, @unchecked Sendable {
        let id: InspectorID
        private let lock = NSLock()
        private var _calls = 0
        var calls: Int { lock.lock(); defer { lock.unlock() }; return _calls }

        init(id: InspectorID) { self.id = id }

        private func count() { lock.lock(); _calls += 1; lock.unlock() }

        func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
            count()
            return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        }
    }

    static func runAll() async {
        print("\n🧪 Running M7 Review Regression Tests...")

        await TestSuite.run("M7 review: an exclusion added during a running cleanup leaves the confirmed run's list alone and makes the Executor skip that item") {
            try await T.withContext { ctx in
                let state = try await T.scanned(ctx)
                let green = try T.actionableItem(state, T.greenRel, ctx.fixture)
                let other = try T.actionableItem(state, T.appsGreenRel, ctx.fixture)
                try TestSuite.assertTrue(state.selection.isSuperset(of: [green.id, other.id]))
                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try state.confirmAndClean(acknowledgedIrreversible: false)
                try TestSuite.assertEqual(state.phase, .executing)
                let confirmed = state.confirmedItemIDs
                try TestSuite.assertTrue(confirmed.contains(green.id))

                let selectionBefore = state.selection
                state.addExclusion(path: "~/Library/Caches/com.example.media.green")
                try TestSuite.assertEqual(state.selection, selectionBefore, "the running selection is not edited")
                try TestSuite.assertEqual(state.confirmedItemIDs, confirmed)
                try TestSuite.assertEqual(state.exclusionsAddedDuringExecution, ["~/Library/Caches/com.example.media.green"])
                try TestSuite.assertEqual(state.settings.userExclusions, ["~/Library/Caches/com.example.media.green"], "persisted for the next scan")
                await state.waitUntilIdle()

                guard let report = state.lastReport else { throw TestError("no report") }
                guard let outcome = report.outcomes.first(where: { $0.id == green.id }) else { throw TestError("no outcome for the excluded item") }
                guard case .skipped(.userExcluded) = outcome.status else {
                    throw TestError("the excluded item must be skipped by the execute-time SafetyGate: \(outcome.status)")
                }
                // The other item went on to the (dry-run) mutation step as usual.
                if let otherOutcome = report.outcomes.first(where: { $0.id == other.id }),
                   case .skipped(.userExcluded) = otherOutcome.status {
                    throw TestError("an item outside the exclusion must not be excluded")
                }
                try TestSuite.assertTrue(T.treeExists(ctx.fixture.path(T.greenRel + "/payload.bin")))
            }
        }

        await TestSuite.run("M7 review: LiveExclusions only grow, and a SafetyGate reads them at every validation") {
            try await M1.withEnv { env in
                let live = LiveExclusions(["", "  "])
                try TestSuite.assertEqual(live.current, [])
                live.add("~/a"); live.add("~/a"); live.add(" ~/b ")
                try TestSuite.assertEqual(live.current, ["~/a", "~/b"])
                let rel = "Library/Caches/com.example.live/item"
                try env.fixture.file(rel + "/x.bin", bytes: 4096)
                let rule = M1.rule()
                let target = env.scanTarget(ruleID: rule.id, path: rel)
                let gate = SafetyGate(environment: env.environment, userExclusions: [], ageThresholdOverrides: [:],
                                      waivedSystemRoots: [env.fixture.root], liveExclusions: live)
                try M1.expectAllowed(await gate.validate(target: target, rule: rule, phase: .execute))
                live.add("~/Library/Caches/com.example.live")
                try M1.expectRejected(await gate.validate(target: target, rule: rule, phase: .execute),
                                      .userExcluded(path: "~/Library/Caches/com.example.live"))
            }
        }

        await TestSuite.run("M7 review: selected Yellow items need their category acknowledged (spec §3.2); what you lose is in the review summary") {
            try await T.withContext { ctx in
                let state = try await T.scanned(ctx)
                let yellow = try T.actionableItem(state, T.yellowRel, ctx.fixture)
                try TestSuite.assertFalse(state.selection.contains(yellow.id), "Yellow is never preselected")
                state.requestToggle(yellow.id)
                try TestSuite.assertTrue(state.selection.contains(yellow.id))
                let summary = state.reviewSummary
                try TestSuite.assertEqual(summary.yellowItems.map(\.id), [yellow.id])
                try TestSuite.assertEqual(summary.yellowCategories, [.media])
                try TestSuite.assertFalse(summary.yellowItems(in: .media).first?.rule.whatYouLose.isEmpty ?? true)

                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try T.expectThrows(AppStateError.categoryNotAcknowledged(.media)) {
                    try state.confirmAndClean(acknowledgedIrreversible: false)
                }
                try T.expectThrows(AppStateError.categoryNotAcknowledged(.media), "another category's box does not count") {
                    try state.confirmAndClean(acknowledgedIrreversible: false, acknowledgedCategories: [.apps])
                }
                try TestSuite.assertEqual(state.phase, .scanned)
                try state.confirmAndClean(acknowledgedIrreversible: false, acknowledgedCategories: [.media])
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .finished)
                try TestSuite.assertTrue(T.treeExists(ctx.fixture.path(T.yellowRel + "/payload.bin")))
            }
        }

        await TestSuite.run("M7 review: the items in the Trash are one \"Empty Trash\" choice with its own confirmation; never bulk-selected") {
            try await T.withContext(bundledRuleIDs: ["trash.empty"]) { ctx in
                try ctx.fixture.file(".Trash/old-report.pdf", bytes: 4096)
                try ctx.fixture.file(".Trash/Old Folder/inner.txt", bytes: 2048)
                let state = try ctx.makeState()
                await state.waitUntilIdle()
                var updated = state.settings
                updated.alwaysQuarantine = false
                state.settings = updated
                try await T.scan(state)

                let trash = state.emptyTrashItems
                try TestSuite.assertEqual(trash.count, 2, "statuses \(state.ruleStatuses); plan \(state.plan?.items.map { "\($0.target.path): \($0.planVerdict)" } ?? [])")
                let ids = Set(trash.map(\.id))
                try TestSuite.assertTrue(state.selection.isDisjoint(with: ids), "never preselected")
                state.setSelection(category: .system, selected: true)
                try TestSuite.assertTrue(state.selection.isDisjoint(with: ids), "never selected in bulk")

                // Selecting one asks to empty the whole Trash; nothing is selected yet.
                state.requestToggle(trash[0].id)
                guard let request = state.pendingEmptyTrashConfirmation else { throw TestError("no Empty Trash dialog") }
                try TestSuite.assertEqual(Set(request.itemIDs), ids)
                try TestSuite.assertEqual(request.count, 2)
                try TestSuite.assertEqual(request.reclaimableBytes, trash.reduce(0) { $0 + $1.target.reclaimableBytes })
                try TestSuite.assertTrue(state.selection.isDisjoint(with: ids))
                state.cancelEmptyTrashConfirmation()
                try TestSuite.assertTrue(state.selection.isDisjoint(with: ids))
                try TestSuite.assertTrue(state.emptyTrashConfirmed.isEmpty)

                // A stale request id is ignored.
                state.requestToggle(trash[1].id)
                guard let second = state.pendingEmptyTrashConfirmation else { throw TestError("no Empty Trash dialog") }
                state.confirmEmptyTrash(request.id)
                try TestSuite.assertTrue(state.selection.isDisjoint(with: ids))
                try TestSuite.assertTrue(nil != state.pendingEmptyTrashConfirmation)
                state.confirmEmptyTrash(second.id)
                try TestSuite.assertTrue(state.selection.isSuperset(of: ids), "all Trash items together")
                try TestSuite.assertEqual(state.emptyTrashConfirmed, ids)

                // Deselecting one deselects the whole choice.
                state.requestToggle(trash[1].id)
                try TestSuite.assertTrue(state.selection.isDisjoint(with: ids))
                try TestSuite.assertTrue(state.emptyTrashConfirmed.isEmpty)

                // Confirmed again → it can be reviewed and confirmed (irreversible + System acknowledged).
                state.requestToggle(trash[0].id)
                if let again = state.pendingEmptyTrashConfirmation { state.confirmEmptyTrash(again.id) }
                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try T.expectThrows(ConfirmationError.irreversibleNotAcknowledged) {
                    try state.confirmAndClean(acknowledgedIrreversible: false, acknowledgedCategories: [.system])
                }
                try state.confirmAndClean(acknowledgedIrreversible: true, acknowledgedCategories: [.system])
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .finished)
                try TestSuite.assertTrue(T.treeExists(ctx.fixture.path(".Trash/old-report.pdf")), "dry-run build: untouched")
                try TestSuite.assertTrue(T.treeExists(ctx.fixture.path(".Trash/Old Folder/inner.txt")))
            }
        }

        await TestSuite.run("M7 review: unavailable rules are listed with their reason; a rule whose access was declined is not scanned again this session") {
            let declining = DecliningInspector(id: .appContainerCaches)
            try await T.withContext(bundledRuleIDs: ["apps.containerCaches"], inspectorOverrides: [declining]) { ctx in
                let state = try await T.scanned(ctx)
                try TestSuite.assertEqual(declining.calls, 1)
                try TestSuite.assertEqual(state.ruleStatuses["apps.containerCaches"], .unavailable(SafeCleanScanner.accessDeclinedMessage))
                try TestSuite.assertEqual(state.unavailableRules().map(\.id), ["apps.containerCaches"])
                try TestSuite.assertEqual(state.unavailableRules().first?.reason, SafeCleanScanner.accessDeclinedMessage)

                try await T.scan(state)
                try TestSuite.assertEqual(declining.calls, 1, "no repeated access in the same session (spec §8)")
                try TestSuite.assertEqual(state.ruleStatuses["apps.containerCaches"], .unavailable(AppState.declinedThisSessionMessage))
                try TestSuite.assertEqual(state.unavailableRules().first?.reason, AppState.declinedThisSessionMessage)
                // The other rules are still scanned and offered.
                try TestSuite.assertTrue(state.selection.contains(try T.actionableItem(state, T.greenRel, ctx.fixture).id))

                // A new session (new AppState) may ask again.
                let fresh = try ctx.makeState()
                await fresh.waitUntilIdle()
                try await T.scan(fresh)
                try TestSuite.assertEqual(declining.calls, 2)
            }
        }

        await TestSuite.run("M7 review: one unreadable settings field never erases the exclusions; cleaning is paused until Settings are checked; the original is backed up") {
            let raw = Data(#"{"userExclusions":["~/Library/Caches/com.example.media.green", 7],"archivesToKeep":"3","projectRoots":["~/Projects"],"alwaysQuarantine":"no","lastSeenVolumes":["A", 1]}"#.utf8)
            let store = SettingsStore.inMemory(rawData: raw)
            let loaded = store.load()
            try TestSuite.assertEqual(loaded.userExclusions, ["~/Library/Caches/com.example.media.green"], "readable exclusions are kept")
            try TestSuite.assertEqual(loaded.projectRoots, ["~/Projects"])
            try TestSuite.assertEqual(loaded.archivesToKeep, ScanSettings.defaultArchivesToKeep)
            try TestSuite.assertTrue(loaded.alwaysQuarantine, "unreadable → ON")
            try TestSuite.assertTrue(loaded.lastSeenVolumes == nil, "partly unreadable drives → never recorded")
            try TestSuite.assertTrue(store.lastLoadFellBackToDefaults)
            try TestSuite.assertEqual(Set(store.lastLoadUnreadableFields),
                                      ["exclusions", "archives to keep", "Always quarantine", "remembered drives"])
            try TestSuite.assertEqual(store.backupData, raw)

            // The reviewer's case: a String where an Int belongs.
            let reviewer = SettingsStore.inMemory(rawData: Data(#"{"userExclusions":["/Users/me/Library/Caches/com.vendor.keep"],"archivesToKeep":"3"}"#.utf8))
            try TestSuite.assertEqual(reviewer.load().userExclusions, ["/Users/me/Library/Caches/com.vendor.keep"])
            try TestSuite.assertTrue(reviewer.lastLoadFellBackToDefaults)

            // A clean load reports nothing.
            let clean = SettingsStore.inMemory()
            clean.save(ScanSettings(userExclusions: ["~/x"]))
            try TestSuite.assertEqual(clean.load().userExclusions, ["~/x"])
            try TestSuite.assertFalse(clean.lastLoadFellBackToDefaults)
            try TestSuite.assertNil(clean.backupData)

            try await T.withContext(store: store) { ctx in
                let state = try await T.scanned(ctx)
                try TestSuite.assertTrue(nil != state.settingsReviewNotice)
                try TestSuite.assertEqual(state.settings.userExclusions, ["~/Library/Caches/com.example.media.green"])
                // The kept exclusion is honoured by the scan.
                let green = try T.item(state, T.greenRel, ctx.fixture)
                try TestSuite.assertFalse(green.isActionable)
                try TestSuite.assertFalse(state.selection.isEmpty, "other Green items are preselected")
                state.beginReview()
                try TestSuite.assertFalse(state.showReview, "review is paused")
                try TestSuite.assertEqual(state.lastError, AppState.settingsReviewBlockedMessage)
                try T.expectThrows(AppStateError.settingsNeedReview) { try state.confirmAndClean(acknowledgedIrreversible: true) }
                // Saving after the scan (lastSeenVolumes) never overwrites the backup.
                try TestSuite.assertEqual(store.backupData, raw)

                state.acknowledgeSettingsReview()
                try TestSuite.assertNil(state.settingsReviewNotice)
                state.clearError()
                state.beginReview()
                try TestSuite.assertTrue(state.showReview)
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try state.confirmAndClean(acknowledgedIrreversible: false)
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .finished)
                try TestSuite.assertEqual(store.backupData, raw)
            }
        }

        await TestSuite.run("M7 review: after a cleanup nothing can be toggled; bulk selection never picks a permanent deletion") {
            try await T.withContext { ctx in
                let state = try await T.scanned(ctx)
                state.beginReview()
                ctx.env.clock.now = ctx.env.clock.now.addingTimeInterval(3)
                try state.confirmAndClean(acknowledgedIrreversible: false)
                await state.waitUntilIdle()
                try TestSuite.assertEqual(state.phase, .finished)
                let yellow = try T.actionableItem(state, T.yellowRel, ctx.fixture)
                state.requestToggle(yellow.id)
                state.setSelection(category: .media, selected: true)
                try TestSuite.assertTrue(state.selection.isEmpty, "the pre-clean plan is for reference only")
            }
        }
    }
}
