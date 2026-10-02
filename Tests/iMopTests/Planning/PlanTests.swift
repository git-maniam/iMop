import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §3.1 / §3.2 / §9.4: PlanBuilder (read-only), ConfirmedPlan.confirm and the plan hash.
struct PlanTests {
    /// Every path below `root` with its (inode, size, mtime), never following symlinks.
    @MainActor
    static func treeSnapshot(_ root: String) -> [String: String] {
        var result: [String: String] = [:]
        var stack = [root]
        while let path = stack.popLast() {
            guard let st = M3.lstatInfo(path) else { continue }
            result[path] = "\(st.st_ino)/\(st.st_size)/\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec)/\(st.st_mode)"
            if (st.st_mode & S_IFMT) == S_IFDIR {
                stack += M3.children(path).map { path + "/" + $0 }
            }
        }
        return result
    }

    @MainActor
    static func runAll() async {
        print("\n🗂️  Running Plan Tests (spec §3.1, §3.2, §9.4)...")

        // MARK: PlanBuilder

        await TestSuite.run("Plan: built from a scanned fixture — Green items preselected, blocked items present with reasons, nothing mutated") {
            try await SafeCleanScannerTests.withScanEnv { env in
                let scanner = try SafeCleanScannerTests.makeScanner(env)
                let results = await scanner.scan()
                let targetCount = results.reduce(0) { $0 + $1.targets.count }
                try TestSuite.assertTrue(targetCount > 10, "scan found only \(targetCount) targets")

                let before = treeSnapshot(env.fixture.root)
                let plan = await PlanBuilder(environment: env.environment, gate: env.makeGate(), settings: PlanSettings())
                    .build(from: results)
                try TestSuite.assertEqual(treeSnapshot(env.fixture.root), before, "PlanBuilder changed the fixture")

                try TestSuite.assertEqual(plan.items.count, targetCount, "every candidate, blocked or not, is in the plan")
                try TestSuite.assertTrue(!plan.actionableItems.isEmpty, "no actionable item")
                try TestSuite.assertTrue(!plan.blockedItems.isEmpty, "no blocked item")
                for item in plan.actionableItems {
                    try TestSuite.assertEqual(item.effectiveTier, .green, item.target.path)
                    try TestSuite.assertTrue(item.selectedByDefault, "Green item not preselected: \(item.target.path)")
                    try TestSuite.assertEqual(item.action, .quarantine(retentionHours: 24), item.target.path)
                    try TestSuite.assertTrue(item.skipReason == nil, item.target.path)
                }
                for item in plan.blockedItems {
                    try TestSuite.assertFalse(item.selectedByDefault, "blocked item preselected: \(item.target.path)")
                    try TestSuite.assertTrue(!(item.skipReason ?? "").isEmpty, "blocked item without a reason: \(item.target.path)")
                }
                try TestSuite.assertEqual(plan.defaultSelection, Set(plan.actionableItems.map(\.id)))

                // Specific outcomes: fresh logs fail "olderThan 7 days"; pip's cache is clean to go.
                let logs = plan.items.filter { $0.rule.id == "logs.user" }
                try TestSuite.assertEqual(logs.count, 2)
                for item in logs {
                    guard case .rejected(.preconditionFailed(let name, _)) = item.planVerdict, name == "olderThan" else {
                        throw TestError("logs.user item should fail olderThan, got \(item.planVerdict)")
                    }
                }
                let pip = plan.items.filter { $0.rule.id == "pip.cache" }
                try TestSuite.assertEqual(pip.count, 1)
                try TestSuite.assertTrue(pip[0].isActionable && pip[0].selectedByDefault, "\(pip[0].planVerdict)")
            }
        }

        await TestSuite.run("Plan: sanity-limit downgrade → effective tier Red, not actionable, never preselected, cannot be confirmed") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.huge", maxBytes: 1_000)
                let path = try M3.cacheItem(ctx.env, "Huge")
                let target = M3.target(ctx.env, rule: rule, path: path, bytes: 50_000)
                let plan = await M3.plan(ctx, [(rule, [target])])
                let item = plan.items[0]
                guard case .downgradedToRed(.sanityLimitExceeded) = item.planVerdict else {
                    throw TestError("expected a sanity downgrade, got \(item.planVerdict)")
                }
                try TestSuite.assertEqual(item.effectiveTier, .red)
                try TestSuite.assertFalse(item.isActionable)
                try TestSuite.assertFalse(item.selectedByDefault)
                try TestSuite.assertTrue(item.requiresPerItemConfirmation)
                try TestSuite.assertTrue(plan.actionableItems.isEmpty)
                try TestSuite.assertEqual(plan.blockedItems.map(\.id), [item.id])
                do {
                    _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [item.id],
                                                  confirmation: M3.confirmation(perItem: [item.id], irreversible: true),
                                                  alwaysQuarantine: false)
                    throw TestError("a downgraded item was confirmed")
                } catch let error as ConfirmationError {
                    try TestSuite.assertEqual(error, .notActionable(item.id))
                }
            }
        }

        await TestSuite.run("Plan: action mapping — Green 24 h / Yellow 7 d quarantine, Red trash, Advisory never actionable, Yellow never preselected") {
            try await M3.withContext { ctx in
                let green = M1.rule(id: "test.green")
                let yellow = M1.rule(id: "test.yellow", tier: .yellow)
                let red = M1.rule(id: "test.red", tier: .red, action: .trash)
                let advisory = M1.rule(id: "test.advisory", tier: .advisory, action: .advisory(.revealInFinder))
                let g = M3.target(ctx.env, rule: green, path: try M3.cacheItem(ctx.env, "G"))
                let y = M3.target(ctx.env, rule: yellow, path: try M3.cacheItem(ctx.env, "Y"))
                let r = M3.target(ctx.env, rule: red, path: try M3.cacheItem(ctx.env, "R"))
                let a = ScanTarget(ruleID: advisory.id, kind: .advisory, path: ctx.fixture.path("Library/Caches/G"),
                                   displayName: "advice", identity: nil, allocatedBytes: 0, reclaimableBytes: 0,
                                   itemCount: 0, lastUsed: nil)
                let plan = await M3.plan(ctx, [(green, [g]), (yellow, [y]), (red, [r]), (advisory, [a])])
                let byID = Dictionary(uniqueKeysWithValues: plan.items.map { ($0.id, $0) })

                try TestSuite.assertEqual(byID[g.id]?.action, .quarantine(retentionHours: 24))
                try TestSuite.assertEqual(byID[g.id]?.selectedByDefault, true)
                try TestSuite.assertEqual(byID[y.id]?.action, .quarantine(retentionHours: 168))
                try TestSuite.assertEqual(byID[y.id]?.isActionable, true)
                try TestSuite.assertEqual(byID[y.id]?.selectedByDefault, false)
                try TestSuite.assertEqual(byID[r.id]?.action, .trash)
                try TestSuite.assertEqual(byID[r.id]?.isActionable, true)
                try TestSuite.assertEqual(byID[r.id]?.selectedByDefault, false)
                try TestSuite.assertEqual(byID[r.id]?.requiresPerItemConfirmation, true)
                try TestSuite.assertEqual(byID[r.id]?.isRestorable, true)
                try TestSuite.assertEqual(byID[a.id]?.action, .advisory(.revealInFinder))
                try TestSuite.assertEqual(byID[a.id]?.isActionable, false)
                try TestSuite.assertTrue(byID[a.id]?.skipReason != nil)
                try TestSuite.assertEqual(plan.defaultSelection, [g.id])
            }
        }

        await TestSuite.run("Plan: user exclusions and non-allow-listed permanent delete are blocked at plan time") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let excludedPath = try M3.cacheItem(ctx.env, "Excluded")
                let keptPath = try M3.cacheItem(ctx.env, "Kept")
                let excluded = M3.target(ctx.env, rule: rule, path: excludedPath)
                let kept = M3.target(ctx.env, rule: rule, path: keptPath)
                let settings = PlanSettings(userExclusions: [excludedPath])
                let plan = await M3.plan(ctx, [(rule, [excluded, kept])], settings: settings)
                let byID = Dictionary(uniqueKeysWithValues: plan.items.map { ($0.id, $0) })
                try TestSuite.assertEqual(byID[excluded.id]?.planVerdict, .rejected(.userExcluded(path: excludedPath)))
                try TestSuite.assertEqual(byID[kept.id]?.isActionable, true)

                let rogue = M1.rule(id: "test.rogueDelete", tier: .yellow, action: .permanentDelete)
                let rogueTarget = M3.target(ctx.env, rule: rogue, path: try M3.cacheItem(ctx.env, "Rogue"))
                let roguePlan = await M3.plan(ctx, [(rogue, [rogueTarget])])
                try TestSuite.assertFalse(roguePlan.items[0].isActionable, "\(roguePlan.items[0].planVerdict)")
                guard case .rejected(.doesNotMatchRule) = roguePlan.items[0].planVerdict else {
                    throw TestError("expected doesNotMatchRule, got \(roguePlan.items[0].planVerdict)")
                }
            }
        }

        // MARK: Confirmation

        await TestSuite.run("Confirm: every ConfirmationError case is raised") {
            try await M3.withContext { ctx in
                let green = M1.rule(id: "test.green")
                let red = M1.rule(id: "test.red", tier: .red, action: .trash)
                let huge = M1.rule(id: "test.huge", maxBytes: 10)
                let deleter = M1.rule(id: "trash.empty", tier: .yellow, action: .permanentDelete)
                let command = M3.commandRule("homebrew.cleanup")
                let g = M3.target(ctx.env, rule: green, path: try M3.cacheItem(ctx.env, "G"))
                let r = M3.target(ctx.env, rule: red, path: try M3.cacheItem(ctx.env, "R"))
                let h = M3.target(ctx.env, rule: huge, path: try M3.cacheItem(ctx.env, "H"))
                let d = M3.target(ctx.env, rule: deleter, path: try M3.cacheItem(ctx.env, "D"))
                let c = M3.commandTarget(rule: command, path: ctx.home)
                // "Always quarantine" OFF in the plan so the permanent delete is a candidate at all.
                let plan = await M3.plan(ctx, [(green, [g]), (red, [r]), (huge, [h]), (deleter, [d]), (command, [c])],
                                         settings: PlanSettings(alwaysQuarantine: false))
                for id in [g.id, r.id, d.id, c.id] {
                    try TestSuite.assertTrue(plan.items.first { $0.id == id }?.isActionable == true, "item \(id) should be actionable")
                }

                @MainActor func expect(_ expected: ConfirmationError, _ ids: Set<UUID>, _ confirmation: UserConfirmation,
                            alwaysQuarantine: Bool = true) throws {
                    do {
                        _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: ids, confirmation: confirmation,
                                                      alwaysQuarantine: alwaysQuarantine)
                        throw TestError("expected \(expected), but the plan was confirmed")
                    } catch let error as ConfirmationError {
                        try TestSuite.assertEqual(error, expected)
                    }
                }
                let ok = M3.confirmation(perItem: [r.id], irreversible: true)
                try expect(.emptySelection, [], ok)
                let stranger = UUID()
                try expect(.unknownItem(stranger), [g.id, stranger], ok)
                try expect(.notActionable(h.id), [h.id], ok)
                try expect(.missingPerItemConfirmation(r.id), [r.id], M3.confirmation(perItem: [], irreversible: true))
                try expect(.irreversibleNotAcknowledged, [c.id], M3.confirmation())
                try expect(.irreversibleNotAcknowledged, [d.id], M3.confirmation(), alwaysQuarantine: false)
                try expect(.permanentDeleteBlockedByAlwaysQuarantine(d.id), [d.id], ok, alwaysQuarantine: true)
                try expect(.confirmedTooQuickly, [g.id], M3.confirmation(after: 1.5))
                try expect(.confirmedTooQuickly, [g.id], M3.confirmation(after: -10))

                // The happy path: exactly the selected items, in plan order.
                let confirmed = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [c.id, g.id, r.id],
                                                          confirmation: M3.confirmation(perItem: [r.id], irreversible: true),
                                                          alwaysQuarantine: true)
                try TestSuite.assertEqual(confirmed.items.map(\.id), [g.id, r.id, c.id])
                try TestSuite.assertEqual(confirmed.planID, plan.id)
                try TestSuite.assertEqual(confirmed.confirmedAt, M3.reviewStart.addingTimeInterval(3))
                // Exactly 2 s is enough (spec: disabled FOR 2 s).
                _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [g.id], confirmation: M3.confirmation(after: 2),
                                              alwaysQuarantine: true)
                // A permanent delete is confirmable only with "Always quarantine" OFF and acknowledged.
                let deletion = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [d.id],
                                                         confirmation: M3.confirmation(irreversible: true),
                                                         alwaysQuarantine: false)
                try TestSuite.assertEqual(deletion.items.map(\.action), [.permanentDelete])
            }
        }

        // MARK: Hash

        await TestSuite.run("Hash: deterministic SHA-256 hex, depends on the selection, verifyHash passes for an untouched plan") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let b = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "B"))
                let plan = await M3.plan(ctx, [(rule, [a, b])])
                let one = try M3.confirmAll(plan)
                let two = try M3.confirmAll(plan)
                try TestSuite.assertEqual(one.contentHash, two.contentHash)
                try TestSuite.assertEqual(one.contentHash.count, 64)
                try TestSuite.assertTrue(one.contentHash.allSatisfy { "0123456789abcdef".contains($0) }, one.contentHash)
                try TestSuite.assertTrue(one.verifyHash())
                let onlyA = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [a.id], confirmation: M3.confirmation(),
                                                      alwaysQuarantine: true)
                try TestSuite.assertTrue(onlyA.contentHash != one.contentHash)
                // The same items under the same hash, rebuilt through the test seam, still verify.
                let rebuilt = ConfirmedPlan.makeForTesting(planID: one.planID, items: one.items, contentHash: one.contentHash,
                                                           confirmedAt: one.confirmedAt)
                try TestSuite.assertTrue(rebuilt.verifyHash())
                // A different plan id changes the hash.
                let otherPlan = ConfirmedPlan.makeForTesting(planID: UUID(), items: one.items, contentHash: one.contentHash,
                                                             confirmedAt: one.confirmedAt)
                try TestSuite.assertFalse(otherPlan.verifyHash())
            }
        }

        await TestSuite.run("Hash: verifyHash detects a changed path, identity, action, tier, size, rule or item order") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let b = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "B"))
                let plan = await M3.plan(ctx, [(rule, [a, b])])
                let confirmed = try M3.confirmAll(plan)
                let original = confirmed.items[0]
                let t = original.target

                @MainActor func target(path: String? = nil, identity: FileIdentity?? = nil, bytes: Int64? = nil) -> ScanTarget {
                    ScanTarget(id: t.id, ruleID: t.ruleID, kind: t.kind, path: path ?? t.path, displayName: t.displayName,
                               identity: identity ?? t.identity, allocatedBytes: bytes ?? t.allocatedBytes,
                               reclaimableBytes: bytes ?? t.reclaimableBytes, itemCount: t.itemCount, lastUsed: t.lastUsed,
                               owningBundleID: t.owningBundleID, notes: t.notes)
                }
                @MainActor func item(target: ScanTarget? = nil, rule r: Rule? = nil, tier: Tier? = nil, action: PlannedAction? = nil) -> PlanItem {
                    PlanItem.makeForTesting(target: target ?? t, rule: r ?? original.rule, effectiveTier: tier ?? original.effectiveTier,
                                            action: action ?? original.action, preconditions: original.preconditions,
                                            planVerdict: original.planVerdict)
                }
                let identity = t.identity!
                let tampered: [(String, PlanItem)] = [
                    ("path", item(target: target(path: ctx.fixture.path("Library/Caches/Elsewhere")))),
                    ("inode", item(target: target(identity: .some(FileIdentity(device: identity.device, inode: identity.inode + 1))))),
                    ("device", item(target: target(identity: .some(FileIdentity(device: identity.device + 1, inode: identity.inode))))),
                    ("identity removed", item(target: target(identity: .some(nil)))),
                    ("bytes", item(target: target(bytes: t.reclaimableBytes + 1))),
                    ("action trash", item(action: .trash)),
                    ("action delete", item(action: .permanentDelete)),
                    ("retention", item(action: .quarantine(retentionHours: 1))),
                    ("tier", item(tier: .yellow)),
                    ("rule allow-root", item(rule: M1.rule(id: "test.caches", allowRoots: ["{HOME}/Library"]))),
                    ("rule version", item(rule: Rule(id: rule.id, version: 2, category: rule.category, tier: rule.tier,
                                                     title: rule.title, explanation: rule.explanation,
                                                     whatYouLose: rule.whatYouLose, howItRegenerates: rule.howItRegenerates,
                                                     discovery: rule.discovery, allowRoots: rule.allowRoots,
                                                     minDepthBelowRoot: rule.minDepthBelowRoot, action: rule.action))),
                ]
                for (label, changed) in tampered {
                    let forged = ConfirmedPlan.makeForTesting(planID: confirmed.planID, items: [changed] + confirmed.items.dropFirst(),
                                                              contentHash: confirmed.contentHash, confirmedAt: confirmed.confirmedAt)
                    try TestSuite.assertFalse(forged.verifyHash(), "tampered \(label) not detected")
                }
                let reordered = ConfirmedPlan.makeForTesting(planID: confirmed.planID, items: confirmed.items.reversed(),
                                                             contentHash: confirmed.contentHash, confirmedAt: confirmed.confirmedAt)
                try TestSuite.assertFalse(reordered.verifyHash(), "reordering not detected")
                let dropped = ConfirmedPlan.makeForTesting(planID: confirmed.planID, items: Array(confirmed.items.prefix(1)),
                                                           contentHash: confirmed.contentHash, confirmedAt: confirmed.confirmedAt)
                try TestSuite.assertFalse(dropped.verifyHash(), "dropped item not detected")
                let wrongHash = ConfirmedPlan.makeForTesting(planID: confirmed.planID, items: confirmed.items,
                                                             contentHash: String(repeating: "0", count: 64), confirmedAt: confirmed.confirmedAt)
                try TestSuite.assertFalse(wrongHash.verifyHash())
            }
        }
    }
}
