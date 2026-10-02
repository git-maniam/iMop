import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §9.9 / §13 M6: Settings → quarantine retention override. It may only LENGTHEN a rule's own
/// retention; the planned value is part of the confirmation hash and is exactly what the Quarantine
/// records.
@MainActor
enum RetentionOverrideTests {
    static let ruleID = "pip.cache"
    static let itemRel = "Library/Caches/pip/http"

    static func setOverride(_ env: FakeEnvironment, _ hours: Int?) {
        var settings = env.scanSettings
        settings.quarantineRetentionOverrideHours = hours.map { [ruleID: $0] } ?? [:]
        env.scanSettings = settings
    }

    static func plannedRetention(_ ctx: M3.Context) async throws -> (CleanupPlan, Int) {
        let results = try await M5.scanner(ctx.env).scan(ruleIDs: [ruleID])
        let plan = await ctx.planBuilder().build(from: results)
        let item = try M5.item(plan, itemRel, ctx.env.fixture)
        guard case .quarantine(let hours) = item.action else { throw TestError("not a quarantine item: \(item.action)") }
        return (plan, hours)
    }

    static func runAll() async {
        print("\n⏱️  Running Retention Override Tests (spec §9.9, §13 M6)...")

        await TestSuite.run("Retention: an override may only lengthen the rule's retention; shorter / non-positive ones are ignored") {
            try await M3.withContext { ctx in
                try ctx.fixture.file(itemRel + "/payload.bin", bytes: 2_000)
                let rule = try M6.rule(ctx.env, ruleID)
                let base = rule.effectiveRetentionHours
                try TestSuite.assertTrue(base > 0)
                var (_, hours) = try await plannedRetention(ctx)
                try TestSuite.assertEqual(hours, base, "no override")
                setOverride(ctx.env, base + 100)
                (_, hours) = try await plannedRetention(ctx)
                try TestSuite.assertEqual(hours, base + 100, "longer override applies")
                for shorter in [base - 1, 1, 0, -24] {
                    setOverride(ctx.env, shorter)
                    (_, hours) = try await plannedRetention(ctx)
                    try TestSuite.assertEqual(hours, base, "override \(shorter) must be ignored")
                    try TestSuite.assertEqual(ctx.env.scanSettings.effectiveRetentionHours(for: rule), base)
                }
                // Overrides for other rules do not leak.
                var settings = ctx.env.scanSettings
                settings.quarantineRetentionOverrideHours = ["logs.user": base + 500]
                ctx.env.scanSettings = settings
                (_, hours) = try await plannedRetention(ctx)
                try TestSuite.assertEqual(hours, base)
            }
        }

        await TestSuite.run("Retention: the overridden retention is hashed, executed and recorded consistently") {
            try await M3.withContext { ctx in
                try ctx.fixture.file(itemRel + "/payload.bin", bytes: 2_000)
                let base = try M6.rule(ctx.env, ruleID).effectiveRetentionHours
                let longer = base + 48
                setOverride(ctx.env, longer)
                let (plan, hours) = try await plannedRetention(ctx)
                try TestSuite.assertEqual(hours, longer)
                let confirmed = try M3.confirmAll(plan)
                try TestSuite.assertEqual(confirmed.contentHash, ConfirmedPlan.hash(planID: plan.id, items: confirmed.items))
                // The retention is part of the hash: the same item with the rule's own retention hashes differently.
                let item = confirmed.items[0]
                let shorterItem = PlanItem.makeForTesting(target: item.target, rule: item.rule, effectiveTier: item.effectiveTier,
                                                          action: .quarantine(retentionHours: base), preconditions: item.preconditions,
                                                          planVerdict: item.planVerdict)
                try TestSuite.assertTrue(ConfirmedPlan.hash(planID: plan.id, items: [shorterItem]) != confirmed.contentHash)

                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .quarantined(let entryID) = try M3.status(run.report, item.id) else {
                    throw TestError("expected quarantined, got \(try M3.status(run.report, item.id))")
                }
                let entries = try await ctx.quarantine.sessions().flatMap(\.entries)
                let entry = try M5.unwrap(entries.first { $0.id == entryID })
                let recorded = entry.expiresAt.timeIntervalSince(entry.quarantinedAt)
                try TestSuite.assertTrue(abs(recorded - TimeInterval(longer) * 3_600) < 2, "recorded \(recorded / 3_600) h, expected \(longer) h")
            }
        }

        await TestSuite.run("Retention: a plan whose retention no longer matches the settings (or is shorter than the rule's) is skipped") {
            try await M3.withContext { ctx in
                try ctx.fixture.file(itemRel + "/payload.bin", bytes: 2_000)
                let base = try M6.rule(ctx.env, ruleID).effectiveRetentionHours
                setOverride(ctx.env, base + 48)
                let (plan, _) = try await plannedRetention(ctx)
                let confirmed = try M3.confirmAll(plan)
                setOverride(ctx.env, nil) // settings changed between plan and execute
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .skipped(.doesNotMatchRule) = try M3.status(run.report, confirmed.items[0].id) else {
                    throw TestError("expected skipped, got \(try M3.status(run.report, confirmed.items[0].id))")
                }
                try TestSuite.assertTrue(M3.exists(ctx.fixture.path(itemRel + "/payload.bin")))

                // A hand-built plan with a SHORTER retention than the rule's is refused too.
                let item = confirmed.items[0]
                let shorter = PlanItem.makeForTesting(target: item.target, rule: item.rule, effectiveTier: item.effectiveTier,
                                                      action: .quarantine(retentionHours: max(1, base - 1)),
                                                      preconditions: item.preconditions, planVerdict: .allowed)
                let shortPlan = CleanupPlan.makeForTesting(createdAt: M3.reviewStart, items: [shorter])
                let shortConfirmed = try M3.confirmAll(shortPlan)
                let shortRun = try await M3.run(ctx.executor(remover: RefusingRemover()), shortConfirmed)
                guard case .skipped = try M3.status(shortRun.report, shorter.id) else {
                    throw TestError("expected skipped, got \(try M3.status(shortRun.report, shorter.id))")
                }
                try TestSuite.assertTrue(M3.exists(ctx.fixture.path(itemRel + "/payload.bin")))
            }
        }
    }
}
