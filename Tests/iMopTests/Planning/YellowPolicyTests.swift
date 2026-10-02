import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Milestone 5 acceptance (spec §3.2, §13 M5): NOTHING that is not Green is ever preselected; every
/// Yellow rule explains what is lost; the bundled catalog loads with zero disabled rules; the M5 rules
/// declare their spec preconditions.
struct YellowPolicyTests {
    @MainActor
    static func runAll() async {
        print("\n🟡 Running Milestone 5 Yellow policy tests (spec §3.2, §13 M5)...")

        await TestSuite.run("YellowPolicy: the bundled catalog loads with zero disabled rules and ships every M5 rule with its tier") {
            try await M1.withEnv { env in
                let bundled = RuleCatalog.loadBundled(environment: env.environment)
                let source = try M5.catalog(env)
                try TestSuite.assertEqual(bundled.disabled, [], "\(bundled.disabled)")
                try TestSuite.assertEqual(source.disabled, [], "\(source.disabled)")
                for (id, tier) in M2.m5RuleTiers {
                    try TestSuite.assertEqual(bundled.rule(id: id)?.tier, tier, id)
                }
                // Also with project roots configured (the {PROJECT_ROOTS} expansion never disables anything).
                try ProjectScannerTests.project(env.fixture, "Projects/app", files: ["package-lock.json"], dirs: ["node_modules"])
                env.scanSettings = ScanSettings(projectRoots: [env.fixture.path("Projects")])
                try TestSuite.assertEqual(RuleCatalog.loadBundled(environment: env.environment).disabled, [])
            }
        }

        await TestSuite.run("YellowPolicy: every non-Green rule has an honest explanation, whatYouLose and howItRegenerates") {
            try await M1.withEnv { env in
                for rule in RuleCatalog.loadBundled(environment: env.environment).rules where rule.tier != .green {
                    for (name, text) in [("explanation", rule.explanation), ("whatYouLose", rule.whatYouLose),
                                         ("howItRegenerates", rule.howItRegenerates)] {
                        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                        try TestSuite.assertTrue(trimmed.count >= 10, "\(rule.id).\(name): \"\(text)\"")
                    }
                }
            }
        }

        await TestSuite.run("YellowPolicy: for EVERY rule with tier != green, an allowed PlanItem is never selectedByDefault") {
            try await M1.withEnv { env in
                let catalog = RuleCatalog.loadBundled(environment: env.environment)
                let nonGreen = catalog.rules.filter { $0.tier != .green }
                try TestSuite.assertTrue(nonGreen.count >= M2.m5RuleTiers.values.filter { $0 != .green }.count)
                try env.fixture.file("Library/Caches/x/data.bin", bytes: 10)
                for rule in nonGreen {
                    let target = env.scanTarget(ruleID: rule.id, path: "Library/Caches/x")
                    let action: PlannedAction
                    switch rule.action {
                    case .command(let spec): action = .command(spec, argument: nil)
                    case .trash: action = .trash
                    case .permanentDelete: action = .permanentDelete
                    case .advisory(let kind): action = .advisory(kind)
                    case .quarantine: action = .quarantine(retentionHours: rule.effectiveRetentionHours)
                    }
                    for tier in [rule.tier, .red] {
                        let item = PlanItem.makeForTesting(target: target, rule: rule, effectiveTier: tier, action: action, planVerdict: .allowed)
                        try TestSuite.assertFalse(item.selectedByDefault, "\(rule.id) as \(tier)")
                    }
                }
                // Quarantine retention for Yellow is at least 7 days.
                for rule in nonGreen where rule.action == .quarantine {
                    try TestSuite.assertTrue(rule.effectiveRetentionHours >= 168, "\(rule.id): \(rule.effectiveRetentionHours)")
                }
            }
        }

        await TestSuite.run("YellowPolicy: a real plan over a fixture with every M5 rule — Yellow items may be actionable but are never preselected") {
            try await SafeCleanScannerTests.withScanEnv { env in
                let f = env.fixture
                // Add M5 Yellow material, all old enough and idle.
                try XcodeInspectorTests.derived(f, "Active-abc", plist: nil)
                try ProjectScannerTests.project(f, "Projects/app", files: ["package-lock.json"], dirs: ["node_modules/pkg"])
                try f.file(".cache/huggingface/hub/models--org--model/blobs/a", bytes: 2_000)
                try f.file(".cargo/registry/cache/index.crates.io-1/serde.crate", bytes: 2_000)
                try f.file("Library/Caches/com.notinstalled.Old/data.bin", bytes: 2_000)
                try f.file("Downloads/Xcode_16.xip", bytes: 2_000)
                for rel in ["Library/Developer/Xcode/DerivedData/Active-abc", "Library/Developer/Xcode/DerivedData/Active-abc/Build",
                            "Projects/app", "Projects/app/node_modules", "Projects/app/node_modules/pkg",
                            ".cache/huggingface/hub/models--org--model", "Library/Caches/com.notinstalled.Old",
                            "Library/Caches/com.notinstalled.App", "Downloads/Xcode_16.xip"] {
                    try M5.age(f, rel, days: 200, clock: env.clock)
                }
                try f.setModificationDate("Projects/app/package-lock.json", daysAgo: 200, clock: env.clock)
                env.scanSettings = ScanSettings(projectRoots: [f.path("Projects")])

                let results = await (try M5.scanner(env)).scan()
                let plan = await M5.plan(env, results)
                try TestSuite.assertFalse(plan.items.isEmpty)
                for item in plan.items where item.rule.tier != .green || item.effectiveTier != .green {
                    try TestSuite.assertFalse(item.selectedByDefault, "\(item.rule.id) \(item.target.path)")
                    try TestSuite.assertFalse(plan.defaultSelection.contains(item.id), item.rule.id)
                }
                let actionableYellow = plan.items.filter { $0.rule.tier == .yellow && $0.isActionable }.map(\.rule.id)
                for id in ["xcode.derivedData.active", "project.nodeModules", "ai.huggingface", "cargo.registryCache",
                           "apps.userCaches.unknownOwner", "xcode.xipDownloads"] {
                    try TestSuite.assertTrue(actionableYellow.contains(id), "\(id) should be actionable (but unselected); actionable: \(Set(actionableYellow).sorted()); blocked: \(plan.items.filter { $0.rule.id == id }.map { $0.preconditions.filter { !$0.passed } })")
                }
                // Green items are still preselected when allowed (the Yellow rules did not swallow them).
                try TestSuite.assertTrue(plan.items.contains { $0.rule.tier == .green && $0.selectedByDefault })
                try TestSuite.assertTrue(plan.defaultSelection.allSatisfy { id in plan.items.first { $0.id == id }?.effectiveTier == .green })
            }
        }

        await TestSuite.run("YellowPolicy: M5 rules declare their spec preconditions") {
            try await M1.withEnv { env in
                let catalog = try M5.catalog(env)
                func pre(_ id: String) throws -> [Precondition] {
                    guard let rule = catalog.rule(id: id) else { throw TestError("missing \(id)") }
                    return rule.preconditions
                }
                let xcode = Precondition.appNotRunning(["com.apple.dt.Xcode"])
                for id in ["xcode.derivedData.orphaned", "xcode.derivedData.active", "xcode.archives.old", "xcode.deviceSupport", "xcode.xipDownloads"] {
                    try TestSuite.assertTrue(try pre(id).contains(xcode), id)
                }
                for id in ["xcode.derivedData.orphaned", "xcode.derivedData.active"] {
                    try TestSuite.assertTrue(try pre(id).contains(.processNotRunning(["xcodebuild"])), id)
                }
                try TestSuite.assertTrue(try pre("xcode.derivedData.active").contains(.olderThan(days: 14)))
                try TestSuite.assertTrue(try pre("xcode.deviceSupport").contains(.olderThan(days: 30)))
                try TestSuite.assertTrue(try pre("xcode.xipDownloads").contains(.olderThan(days: 7)))
                try TestSuite.assertTrue(try pre("xcode.xipDownloads").contains(.notOpenByAnyProcess))
                try TestSuite.assertTrue(try pre("poetry.virtualenvs").contains(.olderThan(days: 60)))
                func processes(_ id: String) throws -> Set<String> {
                    Set(try pre(id).flatMap { p -> [String] in if case .processNotRunning(let n) = p { return n } else { return [] } })
                }
                func apps(_ id: String) throws -> Set<String> {
                    Set(try pre(id).flatMap { p -> [String] in if case .appNotRunning(let n) = p { return n } else { return [] } })
                }
                try TestSuite.assertTrue(try processes("gradle.caches").contains("java"))
                try TestSuite.assertTrue(try processes("maven.repo").isSuperset(of: ["mvn", "java"]))
                try TestSuite.assertTrue(try processes("playwright.browsers").contains("node"))
                try TestSuite.assertTrue(try apps("android.systemImages").contains("com.google.android.studio"))
                try TestSuite.assertTrue(try apps("vscode.oldExtensions").contains("com.microsoft.VSCode"))
                for id in ["jetbrains.caches.orphanedVersion", "jetbrains.caches.current"] {
                    try TestSuite.assertTrue(try apps(id).contains("com.jetbrains.*"), id)
                }
                try TestSuite.assertTrue(try pre("apps.userCaches.unknownOwner").contains(.notOpenByAnyProcess))
                try TestSuite.assertTrue(try pre("apps.userCaches.unknownOwner").contains(.olderThan(days: 30)))
                try TestSuite.assertTrue(try apps("adobe.mediaCache").contains("com.adobe.*"))
                try TestSuite.assertTrue(try apps("lightroom.previews").contains("com.adobe.LightroomClassicCC7"))
                try TestSuite.assertTrue(try pre("ai.huggingface").contains(.notOpenByAnyProcess))
                try TestSuite.assertTrue(try processes("ai.huggingface").isSuperset(of: ["python", "python3"]))
                try TestSuite.assertTrue(try apps("ai.lmstudio").contains("ai.elementlabs.lmstudio"))
                try TestSuite.assertTrue(try pre("browser.chromium.serviceWorkerCache").contains(.owningAppNotRunning))
                let tools: [String: Set<String>] = [
                    "project.nodeModules": ["node", "npm", "yarn", "pnpm", "bun"], "project.rustTarget": ["cargo", "rustc"],
                    "project.pythonVenv": ["python", "python3"], "project.pods": ["pod"], "project.nextBuild": ["node"],
                    "project.gradleBuild": ["java", "gradle"], "project.swiftBuild": ["swift-build", "swift-package"],
                ]
                for (id, names) in tools {
                    let p = try pre(id)
                    try TestSuite.assertTrue(p.contains(.projectOlderThan(days: 90)), id)
                    try TestSuite.assertTrue(p.contains(.notTrackedByGit), id)
                    try TestSuite.assertTrue(try processes(id).isSuperset(of: names), id)
                    try TestSuite.assertEqual(catalog.rule(id: id)?.allowRoots, [Rule.projectRootsToken], id)
                }
                // A project rule built in code with fewer preconditions, or as Green, is disabled.
                guard let node = catalog.rule(id: "project.nodeModules") else { throw TestError("missing") }
                let weaker = Rule(id: node.id, category: node.category, tier: node.tier, title: node.title, explanation: node.explanation,
                                  whatYouLose: node.whatYouLose, howItRegenerates: node.howItRegenerates, discovery: node.discovery,
                                  allowRoots: node.allowRoots, minDepthBelowRoot: node.minDepthBelowRoot,
                                  preconditions: node.preconditions.filter { $0 != .notTrackedByGit }, action: node.action)
                let green = Rule(id: node.id, category: node.category, tier: .green, title: node.title, explanation: node.explanation,
                                 whatYouLose: node.whatYouLose, howItRegenerates: node.howItRegenerates, discovery: node.discovery,
                                 allowRoots: node.allowRoots, minDepthBelowRoot: node.minDepthBelowRoot,
                                 preconditions: node.preconditions, action: node.action)
                for bad in [weaker, green] {
                    try TestSuite.assertEqual(RuleCatalog(validating: [bad], environment: env.environment).rules.count, 0)
                }
            }
        }
    }
}
