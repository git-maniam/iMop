import Foundation

@main
struct TestRunner {
    @MainActor
    static func main() async {
        // Spec §12: install the real-home tripwire before ANY test code runs. Every path the
        // canonicalizer or the file-system probes resolve is checked; a path equal to or inside the
        // real NSHomeDirectory() (normalized, component-wise, any firmlink/case spelling) prints the
        // offending path and aborts the whole run with a non-zero exit (fatalError).
        RealHomeTripwire.install()

        print("\n🚀 Starting iMop Test Suite Execution...")
        // Fixture-leak check: every iMopTests-* tree this run creates must be removed by the end.
        let fixturesBefore = FixtureLeakCheck.fixtureRootNames()

        // Milestone 1 — SafeClean safety layer (spec §12.1).
        await CanonicalizerTests.runAll()
        await DenyListTests.runAll()
        await SafetyGateTests.runAll()
        await PreconditionTests.runAll()
        await ReviewRegressionTests.runAll()

        // Milestone 2 — rules, glob, sizing, read-only scanner (spec §4, §7, §13 M2).
        await RuleCatalogTests.runAll()
        await GlobTests.runAll()
        await SizerTests.runAll()
        await SafeCleanScannerTests.runAll()
        await StaticReadOnlyTests.runAll()
        await M2ReviewRegressionTests.runAll()

        // Milestone 3 — plan, confirmation hash, Quarantine, Executor, audit log (spec §3.1, §5, §11, §13 M3).
        await PlanTests.runAll()
        await QuarantineTests.runAll()
        await ExecutorTests.runAll()
        await AuditLogTests.runAll()
        await M3ReviewRegressionTests.runAll()

        // Milestone 4 — CommandRunner and vendor command rules (spec §5.3, §6, §12.2, §13 M4).
        await CommandRunnerTests.runAll()
        await CommandClientTests.runAll()
        await CommandInspectorTests.runAll()
        await M4ReviewRegressionTests.runAll()

        // Milestone 5 — Yellow rules, XcodeInspector, ProjectScanner, AI model rules (spec §6, §13 M5).
        await XcodeInspectorTests.runAll()
        await ProjectScannerTests.runAll()
        await OtherYellowInspectorTests.runAll()
        await YellowPolicyTests.runAll()
        await M5ReviewRegressionTests.runAll()

        // Milestone 6 — OrphanDetector, LaunchAgents, Trash flows, Advisory rules, permission probes (spec §6.9, §8, §13 M6).
        await OrphanDetectorTests.runAll()
        await LaunchAgentTests.runAll()
        await TrashFlowTests.runAll()
        await AdvisoryTests.runAll()
        await PermissionProbeTests.runAll()
        await RetentionOverrideTests.runAll()

        // Milestone 7 — the app state the SwiftUI app drives (spec §3.2, §9, §13 M7). The v1.0 suites
        // (Scanner, AppRegistry, SafetyAndDeletion) were removed with the v1.0 deletion path; their
        // safety intent is covered by the M1–M6 suites above.
        await AppStateTests.runAll()
        await AboutTextTests.runAll()
        await M7ReviewRegressionTests.runAll()

        await TestSuite.run("Fixtures: no iMopTests-* directory created by this run is left in the temporary directory") {
            let leftovers = FixtureLeakCheck.fixtureRootNames().subtracting(fixturesBefore)
            try TestSuite.assertTrue(leftovers.isEmpty, "leaked fixture roots: \(leftovers.sorted())")
        }

        let exitCode = TestSuite.printSummary()
        exit(exitCode)
    }
}

/// Lists the `iMopTests-*` fixture roots directly inside the temporary directory (names only).
enum FixtureLeakCheck {
    static func fixtureRootNames() -> Set<String> {
        let tmp = FileManager.default.temporaryDirectory.path
        let names = (try? FileManager.default.contentsOfDirectory(atPath: tmp)) ?? []
        return Set(names.filter { $0.hasPrefix("iMopTests-") })
    }
}
