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

        // v1.0 suites (replaced in Milestone 7).
        await ScannerTests.runAll()
        await AppRegistryTests.runAll()
        await SafetyAndDeletionTests.runAll()

        let exitCode = TestSuite.printSummary()
        exit(exitCode)
    }
}
