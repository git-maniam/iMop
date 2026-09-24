import Foundation

@main
struct TestRunner {
    @MainActor
    static func main() async {
        print("\n🚀 Starting iMop Test Suite Execution...")

        await ScannerTests.runAll()
        await AppRegistryTests.runAll()
        await SafetyAndDeletionTests.runAll()

        let exitCode = TestSuite.printSummary()
        exit(exitCode)
    }
}
