import XCTest
@testable import iMop

final class AppRegistryTests: XCTestCase {
    func testProtectedVendorNamesAreGuarded() {
        // Essential vendors and command-line tools should be protected from being flagged as remnants
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Apple"))
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Google"))
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Microsoft"))
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Code"))
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Docker"))
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: ".config"))
        XCTAssertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "com.apple.Safari"))
    }

    func testUnknownRemnantIsCandidate() {
        // A dead reverse-DNS bundle that isn't protected and not installed
        let candidateName = "com.uninstalleddeveloper.obsoletejunk"
        XCTAssertFalse(FileSafetyRules.isProtectedRemnantCandidate(name: candidateName))
    }

    func testAppRegistryIndexing() {
        let registry = AppRegistryService()
        registry.indexInstalledApplications()

        // Built-in macOS apps like Finder should always be recognized
        let isFinderInstalled = registry.isAppInstalled(nameOrBundleID: "com.apple.finder") ||
                                registry.isAppInstalled(nameOrBundleID: "Finder")
        XCTAssertTrue(isFinderInstalled, "System apps like Finder should be indexed as installed")
    }
}
