import XCTest
@testable import iMop

final class SafetyAndDeletionTests: XCTestCase {
    var tempDirectory: URL!

    override func setUpWithError() throws {
        super.setUp()
        tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let dir = tempDirectory, FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.removeItem(at: dir)
        }
        super.tearDown()
    }

    func testFileSafetyRulesBlockRootAndSystemDirs() {
        XCTAssertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/")))
        XCTAssertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/System")))
        XCTAssertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/usr/bin")))
        XCTAssertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/etc")))
        XCTAssertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/Library/Preferences/SystemConfiguration")))

        // User cache or temp path should NOT be blocked by system rules
        XCTAssertFalse(FileSafetyRules.isBlockedSystemPath(tempDirectory))
    }

    func testDryRunDoesNotDeleteFiles() async throws {
        let testFile = tempDirectory.appendingPathComponent("test_cache.tmp")
        let dummyData = Data(repeating: 0x44, count: 2048)
        try dummyData.write(to: testFile)

        let item = JunkItem(
            name: "test_cache.tmp",
            path: testFile,
            size: 2048,
            lastModified: Date(),
            category: .userCaches,
            isSelected: true
        )

        let deletionService = DeletionService()
        let result = await deletionService.delete(items: [item], permanent: false, dryRun: true)

        XCTAssertEqual(result.itemsDeleted, 1)
        XCTAssertEqual(result.bytesReclaimed, 2048)
        XCTAssertTrue(result.isDryRun)
        XCTAssertTrue(FileManager.default.fileExists(atPath: testFile.path), "Dry run must NOT remove the physical file")
    }

    func testPermanentDeletionInTestSandbox() async throws {
        let testFile = tempDirectory.appendingPathComponent("junk_artifact.tmp")
        let dummyData = Data(repeating: 0x33, count: 1024)
        try dummyData.write(to: testFile)

        let item = JunkItem(
            name: "junk_artifact.tmp",
            path: testFile,
            size: 1024,
            lastModified: Date(),
            category: .developer,
            isSelected: true
        )

        let deletionService = DeletionService()
        let result = await deletionService.delete(items: [item], permanent: true, dryRun: false)

        XCTAssertEqual(result.itemsDeleted, 1)
        XCTAssertEqual(result.bytesReclaimed, 1024)
        XCTAssertFalse(FileManager.default.fileExists(atPath: testFile.path), "File should be removed after deletion")
    }
}
