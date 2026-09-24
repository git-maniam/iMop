import XCTest
@testable import iMop

final class ScannerTests: XCTestCase {
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

    func testCalculateSizeNonExistent() {
        let scanner = ScannerEngine()
        let nonExistentURL = tempDirectory.appendingPathComponent("doesNotExist")
        XCTAssertEqual(scanner.calculateSize(at: nonExistentURL), 0)
    }

    func testCalculateSizeWithNestedFiles() throws {
        let scanner = ScannerEngine()
        let folder = tempDirectory.appendingPathComponent("nestedFolder")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)

        let file1 = folder.appendingPathComponent("file1.dat")
        let data1 = Data(repeating: 0x41, count: 1024) // 1 KB
        try data1.write(to: file1)

        let file2 = folder.appendingPathComponent("file2.dat")
        let data2 = Data(repeating: 0x42, count: 2048) // 2 KB
        try data2.write(to: file2)

        let total = scanner.calculateSize(at: folder)
        XCTAssertEqual(total, 3072)
    }

    func testScannerDetectsUserCachesAndLogs() async throws {
        // Set up mock home directory
        let mockHome = tempDirectory.appendingPathComponent("MockHome")
        let cachesDir = mockHome.appendingPathComponent("Library/Caches/com.sample.app")
        let logsDir = mockHome.appendingPathComponent("Library/Logs")

        try FileManager.default.createDirectory(at: cachesDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)

        // Write a 4KB cache file
        let cacheFile = cachesDir.appendingPathComponent("sample_cache.bin")
        try Data(repeating: 0x55, count: 4096).write(to: cacheFile)

        // Write a 1KB log file
        let logFile = logsDir.appendingPathComponent("diagnostic.log")
        try Data(repeating: 0x66, count: 1024).write(to: logFile)

        let scanner = ScannerEngine()
        let results = await scanner.scan(
            categories: [.userCaches, .systemLogs],
            customHome: mockHome
        )

        let cacheItems = results[.userCaches] ?? []
        XCTAssertFalse(cacheItems.isEmpty, "Scanner should discover the mock user cache folder")
        XCTAssertTrue(cacheItems.contains(where: { $0.path.path.contains("com.sample.app") }))

        let logItems = results[.systemLogs] ?? []
        XCTAssertFalse(logItems.isEmpty, "Scanner should discover the mock log file")
        XCTAssertTrue(logItems.contains(where: { $0.name == "diagnostic.log" }))
    }

    func testDeveloperJunkDetection() async throws {
        let mockHome = tempDirectory.appendingPathComponent("MockHome")
        let derivedData = mockHome.appendingPathComponent("Library/Developer/Xcode/DerivedData/App-xyz")
        try FileManager.default.createDirectory(at: derivedData, withIntermediateDirectories: true)

        let dummyBuildFile = derivedData.appendingPathComponent("Build.bin")
        try Data(repeating: 0x99, count: 8192).write(to: dummyBuildFile)

        let scanner = ScannerEngine()
        let results = await scanner.scan(
            categories: [.developer],
            customHome: mockHome
        )

        let devItems = results[.developer] ?? []
        XCTAssertFalse(devItems.isEmpty)
        XCTAssertTrue(devItems.contains(where: { $0.name == "Xcode DerivedData" }))
        XCTAssertGreaterThanOrEqual(devItems.first?.size ?? 0, 8192)
    }
}
