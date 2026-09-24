import Foundation
import iMopCore

public struct ScannerTests {
    @MainActor
    public static func runAll() async {
        print("\n🔍 Running Scanner Engine Tests...")

        await TestSuite.run("Calculate size of nonexistent directory returns 0") {
            let scanner = ScannerEngine()
            let nonexistent = URL(fileURLWithPath: "/tmp/nonexistent_\(UUID().uuidString)")
            let size = scanner.calculateSize(at: nonexistent)
            try TestSuite.assertEqual(size, 0)
        }

        await TestSuite.run("Calculate size of nested folder with files") {
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }

            let f1 = tempDir.appendingPathComponent("f1.dat")
            let f2 = tempDir.appendingPathComponent("f2.dat")
            try Data(repeating: 0x41, count: 1024).write(to: f1)
            try Data(repeating: 0x42, count: 2048).write(to: f2)

            let scanner = ScannerEngine()
            let total = scanner.calculateSize(at: tempDir)
            try TestSuite.assertEqual(total, 3072)
        }

        await TestSuite.run("Scan mock user caches and log files") {
            let mockHome = FileManager.default.temporaryDirectory.appendingPathComponent("MockHome_\(UUID().uuidString)")
            let caches = mockHome.appendingPathComponent("Library/Caches/com.sample.app")
            let logs = mockHome.appendingPathComponent("Library/Logs")

            try FileManager.default.createDirectory(at: caches, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: mockHome) }

            try Data(repeating: 0x55, count: 4096).write(to: caches.appendingPathComponent("cache.bin"))
            try Data(repeating: 0x66, count: 1024).write(to: logs.appendingPathComponent("test.log"))

            let scanner = ScannerEngine()
            let results = await scanner.scan(
                categories: [.userCaches, .systemLogs],
                customHome: mockHome
            )

            let cacheItems = results[.userCaches] ?? []
            let logItems = results[.systemLogs] ?? []

            try TestSuite.assertTrue(!cacheItems.isEmpty, "Should find mock cache items")
            try TestSuite.assertTrue(!logItems.isEmpty, "Should find mock log items")
        }

        await TestSuite.run("Scan developer derived data targets") {
            let mockHome = FileManager.default.temporaryDirectory.appendingPathComponent("MockHomeDev_\(UUID().uuidString)")
            let derivedData = mockHome.appendingPathComponent("Library/Developer/Xcode/DerivedData/App-xyz")
            try FileManager.default.createDirectory(at: derivedData, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: mockHome) }

            try Data(repeating: 0x99, count: 8192).write(to: derivedData.appendingPathComponent("Build.bin"))

            let scanner = ScannerEngine()
            let results = await scanner.scan(
                categories: [.developer],
                customHome: mockHome
            )

            let devItems = results[.developer] ?? []
            try TestSuite.assertTrue(!devItems.isEmpty, "Should discover Developer DerivedData")
            try TestSuite.assertTrue(devItems.contains(where: { $0.name == "Xcode DerivedData" }))
        }
    }
}
