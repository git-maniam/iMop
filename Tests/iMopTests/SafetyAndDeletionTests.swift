import Foundation
import iMopCore

public struct SafetyAndDeletionTests {
    @MainActor
    public static func runAll() async {
        print("\n🛡️ Running Safety Guardrails & Deletion Tests...")

        await TestSuite.run("Blocked system paths cannot be deleted or touched") {
            try TestSuite.assertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/")))
            try TestSuite.assertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/System")))
            try TestSuite.assertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/usr/bin")))
            try TestSuite.assertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/etc")))
            try TestSuite.assertTrue(FileSafetyRules.isBlockedSystemPath(URL(fileURLWithPath: "/Library/Preferences/SystemConfiguration")))

            let safeURL = FileManager.default.temporaryDirectory.appendingPathComponent("safe_dir")
            try TestSuite.assertFalse(FileSafetyRules.isBlockedSystemPath(safeURL))
        }

        await TestSuite.run("Dry-run mode does not modify or delete files") {
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }

            let testFile = tempDir.appendingPathComponent("test_cache.tmp")
            try Data(repeating: 0x44, count: 2048).write(to: testFile)

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

            try TestSuite.assertEqual(result.itemsDeleted, 1)
            try TestSuite.assertEqual(result.bytesReclaimed, 2048)
            try TestSuite.assertTrue(result.isDryRun)
            try TestSuite.assertTrue(FileManager.default.fileExists(atPath: testFile.path), "Physical file must remain untouched during dry-run")
        }

        await TestSuite.run("Permanent deletion removes file in test sandbox") {
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }

            let testFile = tempDir.appendingPathComponent("artifact.tmp")
            try Data(repeating: 0x33, count: 1024).write(to: testFile)

            let item = JunkItem(
                name: "artifact.tmp",
                path: testFile,
                size: 1024,
                lastModified: Date(),
                category: .developer,
                isSelected: true
            )

            let deletionService = DeletionService()
            let result = await deletionService.delete(items: [item], permanent: true, dryRun: false)

            try TestSuite.assertEqual(result.itemsDeleted, 1)
            try TestSuite.assertEqual(result.bytesReclaimed, 1024)
            try TestSuite.assertFalse(FileManager.default.fileExists(atPath: testFile.path), "Physical file must be removed after deletion")
        }
    }
}
