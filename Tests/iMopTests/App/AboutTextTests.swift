import Foundation

/// Milestone 7 (static): the product owner's About text and version badge, and the absence of the
/// v1.0 deletion toggles and types from the app. Reads the SOURCE files (located via #filePath).
struct AboutTextTests {
    /// Repo root: four path components above Tests/iMopTests/App/AboutTextTests.swift.
    static var repoRoot: String {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url.path
    }

    static var appSourcesPath: String { repoRoot + "/Sources/iMop" }

    /// The three About lines, EXACTLY as the product owner wrote them (spacing and case included).
    static let aboutLines = [
        "Created by Ravi Subramaniam, Bangalore (India)",
        "License :This is a Freeware",
        "version 1.1 (Last updated 1/Oct)",
    ]

    /// v1.0 types/files removed in Milestone 7. Matched as whole identifiers, so e.g.
    /// `CategoryDetailViewModel` or `ScanProgressEvent` (current API) do not match.
    static let removedTypes = [
        "JunkItem", "JunkCategory", "JunkCategoryType", "DeletionService", "ScannerEngine", "FileSafetyRules",
        "AppRegistryService", "PermissionService", "SystemHealthService", "DashboardViewModel", "DashboardView",
        "CategoryDetailView", "FileItemRowView", "ConfirmationModalView", "CompletionModalView", "ScanProgress",
        "isDryRunEnabled", "isPermanentDeleteEnabled",
    ]

    /// v1.0 toggle labels that must not come back (case-sensitive, as v1.0 spelled them).
    static let removedToggleLabels = ["Permanent Delete", "Permanent Deletion\"", "Dry Run Mode"]

    static func read(_ path: String) throws -> String {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw TestError("cannot read \(path)") }
        return text
    }

    /// `(repo-relative path, line number, text)` of every Swift line under `directory`.
    static func swiftLines(under directory: String) throws -> [(String, Int, String)] {
        guard let walker = FileManager.default.enumerator(atPath: directory) else { throw TestError("cannot list \(directory)") }
        var result: [(String, Int, String)] = []
        while let rel = walker.nextObject() as? String {
            guard rel.hasSuffix(".swift") else { continue }
            let text = try read(directory + "/" + rel)
            for (index, line) in text.components(separatedBy: "\n").enumerated() {
                result.append((String(directory.dropFirst(repoRoot.count + 1)) + "/" + rel, index + 1, line))
            }
        }
        return result
    }

    @MainActor
    static func runAll() async {
        print("\nℹ️  Running About / v1.1 Static Tests (spec §9, §13 M7)...")

        await TestSuite.run("About: AboutView shows the three About lines verbatim, each as one Text(verbatim:)") {
            let text = try read(appSourcesPath + "/Views/AboutView.swift")
            for line in aboutLines {
                try TestSuite.assertTrue(text.contains("Text(verbatim: \"\(line)\")"), "missing verbatim About line: \(line)")
            }
            try TestSuite.assertTrue(text.contains("Text(verbatim: \"iMop\")"), "About window must show the name iMop")
        }

        await TestSuite.run("About: the app menu replaces the standard About with an \"About iMop\" item opening the about window") {
            let text = try read(appSourcesPath + "/App/iMopApp.swift")
            try TestSuite.assertTrue(text.contains("CommandGroup(replacing: .appInfo)"), "standard About not replaced")
            try TestSuite.assertTrue(text.contains("Button(\"About iMop\")"), "missing About iMop menu item")
            try TestSuite.assertTrue(text.contains("openWindow(id: \"about\")"), "About iMop must open the about window")
            try TestSuite.assertTrue(text.contains("Window(\"About iMop\", id: \"about\")"), "missing About window scene")
            try TestSuite.assertTrue(text.contains("AboutView()"), "About window must show AboutView")
        }

        await TestSuite.run("About: the sidebar version badge reads v1.1 (and no other version)") {
            let text = try read(appSourcesPath + "/Views/SidebarView.swift")
            try TestSuite.assertTrue(text.contains("Text(verbatim: \"v1.1\")"), "sidebar must show the v1.1 badge")
            try TestSuite.assertFalse(text.contains("\"v1.0\""), "sidebar still shows v1.0")
        }

        await TestSuite.run("v1.1: Sources/iMop has no Permanent Delete / Dry Run Mode toggles; no Sources file references a removed v1.0 type") {
            var violations: [String] = []
            for (file, number, line) in try swiftLines(under: appSourcesPath) {
                for label in removedToggleLabels where line.contains(label) {
                    violations.append("\(file):\(number) contains \(label)")
                }
                if line.contains("Toggle("), line.range(of: #"(?i)dry.?run|permanent"#, options: .regularExpression) != nil {
                    violations.append("\(file):\(number) has a dry-run / permanent-delete toggle")
                }
            }
            let patterns = removedTypes.map {
                ($0, try! NSRegularExpression(pattern: "(?<![A-Za-z0-9_])" + $0 + "(?![A-Za-z0-9_])"))
            }
            let sourceLines = try swiftLines(under: repoRoot + "/Sources")
            var scanned = 0
            for (file, number, line) in sourceLines {
                scanned += 1
                for (name, pattern) in patterns
                where pattern.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
                    violations.append("\(file):\(number) references removed v1.0 type \(name)")
                }
            }
            try TestSuite.assertTrue(scanned > 1000, "suspiciously few source lines scanned: \(scanned)")
            try TestSuite.assertTrue(violations.isEmpty, violations.joined(separator: "\n"))
        }
    }
}
