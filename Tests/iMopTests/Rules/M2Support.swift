import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Shared helpers for the Milestone 2 suites (rules, glob, sizing, scanner).
enum M2 {
    /// Repository root, derived from this file's location (`<repo>/Tests/iMopTests/Rules/M2Support.swift`).
    static let repoRoot: String = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url.path
    }()

    static var coreSourcesPath: String { repoRoot + "/Sources/iMopCore" }
    static var sourceRulesJSONPath: String { coreSourcesPath + "/Rules/Rules.json" }

    /// Every Green rule of spec §6 that Milestone 2 ships in Rules.json.
    static let expectedBundledRuleIDs: Set<String> = [
        "xcode.previews", "xcode.docCache", "simulator.caches", "spm.cache", "carthage.cache",
        "cocoapods.cache", "pip.cache", "poetry.cache", "cargo.registrySrc", "vscode.caches",
        "cursor.caches", "jetbrains.logs", "apps.sparkleUpdates", "apps.squirrelShipIt", "apps.savedState",
        "browser.firefox.cache", "browser.safari.cache", "mail.downloads", "logs.user",
        "logs.diagnosticReports", "ios.firmware", "apps.userCaches", "apps.containerCaches",
        "apps.electronCaches", "browser.chromium.cache",
    ]

    /// The bundled Rules.json, read straight from the source tree (not through any guarded probe:
    /// the repository is not user data).
    static func sourceRulesData() throws -> Data {
        guard let data = FileManager.default.contents(atPath: sourceRulesJSONPath) else {
            throw TestError("cannot read \(sourceRulesJSONPath)")
        }
        return data
    }

    /// A minimal valid Green rule as a JSON object; tests mutate copies of it.
    static func ruleJSON(_ id: String, overrides: [String: Any] = [:], removing: [String] = []) -> [String: Any] {
        var rule: [String: Any] = [
            "id": id,
            "category": "apps",
            "tier": "green",
            "title": "Test \(id)",
            "explanation": "A test rule.",
            "whatYouLose": "Nothing.",
            "howItRegenerates": "Automatically.",
            "discovery": ["glob": ["{HOME}/Library/Caches/com.example.\(id)/*"]],
            "allowRoots": ["{HOME}/Library/Caches/com.example.\(id)"],
            "action": "quarantine",
        ]
        for (key, value) in overrides { rule[key] = value }
        for key in removing { rule.removeValue(forKey: key) }
        return rule
    }

    static func catalogData(_ rules: [[String: Any]], version: Int = 1, extra: [String: Any] = [:]) throws -> Data {
        var file: [String: Any] = ["version": version, "rules": rules]
        for (key, value) in extra { file[key] = value }
        return try JSONSerialization.data(withJSONObject: file, options: [.sortedKeys])
    }

    static func disabledIDs(_ catalog: RuleCatalog) -> Set<String> {
        Set(catalog.disabled.map(\.ruleID))
    }

    /// Allocated bytes of a single object per `lstat` (`st_blocks * 512`): the ground truth for sizing.
    static func blocksBytes(_ path: String) -> Int64 {
        var st = Darwin.stat()
        guard Darwin.lstat(path, &st) == 0 else { return -1 }
        return Int64(st.st_blocks) * 512
    }

    /// Sum of `blocksBytes` over the non-directories of a tree, each inode once, never following symlinks.
    static func treeBlocksBytes(_ root: String) -> Int64 {
        var seen = Set<UInt64>()
        var total: Int64 = 0
        var stack = [root]
        while let path = stack.popLast() {
            var st = Darwin.stat()
            guard Darwin.lstat(path, &st) == 0 else { continue }
            let isDir = (st.st_mode & S_IFMT) == S_IFDIR
            // Directories are not counted (ATTR_FILE_ALLOCSIZE is a file attribute).
            if !isDir, seen.insert(UInt64(st.st_ino)).inserted {
                total += Int64(st.st_blocks) * 512
            }
            if isDir, let children = try? FileManager.default.contentsOfDirectory(atPath: path) {
                stack += children.map { path + "/" + $0 }
            }
        }
        return total
    }
}
