import Foundation

/// Spec §13 M2 acceptance: the discovery, sizing, planning and rule code is statically read-only.
/// Greps the SOURCE files (comments included) for any mutation API.
struct StaticReadOnlyTests {
    static let readOnlyDirectories = ["Discovery", "Sizing", "Planning", "Rules"]

    static let forbiddenTokens = [
        "removeItem", "trashItem", "moveItem", "unlink", "rmdir", "removefile", "rename", "renamex_np",
        "copyItem", "replaceItem", "createDirectory", "createFile", ".write(to", "write(to:", "FileHandle(forWriting",
        "FileHandle(forUpdating", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "ftruncate", "mkdir",
        "setxattr", "removexattr", "clonefile", "copyfile", "exchangedata", "fopen", "Process(", "posix_spawn",
    ]

    @MainActor
    static func runAll() async {
        print("\n🔒 Running Static Read-Only Tests (spec §13 M2)...")

        await TestSuite.run("StaticReadOnly: Discovery/, Sizing/, Planning/ (if present) and Rules/ contain no mutation API") {
            let fm = FileManager.default
            var scanned = 0
            var violations: [String] = []
            for directory in readOnlyDirectories {
                let base = M2.coreSourcesPath + "/" + directory
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: base, isDirectory: &isDir), isDir.boolValue else {
                    if directory != "Planning" { throw TestError("missing source directory \(base)") }
                    continue
                }
                guard let walker = fm.enumerator(atPath: base) else { throw TestError("cannot list \(base)") }
                while let rel = walker.nextObject() as? String {
                    guard rel.hasSuffix(".swift") || rel.hasSuffix(".json") else { continue }
                    let path = base + "/" + rel
                    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
                        throw TestError("cannot read \(path)")
                    }
                    scanned += 1
                    for (number, line) in text.components(separatedBy: "\n").enumerated() {
                        for token in forbiddenTokens where line.contains(token) {
                            violations.append("\(directory)/\(rel):\(number + 1): \(token)")
                        }
                    }
                }
            }
            try TestSuite.assertTrue(scanned >= 8, "expected the M2 sources, scanned \(scanned) files")
            try TestSuite.assertEqual(violations, [], "mutation APIs found:\n" + violations.joined(separator: "\n"))
        }

        await TestSuite.run("StaticReadOnly: the grep itself catches a mutation call") {
            let sample = "try FileManager.default.removeItem(atPath: p); let fd = open(p, O_RDWR)"
            let hits = forbiddenTokens.filter { sample.contains($0) }
            try TestSuite.assertTrue(Set(hits).isSuperset(of: ["removeItem", "O_RDWR"]), "\(hits)")
        }
    }
}
