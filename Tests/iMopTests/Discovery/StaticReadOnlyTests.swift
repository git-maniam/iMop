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
        // Review M2: metadata / link mutations.
        "setattrlist", "chmod", "chown", "chflags", "utimes", "utimensat", "truncate(", "linkat", "symlinkat",
        "symlink(", "createSymbolicLink", "linkItem", "setAttributes", "recycle(", "futimens", "lchmod", "mkfifo",
        "mknod", "undelete", "revoke(",
    ]

    /// Review M2: every Discovery/Sizing/Rules file reads the file system only through this probe,
    /// so its section of LiveEnvironment.swift is held to the same rule. The section runs from the
    /// first marker up to (not including) the second.
    static let liveProbeFile = "Environment/LiveEnvironment.swift"
    static let liveProbeSection = (start: "// MARK: - Shared helpers", end: "// MARK: - Processes")

    /// `(label, line number, text)` for every line that must be free of mutation APIs.
    static func linesToScan() throws -> [(String, Int, String)] {
        var lines: [(String, Int, String)] = []
        let path = M2.coreSourcesPath + "/" + liveProbeFile
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw TestError("cannot read \(path)") }
        let all = text.components(separatedBy: "\n")
        guard let start = all.firstIndex(where: { $0.hasPrefix(liveProbeSection.start) }),
              let end = all.firstIndex(where: { $0.hasPrefix(liveProbeSection.end) }), start < end else {
            throw TestError("LiveFileSystemProbe section markers not found in \(liveProbeFile)")
        }
        for index in start..<end { lines.append((liveProbeFile, index + 1, all[index])) }
        return lines
    }


    // MARK: - Milestone 3: mutation confinement (spec §3.1, §10)

    /// The only directory whose sources may call the raw file-mutation primitives.
    static let executionDirectory = "Sources/iMopCore/Execution/"

    /// TODO(M7): the v1.0 deletion path is removed in Milestone 7, together with its views. Until
    /// then it is the single explicitly allow-listed exception.
    static let legacyAllowList: Set<String> = ["Sources/iMopCore/Services/DeletionService.swift"]

    /// Raw removal / move primitives that must stay inside Execution/.
    static let confinedTokens = ["removefile", "renamex_np", "trashItem", "removeItem",
                                 // Review M3: the descriptor-relative variants used by Execution/.
                                 "renameatx_np", "removefileat", "unlinkat"]

    /// Declarations of a raw "delete this path" style API.
    static let rawDeletePattern = try! NSRegularExpression(
        pattern: #"func\s+(delete|remove|erase|wipe|destroy|unlink|trash|purge)[A-Za-z]*\s*\(\s*(_\s+)?(path|paths|at|atPath|url|urls|item|items|file|files)\b"#,
        options: [.caseInsensitive])

    /// `(repo-relative path, line number, text)` of every line of every Swift file under Sources/.
    static func allSourceLines() throws -> [(String, Int, String)] {
        let sources = M2.repoRoot + "/Sources"
        guard let walker = FileManager.default.enumerator(atPath: sources) else { throw TestError("cannot list \(sources)") }
        var result: [(String, Int, String)] = []
        while let rel = walker.nextObject() as? String {
            guard rel.hasSuffix(".swift") else { continue }
            let path = sources + "/" + rel
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw TestError("cannot read \(path)") }
            for (index, line) in text.components(separatedBy: "\n").enumerated() {
                result.append(("Sources/" + rel, index + 1, line))
            }
        }
        return result
    }

    static func declaresRawDelete(_ line: String) -> Bool {
        rawDeletePattern.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil
    }

    /// Review M3: declarations that must be `@_spi(FixtureTesting)` (the line right above them).
    static let spiOnlyDeclarations: [(file: String, declaration: String)] = [
        ("Sources/iMopCore/Execution/Quarantine.swift", "public func quarantine(target:"),
        ("Sources/iMopCore/Execution/Quarantine.swift", "public init(environment: SafeCleanEnvironment, gate: SafetyGate"),
        ("Sources/iMopCore/Execution/Trash.swift", "public init(mutationPolicy: MutationPolicy"),
        ("Sources/iMopCore/Execution/MutationPolicy.swift", "public static func fixtureOnly("),
    ]

    // MARK: - Milestone 4: no shell, no privilege escalation, processes only in CommandRunner (spec §5.3, §10)

    /// The only file that may start a process.
    static let commandRunnerFile = "Sources/iMopCore/Execution/CommandRunner.swift"

    /// Spec §10 tokens that must not appear anywhere in Sources/ (Swift and JSON, comments included).
    static let shellTokens: [(label: String, pattern: NSRegularExpression)] = [
        ("/bin/sh", #"/bin/sh"#), ("/bin/zsh", #"/bin/zsh"#), ("/bin/bash", #"/bin/bash"#),
        // No `\s*` here: prose such as "file system (no …)" is not a call.
        ("system(", #"(?<![A-Za-z0-9_.])system\("#), ("popen(", #"popen\s*\("#), ("sudo", #"sudo"#),
        ("AuthorizationExecuteWithPrivileges", #"AuthorizationExecuteWithPrivileges"#), ("SMJobBless", #"SMJobBless"#),
        ("--volumes", #"--volumes"#), ("autoremove", #"autoremove"#),
    ].map { ($0.0, try! NSRegularExpression(pattern: $0.1)) }

    /// Process creation APIs, allowed only in `commandRunnerFile`.
    static let processTokens: [(label: String, pattern: NSRegularExpression)] = [
        ("Process(", #"(?<![A-Za-z0-9_])Process\s*\("#), ("posix_spawn", #"posix_spawn"#), ("NSTask", #"NSTask"#),
        ("launchPath", #"launchPath"#), ("fork(", #"(?<![A-Za-z0-9_])v?fork\s*\("#), ("execv", #"(?<![A-Za-z0-9_])exec[lv]p?e?\s*\("#),
    ].map { ($0.0, try! NSRegularExpression(pattern: $0.1)) }

    /// SAFETY: the exact, reviewed lines allowed to MENTION a spec §10 token: the forbidden-list
    /// definitions themselves and texts that say iMop never does it. Compared after trimming.
    static let shellTokenAllowList: [String: Set<String>] = [
        "Sources/iMopCore/Rules/CommandAllowList.swift": [
            "/// `--volumes`, `brew autoremove` and anything with a path argument are never listed.",
            "// Docker (§6.4). Never `system prune`, never `--volumes`.",
            "/// shell flags, privilege escalation, `docker … --volumes`, `brew autoremove`, `rm -rf` flags.",
            "\"--volumes\", \"autoremove\", \"sudo\", \"doas\", \"-c\",",
            "\"sudo\", \"su\", \"doas\", \"env\", \"xargs\", \"osascript\", \"perl\", \"ruby\", \"python\", \"python3\",",
        ],
        "Sources/iMopCore/Rules/Rules.json": [
            "\"explanation\": \"Old versions of the packages you installed with Homebrew and the downloads Homebrew keeps in its cache. They are removed with Homebrew's own command (brew cleanup --prune=all). iMop never runs brew autoremove, which can remove packages you rely on.\",",
        ],
    ]

    /// Every line of every Swift and JSON file under Sources/.
    static func allSourceAndJSONLines() throws -> [(String, Int, String)] {
        let sources = M2.repoRoot + "/Sources"
        guard let walker = FileManager.default.enumerator(atPath: sources) else { throw TestError("cannot list \(sources)") }
        var result: [(String, Int, String)] = []
        while let rel = walker.nextObject() as? String {
            guard rel.hasSuffix(".swift") || rel.hasSuffix(".json") else { continue }
            let path = sources + "/" + rel
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw TestError("cannot read \(path)") }
            for (index, line) in text.components(separatedBy: "\n").enumerated() {
                result.append(("Sources/" + rel, index + 1, line))
            }
        }
        return result
    }

    static func matches(_ pattern: NSRegularExpression, _ line: String) -> Bool {
        pattern.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil
    }

    @MainActor
    static func runAll() async {
        print("\n🔒 Running Static Read-Only Tests (spec §13 M2)...")

        await TestSuite.run("StaticReadOnly: Discovery/, Sizing/, Planning/, Rules/ and the live file-system probe contain no mutation API") {
            let fm = FileManager.default
            var scanned = 0
            var violations: [String] = []
            for directory in readOnlyDirectories {
                let base = M2.coreSourcesPath + "/" + directory
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: base, isDirectory: &isDir), isDir.boolValue else {
                    // Milestone 3: Planning/ exists now and is held to the same rule.
                    throw TestError("missing source directory \(base)")
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
            let probeLines = try linesToScan()
            try TestSuite.assertTrue(probeLines.count > 100, "LiveFileSystemProbe section looks truncated (\(probeLines.count) lines)")
            for (label, number, line) in probeLines {
                for token in forbiddenTokens where line.contains(token) {
                    violations.append("\(label):\(number): \(token)")
                }
            }
            try TestSuite.assertTrue(scanned >= 10, "expected the M2 + M3 planning sources, scanned \(scanned) files")
            try TestSuite.assertEqual(violations, [], "mutation APIs found:\n" + violations.joined(separator: "\n"))
        }

        await TestSuite.run("StaticReadOnly: the grep itself catches a mutation call") {
            let sample = "try FileManager.default.removeItem(atPath: p); let fd = open(p, O_RDWR)"
            let hits = forbiddenTokens.filter { sample.contains($0) }
            try TestSuite.assertTrue(Set(hits).isSuperset(of: ["removeItem", "O_RDWR"]), "\(hits)")
        }

        await TestSuite.run("StaticReadOnly: the grep catches metadata mutations (review M2)") {
            let samples = [
                "_ = Darwin.chmod(path, 0o777)", "try? FileManager.default.setAttributes([:], ofItemAtPath: p)",
                "setattrlist(p, &l, &b, 4, 0)", "lchown(p, 0, 0)", "chflags(p, 0)", "utimes(p, nil)",
                "truncate(p, 0)", "linkat(a, p, b, q, 0)", "symlinkat(p, fd, q)", "NSWorkspace.shared.recycle(urls)",
                "try fm.createSymbolicLink(atPath: a, withDestinationPath: b)",
            ]
            for sample in samples {
                try TestSuite.assertTrue(forbiddenTokens.contains { sample.contains($0) }, sample)
            }
        }

        await TestSuite.run("StaticReadOnly (M3): no source file declares a raw delete(path:)-style API; removePermanently(path:) exists only as the Executor's injected primitive") {
            var violations: [String] = []
            var primitives: [String] = []
            for (file, number, line) in try allSourceLines() where declaresRawDelete(line) {
                if legacyAllowList.contains(file) { continue }
                // The agreed PermanentRemoving primitive (Execution/Trash.swift) is reachable only
                // through Executor injection; anything else is a violation.
                if file == executionDirectory + "Trash.swift", line.contains("removePermanently(path:") {
                    primitives.append("\(file):\(number)")
                    continue
                }
                violations.append("\(file):\(number): \(line.trimmingCharacters(in: .whitespaces))")
            }
            try TestSuite.assertEqual(violations, [], "raw delete APIs:\n" + violations.joined(separator: "\n"))
            // The protocol's two requirements (path / path + pinned identity) and RemovefileRemover's two
            // implementations.
            try TestSuite.assertEqual(primitives.count, 4, "expected the protocol requirements and RemovefileRemover: \(primitives)")
        }

        await TestSuite.run("StaticReadOnly (M3): the raw-delete pattern catches the forbidden shapes") {
            for sample in ["public func delete(path: String)", "func deleteItem(at url: URL)", "func removeFile(atPath p: String)",
                           "func trash(_ path: String)", "static func purge(items: [String])"] {
                try TestSuite.assertTrue(declaresRawDelete(sample), sample)
            }
            for sample in ["public func execute(_ plan: ConfirmedPlan)", "func purgeExpired() async", "func removeAll()"] {
                try TestSuite.assertFalse(declaresRawDelete(sample), sample)
            }
        }

        await TestSuite.run("StaticReadOnly (M3): removefile / renamex_np / trashItem / removeItem appear only in Sources/iMopCore/Execution/ (+ TODO(M7) legacy DeletionService)") {
            var violations: [String] = []
            var executionHits = Set<String>()
            for (file, number, line) in try allSourceLines() {
                for token in confinedTokens where line.contains(token) {
                    if file.hasPrefix(executionDirectory) { executionHits.insert(token); continue }
                    if legacyAllowList.contains(file) { continue }
                    violations.append("\(file):\(number): \(token)")
                }
            }
            try TestSuite.assertEqual(violations, [], "mutation primitives outside Execution/:\n" + violations.joined(separator: "\n"))
            // Sanity: the scan does see the Execution module's own uses.
            try TestSuite.assertTrue(executionHits.isSuperset(of: ["removefile", "renamex_np", "trashItem"]), "\(executionHits)")
            for file in legacyAllowList {
                try TestSuite.assertTrue(FileManager.default.fileExists(atPath: M2.repoRoot + "/" + file),
                                         "TODO(M7): \(file) is gone — drop it from the allow-list")
            }
        }

        await TestSuite.run("StaticReadOnly (review M3): Quarantine's move, its gate-injecting init and the primitives' policy inits are SPI-only") {
            let lines = try allSourceLines()
            for (file, declaration) in spiOnlyDeclarations {
                let fileLines = lines.filter { $0.0 == file }
                let hits = fileLines.indices.filter { fileLines[$0].2.contains(declaration) }
                try TestSuite.assertTrue(!hits.isEmpty, "\(declaration) not found in \(file)")
                for index in hits {
                    let previous = index > 0 ? fileLines[index - 1].2.trimmingCharacters(in: .whitespaces) : ""
                    try TestSuite.assertEqual(previous, "@_spi(FixtureTesting)", "\(file):\(fileLines[index].1) \(declaration)")
                }
            }
        }

        await TestSuite.run("StaticReadOnly (M3): the app target never calls the file-action primitives directly (only the Executor may)") {
            let forbidden = ["RemovefileRemover", "FinderTrash", "removePermanently", "moveToTrash", "MutationPolicy", "fixtureOnly",
                             // Review M3: Quarantine's move is reachable only through the Executor.
                             "quarantine(target:", "gate: SafetyGate, mutationPolicy"]
            var violations: [String] = []
            for (file, number, line) in try allSourceLines() where file.hasPrefix("Sources/iMop/") {
                for token in forbidden where line.contains(token) { violations.append("\(file):\(number): \(token)") }
            }
            try TestSuite.assertEqual(violations, [], violations.joined(separator: "\n"))
        }

        await TestSuite.run("StaticReadOnly (M4): no /bin/sh, /bin/zsh, system(), popen(), sudo, AuthorizationExecuteWithPrivileges, --volumes or autoremove in Sources/ (outside the reviewed forbidden-list lines)") {
            var violations: [String] = []
            var allowedHits = 0
            for (file, number, line) in try allSourceAndJSONLines() {
                for (label, pattern) in shellTokens where matches(pattern, line) {
                    if shellTokenAllowList[file]?.contains(line.trimmingCharacters(in: .whitespaces)) == true {
                        allowedHits += 1
                        continue
                    }
                    violations.append("\(file):\(number): \(label): \(line.trimmingCharacters(in: .whitespaces))")
                }
            }
            try TestSuite.assertEqual(violations, [], "spec §10 tokens:\n" + violations.joined(separator: "\n"))
            // Sanity: the allow-listed definition lines are still there (the scan sees them).
            try TestSuite.assertTrue(allowedHits >= 6, "allow-listed lines no longer found (\(allowedHits)); update the allow-list")
            for sample in ["let p = popen(cmd, \"r\")", "system(\"rm -rf x\")", "args = [\"/bin/sh\", \"-c\", s]", "sudo brew",
                           "AuthorizationExecuteWithPrivileges(ref, tool, [], args, nil)", "docker system prune --volumes", "brew autoremove"] {
                try TestSuite.assertTrue(shellTokens.contains { matches($0.pattern, sample) }, sample)
            }
            try TestSuite.assertFalse(shellTokens.contains { matches($0.pattern, "environment.fileSystem(path)") })
        }

        await TestSuite.run("StaticReadOnly (M4): Process( / posix_spawn / NSTask appear only in Execution/CommandRunner.swift; it uses an absolute executableURL and an argument array") {
            var violations: [String] = []
            var runnerHits = 0
            for (file, number, line) in try allSourceAndJSONLines() {
                for (label, pattern) in processTokens where matches(pattern, line) {
                    if file == commandRunnerFile { runnerHits += 1; continue }
                    violations.append("\(file):\(number): \(label)")
                }
            }
            try TestSuite.assertEqual(violations, [], "process creation outside CommandRunner:\n" + violations.joined(separator: "\n"))
            try TestSuite.assertTrue(runnerHits >= 1, "CommandRunner no longer creates its Process")
            let runner = try allSourceAndJSONLines().filter { $0.0 == commandRunnerFile }.map(\.2)
            try TestSuite.assertTrue(runner.contains { $0.contains("process.executableURL = URL(fileURLWithPath: executable") })
            try TestSuite.assertTrue(runner.contains { $0.contains("process.arguments = arguments") })
            try TestSuite.assertTrue(runner.contains { $0.contains("process.standardInput = FileHandle.nullDevice") })
            try TestSuite.assertTrue(runner.contains { $0.contains("process.environment = environment") })
            try TestSuite.assertFalse(runner.contains { $0.contains("launchPath") || $0.contains("\"-c\"") })
            for sample in ["let p = Process()", "posix_spawn(&pid, path, nil, nil, argv, envp)", "let t = NSTask()", "execve(path, argv, envp)"] {
                try TestSuite.assertTrue(processTokens.contains { matches($0.pattern, sample) }, sample)
            }
            try TestSuite.assertFalse(processTokens.contains { matches($0.pattern, "notOpenByAnyProcess(target)") })
        }

        await TestSuite.run("StaticReadOnly (M4): Discovery/, Safety/, Sizing/, Planning/ and Rules/ never ask for purpose .action; only the Executor does") {
            var violations: [String] = []
            var executorHits = 0
            for (file, number, line) in try allSourceAndJSONLines() where line.contains("purpose: .action") {
                for directory in ["Discovery", "Safety", "Sizing", "Planning", "Rules"] where file.hasPrefix("Sources/iMopCore/\(directory)/") {
                    // The allow-list table DEFINES action entries; it never runs anything.
                    if file == "Sources/iMopCore/Rules/CommandAllowList.swift", line.contains("Entry(") { continue }
                    violations.append("\(file):\(number)")
                }
                if file == "Sources/iMopCore/Execution/Executor.swift" { executorHits += 1 }
            }
            try TestSuite.assertEqual(violations, [], violations.joined(separator: "\n"))
            try TestSuite.assertEqual(executorHits, 2, "the Executor: its allow-list lookup and its single run call")
        }
    }
}
