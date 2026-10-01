import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §4 glob grammar (`{HOME}`, literal segments, `*` within one segment) and read-only expansion.
struct GlobTests {
    @MainActor
    static func runAll() async {
        print("\n✳️  Running Glob Tests (spec §4)...")

        await TestSuite.run("Glob: grammar accepts {HOME}-anchored literal and single-segment wildcard patterns") {
            for raw in ["{HOME}/Library/Caches/*", "{HOME}/Library/Caches/*.ShipIt", "{HOME}/Library/Caches/*/org.sparkle-project.Sparkle",
                        "{HOME}/Library/Application Support/Code/Code Cache", "{HOME}/a/*b*c", "{HOME}/.cargo/registry/src/*",
                        "{HOME}/Library/iTunes/iPhone Software Updates/*.ipsw", "/cores/core.*", "/Applications/Install macOS *.app"] {
                try TestSuite.assertTrue(GlobPattern(raw) != nil, raw)
            }
            let p = try unwrap(GlobPattern("{HOME}/Library/Caches/*.ShipIt"))
            try TestSuite.assertEqual(p.segments, ["Library", "Caches", "*.ShipIt"])
            try TestSuite.assertTrue(p.isHomeAnchored)
            try TestSuite.assertEqual(p.resolved(home: "/Users/test"), ["Users", "test", "Library", "Caches", "*.ShipIt"])
            try TestSuite.assertEqual(p.resolved(home: "relative/home"), [])
            try TestSuite.assertFalse(p.isWildcard(at: 1))
            try TestSuite.assertTrue(p.isWildcard(at: 2))
        }

        await TestSuite.run("Glob: grammar rejects **, ?, [, {, .., ., empty segments and non-home roots") {
            for raw in ["", "Library/Caches/*", "~/Library/Caches/*", "{HOME}", "{HOME}/", "{HOME}//Caches", "{HOME}/Library/",
                        "{HOME}/**", "{HOME}/Library/**/Caches", "{HOME}/Library/Caches**", "{HOME}/Library/Cache?",
                        "{HOME}/Library/[Cc]aches", "{HOME}/Library/{Caches,Logs}", "{HOME}/Library/Caches/{HOME}",
                        "{HOME}/Library/../.ssh", "{HOME}/./Library", "{HOME}/..", "{HOME}/Library/Caches/a\\b",
                        "{home}/Library/Caches/*", "{HOME}Library/Caches", "/tmp/*", "/etc/hosts", "/Users/x/Library/*",
                        "/cores", "/*/core", "{HOME}/Library/Caches/a\nb", "/Applications"] {
                try TestSuite.assertTrue(GlobPattern(raw) == nil, "must reject \(raw.debugDescription)")
            }
        }

        await TestSuite.run("Glob: segment matching is case/NFC-insensitive, * stays within one segment and skips dot names") {
            let p = try unwrap(GlobPattern("{HOME}/Library/Caf\u{e9}/*.savedState"))
            try TestSuite.assertTrue(p.matches(segment: "library", at: 0))
            try TestSuite.assertTrue(p.matches(segment: "LIBRARY", at: 0))
            try TestSuite.assertTrue(p.matches(segment: "Cafe\u{301}", at: 1), "NFD spelling")
            try TestSuite.assertTrue(p.matches(segment: "CAF\u{c9}", at: 1))
            try TestSuite.assertTrue(p.matches(segment: "com.example.App.savedState", at: 2))
            try TestSuite.assertTrue(p.matches(segment: "x.SAVEDSTATE", at: 2))
            try TestSuite.assertTrue(p.matches(segment: ".savedState", at: 2) == false, "* never matches a hidden name")
            try TestSuite.assertFalse(p.matches(segment: "a/b.savedState", at: 2))
            try TestSuite.assertFalse(p.matches(segment: "com.example.savedState.bak", at: 2))
            try TestSuite.assertFalse(p.matches(segment: "..", at: 2))
            try TestSuite.assertFalse(p.matches(segment: "Libraryx", at: 0))
            try TestSuite.assertFalse(p.matches(segment: "Library", at: 7), "index out of range")
            let multi = try unwrap(GlobPattern("{HOME}/a*b*c"))
            try TestSuite.assertTrue(multi.matches(segment: "abc", at: 0))
            try TestSuite.assertTrue(multi.matches(segment: "a-x-b-y-c", at: 0))
            try TestSuite.assertFalse(multi.matches(segment: "acb", at: 0))
        }

        await TestSuite.run("GlobExpander: expands on a fixture home and returns only matching entries") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Library/Caches/com.a.App.ShipIt/update.zip", bytes: 10)
                try f.dir("Library/Caches/com.b.App.ShipIt")
                try f.file("Library/Caches/com.c.App.ShipIt", bytes: 3) // a file matches too (final segment)
                try f.dir("Library/Caches/com.d.App")
                try f.dir("Library/Caches/.hidden.ShipIt")
                try f.dir("Library/Caches/one/org.sparkle-project.Sparkle")
                try f.dir("Library/Caches/two/org.sparkle-project.Sparkle")
                try f.dir("Library/Caches/three/other")
                try f.file("Library/Caches/four", bytes: 1)
                let expander = GlobExpander(environment: env.environment)

                let shipIt = expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*.ShipIt")))
                try TestSuite.assertEqual(Set(shipIt), Set(["com.a.App.ShipIt", "com.b.App.ShipIt", "com.c.App.ShipIt"].map { f.path("Library/Caches/" + $0) }))

                let sparkle = expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*/org.sparkle-project.Sparkle")))
                try TestSuite.assertEqual(Set(sparkle), [f.path("Library/Caches/one/org.sparkle-project.Sparkle"),
                                                         f.path("Library/Caches/two/org.sparkle-project.Sparkle")])

                try TestSuite.assertEqual(expander.expand(try unwrap(GlobPattern("{HOME}/Library/Nothing/*"))), [])
                try TestSuite.assertEqual(expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/four/*"))), [])
            }
        }

        await TestSuite.run("GlobExpander: never descends through a symlinked directory; a final symlink is returned as-is") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.dir("outside/org.sparkle-project.Sparkle", base: .root)
                try f.file("outside/org.sparkle-project.Sparkle/big.bin", bytes: 100, base: .root)
                try f.symlink("Library/Caches/linked", to: f.path("outside", base: .root))
                try f.dir("Library/Caches/real/org.sparkle-project.Sparkle")
                try f.symlink("Library/Caches/LinkedLeaf.ShipIt", to: f.path("outside", base: .root))
                let expander = GlobExpander(environment: env.environment)

                let sparkle = expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*/org.sparkle-project.Sparkle")))
                try TestSuite.assertEqual(sparkle, [f.path("Library/Caches/real/org.sparkle-project.Sparkle")])

                let leaf = expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*.ShipIt")))
                try TestSuite.assertEqual(leaf, [f.path("Library/Caches/LinkedLeaf.ShipIt")])

                // A symlinked literal intermediate directory ends the walk too.
                try f.dir("realLogs/JetBrains/IDEA", base: .root)
                try f.symlink("Library/Logs", to: f.path("realLogs", base: .root))
                try TestSuite.assertEqual(expander.expand(try unwrap(GlobPattern("{HOME}/Library/Logs/JetBrains/*"))), [])
                // Nothing outside the fixture home was listed.
                let listed = env.fileSystem.recordedCalls.filter { $0.0 == .contentsOfDirectory }.map(\.1)
                try TestSuite.assertFalse(listed.contains { $0.hasPrefix(f.path("outside", base: .root)) || $0.hasPrefix(f.path("realLogs", base: .root)) },
                                          "\(listed)")
            }
        }

        await TestSuite.run("GlobExpander: a symlinked home directory yields nothing") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.dir("realhome/Library/Caches/x", base: .root)
                try f.symlink("linkhome", to: f.path("realhome", base: .root), base: .root)
                let linked = SafeCleanEnvironment(
                    homeDirectory: URL(fileURLWithPath: f.path("linkhome", base: .root)), fileSystem: env.fileSystem,
                    processes: env.processes, runningApplications: env.runningApplications, applications: env.applications,
                    volumes: env.volumes, commands: env.commands, clock: env.clock, effectiveUserID: geteuid(), userID: getuid())
                try TestSuite.assertEqual(GlobExpander(environment: linked).expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*"))), [])
            }
        }

        await TestSuite.run("GlobExpander: excludedNames are honoured (case-insensitively)") {
            try await M1.withEnv { env in
                let f = env.fixture
                for name in ["iMop", "DiagnosticReports", "JetBrains", "Homebrew", "app.log"] {
                    try f.dir("Library/Logs/" + name)
                }
                try f.dir("Library/Logs/imop-not-excluded")
                let expander = GlobExpander(environment: env.environment)
                let pattern = try unwrap(GlobPattern("{HOME}/Library/Logs/*"))
                let found = expander.expand(pattern, excludedNames: ["IMOP", "DiagnosticReports", "jetbrains"])
                try TestSuite.assertEqual(Set(found), Set(["Homebrew", "app.log", "imop-not-excluded"].map { f.path("Library/Logs/" + $0) }))
                try TestSuite.assertEqual(expander.expand(pattern).count, 6)
            }
        }

        await TestSuite.run("GlobExpander: literal segments match case-insensitively; listing spelling is returned") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.dir("Library/Caches/CocoaPods/Pods")
                let expander = GlobExpander(environment: env.environment)
                let found = expander.expand(try unwrap(GlobPattern("{HOME}/library/CACHES/cocoapods/*")))
                try TestSuite.assertEqual(found, [f.path("Library/Caches/CocoaPods/Pods")])
            }
        }

        await TestSuite.run("GlobExpander: never crosses onto another volume") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.dir("Library/Caches/mounted/org.sparkle-project.Sparkle")
                try f.dir("Library/Caches/local/org.sparkle-project.Sparkle")
                try f.dir("Library/Caches/foreign.ShipIt")
                try f.dir("Library/Caches/local.ShipIt")
                guard let home = env.fileSystem.lstat(f.home) else { throw TestError("lstat home") }
                env.fileSystem.overrideStat(f.path("Library/Caches/mounted"), device: home.device + 1)
                env.fileSystem.overrideStat(f.path("Library/Caches/foreign.ShipIt"), device: home.device + 1)
                let expander = GlobExpander(environment: env.environment)
                try TestSuite.assertEqual(expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*/org.sparkle-project.Sparkle"))),
                                          [f.path("Library/Caches/local/org.sparkle-project.Sparkle")])
                try TestSuite.assertEqual(expander.expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*.ShipIt"))),
                                          [f.path("Library/Caches/local.ShipIt")])
            }
        }

        await TestSuite.run("GlobExpander: is read-only (only lists and lstats)") {
            try await M1.withEnv { env in
                try env.fixture.dir("Library/Caches/a/b")
                _ = GlobExpander(environment: env.environment).expand(try unwrap(GlobPattern("{HOME}/Library/Caches/*/*")))
                let methods = Set(env.fileSystem.recordedCalls.map(\.0))
                try TestSuite.assertTrue(methods.isSubset(of: [.lstat, .contentsOfDirectory]), "\(methods)")
            }
        }
    }

    static func unwrap<T>(_ value: T?, file: StaticString = #file, line: UInt = #line) throws -> T {
        guard let value else { throw TestError("unexpected nil (\(file):\(line))") }
        return value
    }
}
