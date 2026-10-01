import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §3.4 path canonicalization + `CanonicalPath` comparison semantics.
struct CanonicalizerTests {
    @MainActor
    static func runAll() async {
        print("\n🧭 Running PathCanonicalizer Tests (spec §3.4)...")

        // MARK: Expansion

        await TestSuite.run("Canonicalizer: '~' and '{HOME}' expand from environment.homeDirectory") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                let home = env.fixture.home
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("~/Library/Caches")).path, home + "/Library/Caches")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("{HOME}/Library/Caches")).path, home + "/Library/Caches")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("~")).path, home)
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("{HOME}")).path, home)
                // Never from $HOME / NSHomeDirectory: the expansion is the fixture home, not the real one.
                try TestSuite.assertFalse(RealHomeTripwire.isInsideRealHome(try M1.expectSuccess(c.lexical("~/x")).path))
            }
        }

        await TestSuite.run("Canonicalizer: '~user', relative, empty and NUL paths are rejected") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try M1.expectCanonicalizationFailed(c.lexical("~root/Library"))
                try M1.expectCanonicalizationFailed(c.lexical("Library/Caches"))
                try M1.expectCanonicalizationFailed(c.lexical("./Library"))
                try M1.expectCanonicalizationFailed(c.lexical(""))
                try M1.expectCanonicalizationFailed(c.lexical("/tmp/a\0b"))
                try M1.expectCanonicalizationFailed(c.canonicalize("Library/Caches"))
            }
        }

        await TestSuite.run("Canonicalizer: unusable home directory ('/') makes '~' paths fail") {
            try await M1.withEnv { env in
                let base = env.environment
                let rootHome = SafeCleanEnvironment(
                    homeDirectory: URL(fileURLWithPath: "/"), fileSystem: base.fileSystem, processes: base.processes,
                    runningApplications: base.runningApplications, applications: base.applications,
                    volumes: base.volumes, commands: base.commands, clock: base.clock,
                    effectiveUserID: base.effectiveUserID, userID: base.userID)
                try M1.expectCanonicalizationFailed(PathCanonicalizer(environment: rootHome).lexical("~/Library"))
            }
        }

        // MARK: Parent traversal

        await TestSuite.run("Canonicalizer: '..' rejected BEFORE standardizing ({HOME}/Library/Caches/../Keychains)") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try env.fixture.dir("Library/Caches")
                try env.fixture.dir("Library/Keychains")
                for raw in ["{HOME}/Library/Caches/../Keychains", "~/Library/Caches/../Keychains",
                            env.fixture.home + "/Library/Caches/../Keychains", "/..", "..", "/a/b/..", "/a/../a"] {
                    try M1.expectFailure(c.lexical(raw), .parentTraversal, raw)
                    try M1.expectFailure(c.canonicalize(raw), .parentTraversal, raw)
                }
                // "..." and "..x" are ordinary names, not traversal.
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/a/.../..x")).path, "/a/.../..x")
            }
        }

        // MARK: Standardization

        await TestSuite.run("Canonicalizer: '.', duplicate and trailing slashes are standardized") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                let p = try M1.expectSuccess(c.lexical("~//Library///Caches/./com.example.app/"))
                try TestSuite.assertEqual(p.path, env.fixture.home + "/Library/Caches/com.example.app")
                try TestSuite.assertEqual(Array(p.components.suffix(3)), ["Library", "Caches", "com.example.app"])
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/")).path, "/")
            }
        }

        await TestSuite.run("Canonicalizer: /var, /tmp, /etc map to their /private forms (any case)") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/var/folders/x")).path, "/private/var/folders/x")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/tmp/x")).path, "/private/tmp/x")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/etc/hosts")).path, "/private/etc/hosts")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/TMP/x")).path, "/private/tmp/x")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/private/tmp/x")).path, "/private/tmp/x")
                // Only the first component is mapped.
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/Users/tmp")).path, "/Users/tmp")
                // The real /tmp resolves (through the /tmp symlink) to the same logical form.
                try TestSuite.assertEqual(try M1.expectSuccess(c.canonicalize("/tmp")).path, "/private/tmp")
            }
        }

        // MARK: Firmlinks & /System

        await TestSuite.run("Canonicalizer: /System/Volumes/Data prefix is stripped to the logical path") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/System/Volumes/Data/Applications/X.app")).path, "/Applications/X.app")
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical("/system/volumes/DATA/private/tmp")).path, "/private/tmp")
                let firm = "/System/Volumes/Data" + env.fixture.home + "/Library/Caches"
                try TestSuite.assertEqual(try M1.expectSuccess(c.lexical(firm)).path, env.fixture.home + "/Library/Caches")
                try env.fixture.dir("Library/Caches")
                try TestSuite.assertEqual(try M1.expectSuccess(c.canonicalize(firm)).path, env.fixture.home + "/Library/Caches")
            }
        }

        await TestSuite.run("Canonicalizer: any other /System path is denied (.denyListed /System)") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                for raw in ["/System", "/System/Library/CoreServices", "/system/library", "/SYSTEM",
                            "/System/Volumes/Preboot", "/System/Volumes/Data/System/Library",
                            "/System/Volumes/Data/System/Volumes/Data/Users"] {
                    try M1.expectFailure(c.lexical(raw), .denyListed(entry: "/System"), raw)
                    try M1.expectFailure(c.canonicalize(raw), .denyListed(entry: "/System"), raw)
                }
            }
        }

        // MARK: Resolution

        await TestSuite.run("Canonicalizer: existing fixture path resolves to its lexical form") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try env.fixture.dir("Library/Caches/com.example.app")
                let lexical = try M1.expectSuccess(c.lexical("~/Library/Caches/com.example.app"))
                let resolved = try M1.expectSuccess(c.canonicalize("~/Library/Caches/com.example.app"))
                try TestSuite.assertEqual(lexical, resolved)
                try TestSuite.assertEqual(resolved.path, env.fixture.home + "/Library/Caches/com.example.app")
            }
        }

        await TestSuite.run("Canonicalizer: case variant resolves equal (normalized) to the real spelling") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try env.fixture.dir("Library/Caches/com.example.app")
                let resolved = try M1.expectSuccess(c.canonicalize("~/library/CACHES/COM.example.APP"))
                try TestSuite.assertEqual(resolved, try M1.expectSuccess(c.lexical("~/Library/Caches/com.example.app")))
            }
        }

        await TestSuite.run("Canonicalizer: missing path fails (.canonicalizationFailed)") {
            try await M1.withEnv { env in
                try M1.expectCanonicalizationFailed(env.makeCanonicalizer().canonicalize("~/Library/Caches/does-not-exist"))
            }
        }

        await TestSuite.run("Canonicalizer: canonicalPathKey and realpath must agree") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir("Library/Caches/com.example.app")
                env.fileSystem.setRealpath(env.fixture.root + "/elsewhere", for: target)
                try M1.expectCanonicalizationFailed(env.makeCanonicalizer().canonicalize(target))
            }
        }

        await TestSuite.run("Canonicalizer: either resolver failing → .canonicalizationFailed") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir("Library/Caches/com.example.app")
                env.fileSystem.setCanonicalPath(nil, for: target)
                try M1.expectCanonicalizationFailed(env.makeCanonicalizer().canonicalize(target), "canonicalPath nil")
                env.fileSystem.clearOverrides()
                env.fileSystem.fail(.realpath, path: target)
                try M1.expectCanonicalizationFailed(env.makeCanonicalizer().canonicalize(target), "realpath nil")
            }
        }

        await TestSuite.run("Canonicalizer: resolver output under /System is denied") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir("Library/Caches/evil")
                env.fileSystem.setRealpath("/System/Library", for: target)
                env.fileSystem.setCanonicalPath("/System/Library", for: target)
                try M1.expectFailure(env.makeCanonicalizer().canonicalize(target), .denyListed(entry: "/System"))
            }
        }

        await TestSuite.run("Canonicalizer: intermediate directory symlink makes resolved != lexical") {
            try await M1.withEnv { env in
                let c = env.makeCanonicalizer()
                try env.fixture.dir("elsewhere/sub", base: .root)
                try env.fixture.symlink("Library/Caches/link", to: env.fixture.path("elsewhere", base: .root))
                let raw = "~/Library/Caches/link/sub"
                let lexical = try M1.expectSuccess(c.lexical(raw))
                let resolved = try M1.expectSuccess(c.canonicalize(raw))
                try TestSuite.assertFalse(lexical == resolved)
                try TestSuite.assertEqual(resolved.path, env.fixture.root + "/elsewhere/sub")
            }
        }

        await TestSuite.run("Canonicalizer: calls RealHomeGuard with every lexical and resolved path") {
            try await M1.withEnv { env in
                let recorder = PathRecorder()
                RealHomeGuard.install { path in recorder.append(path) }
                defer { RealHomeTripwire.install() }
                let target = try env.fixture.dir("Library/Caches/com.example.app")
                _ = env.makeCanonicalizer().canonicalize("~/Library/Caches/com.example.app")
                try TestSuite.assertTrue(recorder.paths.contains(target), "\(recorder.paths)")
            }
        }

        await TestSuite.run("RealHomeTripwire: detects the real home in every spelling, never the fixture") {
            try await M1.withEnv { env in
                let real = NSHomeDirectory()
                try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome(real))
                try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome(real + "/Library/Caches"))
                try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome(real.uppercased() + "/x"))
                try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome("/System/Volumes/Data" + real + "/Library"))
                try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome("~/Library"))
                try TestSuite.assertFalse(RealHomeTripwire.isInsideRealHome(env.fixture.home))
                try TestSuite.assertFalse(RealHomeTripwire.isInsideRealHome(real + "Evil/x"))
                try TestSuite.assertFalse(RealHomeTripwire.isInsideRealHome("/Users"))
            }
        }

        // MARK: CanonicalPath semantics

        await TestSuite.run("CanonicalPath: prefix confusion (CachesEvil, Lib vs Library) is NOT inside") {
            let caches = CanonicalPath(validatedPath: "/Users/a/Library/Caches")
            try TestSuite.assertFalse(CanonicalPath(validatedPath: "/Users/a/Library/CachesEvil/x").isInsideOrEqual(caches))
            try TestSuite.assertFalse(CanonicalPath(validatedPath: "/Users/a/Library/CachesEvil").isStrictlyInside(caches))
            try TestSuite.assertFalse(CanonicalPath(validatedPath: "/Users/a/Library").isInsideOrEqual(CanonicalPath(validatedPath: "/Users/a/Lib")))
            try TestSuite.assertTrue(CanonicalPath(validatedPath: "/Users/a/Library/Caches/x").isStrictlyInside(caches))
            try TestSuite.assertNil(CanonicalPath(validatedPath: "/Users/a/Library/CachesEvil/x").depth(below: caches))
        }

        await TestSuite.run("CanonicalPath: isInsideOrEqual / isStrictlyInside / depth / appending") {
            let root = CanonicalPath(validatedPath: "/a/b")
            let child = root.appending("c").appending("d")
            try TestSuite.assertEqual(child.path, "/a/b/c/d")
            try TestSuite.assertTrue(root.isInsideOrEqual(root))
            try TestSuite.assertFalse(root.isStrictlyInside(root))
            try TestSuite.assertTrue(child.isStrictlyInside(root))
            try TestSuite.assertFalse(root.isInsideOrEqual(child))
            try TestSuite.assertEqual(child.depth(below: root), 2)
            try TestSuite.assertEqual(root.depth(below: root), 0)
            try TestSuite.assertEqual(child.parent?.path, "/a/b/c")
            try TestSuite.assertEqual(child.lastComponent, "d")
            try TestSuite.assertEqual(CanonicalPath(validatedPath: "/a//b/./").path, "/a/b")
        }

        await TestSuite.run("CanonicalPath: case- and NFC/NFD-insensitive equality, hashing and containment") {
            let nfc = "Caf\u{00E9}"          // é precomposed
            let nfd = "Cafe\u{0301}"         // e + combining acute
            try TestSuite.assertFalse(Array(nfc.unicodeScalars) == Array(nfd.unicodeScalars), "inputs must really differ")
            try TestSuite.assertEqual(PathComparison.normalize(nfc), PathComparison.normalize(nfd))
            try TestSuite.assertEqual(PathComparison.normalize("KEYCHAINS"), "keychains")
            let a = CanonicalPath(validatedPath: "/Users/a/Library/\(nfc)")
            let b = CanonicalPath(validatedPath: "/users/A/library/\(nfd.uppercased())")
            try TestSuite.assertEqual(a, b)
            try TestSuite.assertEqual(Set([a, b]).count, 1)
            try TestSuite.assertTrue(CanonicalPath(validatedPath: "/Users/a/Library/\(nfd)/x").isStrictlyInside(a))
        }
    }
}

/// Thread-safe path collector for hook tests.
final class PathRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var _paths: [String] = []
    func append(_ path: String) { lock.lock(); _paths.append(path); lock.unlock() }
    var paths: [String] { lock.lock(); defer { lock.unlock() }; return _paths }
}

extension TestSuite {
    static func assertNil<T>(_ value: T?, _ message: String = "", file: StaticString = #file, line: UInt = #line) throws {
        if let value { throw TestError("Expected nil but got \(value). \(message) (\(file):\(line))") }
    }
}
