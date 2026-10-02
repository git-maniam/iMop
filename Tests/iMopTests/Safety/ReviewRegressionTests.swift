import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Regression tests for the adversarial review of Milestone 1.
struct ReviewRegressionTests {
    @MainActor
    static func runAll() async {
        print("\n🔁 Running Milestone 1 review regression tests...")

        // MARK: Non-canonical target spellings (trailing "/", "/.", "~", {HOME})

        await TestSuite.run("Review: allowSymlinkTarget link spelled 'lnk/', 'lnk/.', '~/…/lnk/' is refused (would name the destination)") {
            try await M1.withEnv { env in
                let fx = env.fixture
                let important = try fx.dir("Projects/important")
                try fx.file("Projects/important/data.txt", bytes: 8)
                let link = try fx.symlink("Library/Caches/com.foo/lnk", to: important)
                let rule = M1.rule(id: "test.links", allowSymlinkTarget: true)
                let identity = env.fileSystem.lstat(link)?.identity
                try TestSuite.assertTrue(identity != nil)
                // The canonical spelling of the link itself is fine.
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link), rule), "canonical link")
                for raw in [link + "/", link + "/.", link + "//", "~/Library/Caches/com.foo/lnk/", "~/Library/Caches/com.foo/lnk",
                            "{HOME}/Library/Caches/com.foo/lnk", fx.home + "/Library/./Caches/com.foo/lnk"] {
                    let t = ScanTarget(ruleID: rule.id, path: raw, displayName: "lnk", identity: identity,
                                       allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                    try M1.expectRejected(await M1.validate(env, t, rule), .canonicalizationFailed("path is not in canonical form"), raw)
                }
            }
        }

        // MARK: User exclusion that is itself a symlink

        await TestSuite.run("Review: an exclusion that is a symlink also excludes its destination; dangling one fails closed") {
            try await M1.withEnv { env in
                let fx = env.fixture
                let stuff = try fx.dir("Developer/stuff")
                let nodeModules = try fx.dir("Developer/stuff/node_modules")
                try fx.file("Developer/stuff/node_modules/x.js", bytes: 4)
                _ = try fx.symlink("dev", to: stuff)
                let rule = M1.rule(id: "test.dev", allowRoots: ["{HOME}/Developer"])
                let target = env.scanTarget(ruleID: rule.id, path: nodeModules)
                try M1.expectAllowed(await M1.validate(env, target, rule), "control: no exclusion")
                for exclusion in [fx.home + "/dev", fx.home + "/dev/", "~/dev", "{HOME}/dev/"] {
                    try M1.expectRejected(await M1.validate(env, target, rule, userExclusions: [exclusion]),
                                          .userExcluded(path: exclusion), exclusion)
                }
                try M1.expectRejected(await M1.validate(env, target, rule, userExclusions: [stuff]), .userExcluded(path: stuff), "direct")
                // A dangling symlink exclusion cannot be interpreted → refuse.
                let gone = try fx.symlink("gone", to: fx.path("nowhere", base: .root))
                try M1.expectRejected(await M1.validate(env, target, rule, userExclusions: [gone]), .userExcluded(path: gone), "dangling")
            }
        }

        // MARK: Home-relative deny entries that are symlinks

        await TestSuite.run("Review: ~/Documents -> ~/Developer/docs protects the destination under ~/Documents") {
            try await M1.withEnv { env in
                let fx = env.fixture
                let docs = try fx.dir("Developer/docs")
                let drafts = try fx.dir("Developer/docs/report-drafts")
                let other = try fx.dir("Developer/other")
                _ = try fx.symlink("Documents", to: docs)
                let rule = M1.rule(id: "test.dev", allowRoots: ["{HOME}/Developer"])
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: drafts), rule), "~/Documents", "inside destination")
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: docs), rule), "~/Documents", "destination itself")
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: other), rule), "unrelated sibling")
            }
        }

        await TestSuite.run("Review: wildcard entry child that is a symlink (Containers/com.apple.X -> elsewhere) protects the destination") {
            try await M1.withEnv { env in
                let fx = env.fixture
                let notes = try fx.dir("Developer/notesdata")
                let item = try fx.dir("Developer/notesdata/store")
                try fx.dir("Library/Containers/com.example.app")
                _ = try fx.symlink("Library/Containers/com.apple.Notes", to: notes)
                let rule = M1.rule(id: "test.dev", allowRoots: ["{HOME}/Developer"])
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: item), rule),
                                        "~/Library/Containers/com.apple.*")
                // A whole wildcard directory reached through a symlink.
                let prefs = try fx.dir("Developer/prefs")
                let plist = try fx.file("Developer/prefs/com.apple.dock.plist", bytes: 2)
                let other = try fx.file("Developer/prefs/com.example.app.plist", bytes: 2)
                _ = try fx.symlink("Library/Preferences", to: prefs)
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: plist), rule),
                                        "~/Library/Preferences/com.apple.*")
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: other), rule), "non-Apple plist")
            }
        }

        await TestSuite.run("Review: an unresolvable (dangling) protected entry link fails closed for everything under home") {
            try await M1.withEnv { env in
                let fx = env.fixture
                let cache = try fx.dir("Library/Caches/com.example.app")
                let rule = M1.rule()
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: cache), rule), "control")
                _ = try fx.symlink("Music", to: fx.path("unmounted/Music", base: .root))
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: cache), rule),
                                        "~/Music (link could not be resolved)")
            }
        }

        // MARK: Symlink target name spelled with Unicode case folding

        await TestSuite.run("Review: allowSymlinkTarget name must match its on-disk entry ('Addreſſbook' for AddressBook)") {
            try await M1.withEnv { env in
                let fx = env.fixture
                let dest = try fx.dir("Developer/ab")
                let link = try fx.symlink("Library/Application Support/AddressBook", to: dest)
                let rule = M1.rule(id: "test.support.links", allowRoots: ["{HOME}/Library/Application Support"],
                                   allowSymlinkTarget: true)
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link), rule),
                                        "~/Library/Application Support/AddressBook")
                let folded = fx.home + "/Library/Application Support/Addre\u{017F}\u{017F}book"
                let t = ScanTarget(ruleID: rule.id, path: folded, displayName: "x", identity: env.fileSystem.lstat(link)?.identity,
                                   allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                let verdict = await M1.validate(env, t, rule)
                if env.fileSystem.lstat(folded) != nil {
                    try M1.expectRejected(verdict, .canonicalizationFailed("symlink name does not match its directory entry"), "folded spelling")
                } else {
                    try M1.expectRejected(verdict, .itemMissing, "volume does not fold ſ")
                }
                // A plain ASCII case variant of a harmless link is still accepted (spelling taken from disk).
                let real = try fx.file("Library/Caches/com.example.app/real.bin", bytes: 2)
                let alias = try fx.symlink("Library/Caches/com.example.app/Alias", to: real)
                let linkRule = M1.rule(id: "test.links", allowSymlinkTarget: true)
                let upper = fx.home + "/Library/Caches/com.example.app/ALIAS"
                let u = ScanTarget(ruleID: linkRule.id, path: upper, displayName: "x", identity: env.fileSystem.lstat(alias)?.identity,
                                   allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                try M1.expectAllowed(await M1.validate(env, u, linkRule), "ASCII case variant")
            }
        }

        // MARK: Spotlight

        await TestSuite.run("Review: Spotlight bundle-ID query is case-insensitive; implausible IDs never queried") {
            try TestSuite.assertEqual(LiveApplicationLocator.spotlightQueryString(forBundleIdentifier: "com.apple.safari"),
                                      "kMDItemCFBundleIdentifier == \"com.apple.safari\"c")
            try TestSuite.assertNil(LiveApplicationLocator.spotlightQueryString(forBundleIdentifier: "x\" || kMDItemFSName == \"*"))
            try TestSuite.assertNil(LiveApplicationLocator.spotlightQueryString(forBundleIdentifier: ""))
        }

        await TestSuite.run("Review: Spotlight lookup — case variants agree, timeout answers nil (fail closed) without racing") {
            // Read-only Spotlight index queries for a system app; no file under the real home is opened.
            let locator = LiveApplicationLocator(spotlightTimeout: 20)
            let exact = locator.spotlightApplicationPaths(forBundleIdentifier: "com.apple.finder")
            if let exact, !exact.isEmpty {
                let variant = locator.spotlightApplicationPaths(forBundleIdentifier: "COM.APPLE.FINDER")
                try TestSuite.assertEqual(variant.map(Set.init), Set(exact), "case variant must find the same app")
            }
            let instant = LiveApplicationLocator(spotlightTimeout: 0)
            for _ in 0..<3 {
                try TestSuite.assertNil(instant.spotlightApplicationPaths(forBundleIdentifier: "com.apple.finder"))
            }
            // The serial queue keeps working after abandoned requests.
            if exact != nil {
                let again = locator.spotlightApplicationPaths(forBundleIdentifier: "com.apple.finder")
                try TestSuite.assertEqual(again.map(Set.init), exact.map(Set.init))
            }
        }

        // MARK: Real-home tripwire and probe admission

        await TestSuite.run("Review: tripwire treats relative and '..' paths conservatively; probe refuses them") {
            try await M1.withEnv { env in
                let cwd = FileManager.default.currentDirectoryPath
                if RealHomeTripwire.isInsideRealHome(cwd) {
                    try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome("Package.swift"), "relative path resolves against cwd")
                }
                try TestSuite.assertTrue(RealHomeTripwire.isInsideRealHome("/private/tmp/../../Users/someone"))
                try TestSuite.assertFalse(RealHomeTripwire.isInsideRealHome(env.fixture.home + "/x"))

                let probe = LiveFileSystemProbe()
                try env.fixture.file("Library/Caches/f.txt", bytes: 1)
                for bad in ["Package.swift", "relative/x", env.fixture.home + "/Library/../Library/Caches/f.txt", ""] {
                    try TestSuite.assertNil(probe.lstat(bad), bad)
                    try TestSuite.assertNil(probe.stat(bad), bad)
                    try TestSuite.assertNil(probe.realpath(bad), bad)
                    try TestSuite.assertNil(probe.isUbiquitousItem(bad), bad)
                    try TestSuite.assertNil(probe.extendedAttributeNames(bad), bad)
                    try TestSuite.assertNil(probe.contentsOfDirectory(bad), bad)
                }
                try TestSuite.assertTrue(probe.lstat(env.fixture.home + "/Library/Caches/f.txt") != nil)
            }
        }

        await TestSuite.run("Review: probe reports where a link-following call really lands to the real-home guard") {
            try await M1.withEnv { env in
                let elsewhere = try env.fixture.dir("elsewhere", base: .root)
                let link = try env.fixture.symlink("Library/Caches/jump", to: elsewhere)
                let recorder = PathRecorder()
                RealHomeGuard.install { path in recorder.append(path) }
                defer { RealHomeTripwire.install() }
                let probe = LiveFileSystemProbe()
                _ = probe.stat(link + "/")
                _ = probe.stat(link)
                _ = probe.isUbiquitousItem(link)
                try TestSuite.assertTrue(recorder.paths.contains(elsewhere), "\(recorder.paths)")
                // lstat does not follow the final link: it reports the link's resolved parent + name.
                let before = recorder.paths.count
                _ = probe.lstat(link)
                try TestSuite.assertTrue(recorder.paths.dropFirst(before).contains(link), "\(recorder.paths)")
            }
        }

        // MARK: Open-file inspection fails closed

        await TestSuite.run("Review: libproc failure classification (ESRCH/zombie/other-user skip; same-user error → cannot evaluate)") {
            let me = getuid()
            try TestSuite.assertEqual(LiveProcessInspector.classifyFailure(pid: getpid(), errno: ESRCH, myUID: me), .skip)
            try TestSuite.assertEqual(LiveProcessInspector.classifyFailure(pid: getpid(), errno: EPERM, myUID: me), .cannotEvaluate)
            try TestSuite.assertEqual(LiveProcessInspector.classifyFailure(pid: getpid(), errno: EIO, myUID: me), .cannotEvaluate)
            // launchd (pid 1) is root-owned: EPERM there is the normal unprivileged case.
            if me != 0 {
                try TestSuite.assertEqual(LiveProcessInspector.classifyFailure(pid: 1, errno: EPERM, myUID: me), .skip)
                try TestSuite.assertEqual(LiveProcessInspector.classifyFailure(pid: 1, errno: EIO, myUID: me), .cannotEvaluate)
            }
        }

        await TestSuite.run("Review: live open-file scan finds this process's open fixture file") {
            try await M1.withEnv { env in
                let dir = try env.fixture.dir("Library/Caches/com.example.open")
                let file = try env.fixture.file("Library/Caches/com.example.open/held.bin", bytes: 16)
                guard let handle = FileHandle(forReadingAtPath: file) else { throw TestError("cannot open fixture file") }
                defer { try? handle.close() }
                let scan = LiveProcessInspector.openVnodes(of: getpid(), myUID: getuid()) { path in
                    path.hasSuffix("/com.example.open/held.bin")
                }
                try TestSuite.assertEqual(scan, .match)
                let pids = LiveProcessInspector().pidsWithOpenFiles(under: dir)
                try TestSuite.assertTrue(pids != nil, "same-user processes must be inspectable")
                try TestSuite.assertTrue(pids?.contains(getpid()) == true, "\(String(describing: pids))")
            }
        }
    }
}
