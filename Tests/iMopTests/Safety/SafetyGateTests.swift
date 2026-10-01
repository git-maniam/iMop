import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §12.1 SafetyGate adversarial tests. Every test asserts the SPECIFIC rejection.
struct SafetyGateTests {
    static let appID = "com.example.app"
    static let appCache = "Library/Caches/com.example.app"

    @MainActor
    static func runAll() async {
        print("\n🛡️ Running SafetyGate Tests (spec §3.3, §12.1)...")

        // MARK: Happy path

        await TestSuite.run("Gate: fixture ~/Library/Caches/com.example.app with matching identity is allowed (plan + execute)") {
            try await M1.withEnv { env in
                try env.fixture.file(appCache + "/Cache.db", bytes: 128)
                let rule = M1.rule()
                let target = env.scanTarget(ruleID: rule.id, path: appCache)
                try TestSuite.assertTrue(target.identity != nil)
                try M1.expectAllowed(await M1.validate(env, target, rule, phase: .plan), "plan")
                try M1.expectAllowed(await M1.validate(env, target, rule, phase: .execute), "execute")
                let (verdict, preconditions) = await env.makeGate().validateWithDetails(target: target, rule: rule, phase: .plan)
                try M1.expectAllowed(verdict)
                try TestSuite.assertEqual(preconditions.map(\.name), ["ownedByUser", "notInsideCloudRoot"])
                try TestSuite.assertTrue(preconditions.allSatisfy(\.passed), "\(preconditions)")
                // ScanTarget.path must already be canonical: the Executor acts on that exact string, so the
                // ~ spelling (a relative path if used verbatim) is refused, not silently expanded.
                let tilde = ScanTarget(ruleID: rule.id, path: "~/" + appCache, displayName: "x", identity: target.identity,
                                       allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                try M1.expectRejected(await M1.validate(env, tilde, rule), .canonicalizationFailed("path is not in canonical form"), "~ form")
            }
        }

        await TestSuite.run("Gate: a single file deep inside the cache is allowed; non-canonical firmlink spelling is refused") {
            try await M1.withEnv { env in
                let file = try env.fixture.file(appCache + "/fsCachedData/ABC", bytes: 64)
                let rule = M1.rule()
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: file), rule))
                let firm = env.scanTarget(ruleID: rule.id, path: "/System/Volumes/Data" + env.fixture.path(appCache))
                try M1.expectRejected(await M1.validate(env, firm, rule), .canonicalizationFailed("path is not in canonical form"),
                                      "firmlink form of an allowed path")
            }
        }

        // MARK: Check 1

        await TestSuite.run("Gate check 1: injected euid 0 → .runningAsRoot (also uid 0)") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                let rule = M1.rule()
                let target = env.scanTarget(ruleID: rule.id, path: appCache)
                env.effectiveUserID = 0
                try M1.expectRejected(await M1.validate(env, target, rule), .runningAsRoot, "euid 0")
                try M1.expectRejected(await M1.validate(env, target, rule, phase: .execute), .runningAsRoot, "euid 0 execute")
                env.effectiveUserID = geteuid()
                env.userID = 0
                try M1.expectRejected(await M1.validate(env, target, rule), .runningAsRoot, "uid 0")
                // Command items too.
                let cmdRule = M1.rule(id: "test.cmd", action: .command(CommandSpec(tool: "xcrun", arguments: ["simctl", "delete", "{ITEM}"])))
                let cmd = env.scanTarget(ruleID: cmdRule.id, path: "simulator", kind: .commandItem(argument: "UDID"), captureIdentity: false)
                try M1.expectRejected(await M1.validate(env, cmd, cmdRule), .runningAsRoot, "command item")
            }
        }

        // MARK: Check 2

        await TestSuite.run("Gate check 2: '..' traversal ({HOME}/Library/Caches/../Keychains) → .parentTraversal") {
            try await M1.withEnv { env in
                try env.fixture.dir("Library/Caches")
                try env.fixture.dir("Library/Keychains")
                let rule = M1.rule()
                for raw in ["{HOME}/Library/Caches/../Keychains", "~/Library/Caches/../Keychains",
                            env.fixture.home + "/Library/Caches/com.example.app/../../Keychains"] {
                    let t = ScanTarget(ruleID: rule.id, path: raw, displayName: "x", identity: FileIdentity(device: 1, inode: 1),
                                       allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                    try M1.expectRejected(await M1.validate(env, t, rule), .parentTraversal, raw)
                }
            }
        }

        await TestSuite.run("Gate check 2: symlink target → /System is rejected (link refused; destination denied)") {
            try await M1.withEnv { env in
                let link = try env.fixture.symlink("Library/Caches/evil", to: "/System")
                let rule = M1.rule()
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link), rule), .symlinkInPath(component: link))
                let linkRule = M1.rule(id: "test.links", allowSymlinkTarget: true)
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: link), linkRule), "/System")
                // Through the link: ~/Library/Caches/evil/Library resolves under /System → denied at resolution.
                let through = env.scanTarget(ruleID: rule.id, path: link + "/Library")
                try M1.expectDenyListed(await M1.validate(env, through, rule), "/System")
            }
        }

        await TestSuite.run("Gate check 2: symlink target → ~/Documents is rejected") {
            try await M1.withEnv { env in
                let docs = try env.fixture.dir("Documents")
                try env.fixture.file("Documents/thesis.docx", bytes: 10)
                let link = try env.fixture.symlink("Library/Caches/docs", to: docs)
                let rule = M1.rule()
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link), rule), .symlinkInPath(component: link))
                let linkRule = M1.rule(id: "test.links", allowSymlinkTarget: true)
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: link), linkRule), "~/Documents")
                let through = env.scanTarget(ruleID: rule.id, path: link + "/thesis.docx")
                try M1.expectRejected(await M1.validate(env, through, rule), .symlinkInPath(component: link))
            }
        }

        await TestSuite.run("Gate check 2: symlink target → deny-listed paths (~/Library/Keychains, /usr/bin) is rejected") {
            try await M1.withEnv { env in
                let keychains = try env.fixture.dir("Library/Keychains")
                let rule = M1.rule()
                let linkRule = M1.rule(id: "test.links", allowSymlinkTarget: true)
                let k = try env.fixture.symlink("Library/Caches/kc", to: keychains)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: k), rule), .symlinkInPath(component: k))
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: k), linkRule), "~/Library/Keychains")
                let u = try env.fixture.symlink("Library/Caches/usr", to: "/usr/bin")
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: u), rule), .symlinkInPath(component: u))
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: u), linkRule), "/usr")
                // A relative link with "..": ~/Library/Caches/rel -> ../Keychains
                let r = try env.fixture.symlink("Library/Caches/rel", to: "../Keychains")
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: r), linkRule), "~/Library/Keychains")
            }
        }

        await TestSuite.run("Gate check 2: allowSymlinkTarget link to a harmless file is allowed; dangling link refused") {
            try await M1.withEnv { env in
                let real = try env.fixture.file(appCache + "/real.bin", bytes: 4)
                let link = try env.fixture.symlink(appCache + "/alias", to: real)
                let linkRule = M1.rule(id: "test.links", allowSymlinkTarget: true)
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: link), linkRule))
                let dangling = try env.fixture.symlink(appCache + "/dangling", to: env.fixture.path("nowhere", base: .root))
                let verdict = await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: dangling), linkRule)
                guard case .rejected(.canonicalizationFailed) = verdict else {
                    throw TestError("dangling link must fail closed, got \(verdict)")
                }
            }
        }

        await TestSuite.run("Gate check 2/6: intermediate directory symlink → .symlinkInPath") {
            try await M1.withEnv { env in
                try env.fixture.file("outside/data/file.bin", bytes: 8, base: .root)
                let link = try env.fixture.symlink("Library/Caches/com.example.link", to: env.fixture.path("outside", base: .root))
                let rule = M1.rule()
                let target = env.scanTarget(ruleID: rule.id, path: link + "/data/file.bin")
                try M1.expectRejected(await M1.validate(env, target, rule), .symlinkInPath(component: link))
                // Symlink to a sibling inside the same allow-root is equally refused.
                try env.fixture.file("Library/Caches/b/x.bin", bytes: 1)
                let a = try env.fixture.symlink("Library/Caches/a", to: env.fixture.path("Library/Caches/b"))
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: a + "/x.bin"), rule), .symlinkInPath(component: a))
            }
        }

        await TestSuite.run("Gate check 2: allow-root itself replaced by a symlink → .symlinkInPath") {
            try await M1.withEnv { env in
                try env.fixture.file("realcaches/com.example.app/x", bytes: 1, base: .root)
                try env.fixture.dir("Library")
                let link = try env.fixture.symlink("Library/Caches", to: env.fixture.path("realcaches", base: .root))
                let rule = M1.rule()
                let target = env.scanTarget(ruleID: rule.id, path: appCache)
                try M1.expectRejected(await M1.validate(env, target, rule), .symlinkInPath(component: link))
            }
        }

        await TestSuite.run("Gate check 6: symlink appearing in the chain after resolution (fake lstat) → .symlinkInPath") {
            try await M1.withEnv { env in
                let mid = try env.fixture.dir(appCache + "/mid")
                try env.fixture.file(appCache + "/mid/leaf", bytes: 1)
                let rule = M1.rule()
                let target = env.scanTarget(ruleID: rule.id, path: appCache + "/mid/leaf")
                env.fileSystem.overrideStat(mid, mode: UInt16(S_IFLNK | 0o755), scope: .lstat)
                try M1.expectRejected(await M1.validate(env, target, rule), .symlinkInPath(component: mid))
            }
        }

        // MARK: Check 3 (spot checks; every entry is covered in DenyListTests)

        await TestSuite.run("Gate check 3: case variant ~/library/KEYCHAINS → .denyListed(~/Library/Keychains)") {
            try await M1.withEnv { env in
                try env.fixture.file("Library/Keychains/login.db", bytes: 4)
                let rule = M1.rule(allowRoots: ["{HOME}/Library"])
                for raw in ["~/library/KEYCHAINS", "~/LIBRARY/keychains/LOGIN.DB", env.fixture.home + "/Library/KeyChains/login.db"] {
                    let t = env.scanTarget(ruleID: rule.id, path: raw.hasPrefix("~") ? env.fixture.home + raw.dropFirst() : raw)
                    try M1.expectDenyListed(await M1.validate(env, t, rule), "~/Library/Keychains", raw)
                }
            }
        }

        await TestSuite.run("Gate check 3: firmlink form /System/Volumes/Data/<home>/Library/Keychains → .denyListed") {
            try await M1.withEnv { env in
                try env.fixture.file("Library/Keychains/login.db", bytes: 4)
                let rule = M1.rule(allowRoots: ["{HOME}/Library"])
                for suffix in ["/Library/Keychains", "/Library/Keychains/login.db", "/library/KEYCHAINS"] {
                    let raw = "/System/Volumes/Data" + env.fixture.home + suffix
                    let t = ScanTarget(ruleID: rule.id, path: raw, displayName: "k", identity: env.fileSystem.lstat(env.fixture.home + suffix)?.identity,
                                       allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                    try M1.expectDenyListed(await M1.validate(env, t, rule), "~/Library/Keychains", raw)
                }
            }
        }

        await TestSuite.run("Gate check 3: NFD/NFC variants of protected and excluded names are matched") {
            try await M1.withEnv { env in
                // Deny-list: a protected extension written with a decomposed character in the base name.
                let nfc = "Fam\u{00ED}lia.photoslibrary"
                try env.fixture.file("Library/Caches/" + nfc + "/db", bytes: 1)
                let rule = M1.rule()
                let nfdPath = env.fixture.home + "/Library/Caches/Fami\u{0301}lia.PHOTOSLIBRARY/db"
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: nfdPath), rule), ".photoslibrary")
                // Allow-root containment is normalization-insensitive: NFD target inside NFC-created dir is allowed.
                try env.fixture.file("Library/Caches/Caf\u{00E9}/x", bytes: 1)
                let nfdCafe = env.fixture.home + "/Library/Caches/Cafe\u{0301}"
                let t = env.scanTarget(ruleID: rule.id, path: nfdCafe)
                try M1.expectAllowed(await M1.validate(env, t, rule), "NFD spelling of an NFC fixture")
                // Exclusion written NFC rejects the NFD spelling.
                try M1.expectRejected(await M1.validate(env, t, rule, userExclusions: ["~/Library/Caches/Caf\u{00E9}"]),
                                      .userExcluded(path: "~/Library/Caches/Caf\u{00E9}"))
            }
        }

        // MARK: Check 4

        await TestSuite.run("Gate check 4: path equal to the allow-root → .equalsAllowRoot (any spelling)") {
            try await M1.withEnv { env in
                let caches = try env.fixture.dir("Library/Caches")
                let rule = M1.rule()
                for raw in [caches, env.fixture.home + "/library/caches"] {
                    let t = ScanTarget(ruleID: rule.id, path: raw, displayName: "Caches", identity: env.fileSystem.lstat(caches)?.identity,
                                       allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                    try M1.expectRejected(await M1.validate(env, t, rule), .equalsAllowRoot, raw)
                }
                // Non-canonical spellings of the root never get that far.
                for raw in [caches + "/", caches + "/.", "/System/Volumes/Data" + caches] {
                    let t = ScanTarget(ruleID: rule.id, path: raw, displayName: "Caches", identity: env.fileSystem.lstat(caches)?.identity,
                                       allocatedBytes: 1, reclaimableBytes: 1, itemCount: 1, lastUsed: nil)
                    try M1.expectRejected(await M1.validate(env, t, rule), .canonicalizationFailed("path is not in canonical form"), raw)
                }
                // Equal to ANY declared root even when inside another one.
                try env.fixture.dir(appCache)
                let nested = M1.rule(allowRoots: [M1.cachesRoot, "{HOME}/" + appCache])
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: nested.id, path: appCache), nested), .equalsAllowRoot)
            }
        }

        await TestSuite.run("Gate check 4: prefix confusion ~/Library/CachesEvil/x vs root ~/Library/Caches → .notInsideAllowRoot") {
            try await M1.withEnv { env in
                try env.fixture.dir("Library/Caches")
                let evil = try env.fixture.file("Library/CachesEvil/x", bytes: 1)
                let rule = M1.rule()
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: evil), rule), .notInsideAllowRoot)
                let logs = try env.fixture.file("Library/Logs/app.log", bytes: 1)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: logs), rule), .notInsideAllowRoot)
                // Root "/" is never usable as an allow-root.
                let slash = M1.rule(allowRoots: ["/"])
                try env.fixture.dir(appCache)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: slash.id, path: appCache), slash), .notInsideAllowRoot)
            }
        }

        // MARK: Check 5

        await TestSuite.run("Gate check 5: minDepthBelowRoot enforced (.insufficientDepth); 0 means 1") {
            try await M1.withEnv { env in
                try env.fixture.file(appCache + "/sub/leaf", bytes: 1)
                let deep = M1.rule(minDepth: 2)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: deep.id, path: appCache), deep),
                                      .insufficientDepth(required: 2, actual: 1))
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: deep.id, path: appCache + "/sub"), deep))
                let zero = M1.rule(minDepth: 0)
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: zero.id, path: appCache), zero))
                let three = M1.rule(minDepth: 3)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: three.id, path: appCache + "/sub"), three),
                                      .insufficientDepth(required: 3, actual: 2))
            }
        }

        // MARK: Check 7

        await TestSuite.run("Gate check 7: different st_dev (injected) → .crossVolume") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir(appCache)
                let rule = M1.rule()
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                env.fileSystem.overrideStat(target, device: 987_654)
                try M1.expectRejected(await M1.validate(env, scan, rule), .crossVolume, "target")
                env.fileSystem.clearOverrides()
                env.fileSystem.overrideStat(target, device: 987_654, scope: .stat)
                try M1.expectRejected(await M1.validate(env, scan, rule), .crossVolume, "stat only (mount point)")
                // An intermediate mount point is refused too.
                env.fileSystem.clearOverrides()
                let mid = try env.fixture.dir(appCache + "/mnt")
                try env.fixture.file(appCache + "/mnt/x", bytes: 1)
                let leaf = env.scanTarget(ruleID: rule.id, path: appCache + "/mnt/x")
                env.fileSystem.overrideStat(mid, device: 987_654)
                try M1.expectRejected(await M1.validate(env, leaf, rule), .crossVolume, "intermediate")
            }
        }

        // MARK: Check 8

        await TestSuite.run("Gate check 8: different owner uid → .notOwnedByUser") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir(appCache)
                let rule = M1.rule()
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                env.fileSystem.overrideStat(target, uid: M1.otherUID)
                try M1.expectRejected(await M1.validate(env, scan, rule), .notOwnedByUser(uid: M1.otherUID))
                env.fileSystem.overrideStat(target, uid: 0)
                try M1.expectRejected(await M1.validate(env, scan, rule), .notOwnedByUser(uid: 0), "root-owned")
            }
        }

        // MARK: Check 9

        await TestSuite.run("Gate check 9: inode changed between plan and execute → .changedSinceScan") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir(appCache)
                let rule = M1.rule()
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                try M1.expectAllowed(await M1.validate(env, scan, rule, phase: .plan))
                env.fileSystem.overrideStat(target, inode: 1)
                try M1.expectRejected(await M1.validate(env, scan, rule, phase: .execute), .changedSinceScan, "injected inode")
                env.fileSystem.clearOverrides()

                // Real swap: the scanned file is replaced by a different file with the same name.
                let file = try env.fixture.file(appCache + "/blob", bytes: 4)
                let scanned = env.scanTarget(ruleID: rule.id, path: file)
                try M1.expectAllowed(await M1.validate(env, scanned, rule, phase: .plan))
                let keep = try env.fixture.file(appCache + "/blob.keep", bytes: 4) // pins the old inode number
                _ = keep
                try FileManager.default.removeItem(atPath: file)        // fixture under the temp dir only
                try env.fixture.file(appCache + "/blob", bytes: 4)
                if env.fileSystem.lstat(file)?.identity != scanned.identity {
                    try M1.expectRejected(await M1.validate(env, scanned, rule, phase: .execute), .changedSinceScan, "real swap")
                }
            }
        }

        await TestSuite.run("Gate check 9: no identity captured → .missingIdentity; vanished item → .itemMissing") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                let rule = M1.rule()
                let noID = env.scanTarget(ruleID: rule.id, path: appCache, captureIdentity: false)
                try M1.expectRejected(await M1.validate(env, noID, rule), .missingIdentity)
                let missing = ScanTarget(ruleID: rule.id, path: env.fixture.path("Library/Caches/gone"), displayName: "gone",
                                         identity: FileIdentity(device: 1, inode: 2), allocatedBytes: 1, reclaimableBytes: 1,
                                         itemCount: 1, lastUsed: nil)
                try M1.expectRejected(await M1.validate(env, missing, rule), .itemMissing)
            }
        }

        // MARK: Check 10

        await TestSuite.run("Gate check 10: File Provider xattr on target (real setxattr or injected) → .fileProviderItem") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir(appCache)
                let rule = M1.rule()
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                let attribute = "com.apple.fileprovider.domain-id"
                do {
                    try env.fixture.setExtendedAttribute(attribute, value: "dropbox", on: appCache)
                } catch {
                    env.fileSystem.setExtendedAttributes([attribute], for: target)
                }
                try M1.expectRejected(await M1.validate(env, scan, rule), .fileProviderItem(attribute: attribute))
            }
        }

        await TestSuite.run("Gate check 10: com.apple.file-provider-domain-id on an ancestor → .fileProviderItem") {
            try await M1.withEnv { env in
                let parent = try env.fixture.dir(appCache)
                try env.fixture.file(appCache + "/x", bytes: 1)
                let rule = M1.rule()
                let scan = env.scanTarget(ruleID: rule.id, path: appCache + "/x")
                env.fileSystem.setExtendedAttributes(["com.apple.quarantine", "com.apple.file-provider-domain-id"], for: parent)
                try M1.expectRejected(await M1.validate(env, scan, rule), .fileProviderItem(attribute: "com.apple.file-provider-domain-id"))
                env.fileSystem.clearOverrides()
                env.fileSystem.fail(.extendedAttributeNames, path: parent)
                try M1.expectRejected(await M1.validate(env, scan, rule), .fileProviderItem(attribute: "unreadable extended attributes"))
            }
        }

        await TestSuite.run("Gate check 10: isUbiquitousItem true / undeterminable → .ubiquitousItem") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir(appCache)
                let rule = M1.rule()
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                env.fileSystem.setUbiquitous(true, for: target)
                try M1.expectRejected(await M1.validate(env, scan, rule), .ubiquitousItem, "true")
                env.fileSystem.setUbiquitous(nil, for: target)
                try M1.expectRejected(await M1.validate(env, scan, rule), .ubiquitousItem, "nil fails closed")
                env.fileSystem.clearOverrides()
                env.fileSystem.setUbiquitous(true, for: env.fixture.path("Library/Caches"))
                try M1.expectRejected(await M1.validate(env, scan, rule), .ubiquitousItem, "ancestor (allow-root) ubiquitous")
            }
        }

        // MARK: Check 11

        await TestSuite.run("Gate check 11: item inside an .app (and every bundle type) → .insideBundle") {
            try await M1.withEnv { env in
                let rule = M1.rule()
                for ext in ["app", "framework", "bundle", "plugin", "kext", "systemextension", "appex"] {
                    let rel = "Library/Caches/Thing.\(ext)/Contents/Resources/data.bin"
                    try env.fixture.file(rel, bytes: 1)
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: rel), rule),
                                          .insideBundle(component: "Thing.\(ext)"), ext)
                    // The bundle directory itself as the target.
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/Thing.\(ext)"), rule),
                                          .insideBundle(component: "Thing.\(ext)"), ext + " root")
                }
                try env.fixture.file("Library/Caches/Foo.APP/Contents/x", bytes: 1)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/Foo.APP/Contents/x"), rule),
                                      .insideBundle(component: "Foo.APP"), "case variant")
                // Reverse-DNS cache folders ("com.example.app") are bundles only when they look like one.
                try env.fixture.file("Library/Caches/com.vendor.app/Contents/Info.plist", bytes: 1)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/com.vendor.app"), rule),
                                      .insideBundle(component: "com.vendor.app"), "reverse-DNS with Contents/")
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/com.vendor.app/Contents/Info.plist"), rule),
                                      .insideBundle(component: "com.vendor.app"), "inside reverse-DNS bundle")
                try env.fixture.file("Library/Caches/org.shallow.app/Info.plist", bytes: 1)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/org.shallow.app/Info.plist"), rule),
                                      .insideBundle(component: "org.shallow.app"), "shallow bundle with Info.plist")
                try env.fixture.file("Library/Caches/com.plain.app/cache.db", bytes: 1)
                let plainCache = env.scanTarget(ruleID: rule.id, path: "Library/Caches/com.plain.app/cache.db")
                try M1.expectAllowed(await M1.validate(env, plainCache, rule), "reverse-DNS cache folder without bundle structure")
                env.fileSystem.fail(.contentsOfDirectory, path: env.fixture.path("Library/Caches/com.plain.app"))
                try M1.expectRejected(await M1.validate(env, plainCache, rule), .insideBundle(component: "com.plain.app"),
                                      "unreadable listing fails closed")
                env.fileSystem.clearOverrides()
                try env.fixture.file("Library/Caches/Plain.app/cache.db", bytes: 1)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/Plain.app/cache.db"), rule),
                                      .insideBundle(component: "Plain.app"), "ordinary names stay name-based")
                // A regular FILE named like a bundle is not a bundle.
                try env.fixture.file(appCache + "/report.plugin", bytes: 1)
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: appCache + "/report.plugin"), rule))
            }
        }

        await TestSuite.run("Gate check 11: whole-app trash exception only for xcode.extraInstalls / installers.macOS with .trash") {
            try await M1.withEnv { env in
                try env.fixture.file("Applications/Xcode-15.app/Contents/Info.plist", bytes: 1)
                let app = "Applications/Xcode-15.app"
                for id in ["xcode.extraInstalls", "installers.macOS"] {
                    let rule = M1.rule(id: id, tier: .red, allowRoots: ["{HOME}/Applications"], action: .trash)
                    try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: id, path: app), rule), id)
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: id, path: app + "/Contents/Info.plist"), rule),
                                          .insideBundle(component: "Xcode-15.app"), id + " inside")
                    let quarantine = M1.rule(id: id, tier: .red, allowRoots: ["{HOME}/Applications"], action: .quarantine)
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: id, path: app), quarantine),
                                          .insideBundle(component: "Xcode-15.app"), id + " non-trash action")
                }
                let other = M1.rule(id: "apps.other", tier: .red, allowRoots: ["{HOME}/Applications"], action: .trash)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: other.id, path: app), other),
                                      .insideBundle(component: "Xcode-15.app"), "other rule id")
            }
        }

        // MARK: Check 12

        await TestSuite.run("Gate check 12: failing precondition → .preconditionFailed with user-facing detail") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                env.runningApplications.ids = ["com.apple.finder", "com.apple.dt.Xcode"]
                env.applications.applicationURLs = ["com.apple.dt.Xcode": [URL(fileURLWithPath: "/Applications/Xcode.app")]]
                let rule = M1.rule(preconditions: [.appNotRunning(["com.apple.dt.Xcode"])])
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                try M1.expectRejected(await M1.validate(env, scan, rule),
                                      .preconditionFailed(name: "appNotRunning", detail: "Xcode is running — quit it to clean"))
                let (_, details) = await env.makeGate().validateWithDetails(target: scan, rule: rule, phase: .plan)
                try TestSuite.assertEqual(details.map(\.name), ["appNotRunning", "ownedByUser", "notInsideCloudRoot"])
                try TestSuite.assertEqual(details.map(\.passed), [false, true, true])
                env.runningApplications.ids = ["com.apple.finder"]
                try M1.expectAllowed(await M1.validate(env, scan, rule))
            }
        }

        await TestSuite.run("Gate check 12: open file under target → .preconditionFailed(notOpenByAnyProcess)") {
            try await M1.withEnv { env in
                let target = try env.fixture.dir(appCache)
                let rule = M1.rule(preconditions: [.notOpenByAnyProcess])
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                env.processes.openFiles = [target + "/Cache.db-wal": [4242]]
                let verdict = await M1.validate(env, scan, rule)
                guard case .rejected(.preconditionFailed(name: "notOpenByAnyProcess", _)) = verdict else {
                    throw TestError("expected notOpenByAnyProcess failure, got \(verdict)")
                }
                try TestSuite.assertEqual(verdict.rejection?.errorCategory, .inUse)
            }
        }

        await TestSuite.run("Gate check 12: ageThresholdOverrides cannot lower a rule's olderThan") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                try env.fixture.setModificationDate(appCache, daysAgo: 20, clock: env.clock)
                let rule = M1.rule(preconditions: [.olderThan(days: 30)])
                let scan = env.scanTarget(ruleID: rule.id, path: appCache)
                let verdict = await M1.validate(env, scan, rule, ageThresholdOverrides: [rule.id: 10])
                guard case .rejected(.preconditionFailed(name: "olderThan", _)) = verdict else {
                    throw TestError("override must not lower the threshold, got \(verdict)")
                }
            }
        }

        // MARK: Check 13

        await TestSuite.run("Gate check 13: sanity limit exceeded → .downgradedToRed (bytes, items, defaults, negative)") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                let rule = M1.rule(maxBytes: 1_000, maxItems: 10)
                let big = env.scanTarget(ruleID: rule.id, path: appCache, allocatedBytes: 5_000, itemCount: 1)
                try TestSuite.assertEqual(await M1.validate(env, big, rule), .downgradedToRed(.sanityLimitExceeded(bytes: 5_000, items: 1)))
                let many = env.scanTarget(ruleID: rule.id, path: appCache, allocatedBytes: 10, itemCount: 11)
                try TestSuite.assertEqual(await M1.validate(env, many, rule), .downgradedToRed(.sanityLimitExceeded(bytes: 10, items: 11)))
                let atLimit = env.scanTarget(ruleID: rule.id, path: appCache, allocatedBytes: 1_000, itemCount: 10)
                try M1.expectAllowed(await M1.validate(env, atLimit, rule), "exactly at the limit")
                let plain = M1.rule()
                let huge = env.scanTarget(ruleID: plain.id, path: appCache, allocatedBytes: Rule.defaultMaxExpectedBytes + 1, itemCount: 1)
                try TestSuite.assertEqual(await M1.validate(env, huge, plain),
                                          .downgradedToRed(.sanityLimitExceeded(bytes: Rule.defaultMaxExpectedBytes + 1, items: 1)))
                let neg = env.scanTarget(ruleID: plain.id, path: appCache, allocatedBytes: -1, itemCount: 1)
                try TestSuite.assertEqual(await M1.validate(env, neg, plain), .downgradedToRed(.sanityLimitExceeded(bytes: -1, items: 1)))
                try TestSuite.assertFalse(await M1.validate(env, big, rule).isAllowed)
            }
        }

        // MARK: Check 14

        await TestSuite.run("Gate check 14: user exclusion → .userExcluded (inside, equal, containing, case variant)") {
            try await M1.withEnv { env in
                try env.fixture.file(appCache + "/keep/me.db", bytes: 1)
                try env.fixture.dir("Library/Caches/com.other.app")
                let rule = M1.rule()
                let exclusion = "~/Library/Caches/com.example.app/keep"
                for rel in [appCache + "/keep/me.db", appCache + "/keep", appCache] {
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: rel), rule, userExclusions: [exclusion]),
                                          .userExcluded(path: exclusion), rel)
                }
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: appCache), rule,
                                                        userExclusions: ["{HOME}/library/caches/COM.EXAMPLE.APP"]),
                                      .userExcluded(path: "{HOME}/library/caches/COM.EXAMPLE.APP"), "case variant")
                try M1.expectAllowed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/com.other.app"), rule,
                                                       userExclusions: [exclusion]), "sibling not excluded")
                // An unparseable exclusion fails closed.
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: "Library/Caches/com.other.app"), rule,
                                                        userExclusions: ["relative/path"]), .userExcluded(path: "relative/path"))
                // Exclusion wins over a sanity downgrade.
                let limited = M1.rule(maxBytes: 1)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: limited.id, path: appCache, allocatedBytes: 100), limited,
                                                        userExclusions: [exclusion]), .userExcluded(path: exclusion))
            }
        }

        // MARK: Target kinds & coherence

        await TestSuite.run("Gate: advisory target / advisory rule is always rejected (never actionable)") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                let advisoryRule = M1.rule(id: "advisory.ios", tier: .advisory, action: .advisory(.revealInFinder))
                let t = env.scanTarget(ruleID: advisoryRule.id, path: appCache, kind: .advisory)
                for verdict in [await M1.validate(env, t, advisoryRule), await M1.validate(env, t, advisoryRule, phase: .execute)] {
                    guard case .rejected(.preconditionFailed(name: "advisoryOnly", _)) = verdict else {
                        throw TestError("advisory must be rejected, got \(verdict)")
                    }
                }
                // Advisory kind with an otherwise actionable rule.
                let green = M1.rule()
                let adv = env.scanTarget(ruleID: green.id, path: appCache, kind: .advisory)
                guard case .rejected(.preconditionFailed(name: "advisoryOnly", _)) = await M1.validate(env, adv, green) else {
                    throw TestError("advisory kind must be rejected")
                }
                // Filesystem target under an advisory rule.
                let fsUnderAdvisory = env.scanTarget(ruleID: advisoryRule.id, path: appCache)
                guard case .rejected(.preconditionFailed(name: "advisoryOnly", _)) = await M1.validate(env, fsUnderAdvisory, advisoryRule) else {
                    throw TestError("advisory rule must be rejected")
                }
            }
        }

        await TestSuite.run("Gate: target validated against a different rule → rejected (ruleMismatch)") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                let rule = M1.rule()
                let t = env.scanTarget(ruleID: "some.other.rule", path: appCache)
                guard case .rejected(.preconditionFailed(name: "ruleMismatch", _)) = await M1.validate(env, t, rule) else {
                    throw TestError("rule mismatch must be rejected")
                }
            }
        }

        await TestSuite.run("Gate: command items run checks 1, 12, 14 only") {
            try await M1.withEnv { env in
                let spec = CommandSpec(tool: "xcrun", arguments: ["simctl", "delete", "{ITEM}"], idempotentSafe: true)
                let rule = M1.rule(id: "sim.unavailable", tier: .yellow, allowRoots: [], action: .command(spec))
                let item = env.scanTarget(ruleID: rule.id, path: env.fixture.home + "/Library/Developer/CoreSimulator/Devices/UDID-1",
                                          kind: .commandItem(argument: "UDID-1"), captureIdentity: false)
                try M1.expectAllowed(await M1.validate(env, item, rule), "no preconditions, informational path")
                try M1.expectRejected(await M1.validate(env, item, rule, userExclusions: ["~/Library/Developer/CoreSimulator"]),
                                      .userExcluded(path: "~/Library/Developer/CoreSimulator"))
                let idle = M1.rule(id: rule.id, tier: .yellow, allowRoots: [], preconditions: [.simulatorIdle], action: .command(spec))
                guard case .rejected(.preconditionFailed(name: "simulatorIdle", _)) = await M1.validate(env, item, idle) else {
                    throw TestError("simulatorIdle with no xcrun must fail closed")
                }
                // A command item under a file-system action is refused.
                let fsRule = M1.rule(id: rule.id)
                guard case .rejected(.preconditionFailed(name: "actionMismatch", _)) = await M1.validate(env, item, fsRule) else {
                    throw TestError("command item with non-command action must be rejected")
                }
            }
        }

        await TestSuite.run("Gate: validateWithDetails returns no preconditions when an earlier check rejects") {
            try await M1.withEnv { env in
                try env.fixture.dir("Library/Caches")
                let rule = M1.rule(preconditions: [.appNotRunning(["com.example.app"])])
                let t = env.scanTarget(ruleID: rule.id, path: "Library/Caches")
                let (verdict, details) = await env.makeGate().validateWithDetails(target: t, rule: rule, phase: .plan)
                try TestSuite.assertEqual(verdict, .rejected(.equalsAllowRoot))
                try TestSuite.assertTrue(details.isEmpty)
            }
        }

        await TestSuite.run("Gate: without the fixture waiver everything in the temp dir is deny-listed") {
            try await M1.withEnv { env in
                try env.fixture.dir(appCache)
                let rule = M1.rule()
                let gate = SafetyGate(environment: env.environment)
                try M1.expectDenyListed(await gate.validate(target: env.scanTarget(ruleID: rule.id, path: appCache), rule: rule, phase: .plan),
                                        "/private/var/folders")
            }
        }
    }
}
