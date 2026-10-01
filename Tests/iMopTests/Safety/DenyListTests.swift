import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §3.5: one dedicated test per deny-list entry, including case-variant and
/// symlink-to-denied-path attacks.
struct DenyListTests {
    @MainActor
    static func runAll() async {
        print("\n⛔️ Running DenyList Tests (spec §3.5)...")

        // MARK: System entries — one test each

        for entry in DenyList.systemEntries {
            await TestSuite.run("DenyList[system] \(entry): entry, child, case variant, firmlink form; gate rejects real path") {
                try await M1.withEnv { env in
                    let plain = DenyList(homeDirectory: env.fixture.home)
                    let waived = env.makeDenyList()
                    let c = env.makeCanonicalizer()

                    for raw in [entry, entry + "/child", entry + "/a/b/c.txt", M1.swapCase(entry) + "/Child",
                                "/System/Volumes/Data" + entry + "/child"] {
                        let lexical = c.lexical(raw)
                        if entry == "/System" {
                            // /System never even canonicalizes.
                            try M1.expectFailure(lexical, .denyListed(entry: "/System"), raw)
                            let forced = CanonicalPath(validatedPath: raw)
                            try TestSuite.assertEqual(plain.matchingEntry(for: forced, ruleID: nil, purpose: .standard), "/System", raw)
                            try TestSuite.assertEqual(waived.matchingEntry(for: forced, ruleID: nil, purpose: .quarantine), "/System", raw)
                            continue
                        }
                        let path = try M1.expectSuccess(lexical, raw)
                        try TestSuite.assertEqual(plain.matchingEntry(for: path, ruleID: nil, purpose: .standard), entry, raw)
                        // The fixture waiver only applies inside the fixture root, never to the real location.
                        try TestSuite.assertEqual(waived.matchingEntry(for: path, ruleID: nil, purpose: .standard), entry, raw)
                        // Quarantine purpose and arbitrary rule IDs never lift a system entry.
                        try TestSuite.assertEqual(plain.matchingEntry(for: path, ruleID: "xcode.extraInstalls", purpose: .quarantine), entry, raw)
                    }

                    // Prefix confusion: "/usrEvil" is not "/usr".
                    let sibling = try M1.expectSuccess(c.lexical(entry + "Evil/x"))
                    try TestSuite.assertNil(plain.matchingEntry(for: sibling, ruleID: nil, purpose: .standard), "sibling of \(entry)")

                    // Where the real location exists, the full gate rejects it with the specific entry.
                    var st = Darwin.stat()
                    if lstat(entry, &st) == 0 {
                        let rule = M1.rule(id: "test.system", allowRoots: [entry])
                        let target = env.scanTarget(ruleID: rule.id, path: entry)
                        try M1.expectDenyListed(await M1.validate(env, target, rule), entry, "gate on real \(entry)")

                        // Symlink-to-entry attack: ~/Library/Caches/evil -> <entry>.
                        let link = try env.fixture.symlink("Library/Caches/evil", to: entry)
                        let plainRule = M1.rule(id: "test.system.plain")
                        try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: plainRule.id, path: link), plainRule),
                                              .symlinkInPath(component: link), "plain rule, link to \(entry)")
                        let linkRule = M1.rule(id: "test.system.links", allowSymlinkTarget: true)
                        let linkVerdict = await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: link), linkRule)
                        if case .rejected(.canonicalizationFailed) = linkVerdict, Darwin.realpath(entry, nil) == nil {
                            // Destination not resolvable by this user: refused (fail closed) — acceptable.
                        } else {
                            try M1.expectDenyListed(linkVerdict, entry, "allowSymlinkTarget link to \(entry)")
                        }
                        // Traversed intermediate: evil/<child>.
                        if let child = (try? FileManager.default.contentsOfDirectory(atPath: entry))?.sorted().first {
                            let through = env.scanTarget(ruleID: plainRule.id, path: link + "/" + child)
                            let verdict = await M1.validate(env, through, plainRule)
                            switch verdict {
                            case .rejected(.symlinkInPath), .rejected(.denyListed), .rejected(.itemMissing):
                                break
                            default:
                                throw TestError("through-link \(through.path) must be refused, got \(verdict)")
                            }
                        }
                    }
                }
            }
        }

        await TestSuite.run("DenyList[system] /private/etc and /private/tmp also via /etc and /tmp spellings") {
            try await M1.withEnv { env in
                let plain = DenyList(homeDirectory: env.fixture.home)
                let c = env.makeCanonicalizer()
                try TestSuite.assertEqual(plain.matchingEntry(for: try M1.expectSuccess(c.lexical("/etc/hosts")), ruleID: nil, purpose: .standard), "/private/etc")
                try TestSuite.assertEqual(plain.matchingEntry(for: try M1.expectSuccess(c.lexical("/tmp/x")), ruleID: nil, purpose: .standard), "/private/tmp")
                try TestSuite.assertEqual(plain.matchingEntry(for: try M1.expectSuccess(c.lexical("/var/log/system.log")), ruleID: nil, purpose: .standard), "/private/var/log")
                // Even a CanonicalPath built from the unmapped form is caught (deny-list re-cleans its input).
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/tmp/x"), ruleID: nil, purpose: .standard), "/private/tmp")
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/var/db/x"), ruleID: nil, purpose: .standard), "/private/var/db")
            }
        }

        await TestSuite.run("DenyList[system] /Applications itself is not denied, /Applications/Utilities is") {
            try await M1.withEnv { env in
                let plain = DenyList(homeDirectory: env.fixture.home)
                try TestSuite.assertNil(plain.matchingEntry(for: CanonicalPath(validatedPath: "/Applications/Xcode-15.app"), ruleID: "xcode.extraInstalls", purpose: .standard))
                try TestSuite.assertNil(plain.matchingEntry(for: CanonicalPath(validatedPath: "/Applications/Install macOS Sonoma.app"), ruleID: "installers.macOS", purpose: .standard))
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/Applications/Utilities/Terminal.app"), ruleID: "installers.macOS", purpose: .standard), "/Applications/Utilities")
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/applications/UTILITIES"), ruleID: nil, purpose: .standard), "/Applications/Utilities")
            }
        }

        await TestSuite.run("DenyList[system] /cores: only system.coreDumps may reach /cores/core.*") {
            try await M1.withEnv { env in
                let plain = DenyList(homeDirectory: env.fixture.home)
                let core = CanonicalPath(validatedPath: "/cores/core.4242")
                try TestSuite.assertNil(plain.matchingEntry(for: core, ruleID: "system.coreDumps", purpose: .standard))
                try TestSuite.assertEqual(plain.matchingEntry(for: core, ruleID: "other.rule", purpose: .standard), "/cores")
                try TestSuite.assertEqual(plain.matchingEntry(for: core, ruleID: nil, purpose: .standard), "/cores")
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/cores"), ruleID: "system.coreDumps", purpose: .standard), "/cores")
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/cores/other"), ruleID: "system.coreDumps", purpose: .standard), "/cores")
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/cores/core."), ruleID: "system.coreDumps", purpose: .standard), "/cores")
                try TestSuite.assertEqual(plain.matchingEntry(for: CanonicalPath(validatedPath: "/cores/core.1/x"), ruleID: "system.coreDumps", purpose: .standard), "/cores")
            }
        }

        // MARK: Home-relative entries — one test each

        for entry in DenyList.homeRelativeEntries {
            await TestSuite.run("DenyList[home] ~/\(entry): direct, case variant, symlink-to-entry, through-symlink") {
                try await M1.withEnv { env in
                    let label = "~/" + entry
                    let fx = env.fixture
                    let concrete = M1.concreteRelative(entry)
                    let isFileEntry = entry == ".docker/config.json" || entry == ".netrc"

                    // Fixture: the protected location (with content when it is a directory).
                    let protectedPath: String
                    let insidePath: String
                    if isFileEntry {
                        protectedPath = try fx.file(concrete, bytes: 16)
                        insidePath = protectedPath
                    } else {
                        protectedPath = try fx.dir(concrete)
                        insidePath = try fx.file(concrete + "/item.dat", bytes: 16)
                    }
                    try fx.dir("Library/Caches")

                    let deny = env.makeDenyList()
                    let c = env.makeCanonicalizer()
                    let rule = M1.rule(id: "test.home", allowRoots: ["{HOME}", "{HOME}/Library", M1.cachesRoot])

                    // 1. DenyList on lexical forms (entry itself, a child, a case variant, firmlink form).
                    var lexicalForms = ["~/" + concrete, "~/" + M1.swapCase(concrete),
                                        "/System/Volumes/Data" + fx.home + "/" + concrete]
                    if !isFileEntry { lexicalForms.append("~/" + concrete + "/deep/er") }
                    for raw in lexicalForms {
                        let p = try M1.expectSuccess(c.lexical(raw), raw)
                        try TestSuite.assertEqual(deny.matchingEntry(for: p, ruleID: nil, purpose: .standard), label, raw)
                    }

                    // 2. Gate, direct target.
                    let direct = env.scanTarget(ruleID: rule.id, path: insidePath)
                    try M1.expectDenyListed(await M1.validate(env, direct, rule), label, "direct")
                    let entryTarget = env.scanTarget(ruleID: rule.id, path: protectedPath)
                    try M1.expectDenyListed(await M1.validate(env, entryTarget, rule), label, "entry itself")

                    // 3. Gate, case-variant attack.
                    let variantPath = fx.home + "/" + M1.swapCase(String(insidePath.dropFirst(fx.home.count + 1)))
                    let variant = env.scanTarget(ruleID: rule.id, path: variantPath)
                    try TestSuite.assertTrue(variant.identity != nil, "case variant must resolve on the case-insensitive fixture volume")
                    try M1.expectDenyListed(await M1.validate(env, variant, rule), label, "case variant \(variantPath)")

                    // 4. Gate, symlink-to-entry attack: ~/Library/Caches/evil -> <entry>.
                    let link = try fx.symlink("Library/Caches/evil", to: protectedPath)
                    let linkTarget = env.scanTarget(ruleID: rule.id, path: link)
                    try M1.expectRejected(await M1.validate(env, linkTarget, rule), .symlinkInPath(component: link), "symlink target")
                    let linkRule = M1.rule(id: "test.home.links", allowRoots: [M1.cachesRoot], allowSymlinkTarget: true)
                    let linkTarget2 = env.scanTarget(ruleID: linkRule.id, path: link)
                    try M1.expectDenyListed(await M1.validate(env, linkTarget2, linkRule), label, "allowSymlinkTarget link into entry")

                    // 5. Gate, path traversing the symlink into the entry.
                    if !isFileEntry {
                        let through = env.scanTarget(ruleID: rule.id, path: link + "/item.dat")
                        try M1.expectRejected(await M1.validate(env, through, rule), .symlinkInPath(component: link), "through symlink")
                    }
                }
            }
        }

        await TestSuite.run("DenyList[home] negatives: neighbours of protected entries are not denied") {
            try await M1.withEnv { env in
                let deny = env.makeDenyList()
                let c = env.makeCanonicalizer()
                for raw in ["~/Library/Caches/com.example.app", "~/Library/Containers/com.example.app/Data/Library/Caches",
                            "~/Library/Group Containers/group.com.example.shared/Library/Caches",
                            "~/Library/Preferences/com.example.app.plist", "~/Library/LaunchAgents/com.example.agent.plist",
                            "~/.docker/machine", "~/DocumentsEvil/x", "~/Documents-old", "~/Library/MailEvil",
                            "~/Library/Application Support/iMopOther", "~/Library/Application Support/com.apple.TCCx",
                            "~/.sshx", "~/.config/ghx", "~/Library/Developer/Xcode/DerivedData/App-abc"] {
                    let p = try M1.expectSuccess(c.lexical(raw), raw)
                    try TestSuite.assertNil(deny.matchingEntry(for: p, ruleID: nil, purpose: .standard), raw)
                }
            }
        }

        await TestSuite.run("DenyList[home] Apple-managed TeamID group containers and ByHost preferences are denied") {
            let deny = DenyList(homeDirectory: "/Users/zz")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/zz/Library/Group Containers/243LU875E5.groups.com.apple.podcasts/Library/x"), ruleID: nil, purpose: .standard),
                                      "~/Library/Group Containers/*com.apple.*")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/zz/Library/Group Containers/ABCDE12345.com.apple.Something"), ruleID: nil, purpose: .standard),
                                      "~/Library/Group Containers/*com.apple.*")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/zz/Library/Group Containers/group.com.apple.notes"), ruleID: nil, purpose: .standard),
                                      "~/Library/Group Containers/group.com.apple.*")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/zz/Library/Preferences/ByHost/com.apple.loginwindow.ABC.plist"), ruleID: nil, purpose: .standard),
                                      "~/Library/Preferences/ByHost/com.apple.*")
            try TestSuite.assertNil(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/zz/Library/Preferences/ByHost/com.example.app.ABC.plist"), ruleID: nil, purpose: .standard))
            try TestSuite.assertNil(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/zz/Library/Group Containers/ABCDE12345.com.example.shared"), ruleID: nil, purpose: .standard))
        }

        await TestSuite.run("DenyList[home] a path CONTAINING a protected location is denied") {
            try await M1.withEnv { env in
                let deny = env.makeDenyList()
                let c = env.makeCanonicalizer()
                for raw in ["~", "~/Library", "~/.docker", "~/Library/Containers", "~/Library/Group Containers",
                            "~/Library/Application Support", "~/.config"] {
                    let p = try M1.expectSuccess(c.lexical(raw), raw)
                    let hit = deny.matchingEntry(for: p, ruleID: nil, purpose: .standard)
                    try TestSuite.assertTrue(hit?.hasPrefix("contains ") == true, "\(raw) → \(String(describing: hit))")
                }
                try TestSuite.assertTrue(deny.matchingEntry(for: CanonicalPath(validatedPath: "/"), ruleID: nil, purpose: .standard) != nil)
                try TestSuite.assertTrue(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Applications"), ruleID: nil, purpose: .standard) != nil)
            }
        }

        await TestSuite.run("DenyList[home] Mail Downloads exception is narrow (mail.downloads only, contents only)") {
            try await M1.withEnv { env in
                let deny = env.makeDenyList()
                let c = env.makeCanonicalizer()
                let folder = try M1.expectSuccess(c.lexical("~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"))
                let item = folder.appending("invoice.pdf")
                let label = "~/Library/Containers/com.apple.*"
                try TestSuite.assertNil(deny.matchingEntry(for: item, ruleID: "mail.downloads", purpose: .standard))
                // Only DIRECT children ("Mail Downloads/*"); deeper paths stay denied.
                try TestSuite.assertEqual(deny.matchingEntry(for: folder.appending("a").appending("b"), ruleID: "mail.downloads", purpose: .standard), label)
                try TestSuite.assertEqual(deny.matchingEntry(for: folder.appending("a").appending("b").appending("c"), ruleID: "mail.downloads", purpose: .standard), label)
                try TestSuite.assertEqual(deny.matchingEntry(for: item, ruleID: "other.rule", purpose: .standard), label)
                try TestSuite.assertEqual(deny.matchingEntry(for: folder, ruleID: "mail.downloads", purpose: .standard), label)
                let safari = try M1.expectSuccess(c.lexical("~/Library/Containers/com.apple.Safari/Data/Library/Caches/x"))
                try TestSuite.assertEqual(deny.matchingEntry(for: safari, ruleID: "mail.downloads", purpose: .standard), label)
                // ~/Library/Mail itself is never lifted.
                let mail = try M1.expectSuccess(c.lexical("~/Library/Mail/V10/x"))
                try TestSuite.assertEqual(deny.matchingEntry(for: mail, ruleID: "mail.downloads", purpose: .standard), "~/Library/Mail")
            }
        }

        await TestSuite.run("DenyList[home] iMop Quarantine is reachable only with purpose .quarantine") {
            try await M1.withEnv { env in
                let deny = env.makeDenyList()
                let c = env.makeCanonicalizer()
                let q = try M1.expectSuccess(c.lexical("~/Library/Application Support/iMop/Quarantine"))
                let label = "~/Library/Application Support/iMop"
                try TestSuite.assertNil(deny.matchingEntry(for: q.appending("session-1"), ruleID: nil, purpose: .quarantine))
                try TestSuite.assertEqual(deny.matchingEntry(for: q.appending("session-1"), ruleID: nil, purpose: .standard), label)
                try TestSuite.assertEqual(deny.matchingEntry(for: q, ruleID: nil, purpose: .quarantine), label)
                let other = try M1.expectSuccess(c.lexical("~/Library/Application Support/iMop/audit.jsonl"))
                try TestSuite.assertEqual(deny.matchingEntry(for: other, ruleID: nil, purpose: .quarantine), label)
            }
        }

        // MARK: Extensions & .git

        for ext in DenyList.protectedExtensions {
            await TestSuite.run("DenyList[extension] .\(ext): any component, any case, via gate") {
                try await M1.withEnv { env in
                    let deny = env.makeDenyList()
                    let c = env.makeCanonicalizer()
                    for raw in ["~/Library/Caches/Thing.\(ext)", "~/Library/Caches/Thing.\(ext)/inner/file",
                                "~/Library/Caches/THING.\(ext.uppercased())/x", "/Users/Shared/x.\(ext)"] {
                        let p = try M1.expectSuccess(c.lexical(raw), raw)
                        try TestSuite.assertEqual(deny.matchingEntry(for: p, ruleID: nil, purpose: .standard), "." + ext, raw)
                    }
                    let notIt = try M1.expectSuccess(c.lexical("~/Library/Caches/Thing.\(ext)x"))
                    try TestSuite.assertNil(deny.matchingEntry(for: notIt, ruleID: nil, purpose: .standard))

                    let rule = M1.rule()
                    let inner = try env.fixture.file("Library/Caches/Library.\(ext)/database/data.db", bytes: 8)
                    try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: inner), rule), "." + ext)
                    let bundle = env.fixture.path("Library/Caches/Library.\(ext)")
                    try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: bundle), rule), "." + ext)

                    // Symlink-to-protected-extension attack.
                    let media = try env.fixture.dir("Media/Library.\(ext)")
                    try env.fixture.file("Media/Library.\(ext)/db", bytes: 2)
                    let link = try env.fixture.symlink("Library/Caches/evil", to: media)
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link), rule),
                                          .symlinkInPath(component: link))
                    let linkRule = M1.rule(id: "test.ext.links", allowSymlinkTarget: true)
                    try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: link), linkRule),
                                            "." + ext, "allowSymlinkTarget link to Library.\(ext)")
                    try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link + "/db"), rule),
                                          .symlinkInPath(component: link))
                }
            }
        }

        await TestSuite.run("DenyList[.git] any .git component is denied (any case), via gate") {
            try await M1.withEnv { env in
                let deny = env.makeDenyList()
                let c = env.makeCanonicalizer()
                for raw in ["~/Projects/app/.git", "~/Projects/app/.git/objects/ab", "~/Library/Caches/x/.GIT/HEAD"] {
                    try TestSuite.assertEqual(deny.matchingEntry(for: try M1.expectSuccess(c.lexical(raw)), ruleID: nil, purpose: .standard), ".git", raw)
                }
                for raw in ["~/Projects/app/.gitignore", "~/Projects/app/.github/workflows", "~/Projects/app/node_modules"] {
                    try TestSuite.assertNil(deny.matchingEntry(for: try M1.expectSuccess(c.lexical(raw)), ruleID: nil, purpose: .standard), raw)
                }
                let rule = M1.rule()
                let head = try env.fixture.file("Library/Caches/proj/.git/HEAD", bytes: 4)
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: head), rule), ".git")
                let dotgit = env.fixture.path("Library/Caches/proj/.git")
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: dotgit), rule), ".git")

                // Symlink-to-.git attack.
                let realGit = try env.fixture.dir("Projects/app/.git")
                try env.fixture.file("Projects/app/.git/HEAD", bytes: 4)
                let link = try env.fixture.symlink("Library/Caches/evil", to: realGit)
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link), rule),
                                      .symlinkInPath(component: link))
                let linkRule = M1.rule(id: "test.git.links", allowSymlinkTarget: true)
                try M1.expectDenyListed(await M1.validate(env, env.scanTarget(ruleID: linkRule.id, path: link), linkRule), ".git")
                try M1.expectRejected(await M1.validate(env, env.scanTarget(ruleID: rule.id, path: link + "/HEAD"), rule),
                                      .symlinkInPath(component: link))
            }
        }

        // MARK: Normalization, waivers, constants

        await TestSuite.run("DenyList: NFC home vs NFD path (and case) still match home entries") {
            let deny = DenyList(homeDirectory: "/Users/Jos\u{00E9}")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/Jose\u{0301}/Library/Keychains/login.db"), ruleID: nil, purpose: .standard), "~/Library/Keychains")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: "/users/JOSE\u{0301}/library/KEYCHAINS"), ruleID: nil, purpose: .standard), "~/Library/Keychains")
            let nfdHome = DenyList(homeDirectory: "/Users/Jose\u{0301}")
            try TestSuite.assertEqual(nfdHome.matchingEntry(for: CanonicalPath(validatedPath: "/Users/Jos\u{00E9}/Documents/a.txt"), ruleID: nil, purpose: .standard), "~/Documents")
        }

        await TestSuite.run("DenyList: fixture waiver lifts only enclosing system entries; /System never waivable") {
            try await M1.withEnv { env in
                let waived = env.makeDenyList()
                let plain = DenyList(homeDirectory: env.fixture.home)
                let inside = CanonicalPath(validatedPath: env.fixture.home + "/Library/Caches/x")
                try TestSuite.assertNil(waived.matchingEntry(for: inside, ruleID: nil, purpose: .standard))
                try TestSuite.assertEqual(plain.matchingEntry(for: inside, ruleID: nil, purpose: .standard), "/private/var/folders")
                // Home entries still apply inside the waived root.
                let keychain = CanonicalPath(validatedPath: env.fixture.home + "/Library/Keychains/x")
                try TestSuite.assertEqual(waived.matchingEntry(for: keychain, ruleID: nil, purpose: .standard), "~/Library/Keychains")
                let systemWaiver = DenyList(homeDirectory: env.fixture.home, waivedSystemRoots: ["/System/Library", "/"])
                try TestSuite.assertEqual(systemWaiver.matchingEntry(for: CanonicalPath(validatedPath: "/System/Library/x"), ruleID: nil, purpose: .standard), "/System")
                try TestSuite.assertEqual(systemWaiver.matchingEntry(for: CanonicalPath(validatedPath: "/usr/bin/true"), ruleID: nil, purpose: .standard), "/usr")
            }
        }

        await TestSuite.run("DenyList: the fixture waiver only accepts iMopTests-* roots in the temp dir") {
            let home = "/Users/zz"
            for (root, path, entry) in [("/usr", "/usr/bin/true", "/usr"),
                                        ("/Library", "/Library/Keychains/System.keychain", "/Library"),
                                        ("/private/etc", "/private/etc/sudoers", "/private/etc"),
                                        ("/Volumes", "/Volumes/Backup/x", "/Volumes"),
                                        ("/Volumes/X", "/Volumes/X/y", "/Volumes"),
                                        ("/cores", "/cores/x", "/cores"),
                                        ("/Applications/Utilities", "/Applications/Utilities/Terminal.app", "/Applications/Utilities"),
                                        ("/private/var/folders", "/private/var/folders/ab/x", "/private/var/folders"),
                                        ("/private/tmp", "/private/tmp/x", "/private/tmp")] {
                let deny = DenyList(homeDirectory: home, waivedSystemRoots: [root])
                try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: path), ruleID: nil, purpose: .standard), entry, "waiver \(root)")
            }
            // A temp-dir folder without the iMopTests- prefix is not a fixture root.
            let tmp = FixtureBuilder.realpath(NSTemporaryDirectory()) ?? NSTemporaryDirectory()
            let other = tmp + "/someone-else"
            let deny = DenyList(homeDirectory: home, waivedSystemRoots: [other, tmp, tmp + "/iMopTests-"])
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: other + "/x"), ruleID: nil, purpose: .standard), "/private/var/folders")
            try TestSuite.assertEqual(deny.matchingEntry(for: CanonicalPath(validatedPath: tmp + "/iMopTests-/x"), ruleID: nil, purpose: .standard), "/private/var/folders")
            // A genuine fixture root works, but only for the temp-dir entry.
            let fixtureRoot = tmp + "/iMopTests-abc"
            let ok = DenyList(homeDirectory: home, waivedSystemRoots: [fixtureRoot])
            try TestSuite.assertNil(ok.matchingEntry(for: CanonicalPath(validatedPath: fixtureRoot + "/home/x"), ruleID: nil, purpose: .standard))
        }

        await TestSuite.run("DenyList: unusable home directory denies everything") {
            for home in ["relative/home", "/", ""] {
                let deny = DenyList(homeDirectory: home)
                try TestSuite.assertTrue(deny.matchingEntry(for: CanonicalPath(validatedPath: "/Users/x/Library/Caches/y"), ruleID: nil, purpose: .standard) != nil, home)
            }
        }

        await TestSuite.run("DenyList: constants cover every spec §3.5 entry") {
            try TestSuite.assertEqual(DenyList.systemEntries.count, 22)
            try TestSuite.assertEqual(DenyList.protectedExtensions.count, 9)
            try TestSuite.assertEqual(DenyList.cloudRootsRelativeToHome, ["Library/Mobile Documents", "Library/CloudStorage"])
            for required in ["Library/Keychains", "Library/Mobile Documents", "Library/CloudStorage", "Library/Mail",
                             "Library/Messages", "Library/Photos", "Library/Accounts", "Library/Cookies",
                             "Library/HTTPStorages", "Library/Safari", "Library/Calendars", "Library/Reminders",
                             "Library/Contacts", "Library/Application Support/AddressBook",
                             "Library/Application Support/MobileSync", "Library/Application Support/com.apple.TCC",
                             "Library/Application Support/iMop", "Library/Group Containers/group.com.apple.*",
                             "Library/Containers/com.apple.*", "Library/Preferences/com.apple.*",
                             "Library/LaunchAgents/com.apple.*", ".ssh", ".gnupg", ".aws", ".kube",
                             ".docker/config.json", ".config/gh", ".netrc", "Documents", "Desktop", "Pictures",
                             "Movies", "Music"] {
                try TestSuite.assertTrue(DenyList.homeRelativeEntries.contains(required), required)
            }
        }
    }
}
