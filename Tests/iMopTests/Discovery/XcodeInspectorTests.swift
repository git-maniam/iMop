import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Milestone 5 (spec §6.1): XcodeInspector — DerivedData orphaned / active, Archives keep-N,
/// DeviceSupport version parsing, `.xip` downloads.
struct XcodeInspectorTests {
    static let derivedData = "Library/Developer/Xcode/DerivedData"
    static let archives = "Library/Developer/Xcode/Archives"

    /// A DerivedData folder whose `info.plist` is `plist` (nil = no info.plist, Data = raw bytes).
    @MainActor
    static func derived(_ f: FixtureBuilder, _ name: String, plist: Any?) throws {
        let dir = derivedData + "/" + name
        try f.file(dir + "/Build/Products/Debug/app.bin", bytes: 4_000)
        switch plist {
        case nil: break
        case let raw as Data: try f.file(dir + "/info.plist", contents: raw)
        case let object?: try f.file(dir + "/info.plist", contents: try M5.plistData(object))
        }
    }

    /// An `.xcarchive` with a top-level Info.plist (`bundleID` / `created` nil = key missing;
    /// `raw` replaces the whole plist).
    @MainActor
    static func archive(_ f: FixtureBuilder, folder: String, name: String, bundleID: String?, created: Date?,
                        raw: Data? = nil) throws -> String {
        let rel = archives + "/" + folder + "/" + name + ".xcarchive"
        try f.file(rel + "/Products/Applications/App.app/App", bytes: 3_000)
        try f.file(rel + "/dSYMs/App.app.dSYM/Contents/Resources/DWARF/App", bytes: 2_000)
        if let raw {
            try f.file(rel + "/Info.plist", contents: raw)
        } else {
            var plist: [String: Any] = ["Name": name, "ArchiveVersion": 2]
            if let bundleID {
                plist["ApplicationProperties"] = ["CFBundleIdentifier": bundleID, "CFBundleShortVersionString": "1.0",
                                                  "CFBundleVersion": "7"]
            }
            if let created { plist["CreationDate"] = created }
            try f.file(rel + "/Info.plist", contents: try M5.plistData(plist))
        }
        return rel
    }

    @MainActor
    static func runAll() async {
        print("\n🛠️ Running Milestone 5 Xcode inspector tests (spec §6.1)...")
        await derivedDataTests()
        await archivesTests()
        await deviceSupportTests()
        await xipTests()
    }

    // MARK: DerivedData

    @MainActor
    static func derivedDataTests() async {
        await TestSuite.run("XcodeInspector: DerivedData is orphaned only when WorkspacePath is PROVEN gone; missing/unreadable/garbage info.plist → active") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.dir("work/App.xcodeproj", base: .root)
                try f.dir("locked/inner", base: .root)
                try derived(f, "App-exists", plist: ["WorkspacePath": f.path("work/App.xcodeproj", base: .root)])
                try derived(f, "Old-gone", plist: ["WorkspacePath": f.path("gone/Old.xcodeproj", base: .root)])
                try derived(f, "GoneLeaf-abc", plist: ["WorkspacePath": f.path("work/Deleted.xcworkspace", base: .root)])
                try derived(f, "NoPlist-abc", plist: nil)
                try derived(f, "Garbage-abc", plist: Data("this is not a property list".utf8))
                try derived(f, "NoKey-abc", plist: ["LastAccessedDate": Date()])
                try derived(f, "WrongType-abc", plist: ["WorkspacePath": 42])
                try derived(f, "Relative-abc", plist: ["WorkspacePath": "Projects/App.xcodeproj"])
                try derived(f, "Dotdot-abc", plist: ["WorkspacePath": f.path("work/../gone/X.xcodeproj", base: .root)])
                try derived(f, "Volume-abc", plist: ["WorkspacePath": "/Volumes/External SSD/Projects/App.xcodeproj"])
                // The parent of the workspace cannot be listed: absence is not proven.
                try derived(f, "Unlistable-abc", plist: ["WorkspacePath": f.path("locked/inner/X.xcodeproj", base: .root)])
                env.fileSystem.fail(.contentsOfDirectory, path: f.path("locked/inner", base: .root))
                // A symlinked info.plist is never read.
                try f.file("elsewhere/info.plist", contents: try M5.plistData(["WorkspacePath": f.path("gone/Y.xcodeproj", base: .root)]), base: .root)
                try derived(f, "LinkedPlist-abc", plist: nil)
                try f.symlink(derivedData + "/LinkedPlist-abc/info.plist", to: f.path("elsewhere/info.plist", base: .root))
                // A symlinked DerivedData entry is never offered by either rule.
                try f.dir("elsewhere/dd", base: .root)
                try f.symlink(derivedData + "/Linked-abc", to: f.path("elsewhere/dd", base: .root))

                let orphaned = try await M5.discover(XcodeDerivedDataInspector(), env, "xcode.derivedData.orphaned")
                let active = try await M5.discover(XcodeDerivedDataInspector(), env, "xcode.derivedData.active")
                try TestSuite.assertEqual(orphaned.status, .ok)
                try TestSuite.assertEqual(M5.paths(orphaned, f), [derivedData + "/Old-gone", derivedData + "/GoneLeaf-abc"])
                try TestSuite.assertEqual(M5.paths(active, f), Set(["App-exists", "NoPlist-abc", "Garbage-abc", "NoKey-abc", "WrongType-abc",
                                                                     "Relative-abc", "Dotdot-abc", "Volume-abc", "Unlistable-abc",
                                                                     "LinkedPlist-abc"].map { derivedData + "/" + $0 }))
                try TestSuite.assertTrue((orphaned.candidates + active.candidates).allSatisfy { $0.owningBundleID == M5.xcodeBundleID })
                try TestSuite.assertTrue(orphaned.candidates.allSatisfy { $0.notes.contains { $0.contains("no longer exists") } })

                // Through the Scanner: both rules offer exactly these (matcher + scanner wiring).
                let results = try await M5.scan(env, ["xcode.derivedData.orphaned", "xcode.derivedData.active"])
                try TestSuite.assertEqual(M5.paths(results["xcode.derivedData.orphaned"], f), M5.paths(orphaned, f))
                try TestSuite.assertEqual(M5.paths(results["xcode.derivedData.active"], f), M5.paths(active, f))
                try TestSuite.assertEqual(results["xcode.derivedData.orphaned"]?.rule.tier, .green)
                try TestSuite.assertEqual(results["xcode.derivedData.active"]?.rule.tier, .yellow)

                // A rule id the inspector does not know gets nothing.
                let foreign = M1.rule(id: "test.dd", discovery: .inspector(.xcodeDerivedData))
                let none = await XcodeDerivedDataInspector().discover(rule: foreign, environment: env.environment)
                try TestSuite.assertTrue(none.candidates.isEmpty)
            }
        }

        await TestSuite.run("XcodeInspector: DerivedData plan — orphaned is Green & preselected; active is Yellow, age-gated (14 d) and never preselected; Xcode/xcodebuild block both") {
            try await M1.withEnv { env in
                let f = env.fixture
                try derived(f, "Gone-abc", plist: ["WorkspacePath": f.path("gone/Old.xcodeproj", base: .root)])
                try derived(f, "Fresh-abc", plist: nil)
                try derived(f, "Stale-abc", plist: nil)
                try M5.age(f, derivedData + "/Stale-abc", days: 20, clock: env.clock)
                try M5.age(f, derivedData + "/Stale-abc/Build", days: 20, clock: env.clock)
                let ids: Set<String> = ["xcode.derivedData.orphaned", "xcode.derivedData.active"]
                var plan = await M5.plan(env, Array(try await M5.scan(env, ids).values))
                let gone = try M5.item(plan, derivedData + "/Gone-abc", f)
                try TestSuite.assertTrue(gone.isActionable, "\(gone.preconditions)")
                try TestSuite.assertTrue(gone.selectedByDefault)
                let stale = try M5.item(plan, derivedData + "/Stale-abc", f)
                try TestSuite.assertTrue(stale.isActionable, "\(stale.preconditions)")
                try TestSuite.assertFalse(stale.selectedByDefault, "Yellow is never preselected")
                let fresh = try M5.item(plan, derivedData + "/Fresh-abc", f)
                try TestSuite.assertFalse(fresh.isActionable)
                try TestSuite.assertEqual(M5.failedPrecondition(fresh), "olderThan")

                env.processes.names = ["launchd", "xcodebuild"]
                plan = await M5.plan(env, Array(try await M5.scan(env, ids).values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.isActionable && !$0.selectedByDefault })
                env.processes.names = ["launchd"]
                env.runningApplications.ids = ["com.apple.finder", M5.xcodeBundleID]
                plan = await M5.plan(env, Array(try await M5.scan(env, ids).values))
                try TestSuite.assertFalse(plan.items.isEmpty)
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.isActionable && M5.failedPrecondition($0) == "appNotRunning" })
            }
        }
    }

    // MARK: Archives

    @MainActor
    static func archivesTests() async {
        await TestSuite.run("XcodeInspector: Archives keep the newest N per bundle id (3 default, 1, clamp), ties keep all, unparsable archives are KEPT") {
            try await M1.withEnv { env in
                let f = env.fixture
                let now = env.clock.now
                func daysAgo(_ d: Double) -> Date { now.addingTimeInterval(-d * 86_400) }
                // com.x.app: five archives across two date folders.
                var x: [String] = []
                for (i, age) in [1.0, 10, 20, 30, 40].enumerated() {
                    x.append(try archive(f, folder: i < 2 ? "2026-09-30" : "2026-08-01", name: "X \(i)", bundleID: "com.x.app", created: daysAgo(age)))
                }
                // com.y.app: two archives share the newest date; one older.
                let y0 = try archive(f, folder: "2026-09-30", name: "Y a", bundleID: "com.y.app", created: daysAgo(2))
                let y1 = try archive(f, folder: "2026-09-30", name: "Y b", bundleID: "com.y.app", created: daysAgo(2))
                let y2 = try archive(f, folder: "2026-08-01", name: "Y c", bundleID: "com.y.app", created: daysAgo(50))
                // Unparsable / incomplete archives of com.x.app, all OLDER than everything: always kept.
                let garbage = try archive(f, folder: "2026-01-01", name: "X garbage", bundleID: nil, created: nil,
                                          raw: Data("<plist>broken".utf8))
                let noID = try archive(f, folder: "2026-01-01", name: "X noid", bundleID: nil, created: daysAgo(400))
                let noDate = try archive(f, folder: "2026-01-01", name: "X nodate", bundleID: "com.x.app", created: nil)
                let wrongCase = try archive(f, folder: "2026-01-01", name: "X case", bundleID: "COM.X.APP", created: daysAgo(500))
                // Not archives.
                try f.file(archives + "/2026-01-01/notes.txt", bytes: 10)
                try f.dir(archives + "/2026-01-01/Folder")

                @MainActor func offered(keep: Int) async throws -> Set<String> {
                    env.scanSettings = ScanSettings(archivesToKeep: keep)
                    let out = try await M5.discover(XcodeArchivesInspector(), env, "xcode.archives.old")
                    try TestSuite.assertEqual(out.status, .ok)
                    try TestSuite.assertTrue(out.candidates.allSatisfy { $0.owningBundleID == M5.xcodeBundleID })
                    return M5.paths(out, f)
                }
                try TestSuite.assertEqual(try await offered(keep: 3), [x[3], x[4]], "default keep 3")
                try TestSuite.assertEqual(try await offered(keep: 1), Set([x[1], x[2], x[3], x[4], y2]), "keep 1; tied newest Y kept")
                try TestSuite.assertEqual(try await offered(keep: 0), try await offered(keep: 1), "0 clamps to 1")
                try TestSuite.assertEqual(try await offered(keep: 2), Set([x[2], x[3], x[4], y2]))
                try TestSuite.assertEqual(try await offered(keep: 50), [])
                for kept in [y0, y1, garbage, noID, noDate] {
                    try TestSuite.assertFalse(try await offered(keep: 1).contains(kept), kept)
                }
                // A differently-cased bundle id is its own group (never merged → never fewer kept).
                try TestSuite.assertFalse(try await offered(keep: 1).contains(wrongCase))

                // Default settings = 3; the scanner offers them with the 7-day retention and the dSYM warning.
                env.scanSettings = .default
                let results = try await M5.scan(env, ["xcode.archives.old"])
                guard let result = results["xcode.archives.old"] else { throw TestError("no result") }
                try TestSuite.assertEqual(M5.paths(result, f), [x[3], x[4]])
                try TestSuite.assertEqual(result.rule.whatYouLose, "dSYMs needed to symbolicate crash reports for these builds.")
                try TestSuite.assertEqual(result.rule.effectiveRetentionHours, 168)
                let plan = await M5.plan(env, [result])
                for item in plan.items {
                    try TestSuite.assertEqual(item.action, .quarantine(retentionHours: 168))
                    try TestSuite.assertTrue(item.isActionable, "\(item.preconditions)")
                    try TestSuite.assertFalse(item.selectedByDefault)
                }
            }
        }
    }

    // MARK: DeviceSupport

    @MainActor
    static func deviceSupportTests() async {
        await TestSuite.run("XcodeInspector: DeviceSupport folder-name parsing") {
            typealias P = XcodeDeviceSupportInspector
            let a = try M5.unwrap(P.parseFolderName("17.5 (21F79)"))
            try TestSuite.assertEqual(a.version, [17, 5]); try TestSuite.assertEqual(a.build, "21F79"); try TestSuite.assertNil(a.device)
            let b = try M5.unwrap(P.parseFolderName("17.5.1 (21F90) arm64e"))
            try TestSuite.assertEqual(b.version, [17, 5, 1]); try TestSuite.assertEqual(b.build, "21F90")
            let c = try M5.unwrap(P.parseFolderName("iPhone15,2 17.5 (21F79)"))
            try TestSuite.assertEqual(c.version, [17, 5]); try TestSuite.assertEqual(c.device, "iPhone15,2")
            let d = try M5.unwrap(P.parseFolderName("watchOS 10.5 (21T575)"))
            try TestSuite.assertEqual(d.version, [10, 5]); try TestSuite.assertNil(d.device)
            let e = try M5.unwrap(P.parseFolderName("16.4"))
            try TestSuite.assertEqual(e.version, [16, 4]); try TestSuite.assertNil(e.build)
            for bad in ["junk", "", "(21F79)", "Latest", "iPhone (abc)", "1.2.3.4.5 (x)"] {
                try TestSuite.assertNil(P.parseFolderName(bad), bad)
            }
        }

        await TestSuite.run("XcodeInspector: DeviceSupport — four platform folders only, unparsable names skipped, versions older than newest-2 highlighted per platform") {
            try await M1.withEnv { env in
                let f = env.fixture
                let base = "Library/Developer/Xcode/"
                let ios = ["18.2 (22C152)", "17.5.1 (21F90) arm64e", "iPhone15,2 16.4 (20E247)", "15.0 (19A346)", "junk folder"]
                let watch = ["watchOS 10.5 (21T575)", "Watch6,1 9.0 (20R362)", "7.0 (18R382)"]
                for name in ios { try f.file(base + "iOS DeviceSupport/\(name)/Symbols/x", bytes: 1_000) }
                for name in watch { try f.file(base + "watchOS DeviceSupport/\(name)/Symbols/x", bytes: 1_000) }
                try f.file(base + "tvOS DeviceSupport/17.0 (21J354)/Symbols/x", bytes: 1_000)
                try f.file(base + "visionOS DeviceSupport/2.0 (22N320)/Symbols/x", bytes: 1_000)
                try f.file(base + "macOS DeviceSupport/14.0 (23A344)/Symbols/x", bytes: 1_000) // not in the spec
                try f.file(base + "iOS DeviceSupport/file.txt", bytes: 10)

                let out = try await M5.discover(XcodeDeviceSupportInspector(), env, "xcode.deviceSupport")
                try TestSuite.assertEqual(out.status, .ok)
                var expected = Set(ios.dropLast().map { base + "iOS DeviceSupport/" + $0 })
                expected.formUnion(watch.map { base + "watchOS DeviceSupport/" + $0 })
                expected.insert(base + "tvOS DeviceSupport/17.0 (21J354)")
                expected.insert(base + "visionOS DeviceSupport/2.0 (22N320)")
                try TestSuite.assertEqual(M5.paths(out, f), expected)
                func notes(_ rel: String) throws -> [String] {
                    guard let c = out.candidates.first(where: { M5.relative($0.path, f) == base + rel }) else { throw TestError("missing \(rel)") }
                    return c.notes
                }
                func highlighted(_ rel: String) throws -> Bool { try notes(rel).contains { $0.hasPrefix("Older than") } }
                // iOS newest major 18 → highlight majors below 16.
                try TestSuite.assertTrue(try highlighted("iOS DeviceSupport/15.0 (19A346)"))
                try TestSuite.assertFalse(try highlighted("iOS DeviceSupport/iPhone15,2 16.4 (20E247)"))
                try TestSuite.assertFalse(try highlighted("iOS DeviceSupport/17.5.1 (21F90) arm64e"))
                try TestSuite.assertFalse(try highlighted("iOS DeviceSupport/18.2 (22C152)"))
                // watchOS is judged against its own newest (10), not iOS 18.
                try TestSuite.assertTrue(try highlighted("watchOS DeviceSupport/7.0 (18R382)"))
                try TestSuite.assertFalse(try highlighted("watchOS DeviceSupport/Watch6,1 9.0 (20R362)"))
                try TestSuite.assertTrue(try notes("iOS DeviceSupport/iPhone15,2 16.4 (20E247)").contains("Device: iPhone15,2"))
                try TestSuite.assertTrue(try notes("iOS DeviceSupport/18.2 (22C152)").contains("iOS 18.2 (build 22C152)"))

                // Scanner + plan: Yellow, olderThan(30) — fresh folders are blocked, old ones actionable, none preselected.
                try M5.age(f, base + "iOS DeviceSupport/15.0 (19A346)", days: 40, clock: env.clock)
                try M5.age(f, base + "iOS DeviceSupport/15.0 (19A346)/Symbols", days: 40, clock: env.clock)
                let results = try await M5.scan(env, ["xcode.deviceSupport"])
                try TestSuite.assertEqual(M5.paths(results["xcode.deviceSupport"], f), expected)
                let plan = await M5.plan(env, Array(results.values))
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.selectedByDefault })
                let old = try M5.item(plan, base + "iOS DeviceSupport/15.0 (19A346)", f)
                try TestSuite.assertTrue(old.isActionable, "\(old.preconditions)")
                try TestSuite.assertEqual(M5.failedPrecondition(try M5.item(plan, base + "iOS DeviceSupport/18.2 (22C152)", f)), "olderThan")
            }
        }
    }

    // MARK: .xip downloads

    @MainActor
    static func xipTests() async {
        await TestSuite.run("XcodeInspector: Xcode .xip downloads — only *.xip directly in Downloads; olderThan(7), not open, Xcode not running; never preselected") {
            try await M1.withEnv { env in
                let f = env.fixture
                try f.file("Downloads/Xcode_16.xip", bytes: 50_000)
                try f.file("Downloads/Xcode_17.xip", bytes: 50_000)
                try f.file("Downloads/InUse.xip", bytes: 50_000)
                try f.file("Downloads/Xcode_15.zip", bytes: 50_000)
                try f.file("Downloads/sub/Nested.xip", bytes: 50_000)
                try f.setModificationDate("Downloads/Xcode_16.xip", daysAgo: 10, clock: env.clock)
                try f.setModificationDate("Downloads/InUse.xip", daysAgo: 10, clock: env.clock)
                try f.setModificationDate("Downloads/Xcode_17.xip", daysAgo: 2, clock: env.clock)
                env.processes.openFiles = [f.path("Downloads/InUse.xip"): [4242]]

                let results = try await M5.scan(env, ["xcode.xipDownloads"])
                try TestSuite.assertEqual(results["xcode.xipDownloads"]?.status, .ok)
                try TestSuite.assertEqual(M5.paths(results["xcode.xipDownloads"], f),
                                          ["Downloads/Xcode_16.xip", "Downloads/Xcode_17.xip", "Downloads/InUse.xip"])
                let plan = await M5.plan(env, Array(results.values))
                let old = try M5.item(plan, "Downloads/Xcode_16.xip", f)
                try TestSuite.assertTrue(old.isActionable, "\(old.preconditions)")
                try TestSuite.assertFalse(old.selectedByDefault)
                try TestSuite.assertEqual(M5.failedPrecondition(try M5.item(plan, "Downloads/Xcode_17.xip", f)), "olderThan")
                try TestSuite.assertEqual(M5.failedPrecondition(try M5.item(plan, "Downloads/InUse.xip", f)), "notOpenByAnyProcess")
            }
        }
    }
}
