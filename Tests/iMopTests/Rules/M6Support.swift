import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Shared helpers for the Milestone 6 suites (OrphanDetector, LaunchAgents, Trash flows, Advisory
/// rules, permission probes, retention override).
///
/// Every inspector that would otherwise read a real system folder (`/Applications`, `/Library/…`,
/// `/System/Library/AssetsV2`, `/Applications/Setapp`) is replaced by its `@_spi(FixtureTesting)`
/// variant rooted in the fixture tree, so scans in tests are deterministic and never look at the
/// real machine's apps. No command really runs (FakeCommandRunner), nothing is really trashed
/// (FixtureTrash) and nothing outside the fixture root is modified.
enum M6 {
    /// Milestone 6 rules with their tiers (spec §6.1, §6.3, §6.4, §6.6, §6.7, §6.9, §6.10).
    static let ruleTiers: [String: Tier] = [
        "leftovers.appData": .red, "leftovers.launchAgents": .red,
        "xcode.extraInstalls": .red, "installers.macOS": .yellow, "jetbrains.config.orphanedVersion": .red,
        "downloads.diskImages": .yellow, "downloads.archives": .red, "trash.empty": .yellow, "system.coreDumps": .yellow,
        "docker.diskImage": .advisory, "finalcut.generated": .advisory, "audio.soundLibraries": .advisory,
        "advisory.timeMachineSnapshots": .advisory, "advisory.purgeableSpace": .advisory, "advisory.iosBackups": .advisory,
        "advisory.systemStorage": .advisory, "advisory.appleIntelligenceAssets": .advisory, "advisory.iCloudDrive": .advisory,
        "advisory.rootOwnedLocations": .advisory,
    ]
    static var ruleIDs: Set<String> { Set(ruleTiers.keys) }
    static var advisoryRuleIDs: Set<String> { Set(ruleTiers.filter { $0.value == .advisory }.keys) }
    static var actionableRuleIDs: Set<String> { ruleIDs.subtracting(advisoryRuleIDs) }

    /// Rules whose allow-roots are outside the home folder (Swift-pinned `RuleCatalog.nonHomeRuleSpecs`).
    static let nonHomeRuleIDs: Set<String> = ["xcode.extraInstalls", "installers.macOS", "system.coreDumps"]

    // MARK: Fixture system folders

    /// Fixture stand-in for `/Applications` (below the fixture ROOT, not the home).
    static func applicationsDirectory(_ f: FixtureBuilder) -> String { f.path("System/Applications-root", base: .root) }
    static func systemApplicationsDirectory(_ f: FixtureBuilder) -> String { f.path("System/System-Applications", base: .root) }
    static func setappDirectory(_ f: FixtureBuilder) -> String { applicationsDirectory(f) + "/Setapp" }
    static func systemRoot(_ f: FixtureBuilder) -> String { f.path("SystemRoot", base: .root) }

    /// The OrphanDetector over fixture application folders (both required roots are created).
    static func orphanInspector(_ f: FixtureBuilder, catalog: RuleCatalog? = nil) throws -> OrphanedAppDataInspector {
        try f.dir("System/Applications-root", base: .root)
        try f.dir("System/System-Applications", base: .root)
        return OrphanedAppDataInspector(
            catalog: catalog,
            applicationRoots: [applicationsDirectory(f), applicationsDirectory(f) + "/Utilities", "{HOME}/Applications",
                               systemApplicationsDirectory(f)],
            requiredApplicationRoots: [applicationsDirectory(f), systemApplicationsDirectory(f)],
            setappDirectory: setappDirectory(f))
    }

    static func orphanEvaluator(_ env: FakeEnvironment, catalog: RuleCatalog?) throws -> OrphanEvaluator {
        let f = env.fixture
        try f.dir("System/Applications-root", base: .root)
        try f.dir("System/System-Applications", base: .root)
        return OrphanEvaluator(
            environment: env.environment, catalog: catalog,
            applicationRoots: [applicationsDirectory(f), applicationsDirectory(f) + "/Utilities", "{HOME}/Applications",
                               systemApplicationsDirectory(f)],
            requiredApplicationRoots: [applicationsDirectory(f), systemApplicationsDirectory(f)],
            setappDirectory: setappDirectory(f))
    }

    /// `SafeCleanScanner.defaultInspectors` with every system-folder reader re-rooted in the fixture.
    static func fixtureInspectors(_ f: FixtureBuilder) throws -> [any Inspector] {
        let orphans = try orphanInspector(f)
        try f.dir("SystemRoot", base: .root)
        let replacements: [InspectorID: any Inspector] = [
            .orphanedAppData: orphans,
            .xcodeExtraInstalls: XcodeExtraInstallsInspector(systemApplicationsDirectory: applicationsDirectory(f)),
            .macOSInstallers: MacOSInstallersInspector(applicationsDirectory: applicationsDirectory(f)),
            .advisory: AdvisoryInspector(systemRoot: systemRoot(f)),
        ]
        return SafeCleanScanner.defaultInspectors.map { replacements[$0.id] ?? $0 }
    }

    // MARK: Commands

    static let pkgutilPath = "/usr/sbin/pkgutil"
    static let tmutilPath = "/usr/bin/tmutil"
    static let launchctlPath = "/bin/launchctl"

    /// A believable receipt listing (Apple receipts only unless `extra` is given).
    static func usePkgutil(_ env: FakeEnvironment, receipts extra: [String] = [], result: CommandResult? = nil) {
        var executables = env.commands.executables
        executables["pkgutil"] = pkgutilPath
        env.commands.executables = executables
        let listing = (["com.apple.pkg.CLTools_Executables", "com.apple.pkg.MobileAssets"] + extra).joined(separator: "\n") + "\n"
        env.commands.setResponse(result ?? CommandResult(exitCode: 0, stdout: listing, stderr: ""), for: ["--pkgs"])
    }

    static func useLaunchctl(_ env: FakeEnvironment) {
        var executables = env.commands.executables
        executables["launchctl"] = launchctlPath
        env.commands.executables = executables
    }

    // MARK: Fixture items

    /// Writes `Contents/Info.plist` for an app bundle at `rel` (relative to `base`).
    @discardableResult
    static func appBundle(_ f: FixtureBuilder, _ rel: String, bundleID: String, version: String = "1.0",
                          extra: [String: Any] = [:], base: FixtureBuilder.Base = .home) throws -> String {
        var plist: [String: Any] = ["CFBundleIdentifier": bundleID, "CFBundleShortVersionString": version]
        for (k, v) in extra { plist[k] = v }
        try f.file(rel + "/Contents/Info.plist", contents: try M5.plistData(plist), base: base)
        try f.file(rel + "/Contents/MacOS/binary", bytes: 64, base: base)
        return f.path(rel, base: base)
    }

    /// Ages `rel` and every entry below it (recursively) by `days`.
    static func ageTree(_ f: FixtureBuilder, _ rel: String, days: Int, clock: any iMopCore.Clock) throws {
        let absolute = f.path(rel)
        if let enumerator = FileManager.default.enumerator(atPath: absolute) {
            var children: [String] = []
            while let child = enumerator.nextObject() as? String { children.append(child) }
            for child in children.sorted(by: { $0.count > $1.count }) {
                try f.setModificationDate(rel + "/" + child, daysAgo: days, clock: clock)
            }
        }
        try f.setModificationDate(rel, daysAgo: days, clock: clock)
    }

    /// The source catalog's rule `id`.
    @MainActor
    static func rule(_ env: FakeEnvironment, _ id: String) throws -> Rule { try M5.rule(env, id) }
}
