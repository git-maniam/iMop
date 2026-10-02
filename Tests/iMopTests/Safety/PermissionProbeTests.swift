import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §8 / §13 M6: the Full Disk Access probe (read-only listing of TCC-protected folders) and the
/// App Management probe (no reliable read-only probe → `.unknown`), with their exact deep links.
@MainActor
enum PermissionProbeTests {
    static let safari = "Library/Safari"
    static let safariContainer = "Library/Containers/com.apple.Safari"

    /// Fails the listing of `rel` under both spellings of the fixture home.
    static func refuseListing(_ env: FakeEnvironment, _ rel: String) {
        env.fileSystem.fail(.contentsOfDirectory, path: env.fixture.path(rel))
        env.fileSystem.fail(.contentsOfDirectory, path: env.environment.homePath + "/" + rel)
    }

    static func runAll() async {
        print("\n🔐 Running Permission Probe Tests (spec §8, §13 M6)...")

        await TestSuite.run("Permissions: Full Disk Access — granted when a protected folder can be listed") {
            try await M1.withEnv { env in
                try env.fixture.file(safari + "/History.db", bytes: 10)
                try TestSuite.assertEqual(FullDiskAccessProbe(environment: env.environment).fullDiskAccessState(), .granted)
                try TestSuite.assertTrue(FullDiskAccessProbe(environment: env.environment).hasFullDiskAccess)
                // The second location alone is enough.
                try await M1.withEnv { other in
                    try other.fixture.dir(safariContainer + "/Data")
                    try TestSuite.assertEqual(FullDiskAccessProbe(environment: other.environment).fullDiskAccessState(), .granted)
                }
            }
        }

        await TestSuite.run("Permissions: Full Disk Access — denied when the protected folders exist but cannot be listed") {
            try await M1.withEnv { env in
                try env.fixture.dir(safari)
                try env.fixture.dir(safariContainer)
                refuseListing(env, safari)
                refuseListing(env, safariContainer)
                let probe = FullDiskAccessProbe(environment: env.environment)
                try TestSuite.assertEqual(probe.fullDiskAccessState(), .denied)
                try TestSuite.assertFalse(probe.hasFullDiskAccess)
                // Review M6: one refused, the other listable → denied (a refusal is evidence; never granted).
                for refused in [safari, safariContainer] {
                    try await M1.withEnv { other in
                        try other.fixture.dir(safari)
                        try other.fixture.dir(safariContainer + "/Data")
                        refuseListing(other, refused)
                        try TestSuite.assertEqual(FullDiskAccessProbe(environment: other.environment).fullDiskAccessState(), .denied, refused)
                    }
                }
            }
        }

        await TestSuite.run("Permissions: Full Disk Access — unknown when nothing can be probed (missing or symlinked folders)") {
            try await M1.withEnv { env in
                let probe = FullDiskAccessProbe(environment: env.environment)
                try TestSuite.assertEqual(probe.fullDiskAccessState(), .unknown)
                try TestSuite.assertFalse(probe.hasFullDiskAccess, "unknown is never treated as granted")
                try env.fixture.dir("elsewhere", base: .root)
                try env.fixture.symlink(safari, to: env.fixture.path("elsewhere", base: .root))
                try TestSuite.assertEqual(probe.fullDiskAccessState(), .unknown)
                let listed = env.fileSystem.recordedCalls.filter { $0.0 == .contentsOfDirectory }
                try TestSuite.assertTrue(listed.isEmpty, "a symlink is never listed: \(listed.map(\.1))")
            }
        }

        await TestSuite.run("Permissions: the Full Disk Access probe is read-only (only lstat + listing, fixture unchanged)") {
            try await M1.withEnv { env in
                try env.fixture.file(safari + "/History.db", bytes: 10)
                let before = M3.children(env.fixture.path(safari))
                _ = FullDiskAccessProbe(environment: env.environment).fullDiskAccessState()
                let methods = Set(env.fileSystem.recordedCalls.map(\.0))
                try TestSuite.assertTrue(methods.isSubset(of: [.lstat, .contentsOfDirectory]), "\(methods)")
                try TestSuite.assertEqual(M3.children(env.fixture.path(safari)), before)
            }
        }

        await TestSuite.run("Permissions: App Management is always unknown (no probe ever changes an app); deep links are exact") {
            try await M1.withEnv { env in
                try TestSuite.assertEqual(AppManagementProbe().appManagementState(), .unknown)
                let probes = PermissionProbes.live(environment: env.environment)
                try TestSuite.assertEqual(probes.appManagement.appManagementState(), .unknown)
                try TestSuite.assertEqual(probes.fullDiskAccess.fullDiskAccessState(), .unknown)
                try TestSuite.assertEqual(FullDiskAccessProbe.settingsDeepLink,
                                          "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
                try TestSuite.assertEqual(AppManagementProbe.settingsDeepLink,
                                          "x-apple.systempreferences:com.apple.preference.security?Privacy_AppBundles")
                try TestSuite.assertTrue(AppManagementProbe.isAppBundlePath("/Applications/Xcode-beta.app"))
                try TestSuite.assertTrue(AppManagementProbe.isAppBundlePath("/Applications/Install macOS Sequoia.APP/"))
                try TestSuite.assertFalse(AppManagementProbe.isAppBundlePath("/Applications/.app"))
                try TestSuite.assertFalse(AppManagementProbe.isAppBundlePath("/Users/x/Downloads/app"))
                try TestSuite.assertTrue(AppManagementProbe.isPermissionError(POSIXError(.EPERM)))
                try TestSuite.assertTrue(AppManagementProbe.isPermissionError(NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError)))
                try TestSuite.assertFalse(AppManagementProbe.isPermissionError(POSIXError(.ENOENT)))
            }
        }

        await TestSuite.run("Permissions: probes are injectable (fakes stand in for the real TCC state)") {
            struct FixedFDA: FullDiskAccessProbing { let state: PermissionState; func fullDiskAccessState() -> PermissionState { state } }
            struct FixedAppManagement: AppManagementProbing { func appManagementState() -> PermissionState { .denied } }
            for state in PermissionState.allCases {
                let probes = PermissionProbes(fullDiskAccess: FixedFDA(state: state), appManagement: FixedAppManagement())
                try TestSuite.assertEqual(probes.fullDiskAccess.fullDiskAccessState(), state)
                try TestSuite.assertEqual(probes.appManagement.appManagementState(), .denied)
            }
        }
    }
}
