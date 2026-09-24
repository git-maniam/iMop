import Foundation
import iMopCore

public struct AppRegistryTests {
    @MainActor
    public static func runAll() async {
        print("\n📱 Running App Registry & Safety Tests...")

        await TestSuite.run("Protected vendor and tool names are guarded") {
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Apple"))
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Google"))
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Microsoft"))
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Docker"))
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "Code"))
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: ".config"))
            try TestSuite.assertTrue(FileSafetyRules.isProtectedRemnantCandidate(name: "com.apple.Safari"))
        }

        await TestSuite.run("Uninstalled third-party bundle ID is recognized as candidate") {
            let deadCandidate = "com.uninstalleddeveloper.obsoletejunk"
            try TestSuite.assertFalse(FileSafetyRules.isProtectedRemnantCandidate(name: deadCandidate))
        }

        await TestSuite.run("AppRegistry indexes active system apps") {
            let registry = AppRegistryService()
            registry.indexInstalledApplications()

            let isFinderOrSystemInstalled = registry.isAppInstalled(nameOrBundleID: "com.apple.finder") ||
                                           registry.isAppInstalled(nameOrBundleID: "finder")
            try TestSuite.assertTrue(isFinderOrSystemInstalled, "System apps like Finder must be indexed")
        }
    }
}
