import Foundation
import AppKit

public final class AppRegistryService: @unchecked Sendable {
    public static let shared = AppRegistryService()

    private var installedBundleIDs: Set<String> = []
    private var installedAppNames: Set<String> = []
    private var isIndexed = false
    private let lock = NSLock()

    public init() {}

    /// Scan system and user application directories to build an in-memory index
    public func indexInstalledApplications() {
        lock.lock()
        defer { lock.unlock() }

        var bundleIDs = Set<String>()
        var appNames = Set<String>()

        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser

        let searchDirs: [URL] = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications/Utilities", isDirectory: true),
            URL(fileURLWithPath: "/Applications/Utilities", isDirectory: true),
            home.appendingPathComponent("Applications", isDirectory: true)
        ]

        for dir in searchDirs {
            guard fileManager.fileExists(atPath: dir.path) else { continue }
            if let enumerator = fileManager.enumerator(
                at: dir,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) {
                for case let fileURL as URL in enumerator {
                    if fileURL.pathExtension == "app" {
                        let appName = fileURL.deletingPathExtension().lastPathComponent.lowercased()
                        appNames.insert(appName)

                        // Read bundle identifier from Info.plist
                        let infoPlistURL = fileURL.appendingPathComponent("Contents/Info.plist")
                        if let infoData = try? Data(contentsOf: infoPlistURL),
                           let plist = try? PropertyListSerialization.propertyList(from: infoData, options: [], format: nil) as? [String: Any] {
                            if let bundleID = plist["CFBundleIdentifier"] as? String {
                                bundleIDs.insert(bundleID.lowercased())
                            }
                            if let bundleName = plist["CFBundleName"] as? String {
                                appNames.insert(bundleName.lowercased())
                            }
                            if let displayName = plist["CFBundleDisplayName"] as? String {
                                appNames.insert(displayName.lowercased())
                            }
                        }
                    }
                }
            }
        }

        self.installedBundleIDs = bundleIDs
        self.installedAppNames = appNames
        self.isIndexed = true
    }

    /// Check if a candidate name or bundle ID matches any installed application
    public func isAppInstalled(nameOrBundleID: String) -> Bool {
        lock.lock()
        let needsIndex = !isIndexed
        lock.unlock()

        if needsIndex {
            indexInstalledApplications()
        }

        lock.lock()
        defer { lock.unlock() }

        let lower = nameOrBundleID.lowercased()

        // 1. Direct match on bundle ID
        if installedBundleIDs.contains(lower) {
            return true
        }

        // 2. Direct match on app name
        if installedAppNames.contains(lower) {
            return true
        }

        // 3. Partial check: bundle ID suffix (e.g., com.tinyspeck.slackmacgap -> contains "slackmacgap" or "slack")
        let components = lower.split(separator: ".")
        if let last = components.last, installedAppNames.contains(String(last)) {
            return true
        }

        return false
    }

    /// Retrieve currently running application bundle identifiers
    @MainActor
    public func getRunningApplicationBundleIDs() -> Set<String> {
        let apps = NSWorkspace.shared.runningApplications
        return Set(apps.compactMap { $0.bundleIdentifier?.lowercased() })
    }

    /// Retrieve currently running application names
    @MainActor
    public func getRunningApplicationNames() -> Set<String> {
        let apps = NSWorkspace.shared.runningApplications
        return Set(apps.compactMap { $0.localizedName?.lowercased() })
    }
}
