import Foundation
import AppKit

public struct FileSafetyRules: Sendable {
    /// Critical system paths that must NEVER be scanned or touched
    public static let blockedSystemPrefixes: [String] = [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/var",
        "/etc",
        "/private/etc",
        "/private/var",
        "/dev",
        "/Volumes",
        "/Library/Preferences/SystemConfiguration"
    ]

    /// Well-known vendor, system, or command-line directories in Application Support / Preferences
    /// that do not have standard macOS .app bundles and must NOT be flagged as orphaned remnants.
    public static let protectedVendorOrToolNames: Set<String> = [
        "Apple",
        "Google",
        "Microsoft",
        "Adobe",
        "Mozilla",
        "Code",
        "Visual Studio Code",
        "Sublime Text",
        "Sublime Text 3",
        "Git",
        "GitHub",
        "Homebrew",
        "Docker",
        "Telegram",
        "Slack",
        "Discord",
        "Spotify",
        "Dropbox",
        "Box",
        "OneDrive",
        "iCloud",
        "AddressBook",
        "Dock",
        "Safari",
        "Mail",
        "Calendar",
        "Contacts",
        "Notes",
        "Reminders",
        "QuickLook",
        "SyncServices",
        "CloudDocs",
        "Containers",
        "Group Containers"
    ]

    /// Check if a path is strictly inside an absolute blocked system location
    public static func isBlockedSystemPath(_ url: URL) -> Bool {
        let standardized = url.standardizedFileURL.path
        if standardized == "/" { return true }

        // Explicitly allow user temporary sandbox paths in /var/folders or /private/var/folders
        if standardized.hasPrefix("/var/folders") || standardized.hasPrefix("/private/var/folders") {
            return false
        }

        for prefix in blockedSystemPrefixes {
            if standardized == prefix || standardized.hasPrefix(prefix + "/") {
                return true
            }
        }
        return false
    }

    /// Check if a path is inside an iCloud drive sync repository
    public static func isCloudSyncedPath(_ url: URL) -> Bool {
        let path = url.path
        return path.contains("com~apple~CloudDocs") ||
               path.contains("Mobile Documents") ||
               path.hasSuffix(".icloud")
    }

    /// Check if a URL is a symbolic link
    public static func isSymlink(_ url: URL) -> Bool {
        let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey])
        return values?.isSymbolicLink ?? false
    }

    /// Check if a directory or item name belongs to the protected vendor or tool allowlist
    public static func isProtectedRemnantCandidate(name: String) -> Bool {
        // Protect dotfiles/directories (e.g. .git, .config)
        if name.hasPrefix(".") { return true }

        // Exact match in protected vendor list
        if protectedVendorOrToolNames.contains(name) { return true }

        // Apple system reverse-DNS prefixes
        if name.hasPrefix("com.apple.") || name.hasPrefix("group.com.apple.") {
            return true
        }

        return false
    }

    /// Check if a candidate bundle identifier or folder belongs to any currently running application
    public static func isRunningApplication(nameOrBundleID: String, runningBundleIDs: Set<String>, runningAppNames: Set<String>) -> Bool {
        let lower = nameOrBundleID.lowercased()
        if runningBundleIDs.contains(where: { $0.lowercased() == lower }) {
            return true
        }
        if runningAppNames.contains(where: { $0.lowercased() == lower }) {
            return true
        }
        return false
    }

    /// Comprehensive safety gate: returns true if the URL is safe to clean
    public static func isSafeToDelete(_ url: URL, runningBundleIDs: Set<String> = [], runningAppNames: Set<String> = []) -> Bool {
        // 1. Guard against system blocklist
        if isBlockedSystemPath(url) {
            return false
        }

        // 2. Guard against iCloud docs
        if isCloudSyncedPath(url) {
            return false
        }

        // 3. Guard against symlinks (don't delete symlink targets)
        if isSymlink(url) {
            return false
        }

        // 4. Guard against active running applications
        let lastComponent = url.lastPathComponent
        let nameWithoutExt = url.deletingPathExtension().lastPathComponent
        if isRunningApplication(nameOrBundleID: lastComponent, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) ||
           isRunningApplication(nameOrBundleID: nameWithoutExt, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) {
            return false
        }

        return true
    }
}
