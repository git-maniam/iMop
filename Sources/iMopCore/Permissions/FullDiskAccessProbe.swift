import Foundation

// Full Disk Access probe (spec §8). Strictly read-only: it lists a TCC-protected folder through
// `SafeCleanEnvironment.fileSystem` and never writes, creates or changes anything to find out.

/// Result of a permission probe.
public enum PermissionState: String, Sendable, Hashable, Codable, CaseIterable {
    case granted
    case denied
    /// Could not be determined (nothing to probe, or no reliable read-only probe exists).
    case unknown
}

/// Answers whether iMop has Full Disk Access. Injectable so tests never depend on the real TCC state.
public protocol FullDiskAccessProbing: Sendable {
    func fullDiskAccessState() -> PermissionState
}

/// Lists `{HOME}/Library/Safari`, then `{HOME}/Library/Containers/com.apple.Safari` (both protected by
/// Full Disk Access) through the environment's read-only file-system probe.
///
/// - `.granted`: every one that exists as a real directory could be listed (at least one exists).
/// - `.denied`: at least one exists as a real directory and could NOT be listed.
/// - `.unknown`: neither exists as a real directory.
public struct FullDiskAccessProbe: FullDiskAccessProbing {
    /// System Settings › Privacy & Security › Full Disk Access.
    public static let settingsDeepLink = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"

    /// Probed locations, relative to the home folder, in order.
    public static let protectedLocations: [[String]] = [
        ["Library", "Safari"],
        ["Library", "Containers", "com.apple.Safari"],
    ]

    private let fileSystem: any FileSystemProbe
    private let homePath: String

    public init(environment: SafeCleanEnvironment) {
        self.fileSystem = environment.fileSystem
        self.homePath = environment.homePath
    }

    public func fullDiskAccessState() -> PermissionState {
        // SAFETY-DECISION (review M6): EVERY existing protected folder is probed. A refusal of any one of
        // them is direct evidence that access is not (fully) granted, so a mixed result is `.denied`,
        // never `.granted` — rules that need Full Disk Access stay locked.
        var sawRefusal = false
        var sawListing = false
        for components in Self.protectedLocations {
            let path = homePath + "/" + components.joined(separator: "/")
            // SAFETY-DECISION: only a real directory is probed; a symlink (which could point anywhere)
            // or a missing folder says nothing about the permission.
            guard let info = fileSystem.lstat(path), info.isDirectory, !info.isSymlink else { continue }
            if fileSystem.contentsOfDirectory(path) != nil {
                sawListing = true
                continue
            }
            // SAFETY-DECISION: any listing failure (not only EPERM) counts as "denied", so rules that
            // need Full Disk Access stay locked rather than failing half-way.
            sawRefusal = true
        }
        if sawRefusal { return .denied }
        return sawListing ? .granted : .unknown
    }

    /// `true` only when access is positively confirmed (`.unknown` is treated as not granted).
    public var hasFullDiskAccess: Bool { fullDiskAccessState() == .granted }
}
