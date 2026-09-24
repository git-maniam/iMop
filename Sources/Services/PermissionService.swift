import Foundation
import AppKit

public final class PermissionService: Sendable {
    public static let shared = PermissionService()

    private init() {}

    /// Checks whether Full Disk Access (FDA) is granted to the running process.
    /// Attempts to read a directory protected by macOS TCC privacy controls.
    public func hasFullDiskAccess() -> Bool {
        // macOS TCC protects ~/Library/Safari and ~/Library/Containers
        let home = FileManager.default.homeDirectoryForCurrentUser
        let safariDir = home.appendingPathComponent("Library/Safari", isDirectory: true)

        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: safariDir.path) {
            do {
                _ = try fileManager.contentsOfDirectory(atPath: safariDir.path)
                return true
            } catch {
                return false
            }
        }

        // Fallback test on ~/Library/Containers
        let containersDir = home.appendingPathComponent("Library/Containers", isDirectory: true)
        if fileManager.fileExists(atPath: containersDir.path) {
            do {
                _ = try fileManager.contentsOfDirectory(atPath: containersDir.path)
                return true
            } catch {
                return false
            }
        }

        return false
    }

    /// Opens System Settings directly to the Full Disk Access configuration pane
    @MainActor
    public func openSystemSettingsFullDiskAccess() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}
