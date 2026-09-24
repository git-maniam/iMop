import Foundation

public enum JunkCategoryType: String, CaseIterable, Identifiable, Sendable {
    case appRemnants = "App Remnants"
    case userCaches = "Application Caches"
    case systemLogs = "Logs & Diagnostics"
    case developer = "Developer Artifacts"
    case trashAndTemp = "Trash & Temporary Files"

    public var id: String { rawValue }
    
    public var iconName: String {
        switch self {
        case .appRemnants: return "trash.square"
        case .userCaches: return "externaldrive.badge.timemachine"
        case .systemLogs: return "doc.plaintext"
        case .developer: return "hammer"
        case .trashAndTemp: return "trash"
        }
    }

    public var subtitle: String {
        switch self {
        case .appRemnants:
            return "Leftover files from uninstalled applications"
        case .userCaches:
            return "Disposable user and app cache files"
        case .systemLogs:
            return "Old crash reports, diagnostics, and log files"
        case .developer:
            return "DerivedData, package manager caches, and build tools"
        case .trashAndTemp:
            return "Items in Trash and temporary download caches"
        }
    }

    /// Smart default selection policy:
    /// Disposable caches, logs, and trash are pre-selected.
    /// Developer artifacts and App Remnants require user review.
    public var recommendedByDefault: Bool {
        switch self {
        case .userCaches, .systemLogs, .trashAndTemp:
            return true
        case .developer, .appRemnants:
            return false
        }
    }
}
