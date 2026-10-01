import Foundation

/// Why SafetyGate refused an item. Every rejection is written to the audit log.
public enum SafetyRejection: Sendable, Hashable, Codable {
    case runningAsRoot
    case canonicalizationFailed(String)
    case parentTraversal
    case denyListed(entry: String)
    case notInsideAllowRoot
    case equalsAllowRoot
    case insufficientDepth(required: Int, actual: Int)
    case symlinkInPath(component: String)
    case crossVolume
    case notOwnedByUser(uid: UInt32)
    case changedSinceScan
    case missingIdentity
    case insideCloudRoot
    case ubiquitousItem
    case fileProviderItem(attribute: String)
    case insideBundle(component: String)
    case preconditionFailed(name: String, detail: String)
    case sanityLimitExceeded(bytes: Int64, items: Int)
    case userExcluded(path: String)
    case itemMissing

    /// Short, user-facing reason ("Skipped for safety: …").
    public var reason: String {
        switch self {
        case .runningAsRoot: return "iMop refuses to run as root"
        case .canonicalizationFailed(let detail): return "Path could not be resolved safely (\(detail))"
        case .parentTraversal: return "Path contains a '..' component"
        case .denyListed(let entry): return "Protected location (\(entry))"
        case .notInsideAllowRoot: return "Outside the locations this rule may touch"
        case .equalsAllowRoot: return "Refusing to remove a top-level folder itself"
        case .insufficientDepth(let required, let actual): return "Too shallow (needs \(required) level(s) below root, has \(actual))"
        case .symlinkInPath(let component): return "Symbolic link in path (\(component))"
        case .crossVolume: return "Item is on a different volume"
        case .notOwnedByUser(let uid): return "Owned by another user (uid \(uid))"
        case .changedSinceScan: return "Item changed since scan"
        case .missingIdentity: return "Item identity was not captured at scan time"
        case .insideCloudRoot: return "Inside a cloud-synced folder"
        case .ubiquitousItem: return "iCloud item"
        case .fileProviderItem(let attribute): return "Managed by a cloud File Provider (\(attribute))"
        case .insideBundle(let component): return "Inside an application or bundle (\(component))"
        case .preconditionFailed(let name, let detail): return detail.isEmpty ? "Precondition not met: \(name)" : detail
        case .sanityLimitExceeded(let bytes, let items): return "Unexpectedly large (\(bytes) bytes, \(items) items) — needs manual review"
        case .userExcluded(let path): return "Excluded in Settings (\(path))"
        case .itemMissing: return "Item no longer exists"
        }
    }

    /// Spec §11 error category.
    public var errorCategory: ErrorCategory {
        switch self {
        case .changedSinceScan, .missingIdentity, .itemMissing: return .changedSinceScan
        case .crossVolume: return .crossVolume
        case .preconditionFailed(let name, _): return name == "notOpenByAnyProcess" ? .inUse : .preconditionFailed(name)
        default: return .safetyRejected(reason)
        }
    }
}

/// Spec §11 error categories for per-item failures.
public enum ErrorCategory: Sendable, Hashable, Codable {
    case permissionDenied
    case inUse
    case changedSinceScan
    case preconditionFailed(String)
    case safetyRejected(String)
    case commandFailed(Int32)
    case timeout
    case crossVolume
    case mutationDisabled
}

public enum SafetyVerdict: Sendable, Hashable {
    case allowed
    /// Sanity limit tripped: never act; present as Red for manual review.
    case downgradedToRed(SafetyRejection)
    case rejected(SafetyRejection)

    public var isAllowed: Bool { if case .allowed = self { return true } else { return false } }

    public var rejection: SafetyRejection? {
        switch self {
        case .allowed: return nil
        case .downgradedToRed(let r), .rejected(let r): return r
        }
    }
}
