import Foundation

/// What a target refers to.
public enum TargetKind: Sendable, Hashable, Codable {
    /// A file or directory on disk acted on by Quarantine / Trash / permanent delete.
    case filesystem
    /// An item handled by a vendor command (simulator UDID, Docker volume, Ollama model, or the
    /// whole command when `argument` is nil).
    case commandItem(argument: String?)
    /// Explanation only — never acted on.
    case advisory
}

/// One discovered candidate. Produced by the read-only Scanner, consumed by PlanBuilder.
public struct ScanTarget: Sendable, Hashable, Identifiable {
    public let id: UUID
    public let ruleID: String
    public let kind: TargetKind
    /// Canonical absolute path (for `.filesystem`) or the most relevant path for display.
    public let path: String
    public let displayName: String
    /// `(dev, ino)` captured at scan time; required for filesystem targets.
    public let identity: FileIdentity?
    /// Bytes allocated on disk.
    public let allocatedBytes: Int64
    /// Bytes that would actually be freed (APFS private size, hard links excluded).
    public let reclaimableBytes: Int64
    public let itemCount: Int
    public let lastUsed: Date?
    /// Bundle identifier of the owning app, when known.
    public let owningBundleID: String?
    /// Extra facts shown in the detail view (OS version, archive date, missing binary, …).
    public let notes: [String]

    public init(
        id: UUID = UUID(),
        ruleID: String,
        kind: TargetKind = .filesystem,
        path: String,
        displayName: String,
        identity: FileIdentity?,
        allocatedBytes: Int64,
        reclaimableBytes: Int64,
        itemCount: Int,
        lastUsed: Date?,
        owningBundleID: String? = nil,
        notes: [String] = []
    ) {
        self.id = id
        self.ruleID = ruleID
        self.kind = kind
        self.path = path
        self.displayName = displayName
        self.identity = identity
        self.allocatedBytes = allocatedBytes
        self.reclaimableBytes = reclaimableBytes
        self.itemCount = itemCount
        self.lastUsed = lastUsed
        self.owningBundleID = owningBundleID
        self.notes = notes
    }
}
