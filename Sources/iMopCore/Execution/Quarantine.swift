import Darwin
import Foundation

// Spec §5.1 Quarantine and §11 crash safety.
//
// This is the ONLY module that writes under {HOME}/Library/Application Support/iMop/Quarantine.
// Layout:
//
//   Quarantine/                         (0700, real directory owned by the user)
//     .metadata_never_index             (keeps Spotlight out)
//     <session-UUID>/                   (0700)
//       manifest.json                   (atomic: temp file with O_EXCL in the same dir + rename)
//       <entry-UUID>/                   (0700)
//         <original name>               (the moved item, renamex_np(RENAME_EXCL), never copied)
//
// SAFETY-DECISION: each item gets its own `<entry-UUID>/` directory and keeps its ORIGINAL name
// (`quarantinedName` = "<entry-UUID>/<original name>") instead of a flat "<uuid>-<name>". Renaming
// the item would change how SafetyGate classifies it at purge time: a per-app cache folder such as
// "com.example.app" is recognised as a cache (reverse-DNS name) only under its own name; with a
// "<uuid>-" prefix it would look like an `.app` bundle and could never be purged, and other
// name-based checks would differ from the ones the item passed at execute time.
//
// Review M3 hardening:
// - `quarantine(...)` is SPI-only (the Executor is its only production caller) and re-runs SafetyGate
//   (phase .execute) itself, so no public API can move an item SafetyGate would refuse.
// - The move is made relative to verified directory descriptors (parent and entry folder opened
//   without following symlinks); the pinned identity is checked with fstatat immediately before
//   renameatx_np, and a mismatching item found after the move is moved straight back.
// - Every state change of an entry is written to the manifest BEFORE it happens (`.pending`,
//   `.restoring`, `.purging`), so `reconcile()` can finish or undo it after a crash, and an item that
//   is physically in Quarantine is never forgotten (`.needsReview` instead of dropping it).
// - Identity checks that span launches compare the inode plus the persistent volume UUID recorded
//   in the entry (`st_dev` is assigned per mount and is not stable).
//
// Every mutation (directory creation, manifest write, move, restore, purge, cleanup) asks
// `MutationPolicy.permits` first and throws `.mutationDisabled` when denied. Before every write the
// Quarantine root and the session directory are lstat'ed: they must be real directories (never
// symlinks) owned by the user and not writable by group/others.

// MARK: - Model

public enum QuarantineStatus: String, Sendable, Codable, Hashable {
    /// Manifest written, move not (yet) confirmed. Reconciled on launch.
    case pending
    case moved
    /// Restore started: `restoredPath` holds the chosen destination (written BEFORE the move back).
    /// Reconciled on launch.
    case restoring
    case restored
    /// Purge started: the item may be partly removed and can no longer be restored. Every purge
    /// retries it; reconciled on launch.
    case purging
    case purged
    /// Crash recovery could not prove what this entry holds. Never purged; never dropped; restored
    /// only on explicit request (restore never overwrites anything).
    case needsReview
}

public struct QuarantineEntry: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let sessionID: UUID
    /// Canonical path the item was moved from.
    public let originalPath: String
    /// Location relative to the session directory: "<entry-UUID>/<original name>".
    public let quarantinedName: String
    /// `(dev, ino)` pinned at scan time; preserved by rename(2).
    public let identity: FileIdentity
    public let allocatedBytes: Int64
    public let reclaimableBytes: Int64
    public let ruleID: String
    public let tier: Tier
    public let quarantinedAt: Date
    public let expiresAt: Date
    public var status: QuarantineStatus
    /// Where the item was put back (`.restored`), or is being put back (`.restoring`).
    public var restoredPath: String?
    /// Persistent UUID of the volume the item was quarantined on. `st_dev` changes when a volume is
    /// mounted again, so checks across launches compare the inode plus this UUID.
    public var volumeUUID: String?

    public init(id: UUID, sessionID: UUID, originalPath: String, quarantinedName: String, identity: FileIdentity,
                allocatedBytes: Int64, reclaimableBytes: Int64, ruleID: String, tier: Tier,
                quarantinedAt: Date, expiresAt: Date, status: QuarantineStatus, restoredPath: String? = nil,
                volumeUUID: String? = nil) {
        self.id = id
        self.sessionID = sessionID
        self.originalPath = originalPath
        self.quarantinedName = quarantinedName
        self.identity = identity
        self.allocatedBytes = allocatedBytes
        self.reclaimableBytes = reclaimableBytes
        self.ruleID = ruleID
        self.tier = tier
        self.quarantinedAt = quarantinedAt
        self.expiresAt = expiresAt
        self.status = status
        self.restoredPath = restoredPath
        self.volumeUUID = volumeUUID
    }

    /// Identity check that holds across launches: same inode, and the same volume — by recorded
    /// volume UUID when both are known, else by exact `st_dev`.
    func isPinnedItem(_ info: QuarantineFS.Info, at path: String) -> Bool {
        guard !info.isSymlink, info.inode == identity.inode else { return false }
        if let recorded = volumeUUID, let current = SecureFS.volumeUUID(path) { return recorded == current }
        return info.device == identity.device
    }

    /// The original item's name (last component of `quarantinedName`), when well formed.
    var itemName: String? {
        let parts = quarantinedName.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, parts[0] == id.uuidString, Quarantine.isSafeName(parts[1]) else { return nil }
        return parts[1]
    }
}

public struct QuarantineSessionInfo: Sendable, Identifiable {
    public let id: UUID
    public let createdAt: Date
    public let entries: [QuarantineEntry]

    public init(id: UUID, createdAt: Date, entries: [QuarantineEntry]) {
        self.id = id
        self.createdAt = createdAt
        self.entries = entries
    }
}

public enum QuarantineError: Error, Sendable, Equatable, Hashable {
    case mutationDisabled
    case crossVolume
    case sourceMissing
    case destinationExists
    case originalParentMissing
    case manifestCorrupt
    case safetyRejected(SafetyRejection)
    /// System-call or bookkeeping failure. System-call messages end with "[errno N]".
    case io(String)

    public var message: String {
        switch self {
        case .mutationDisabled: return MutationPolicy.disabledMessage
        case .crossVolume: return "Item is on a different volume than the Quarantine (never copied)"
        case .sourceMissing: return "Item no longer exists"
        case .destinationExists: return "Destination already exists (never overwritten)"
        case .originalParentMissing: return "The original folder no longer exists; the item stays in Quarantine"
        case .manifestCorrupt: return "Quarantine manifest is missing or unreadable"
        case .safetyRejected(let rejection): return rejection.reason
        case .io(let detail): return detail
        }
    }

    /// Spec §11 category, for the Executor's per-item outcome.
    public var errorCategory: ErrorCategory {
        switch self {
        case .mutationDisabled: return .mutationDisabled
        case .crossVolume: return .crossVolume
        case .sourceMissing: return .changedSinceScan
        case .safetyRejected(let rejection): return rejection.errorCategory
        case .destinationExists, .originalParentMissing, .manifestCorrupt: return .safetyRejected(message)
        case .io(let detail):
            if detail.hasSuffix("[errno \(EACCES)]") || detail.hasSuffix("[errno \(EPERM)]") { return .permissionDenied }
            if detail.hasSuffix("[errno \(EBUSY)]") { return .inUse }
            if detail.hasSuffix("[errno \(EXDEV)]") { return .crossVolume }
            return .safetyRejected(detail)
        }
    }
}

/// Result of purging one quarantined item.
public struct QuarantinePurgeOutcome: Sendable, Hashable {
    public enum Status: Sendable, Hashable {
        case purged
        /// SafetyGate refused (the item stays in Quarantine).
        case rejected(SafetyRejection)
        case failed(QuarantineError)
        /// Removal started but did not finish (the item may be partly removed). The entry is
        /// `.purging`: it can no longer be restored and the next purge retries it.
        case incomplete(QuarantineError)
    }

    public let entry: QuarantineEntry
    public let status: Status

    public init(entry: QuarantineEntry, status: Status) {
        self.entry = entry
        self.status = status
    }

    public var freedBytes: Int64 { if case .purged = status { return entry.reclaimableBytes } else { return 0 } }
}

/// What `reconcile()` did (the caller writes these to the audit log).
public struct QuarantineReconcileEvent: Sendable, Hashable {
    public enum Kind: Sendable, Hashable {
        /// Pending entry whose move had completed (the pinned item is in Quarantine) → `.moved`.
        case markedMoved
        /// Pending entry with nothing in Quarantine and the source still in place → dropped.
        case droppedSourceStillPresent
        /// Pending entry whose source and destination are both gone → dropped.
        case droppedBothMissing
        /// Malformed pending entry → dropped (whatever it points at is left alone, never purged).
        case droppedIdentityMismatch
        /// Interrupted restore (or a moved entry whose item is back at its origin) → `.restored`.
        case markedRestored
        /// Interrupted restore whose item is still in Quarantine → `.moved` again.
        case revertedToMoved
        /// Interrupted purge whose item is gone → `.purged`.
        case markedPurged
        /// The entry could not be proven to hold the pinned item → `.needsReview` (never purged).
        case flaggedForReview
        /// A session manifest could not be read; the session is left untouched.
        case manifestCorrupt
    }

    public let sessionID: UUID
    public let entry: QuarantineEntry?
    public let kind: Kind
}

/// On-disk manifest (one per session).
struct QuarantineManifest: Codable, Sendable {
    static let currentFormatVersion = 1

    var formatVersion: Int
    var sessionID: UUID
    var createdAt: Date
    var entries: [QuarantineEntry]
}

// MARK: - Quarantine

public actor Quarantine {
    public static let spaceNotice = "Space from quarantined items is freed when quarantine is emptied. Empty now to reclaim immediately."
    public static let manifestFileName = "manifest.json"
    public static let neverIndexFileName = ".metadata_never_index"
    /// Rule id of the synthetic rule purges are validated with.
    public static let purgeRuleID = "imop.quarantine.purge"

    static let rootComponents = ["Library", "Application Support", "iMop", "Quarantine"]
    private static let maxManifestBytes = 32 * 1024 * 1024

    /// `{homePath}/Library/Application Support/iMop/Quarantine`.
    public nonisolated let rootPath: String

    private let environment: SafeCleanEnvironment
    private let gate: SafetyGate
    private let mutationPolicy: MutationPolicy
    private let rootCanonical: CanonicalPath?
    private let homeCanonical: CanonicalPath?
    /// Sessions begun by this instance and not yet ended. Such a session is never cleaned up (the
    /// Executor keeps adding items to it until its run calls `endSession(_:)`).
    private var sessionsBegun: Set<UUID> = []

    public init(environment: SafeCleanEnvironment, mutationPolicy: MutationPolicy = .compiledIn) {
        self.init(environment: environment, gate: SafetyGate(environment: environment), mutationPolicy: mutationPolicy)
    }

    /// `gate` validates every quarantine move (purpose `.standard`) and every purge (purpose
    /// `.quarantine`). Tests pass a fixture gate.
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, gate: SafetyGate, mutationPolicy: MutationPolicy = .compiledIn) {
        self.environment = environment
        self.gate = gate
        self.mutationPolicy = mutationPolicy
        let home = environment.homePath
        self.rootPath = ([home] + Self.rootComponents).joined(separator: "/")
        // SAFETY-DECISION: an unusable (non-canonical) home makes every operation refuse.
        if case .success(let homePath) = PathCanonicalizer.clean(home, home: nil), homePath.path == home,
           !homePath.components.isEmpty {
            homeCanonical = homePath
            rootCanonical = Self.rootComponents.reduce(homePath) { $0.appending($1) }
        } else {
            homeCanonical = nil
            rootCanonical = nil
        }
    }

    // MARK: Sessions

    /// Creates a new session directory (0700) and its empty manifest; ensures
    /// `.metadata_never_index` exists in the Quarantine root.
    public func beginSession() throws -> UUID {
        try requirePermission(rootPath)
        guard let root = try verifiedRoot(create: true) else { throw QuarantineError.io("Quarantine folder unavailable") }
        try ensureNeverIndex(root: root)
        let id = UUID()
        let sessionDir = sessionPath(id)
        try makeDirectory(sessionDir)
        guard try directoryExists(sessionDir, strict: true) else { throw QuarantineError.io("session folder was not created") }
        let manifest = QuarantineManifest(formatVersion: QuarantineManifest.currentFormatVersion, sessionID: id,
                                          createdAt: Self.wholeSeconds(environment.clock.now), entries: [])
        do {
            try writeManifest(manifest)
        } catch {
            _ = Darwin.rmdir(sessionDir)
            throw error
        }
        sessionsBegun.insert(id)
        return id
    }

    /// Marks a session begun by this instance as no longer in use (the Executor calls it when its run
    /// ends) and removes it if every entry is restored or purged.
    public func endSession(_ sessionID: UUID) {
        sessionsBegun.remove(sessionID)
        cleanupSessionIfFinished(sessionID)
    }

    /// Every readable session, oldest first. Sessions with an unreadable manifest are omitted (and
    /// never purged).
    public func sessions() throws -> [QuarantineSessionInfo] {
        guard let root = try verifiedRoot(create: false) else { return [] }
        var result: [QuarantineSessionInfo] = []
        for id in try sessionIDs(root: root) {
            guard let manifest = try? readManifest(id) else { continue }
            result.append(QuarantineSessionInfo(id: id, createdAt: manifest.createdAt, entries: manifest.entries))
        }
        return result.sorted { $0.createdAt < $1.createdAt }
    }

    // MARK: Quarantine

    /// Moves `target` into the session with `renameatx_np(RENAME_EXCL)`. The manifest entry is written
    /// with status `.pending` BEFORE the move and updated to `.moved` after it (spec §11).
    /// Same volume only: never copies.
    ///
    /// SAFETY-DECISION: SPI only — the Executor (same module) is the only production caller — and
    /// fail-closed on its own: SafetyGate (phase `.execute`, purpose `.standard`) must return
    /// `.allowed` first, whatever the caller validated.
    @_spi(FixtureTesting)
    public func quarantine(target: ScanTarget, rule: Rule, tier: Tier, sessionID: UUID) async throws -> QuarantineEntry {
        try await quarantine(target: target, rule: rule, tier: tier, sessionID: sessionID, retentionHours: nil)
    }

    /// `retentionHours`, when given (the confirmed plan's value), must equal the rule's retention.
    func quarantine(target: ScanTarget, rule: Rule, tier: Tier, sessionID: UUID,
                    retentionHours: Int?) async throws -> QuarantineEntry {
        guard case .filesystem = target.kind else {
            throw QuarantineError.safetyRejected(.preconditionFailed(name: "actionMismatch", detail: "Only files and folders can be quarantined"))
        }
        guard target.ruleID == rule.id else {
            throw QuarantineError.safetyRejected(.preconditionFailed(name: "ruleMismatch", detail: "Item does not belong to this rule"))
        }
        // SAFETY-DECISION: a quarantined item is purged automatically when its retention ends, so only
        // rules whose action already removes the item may quarantine it (a Trash rule may not).
        switch rule.action {
        case .quarantine, .permanentDelete: break
        default: throw QuarantineError.safetyRejected(.doesNotMatchRule(detail: "rule does not quarantine items"))
        }
        guard tier >= rule.tier else { throw QuarantineError.safetyRejected(.doesNotMatchRule(detail: "tier lower than rule tier")) }
        // SAFETY-DECISION: a non-positive retention would make the item purgeable at once, i.e. an
        // unconfirmed permanent deletion. A retention that differs from the confirmed plan's is refused.
        let retention = rule.effectiveRetentionHours
        guard retention > 0 else { throw QuarantineError.safetyRejected(.doesNotMatchRule(detail: "invalid quarantine retention")) }
        if let retentionHours, retentionHours != retention {
            throw QuarantineError.safetyRejected(.doesNotMatchRule(detail: "quarantine retention does not match the rule"))
        }
        guard let pinned = target.identity else { throw QuarantineError.safetyRejected(.missingIdentity) }
        guard case .success(let source) = PathCanonicalizer.clean(target.path, home: nil), source.path == target.path,
              let name = source.lastComponent, Self.isSafeName(name), source.components.count >= 2,
              let parent = source.parent else {
            throw QuarantineError.safetyRejected(.canonicalizationFailed("path is not in canonical form"))
        }
        guard let rootCanonical, let homeCanonical else { throw QuarantineError.io("home directory is unusable") }
        // SAFETY-DECISION: iMop's own Quarantine is never quarantined into itself, and neither the
        // home directory nor any of its ancestors is ever moved.
        if source.isInsideOrEqual(rootCanonical) || rootCanonical.isInsideOrEqual(source) {
            throw QuarantineError.safetyRejected(.denyListed(entry: "~/Library/Application Support/iMop"))
        }
        if homeCanonical.isInsideOrEqual(source) {
            throw QuarantineError.safetyRejected(.equalsAllowRoot)
        }
        try requirePermission(target.path)

        // SafetyGate, here too (deny-list, allow-roots, cloud, bundles, preconditions, identity).
        switch await gate.validate(target: target, rule: rule, phase: .execute) {
        case .allowed:
            break
        case .rejected(let rejection), .downgradedToRed(let rejection):
            if rejection == .crossVolume { throw QuarantineError.crossVolume }
            throw QuarantineError.safetyRejected(rejection)
        }

        // The actor may have run other work during the await: everything below is checked afresh.
        guard try verifiedRoot(create: false) != nil else { throw QuarantineError.io("Quarantine session \(sessionID) does not exist") }
        let sessionDir = sessionPath(sessionID)
        guard try directoryExists(sessionDir, strict: true) else {
            throw QuarantineError.io("Quarantine session \(sessionID) does not exist")
        }
        var manifest = try readManifest(sessionID)

        // Injected probe (tests simulate device, owner and identity through it).
        guard let probedSource = environment.fileSystem.lstat(target.path),
              let probedSession = environment.fileSystem.stat(sessionDir) else {
            throw QuarantineError.io("could not inspect item or session folder")
        }
        if probedSource.isSymlink { throw QuarantineError.safetyRejected(.symlinkInPath(component: target.path)) }
        guard probedSource.device == probedSession.device else { throw QuarantineError.crossVolume }
        guard probedSource.identity == pinned else { throw QuarantineError.safetyRejected(.changedSinceScan) }
        guard probedSource.uid == environment.userID else {
            throw QuarantineError.safetyRejected(.notOwnedByUser(uid: probedSource.uid))
        }

        // Verified handles: the item's parent and the session folder, reached without any symlink.
        let parentFD = try Self.openVerifiedDirectory(parent.path, what: "the item's folder")
        defer { Darwin.close(parentFD) }
        let sessionFD = try Self.openVerifiedDirectory(sessionDir, what: "the session folder")
        defer { Darwin.close(sessionFD) }
        guard let sessionInfo = SecureFS.fstat(sessionFD), sessionInfo.isDirectory, sessionInfo.uid == environment.userID,
              (sessionInfo.mode & 0o077) == 0 else {
            throw QuarantineError.io("unsafe session folder \(sessionDir)")
        }
        // Cheap real check before anything is written (repeated right before the move).
        let initial = try checkSource(parentFD: parentFD, name: name, path: target.path, pinned: pinned)
        guard initial.device == sessionInfo.device else { throw QuarantineError.crossVolume }

        let entryID = UUID()
        let entryName = entryID.uuidString
        let entryDir = sessionDir + "/" + entryName
        let destination = entryDir + "/" + name
        try requirePermission(entryDir)
        try requirePermission(destination)

        let now = Self.wholeSeconds(environment.clock.now)
        var entry = QuarantineEntry(
            id: entryID, sessionID: sessionID, originalPath: target.path,
            quarantinedName: entryName + "/" + name, identity: pinned,
            allocatedBytes: target.allocatedBytes, reclaimableBytes: target.reclaimableBytes,
            ruleID: rule.id, tier: tier, quarantinedAt: now,
            expiresAt: now.addingTimeInterval(TimeInterval(retention) * 3600),
            status: .pending, volumeUUID: SecureFS.volumeUUID(sessionDir))

        // Entry folder, created and opened relative to the verified session descriptor.
        errno = 0
        guard Darwin.mkdirat(sessionFD, entryName, 0o700) == 0 else { throw QuarantineFS.ioError("create entry folder", errno) }
        let entryFD = Darwin.openat(sessionFD, entryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard entryFD >= 0 else {
            let code = errno
            _ = Darwin.unlinkat(sessionFD, entryName, AT_REMOVEDIR)
            throw QuarantineFS.ioError("open entry folder", code)
        }
        defer { Darwin.close(entryFD) }
        guard let entryInfo = SecureFS.fstat(entryFD), entryInfo.isDirectory, entryInfo.uid == environment.userID else {
            _ = Darwin.unlinkat(sessionFD, entryName, AT_REMOVEDIR)
            throw QuarantineError.io("entry folder was not created")
        }

        // Nothing moved: drop the pending entry and the (empty) entry folder.
        func rollBack() {
            manifest.entries.removeAll { $0.id == entryID }
            try? writeManifest(manifest)
            _ = Darwin.unlinkat(sessionFD, entryName, AT_REMOVEDIR)
        }

        // Crash safety: pending entry first.
        manifest.entries.append(entry)
        do {
            try writeManifest(manifest)
        } catch {
            _ = Darwin.unlinkat(sessionFD, entryName, AT_REMOVEDIR)
            throw error
        }

        // LAST check (relative to the verified parent), immediately followed by the move.
        do {
            let last = try checkSource(parentFD: parentFD, name: name, path: target.path, pinned: pinned)
            guard last.device == sessionInfo.device else { throw QuarantineError.crossVolume }
        } catch {
            rollBack()
            throw error
        }
        errno = 0
        if renameatx_np(parentFD, name, entryFD, name, UInt32(RENAME_EXCL)) != 0 {
            let code = errno
            rollBack()
            switch code {
            case EXDEV: throw QuarantineError.crossVolume
            case ENOENT: throw QuarantineError.sourceMissing
            case EEXIST, ENOTEMPTY: throw QuarantineError.destinationExists
            default: throw QuarantineFS.ioError("move into Quarantine", code)
            }
        }

        // Verify the outcome: the pinned item is now in the entry folder.
        let moved = SecureFS.lstat(at: entryFD, name)
        guard case .ok(let movedInfo) = moved, !movedInfo.isSymlink, movedInfo.identity == pinned else {
            // SAFETY-DECISION: whatever was moved is not the pinned item → put it straight back.
            if case .ok = moved, renameatx_np(entryFD, name, parentFD, name, UInt32(RENAME_EXCL)) == 0 {
                rollBack()
                throw QuarantineError.safetyRejected(.changedSinceScan)
            }
            // It could not be put back: keep it listed (never purged, restorable on request) rather
            // than strand it in Quarantine without a manifest entry.
            entry.status = .needsReview
            if let index = manifest.entries.firstIndex(where: { $0.id == entryID }) { manifest.entries[index] = entry }
            try? writeManifest(manifest)
            throw QuarantineError.io("could not verify the quarantined item; it was kept in Quarantine for review")
        }

        entry.status = .moved
        if let index = manifest.entries.firstIndex(where: { $0.id == entryID }) { manifest.entries[index] = entry }
        do {
            try writeManifest(manifest)
        } catch {
            // The item is in Quarantine; the entry stays `.pending` until `reconcile()` marks it moved.
            throw QuarantineError.io("item moved into Quarantine but the manifest could not be updated (\((error as? QuarantineError)?.message ?? "\(error)"))")
        }
        return entry
    }

    /// The item (not followed) relative to its verified parent: present, not a symlink, the pinned
    /// identity, owned by the user.
    private func checkSource(parentFD: Int32, name: String, path: String, pinned: FileIdentity) throws -> QuarantineFS.Info {
        switch SecureFS.lstat(at: parentFD, name) {
        case .missing: throw QuarantineError.sourceMissing
        case .failed(let code): throw QuarantineFS.ioError("inspect item", code)
        case .ok(let info):
            // SAFETY-DECISION: a symlink is never quarantined (whatever the rule's allowSymlinkTarget):
            // purges validate items without the symlink exception, so a quarantined link could never
            // be purged, and moving it gains nothing.
            if info.isSymlink { throw QuarantineError.safetyRejected(.symlinkInPath(component: path)) }
            guard info.identity == pinned else { throw QuarantineError.safetyRejected(.changedSinceScan) }
            guard info.uid == environment.userID else { throw QuarantineError.safetyRejected(.notOwnedByUser(uid: info.uid)) }
            return info
        }
    }

    private static func openVerifiedDirectory(_ path: String, what: String) throws -> Int32 {
        switch SecureFS.openDirectory(path) {
        case .success(let fd): return fd
        case .failure(let failure):
            let code = failure.code
            if code == ELOOP || code == ENOTDIR { throw QuarantineError.safetyRejected(.symlinkInPath(component: path)) }
            if code == ENOENT { throw QuarantineError.sourceMissing }
            throw QuarantineFS.ioError("open \(what)", code)
        }
    }

    // MARK: Restore

    /// Moves the item back with `RENAME_EXCL`. If the original path exists, the item is restored
    /// beside it as "<name> (restored yyyy-MM-dd HH.mm.ss)". Never overwrites.
    public func restore(entryID: UUID) throws -> QuarantineEntry {
        guard let root = try verifiedRoot(create: false) else { throw QuarantineError.io("no quarantined item \(entryID)") }
        for sessionID in try sessionIDs(root: root) {
            guard let manifest = try? readManifest(sessionID),
                  let entry = manifest.entries.first(where: { $0.id == entryID }) else { continue }
            return try restore(entry: entry)
        }
        throw QuarantineError.io("no quarantined item \(entryID)")
    }

    /// Restores every item of the session that is not yet restored or purged. Entries that cannot
    /// be restored (pending crash recovery, partly purged, ...) are reported as failures, never
    /// silently skipped.
    public func restoreSession(_ sessionID: UUID) -> [Result<QuarantineEntry, QuarantineError>] {
        let manifest: QuarantineManifest
        do {
            guard try verifiedRoot(create: false) != nil else { return [.failure(.manifestCorrupt)] }
            manifest = try readManifest(sessionID)
        } catch {
            return [.failure(Self.quarantineError(error))]
        }
        return manifest.entries.filter { $0.status != .restored && $0.status != .purged }.map { entry in
            do { return .success(try restore(entry: entry)) } catch { return .failure(Self.quarantineError(error)) }
        }
    }

    private func restore(entry: QuarantineEntry) throws -> QuarantineEntry {
        switch entry.status {
        case .moved, .needsReview:
            break
        case .purging:
            throw QuarantineError.io("The item was partly purged and can no longer be restored")
        case .pending:
            throw QuarantineError.io("The item is awaiting crash recovery and cannot be restored yet")
        case .restoring:
            throw QuarantineError.io("An earlier restore of this item did not finish; it is resolved at the next launch")
        case .restored, .purged:
            throw QuarantineError.io("item is not in Quarantine (\(entry.status.rawValue))")
        }
        guard let name = entry.itemName else { throw QuarantineError.manifestCorrupt }
        let sessionDir = sessionPath(entry.sessionID)
        guard try directoryExists(sessionDir, strict: true) else { throw QuarantineError.manifestCorrupt }
        let entryDir = sessionDir + "/" + entry.id.uuidString
        guard try directoryExists(entryDir, strict: true) else { throw QuarantineError.sourceMissing }
        let itemPath = entryDir + "/" + name

        switch QuarantineFS.lstat(itemPath) {
        case .missing: throw QuarantineError.sourceMissing
        case .failed(let code): throw QuarantineFS.ioError("inspect quarantined item", code)
        case .ok(let info):
            if info.isSymlink { throw QuarantineError.safetyRejected(.symlinkInPath(component: itemPath)) }
            guard info.uid == environment.userID else { throw QuarantineError.safetyRejected(.notOwnedByUser(uid: info.uid)) }
            // SAFETY-DECISION: a `.needsReview` entry could not be proven to hold the pinned item; it
            // is still restored on explicit request, because a restore never overwrites or removes
            // anything (RENAME_EXCL, "(restored …)" name on conflict) — leaving it stranded is worse.
            if entry.status == .moved, !entry.isPinnedItem(info, at: itemPath) {
                throw QuarantineError.safetyRejected(.changedSinceScan)
            }
        }

        guard case .success(let original) = PathCanonicalizer.clean(entry.originalPath, home: nil),
              original.path == entry.originalPath, let originalName = original.lastComponent,
              let parent = original.parent, !parent.components.isEmpty, let rootCanonical,
              !original.isInsideOrEqual(rootCanonical) else {
            throw QuarantineError.manifestCorrupt
        }

        // SAFETY-DECISION: the original parent must still exist as a real directory reached without
        // any symlink (realpath spells the same path). Otherwise the item stays in Quarantine: iMop
        // never recreates folders and never restores through a link to somewhere else.
        switch QuarantineFS.lstat(parent.path) {
        case .missing: throw QuarantineError.originalParentMissing
        case .failed(let code): throw QuarantineFS.ioError("inspect original folder", code)
        case .ok(let info):
            if info.isSymlink { throw QuarantineError.safetyRejected(.symlinkInPath(component: parent.path)) }
            guard info.isDirectory else { throw QuarantineError.originalParentMissing }
        }
        guard let resolved = QuarantineFS.realpath(parent.path),
              case .success(let resolvedParent) = PathCanonicalizer.clean(resolved, home: nil),
              resolvedParent == parent else {
            throw QuarantineError.safetyRejected(.symlinkInPath(component: parent.path))
        }

        var destination = original.path
        switch QuarantineFS.lstat(original.path) {
        case .missing:
            break
        case .failed(let code):
            throw QuarantineFS.ioError("inspect original location", code)
        case .ok:
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone.current
            formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
            let restoredName = "\(originalName) (restored \(formatter.string(from: environment.clock.now)))"
            guard Self.isSafeName(restoredName) else { throw QuarantineError.destinationExists }
            destination = parent.appending(restoredName).path
        }

        try requirePermission(itemPath)
        try requirePermission(destination)

        // Crash safety: the intent (with its destination) is recorded BEFORE the move back.
        var restoring = entry
        restoring.status = .restoring
        restoring.restoredPath = destination
        try updateEntry(restoring)

        errno = 0
        if renamex_np(itemPath, destination, UInt32(RENAME_EXCL)) != 0 {
            let code = errno
            // Nothing moved: back to the previous state.
            try? updateEntry(entry)
            switch code {
            case EEXIST, ENOTEMPTY: throw QuarantineError.destinationExists
            case EXDEV: throw QuarantineError.crossVolume
            case ENOENT: throw QuarantineError.sourceMissing
            default: throw QuarantineFS.ioError("restore from Quarantine", code)
            }
        }

        var restored = entry
        restored.status = .restored
        restored.restoredPath = destination
        // SAFETY-DECISION: a failed manifest update is not reported as a failed restore — the item IS
        // back. The entry stays `.restoring` (never purged, never restored twice) until `reconcile()`
        // finds the item at `restoredPath` and marks it `.restored`.
        try? updateEntry(restored)
        if mutationPolicy.permits(path: entryDir, environment: environment) { _ = Darwin.rmdir(entryDir) }
        cleanupSessionIfFinished(entry.sessionID)
        return restored
    }

    // MARK: Purge

    /// Permanently removes items whose retention expired (`expiresAt <= clock.now`).
    public func purgeExpired() async -> [QuarantinePurgeOutcome] {
        let now = environment.clock.now
        return await purge { $0.expiresAt <= now }
    }

    /// "Empty Quarantine Now": permanently removes every quarantined item.
    public func purgeAll() async -> [QuarantinePurgeOutcome] {
        await purge { _ in true }
    }

    private func purge(where shouldPurge: @Sendable (QuarantineEntry) -> Bool) async -> [QuarantinePurgeOutcome] {
        let candidates: [(UUID, [QuarantineEntry])]
        do {
            guard let root = try verifiedRoot(create: false) else { return [] }
            candidates = try sessionIDs(root: root).compactMap { id in
                // SAFETY-DECISION: a session whose manifest cannot be read is never purged: only
                // items listed in a valid manifest are ever removed.
                guard let manifest = try? readManifest(id) else { return nil }
                // An interrupted purge (`.purging`) is always retried: the item can no longer be restored.
                return (id, manifest.entries.filter { ($0.status == .moved && shouldPurge($0)) || $0.status == .purging })
            }
        } catch {
            return []
        }
        var outcomes: [QuarantinePurgeOutcome] = []
        for (sessionID, entries) in candidates {
            for entry in entries {
                outcomes.append(await purge(entry: entry))
            }
            cleanupSessionIfFinished(sessionID)
        }
        return outcomes
    }

    private func purge(entry: QuarantineEntry) async -> QuarantinePurgeOutcome {
        func failed(_ error: QuarantineError) -> QuarantinePurgeOutcome { QuarantinePurgeOutcome(entry: entry, status: .failed(error)) }
        func rejected(_ rejection: SafetyRejection) -> QuarantinePurgeOutcome { QuarantinePurgeOutcome(entry: entry, status: .rejected(rejection)) }

        guard let name = entry.itemName else { return failed(.manifestCorrupt) }
        let sessionDir = sessionPath(entry.sessionID)
        let entryDir = sessionDir + "/" + entry.id.uuidString
        let itemPath = entryDir + "/" + name
        guard mutationPolicy.permits(path: itemPath, environment: environment) else { return failed(.mutationDisabled) }

        // The item as it is now. Across launches the pinned identity is the inode plus the recorded
        // volume UUID; the current `st_dev` is then pinned for this purge.
        let currentIdentity: FileIdentity
        switch QuarantineFS.lstat(itemPath) {
        case .missing:
            // An interrupted purge that had in fact completed.
            if entry.status == .purging { return markPurged(entry, entryDir: entryDir) }
            return failed(.sourceMissing)
        case .failed(let code): return failed(QuarantineFS.ioError("inspect quarantined item", code))
        case .ok(let info):
            if info.isSymlink { return rejected(.symlinkInPath(component: itemPath)) }
            guard entry.isPinnedItem(info, at: itemPath) else { return rejected(.changedSinceScan) }
            currentIdentity = info.identity
        }

        // Spec §5.1: every purged item goes through SafetyGate, with the Quarantine as allow-root.
        let rule = Self.purgeRule(sessionID: entry.sessionID, entryID: entry.id, itemName: name)
        let target = ScanTarget(id: entry.id, ruleID: rule.id, kind: .filesystem, path: itemPath, displayName: name,
                                identity: currentIdentity, allocatedBytes: entry.allocatedBytes,
                                reclaimableBytes: entry.reclaimableBytes, itemCount: 0, lastUsed: nil)
        let verdict = await gate.validate(target: target, rule: rule, phase: .execute, purpose: .quarantine)
        if let rejection = verdict.rejection { return rejected(rejection) }

        // The actor may have run other work during the await: re-read everything.
        let current: QuarantineEntry
        do {
            guard try verifiedRoot(create: false) != nil, try directoryExists(sessionDir, strict: true),
                  try directoryExists(entryDir, strict: true) else { return failed(.sourceMissing) }
            let manifest = try readManifest(entry.sessionID)
            guard let found = manifest.entries.first(where: { $0.id == entry.id }),
                  found.status == .moved || found.status == .purging,
                  found.quarantinedName == entry.quarantinedName, found.identity == entry.identity else {
                return failed(.io("item is no longer in Quarantine"))
            }
            current = found
        } catch {
            return failed(Self.quarantineError(error))
        }

        // Last look relative to the verified entry folder, immediately before removing.
        let entryFD: Int32
        do {
            entryFD = try Self.openVerifiedDirectory(entryDir, what: "the entry folder")
        } catch {
            return failed(Self.quarantineError(error))
        }
        defer { Darwin.close(entryFD) }
        switch SecureFS.lstat(at: entryFD, name) {
        case .missing: return failed(.sourceMissing)
        case .failed(let code): return failed(QuarantineFS.ioError("inspect quarantined item", code))
        case .ok(let info):
            if info.isSymlink { return rejected(.symlinkInPath(component: itemPath)) }
            guard info.identity == currentIdentity else { return rejected(.changedSinceScan) }
        }
        guard mutationPolicy.permits(path: itemPath, environment: environment) else { return failed(.mutationDisabled) }

        // Crash / failure safety: the intent is recorded BEFORE anything is removed. From here on the
        // item is never restored (it may be partly removed) and every purge retries it.
        var purging = current
        if current.status != .purging {
            purging.status = .purging
            do { try updateEntry(purging) } catch { return failed(Self.quarantineError(error)) }
        }

        // SAFETY-DECISION: removefileat relative to the entry folder (short relative path, so the long
        // Quarantine prefix does not count against PATH_MAX). REMOVEFILE_ALLOW_LONG_PATHS is NOT used:
        // it changes the process-wide working directory while other threads run.
        guard let state = removefile_state_alloc() else {
            return QuarantinePurgeOutcome(entry: purging, status: .incomplete(QuarantineFS.ioError("purge", ENOMEM)))
        }
        errno = 0
        let rc = removefileat(entryFD, name, state, removefile_flags_t(REMOVEFILE_RECURSIVE))
        let code = errno
        removefile_state_free(state)
        guard rc == 0 else {
            return QuarantinePurgeOutcome(entry: purging, status: .incomplete(QuarantineFS.ioError("purge", code == 0 ? EIO : code)))
        }
        guard case .missing = SecureFS.lstat(at: entryFD, name) else {
            return QuarantinePurgeOutcome(entry: purging, status: .incomplete(.io("item still present after purge")))
        }
        return markPurged(purging, entryDir: entryDir)
    }

    /// The item is gone: `.purged`, and the (empty) entry folder is removed.
    private func markPurged(_ entry: QuarantineEntry, entryDir: String) -> QuarantinePurgeOutcome {
        if mutationPolicy.permits(path: entryDir, environment: environment) { _ = Darwin.rmdir(entryDir) }
        var purged = entry
        purged.status = .purged
        // SAFETY-DECISION: the item is gone, so the outcome is `.purged` even if the manifest update
        // fails; the entry then stays `.purging`, which can never restore anything and which the next
        // purge or `reconcile()` marks `.purged`.
        try? updateEntry(purged)
        return QuarantinePurgeOutcome(entry: purged, status: .purged)
    }

    /// Synthetic Green rule for purges: allow-root = the session directory; the only shape it may
    /// touch is `<session>/<entry-UUID>/<one item>`.
    static func purgeRule(sessionID: UUID, entryID: UUID, itemName: String) -> Rule {
        let sessionRoot = (["{HOME}"] + rootComponents + [sessionID.uuidString]).joined(separator: "/")
        // "*" never matches a hidden name, ".*" matches only hidden names; the entry directory holds
        // exactly one item, so this is that item and nothing else.
        let last = itemName.hasPrefix(".") ? ".*" : "*"
        return Rule(
            id: purgeRuleID, version: 1, category: .system, tier: .green,
            title: "Quarantine purge",
            explanation: "Permanently removes an item whose Quarantine retention ended.",
            whatYouLose: "The quarantined item can no longer be restored.",
            howItRegenerates: "Caches are rebuilt by their apps.",
            discovery: .glob([sessionRoot + "/" + entryID.uuidString + "/" + last]),
            allowRoots: [sessionRoot], minDepthBelowRoot: 2, preconditions: [],
            action: .permanentDelete)
    }

    // MARK: Reconcile

    /// Launch-time crash recovery (spec §11).
    ///
    /// - `.pending`: the pinned item is in Quarantine → `.moved` (whatever is at the origin now — an
    ///   app may have rebuilt its cache there); something else is in Quarantine → `.needsReview`;
    ///   nothing in Quarantine → dropped (the item was never moved, or is gone).
    /// - `.restoring`: the pinned item is at `restoredPath` → `.restored`; still in Quarantine →
    ///   `.moved`; otherwise `.needsReview`.
    /// - `.moved` whose item is missing from Quarantine: back at its origin → `.restored`; otherwise
    ///   `.needsReview`.
    /// - `.purging` whose item is gone → `.purged` (otherwise the next purge retries it).
    ///
    /// SAFETY-DECISION: an entry is only ever dropped when nothing is in its Quarantine folder, so an
    /// item that is physically in Quarantine is never forgotten.
    @discardableResult
    public func reconcile() throws -> [QuarantineReconcileEvent] {
        guard let root = try verifiedRoot(create: false) else { return [] }
        var events: [QuarantineReconcileEvent] = []
        for sessionID in try sessionIDs(root: root) {
            guard var manifest = try? readManifest(sessionID) else {
                events.append(QuarantineReconcileEvent(sessionID: sessionID, entry: nil, kind: .manifestCorrupt))
                continue
            }
            var changed = false
            var kept: [QuarantineEntry] = []
            var emptiedEntryDirs: [String] = []
            func record(_ entry: QuarantineEntry, _ kind: QuarantineReconcileEvent.Kind) {
                events.append(QuarantineReconcileEvent(sessionID: sessionID, entry: entry, kind: kind))
                changed = true
            }
            for var entry in manifest.entries {
                let entryDir = sessionPath(sessionID) + "/" + entry.id.uuidString
                guard let name = entry.itemName else {
                    // Unreachable (readManifest rejects malformed entries); fail closed anyway.
                    if entry.status == .pending { record(entry, .droppedIdentityMismatch); continue }
                    kept.append(entry)
                    continue
                }
                let itemPath = entryDir + "/" + name
                let itemState = QuarantineFS.lstat(itemPath)
                if case .failed(let code) = itemState { throw QuarantineFS.ioError("inspect quarantined item", code) }
                let pinnedInQuarantine: Bool
                let somethingInQuarantine: Bool
                switch itemState {
                case .ok(let info):
                    somethingInQuarantine = true
                    pinnedInQuarantine = entry.isPinnedItem(info, at: itemPath)
                default:
                    somethingInQuarantine = false
                    pinnedInQuarantine = false
                }

                switch entry.status {
                case .pending:
                    if pinnedInQuarantine {
                        // The rename completed before the crash.
                        entry.status = .moved
                        kept.append(entry)
                        record(entry, .markedMoved)
                    } else if somethingInQuarantine {
                        entry.status = .needsReview
                        kept.append(entry)
                        record(entry, .flaggedForReview)
                    } else {
                        let sourceState = QuarantineFS.lstat(entry.originalPath)
                        if case .failed(let code) = sourceState { throw QuarantineFS.ioError("inspect original location", code) }
                        if case .ok = sourceState {
                            record(entry, .droppedSourceStillPresent)
                        } else {
                            record(entry, .droppedBothMissing)
                        }
                        emptiedEntryDirs.append(entryDir)
                    }

                case .restoring:
                    if pinnedInQuarantine {
                        entry.status = .moved
                        entry.restoredPath = nil
                        kept.append(entry)
                        record(entry, .revertedToMoved)
                    } else if !somethingInQuarantine, let restoredPath = entry.restoredPath,
                              case .ok(let info) = QuarantineFS.lstat(restoredPath), entry.isPinnedItem(info, at: restoredPath) {
                        entry.status = .restored
                        kept.append(entry)
                        record(entry, .markedRestored)
                        emptiedEntryDirs.append(entryDir)
                    } else {
                        entry.status = .needsReview
                        kept.append(entry)
                        record(entry, .flaggedForReview)
                    }

                case .moved:
                    if somethingInQuarantine {
                        kept.append(entry)
                    } else if case .ok(let info) = QuarantineFS.lstat(entry.originalPath),
                              entry.isPinnedItem(info, at: entry.originalPath) {
                        // Put back without the manifest being updated.
                        entry.status = .restored
                        entry.restoredPath = entry.originalPath
                        kept.append(entry)
                        record(entry, .markedRestored)
                        emptiedEntryDirs.append(entryDir)
                    } else {
                        entry.status = .needsReview
                        kept.append(entry)
                        record(entry, .flaggedForReview)
                    }

                case .purging:
                    if !somethingInQuarantine {
                        entry.status = .purged
                        kept.append(entry)
                        record(entry, .markedPurged)
                        emptiedEntryDirs.append(entryDir)
                    } else {
                        kept.append(entry) // retried by the next purge
                    }

                case .restored, .purged, .needsReview:
                    kept.append(entry)
                }
            }
            guard changed else { continue }
            manifest.entries = kept
            try writeManifest(manifest)
            for dir in emptiedEntryDirs where mutationPolicy.permits(path: dir, environment: environment) {
                // rmdir only removes an EMPTY, real directory.
                if case .ok(let info) = QuarantineFS.lstat(dir), info.isDirectory { _ = Darwin.rmdir(dir) }
            }
            cleanupSessionIfFinished(sessionID)
        }
        return events
    }

    // MARK: - Session cleanup

    /// Removes a session directory once every entry is restored or purged and nothing but the
    /// manifest remains in it (rmdir only ever removes an empty directory).
    private func cleanupSessionIfFinished(_ sessionID: UUID) {
        // SAFETY-DECISION: a session this instance began is never removed until `endSession(_:)`: the
        // Executor may still be adding items to it (a purge or restore can run between two items).
        if sessionsBegun.contains(sessionID) { return }
        guard let manifest = try? readManifest(sessionID) else { return }
        guard manifest.entries.allSatisfy({ $0.status == .restored || $0.status == .purged }) else { return }
        let sessionDir = sessionPath(sessionID)
        guard (try? directoryExists(sessionDir, strict: true)) == true,
              let children = try? FileManager.default.contentsOfDirectory(atPath: sessionDir),
              children == [Self.manifestFileName] else { return }
        let manifestPath = sessionDir + "/" + Self.manifestFileName
        guard mutationPolicy.permits(path: manifestPath, environment: environment),
              mutationPolicy.permits(path: sessionDir, environment: environment) else { return }
        guard case .ok(let info) = QuarantineFS.lstat(manifestPath), info.isRegularFile else { return }
        guard Darwin.unlink(manifestPath) == 0 else { return }
        _ = Darwin.rmdir(sessionDir)
        sessionsBegun.remove(sessionID)
    }

    // MARK: - Paths & directories

    private func sessionPath(_ id: UUID) -> String { rootPath + "/" + id.uuidString }

    private func requirePermission(_ path: String) throws {
        guard mutationPolicy.permits(path: path, environment: environment) else { throw QuarantineError.mutationDisabled }
    }

    /// Verifies (and, when `create`, creates with 0700) home → Library → Application Support → iMop
    /// → Quarantine. `nil` when the root does not exist and `create` is false.
    private func verifiedRoot(create: Bool) throws -> String? {
        guard let homeCanonical else { throw QuarantineError.io("home directory is unusable") }
        guard try directoryExists(homeCanonical.path, strict: false) else { throw QuarantineError.io("home directory is missing") }
        var current = homeCanonical.path
        for (index, component) in Self.rootComponents.enumerated() {
            current += "/" + component
            // iMop's own folders must not be writable by group/others.
            let strict = index >= 2
            let isRoot = index == Self.rootComponents.count - 1
            if try directoryExists(current, strict: strict) {
                if isRoot { try makePrivate(current) }
                continue
            }
            guard create else { return nil }
            try makeDirectory(current)
            guard try directoryExists(current, strict: strict) else { throw QuarantineError.io("could not create \(current)") }
            if isRoot { try makePrivate(current) }
        }
        return current
    }

    /// The Quarantine root must be private (no group/other access at all). An existing root with a
    /// looser mode (an earlier build, a migration, the user) is tightened to 0700 through a
    /// descriptor opened without following symlinks; if that is not permitted or fails, it is refused.
    private func makePrivate(_ path: String) throws {
        guard case .ok(let info) = QuarantineFS.lstat(path), info.isDirectory, !info.isSymlink else {
            throw QuarantineError.io("not a folder: \(path)")
        }
        if (info.mode & 0o077) == 0 { return }
        guard mutationPolicy.permits(path: path, environment: environment) else {
            throw QuarantineError.io("unsafe permissions on \(path)")
        }
        let fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw QuarantineFS.ioError("open \(path)", errno) }
        defer { Darwin.close(fd) }
        guard let opened = SecureFS.fstat(fd), opened.isDirectory, opened.uid == environment.userID,
              Darwin.fchmod(fd, 0o700) == 0, let after = SecureFS.fstat(fd), (after.mode & 0o077) == 0 else {
            throw QuarantineError.io("unsafe permissions on \(path)")
        }
    }

    /// `true` if `path` is a real directory owned by the user (and, when `strict`, not writable by
    /// group/others); `false` if missing; throws for anything else (symlink, file, foreign owner).
    /// The real lstat(2) AND the injected probe must agree.
    private func directoryExists(_ path: String, strict: Bool) throws -> Bool {
        switch QuarantineFS.lstat(path) {
        case .missing:
            return false
        case .failed(let code):
            throw QuarantineFS.ioError("inspect \(path)", code)
        case .ok(let info):
            if info.isSymlink { throw QuarantineError.safetyRejected(.symlinkInPath(component: path)) }
            guard info.isDirectory else { throw QuarantineError.io("not a folder: \(path)") }
            guard info.uid == environment.userID else { throw QuarantineError.safetyRejected(.notOwnedByUser(uid: info.uid)) }
            if strict && (info.mode & 0o022) != 0 { throw QuarantineError.io("unsafe permissions on \(path)") }
        }
        guard let probed = environment.fileSystem.lstat(path) else { throw QuarantineError.io("could not inspect \(path)") }
        if probed.isSymlink { throw QuarantineError.safetyRejected(.symlinkInPath(component: path)) }
        guard probed.isDirectory else { throw QuarantineError.io("not a folder: \(path)") }
        guard probed.uid == environment.userID else { throw QuarantineError.safetyRejected(.notOwnedByUser(uid: probed.uid)) }
        return true
    }

    private func makeDirectory(_ path: String) throws {
        try requirePermission(path)
        errno = 0
        if Darwin.mkdir(path, 0o700) != 0 {
            let code = errno
            // An existing entry is re-verified by the caller (never trusted).
            guard code == EEXIST else { throw QuarantineFS.ioError("create \(path)", code) }
        }
    }

    private func ensureNeverIndex(root: String) throws {
        let path = root + "/" + Self.neverIndexFileName
        switch QuarantineFS.lstat(path) {
        case .ok(let info):
            guard info.isRegularFile else { throw QuarantineError.io("unexpected item at \(path)") }
            return
        case .failed(let code):
            throw QuarantineFS.ioError("inspect \(path)", code)
        case .missing:
            try requirePermission(path)
            let fd = Darwin.open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            if fd < 0 {
                let code = errno
                guard code == EEXIST else { throw QuarantineFS.ioError("create \(path)", code) }
                return
            }
            Darwin.close(fd)
        }
    }

    /// Session directories (exact UUID names, real directories) in the root.
    private func sessionIDs(root: String) throws -> [UUID] {
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: root)
        } catch {
            throw QuarantineError.io("could not list the Quarantine folder")
        }
        return names.sorted().compactMap { name in
            guard let id = UUID(uuidString: name), id.uuidString == name else { return nil }
            guard case .ok(let info) = QuarantineFS.lstat(root + "/" + name), info.isDirectory, !info.isSymlink else { return nil }
            return id
        }
    }

    // MARK: - Manifest

    private func readManifest(_ sessionID: UUID) throws -> QuarantineManifest {
        let path = sessionPath(sessionID) + "/" + Self.manifestFileName
        // O_NONBLOCK: a FIFO planted at the manifest name must not block the actor.
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw QuarantineError.manifestCorrupt }
        defer { Darwin.close(fd) }
        var st = Darwin.stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == environment.userID,
              st.st_size >= 0, st.st_size <= Int64(Self.maxManifestBytes) else {
            throw QuarantineError.manifestCorrupt
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw QuarantineError.manifestCorrupt
            }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
            guard data.count <= Self.maxManifestBytes else { throw QuarantineError.manifestCorrupt }
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let manifest = try? decoder.decode(QuarantineManifest.self, from: data) else { throw QuarantineError.manifestCorrupt }
        guard manifest.formatVersion == QuarantineManifest.currentFormatVersion, manifest.sessionID == sessionID,
              Set(manifest.entries.map(\.id)).count == manifest.entries.count,
              manifest.entries.allSatisfy({ $0.sessionID == sessionID && $0.itemName != nil }) else {
            throw QuarantineError.manifestCorrupt
        }
        return manifest
    }

    /// Replaces one entry (by id) in its session's manifest. Throws when the entry is not listed.
    private func updateEntry(_ entry: QuarantineEntry) throws {
        var manifest = try readManifest(entry.sessionID)
        guard let index = manifest.entries.firstIndex(where: { $0.id == entry.id }) else {
            throw QuarantineError.io("no quarantined item \(entry.id)")
        }
        manifest.entries[index] = entry
        try writeManifest(manifest)
    }

    /// Atomic: temp file created with O_EXCL|O_NOFOLLOW in the session directory, fsync, rename.
    private func writeManifest(_ manifest: QuarantineManifest) throws {
        let sessionDir = sessionPath(manifest.sessionID)
        guard try directoryExists(rootPath, strict: true), try directoryExists(sessionDir, strict: true) else {
            throw QuarantineError.io("Quarantine session \(manifest.sessionID) does not exist")
        }
        let manifestPath = sessionDir + "/" + Self.manifestFileName
        let tempPath = sessionDir + "/.manifest-" + UUID().uuidString + ".tmp"
        try requirePermission(manifestPath)
        try requirePermission(tempPath)
        switch QuarantineFS.lstat(manifestPath) {
        case .missing: break
        case .failed(let code): throw QuarantineFS.ioError("inspect manifest", code)
        case .ok(let info): guard info.isRegularFile else { throw QuarantineError.manifestCorrupt }
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do { data = try encoder.encode(manifest) } catch { throw QuarantineError.io("could not encode manifest") }

        let fd = Darwin.open(tempPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw QuarantineFS.ioError("write manifest", errno) }
        var writeError: Int32 = 0
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let written = Darwin.write(fd, base + offset, raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    writeError = errno
                    return
                }
                offset += written
            }
        }
        if writeError == 0 && fsync(fd) != 0 { writeError = errno }
        Darwin.close(fd)
        if writeError != 0 {
            _ = Darwin.unlink(tempPath)
            throw QuarantineFS.ioError("write manifest", writeError)
        }
        if Darwin.rename(tempPath, manifestPath) != 0 {
            let code = errno
            _ = Darwin.unlink(tempPath)
            throw QuarantineFS.ioError("replace manifest", code)
        }
    }

    // MARK: - Helpers

    /// A single, non-special path component.
    static func isSafeName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
            && name.utf8.count <= 255
    }

    /// Dates are stored with whole-second precision so a manifest round-trip is exact.
    static func wholeSeconds(_ date: Date) -> Date {
        Date(timeIntervalSince1970: date.timeIntervalSince1970.rounded(.down))
    }

    static func quarantineError(_ error: any Error) -> QuarantineError {
        (error as? QuarantineError) ?? .io("\(error)")
    }
}

// MARK: - System calls

/// Thin wrappers over the real system calls (the item being moved is real; the injected probe is
/// consulted in addition where tests need to simulate metadata).
enum QuarantineFS {
    struct Info: Sendable {
        let device: Int64
        let inode: UInt64
        let uid: UInt32
        let mode: UInt16

        init(device: Int64, inode: UInt64, uid: UInt32, mode: UInt16) {
            self.device = device
            self.inode = inode
            self.uid = uid
            self.mode = mode
        }

        init(_ st: Darwin.stat) {
            self.init(device: Int64(st.st_dev), inode: UInt64(st.st_ino), uid: st.st_uid, mode: UInt16(st.st_mode))
        }

        var identity: FileIdentity { FileIdentity(device: device, inode: inode) }
        var isSymlink: Bool { (mode & UInt16(S_IFMT)) == UInt16(S_IFLNK) }
        var isDirectory: Bool { (mode & UInt16(S_IFMT)) == UInt16(S_IFDIR) }
        var isRegularFile: Bool { (mode & UInt16(S_IFMT)) == UInt16(S_IFREG) }
    }

    enum LstatResult: Sendable {
        case ok(Info)
        case missing
        case failed(Int32)
    }

    static func lstat(_ path: String) -> LstatResult {
        RealHomeGuard.check(path)
        var st = Darwin.stat()
        errno = 0
        guard Darwin.lstat(path, &st) == 0 else {
            let code = errno
            return code == ENOENT ? .missing : .failed(code)
        }
        return .ok(Info(device: Int64(st.st_dev), inode: UInt64(st.st_ino), uid: st.st_uid, mode: UInt16(st.st_mode)))
    }

    static func realpath(_ path: String) -> String? {
        guard let pointer = Darwin.realpath(path, nil) else { return nil }
        defer { free(pointer) }
        return String(cString: pointer)
    }

    static func ioError(_ operation: String, _ code: Int32) -> QuarantineError {
        .io("\(operation): \(String(cString: strerror(code))) [errno \(code)]")
    }
}
