import Darwin
import Foundation

// Spec §5.2 (Finder Trash) and the permanent-removal primitive used by the Executor for the few
// rules allowed to use `Action.permanentDelete`.
//
// These are low-level primitives. They do NOT validate anything against the rules: the Executor
// calls them only after SafetyGate re-validated the item (phase .execute) and MutationPolicy
// permitted the mutation.
//
// Review M3: the primitives are nevertheless gated on their own, so no public API can move or
// delete a path outside `Executor.execute(_:)` in a build without IMOP_ALLOW_MUTATION:
// - each one carries a `MutationPolicy` (default `.compiledIn`, overridable only through SPI) and
//   asks it before acting (`FileActionError.mutationDisabled` when denied);
// - each one acts only on the item pinned by `(dev, ino)` at scan time, re-checked relative to an
//   `O_NOFOLLOW` parent descriptor immediately before acting. The identity-less requirement
//   (`moveToTrash(path:)` / `removePermanently(path:)`, kept for API compatibility) always refuses.

/// Moves one item to the Trash. Implementations must never empty the Trash.
public protocol TrashMoving: Sendable {
    /// Moves `path` to the Trash and returns the item's resulting path.
    func moveToTrash(path: String) throws -> String
    /// Moves `path` to the Trash only while it still is the item with `expectedIdentity`, and returns
    /// the item's resulting path. The Executor only ever calls this variant.
    func moveToTrash(path: String, expectedIdentity: FileIdentity) throws -> String
}

/// Removes one item permanently (not restorable).
public protocol PermanentRemoving: Sendable {
    func removePermanently(path: String) throws
    /// Removes `path` only while it still is the item with `expectedIdentity`. The Executor only ever
    /// calls this variant.
    func removePermanently(path: String, expectedIdentity: FileIdentity) throws
}

/// Refusals raised by the primitives themselves (system-call failures are thrown as `POSIXError`,
/// Finder Trash failures as Foundation's own error).
public enum FileActionError: Error, Sendable, Equatable {
    /// The real Finder Trash is never used while the test-suite guard is installed.
    case refusedInTestRun
    /// The path is not an absolute canonical path, is too shallow, or is the home directory (or an
    /// ancestor of it).
    case invalidPath(String)
    /// `trashItem` reported success without a resulting location.
    case missingResultingLocation
    /// The primitive's `MutationPolicy` refused (build without IMOP_ALLOW_MUTATION).
    case mutationDisabled
    /// The identity-less entry point was called: the primitives only act on a pinned item.
    case identityRequired
    /// The item at the path is not the pinned item (or is no longer there).
    case changedSinceScan
    /// The action ran, but the item at the resulting location is not the pinned item.
    case unverifiedResult(String)

    /// Best-effort `errno` behind `error` (POSIXError, NSPOSIXErrorDomain, Cocoa file errors and
    /// their underlying errors). Lets the Executor map failures to `ErrorCategory`.
    public static func posixCode(of error: any Error) -> Int32? {
        if let posix = error as? POSIXError { return posix.code.rawValue }
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain { return Int32(truncatingIfNeeded: ns.code) }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError, underlying !== ns {
            if let code = posixCode(of: underlying) { return code }
        }
        if ns.domain == NSCocoaErrorDomain {
            switch CocoaError.Code(rawValue: ns.code) {
            case .fileReadNoPermission, .fileWriteNoPermission: return EACCES
            case .fileNoSuchFile, .fileReadNoSuchFile: return ENOENT
            case .fileWriteFileExists: return EEXIST
            case .fileWriteVolumeReadOnly: return EROFS
            case .fileWriteOutOfSpace: return ENOSPC
            default: return nil
            }
        }
        return nil
    }

    /// Opens the parent of `path` without following any symlink and checks that the item itself (not
    /// followed) is still the pinned item. Returns the parent descriptor (caller closes) and the name.
    static func verifiedParent(of path: String, expectedIdentity: FileIdentity) throws -> (fd: Int32, name: String) {
        guard let (parentPath, name) = SecureFS.split(path) else { throw FileActionError.invalidPath(path) }
        let fd: Int32
        switch SecureFS.openDirectory(parentPath) {
        case .success(let opened): fd = opened
        case .failure(let failure):
            let code = failure.code
            // A symlinked or missing ancestor: the path no longer leads to the item that was validated.
            if code == ENOENT || code == ELOOP || code == ENOTDIR { throw FileActionError.changedSinceScan }
            throw RemovefileRemover.posixError(code)
        }
        switch SecureFS.lstat(at: fd, name) {
        case .ok(let info) where info.identity == expectedIdentity:
            return (fd, name)
        case .ok, .missing:
            Darwin.close(fd)
            throw FileActionError.changedSinceScan
        case .failed(let code):
            Darwin.close(fd)
            throw RemovefileRemover.posixError(code)
        }
    }

    /// Shared defence-in-depth path check.
    static func validate(_ path: String) throws {
        // Test-suite tripwire (no-op in production).
        RealHomeGuard.check(path)
        guard case .success(let canonical) = PathCanonicalizer.clean(path, home: nil), canonical.path == path else {
            throw FileActionError.invalidPath(path)
        }
        // SAFETY-DECISION: "/" and top-level folders ("/Users", "/Applications") are never acted on.
        guard canonical.components.count >= 2 else { throw FileActionError.invalidPath(path) }
        // SAFETY-DECISION: the real home directory and its ancestors are never acted on, whatever
        // the caller validated.
        if case .success(let home) = PathCanonicalizer.clean(NSHomeDirectory(), home: nil),
           !home.components.isEmpty, home.isInsideOrEqual(canonical) {
            throw FileActionError.invalidPath(path)
        }
    }
}

/// Finder Trash via `FileManager.trashItem(at:resultingItemURL:)` only. Never empties the Trash.
public struct FinderTrash: TrashMoving {
    private let mutationPolicy: MutationPolicy
    private let homePath: String?

    /// Uses `MutationPolicy.compiledIn`: refuses everything in a build without IMOP_ALLOW_MUTATION.
    public init() {
        self.mutationPolicy = .compiledIn
        self.homePath = nil
    }

    @_spi(FixtureTesting)
    public init(mutationPolicy: MutationPolicy, environment: SafeCleanEnvironment) {
        self.mutationPolicy = mutationPolicy
        self.homePath = environment.homePath
    }

    /// SAFETY-DECISION: always refuses — an item is only ever trashed by pinned identity.
    public func moveToTrash(path: String) throws -> String {
        throw FileActionError.identityRequired
    }

    public func moveToTrash(path: String, expectedIdentity: FileIdentity) throws -> String {
        try FileActionError.validate(path)
        guard mutationPolicy.permits(path: path, homePath: homePath) else { throw FileActionError.mutationDisabled }
        // SAFETY-DECISION: while the test-suite guard is installed (a test run), the real Trash is
        // never touched: `trashItem` always targets the real user's Trash, which no fixture can
        // redirect. Tests must inject a fake `TrashMoving`.
        guard !RealHomeGuard.isActive else { throw FileActionError.refusedInTestRun }
        // Last look relative to an O_NOFOLLOW parent descriptor (trashItem itself is path-based).
        let (parentFD, _) = try FileActionError.verifiedParent(of: path, expectedIdentity: expectedIdentity)
        Darwin.close(parentFD)
        var resulting: NSURL?
        try FileManager.default.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: &resulting)
        guard let resultPath = (resulting as URL?)?.path, !resultPath.isEmpty else {
            throw FileActionError.missingResultingLocation
        }
        // SAFETY-DECISION: the trashed object must be the pinned item; otherwise report failure (the
        // object stays in the Trash, where the user can still put it back).
        var st = Darwin.stat()
        guard Darwin.lstat(resultPath, &st) == 0,
              FileIdentity(device: Int64(st.st_dev), inode: UInt64(st.st_ino)) == expectedIdentity else {
            throw FileActionError.unverifiedResult(resultPath)
        }
        return resultPath
    }
}

/// `removefile(3)` with `REMOVEFILE_RECURSIVE` (never follows symlinks), relative to a parent
/// descriptor opened without following symlinks (`removefileat`).
public struct RemovefileRemover: PermanentRemoving {
    private let mutationPolicy: MutationPolicy
    private let homePath: String?

    /// Uses `MutationPolicy.compiledIn`: refuses everything in a build without IMOP_ALLOW_MUTATION.
    public init() {
        self.mutationPolicy = .compiledIn
        self.homePath = nil
    }

    @_spi(FixtureTesting)
    public init(mutationPolicy: MutationPolicy, environment: SafeCleanEnvironment) {
        self.mutationPolicy = mutationPolicy
        self.homePath = environment.homePath
    }

    /// SAFETY-DECISION: always refuses — an item is only ever removed by pinned identity.
    public func removePermanently(path: String) throws {
        throw FileActionError.identityRequired
    }

    public func removePermanently(path: String, expectedIdentity: FileIdentity) throws {
        try FileActionError.validate(path)
        guard mutationPolicy.permits(path: path, homePath: homePath) else { throw FileActionError.mutationDisabled }
        let (parentFD, name) = try FileActionError.verifiedParent(of: path, expectedIdentity: expectedIdentity)
        defer { Darwin.close(parentFD) }
        guard let state = removefile_state_alloc() else { throw Self.posixError(ENOMEM) }
        defer { removefile_state_free(state) }
        errno = 0
        guard removefileat(parentFD, name, state, removefile_flags_t(REMOVEFILE_RECURSIVE)) == 0 else {
            throw Self.posixError(errno == 0 ? EIO : errno)
        }
        // Verify the outcome.
        guard case .missing = SecureFS.lstat(at: parentFD, name) else { throw Self.posixError(EIO) }
    }

    static func posixError(_ code: Int32) -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
    }
}
