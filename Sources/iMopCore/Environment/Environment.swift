import Foundation

// MARK: - File metadata

/// Minimal, injectable view of `stat(2)` / `lstat(2)` results.
/// Tests construct these directly to simulate other volumes, owners and inodes.
public struct FileStat: Sendable, Equatable, Hashable {
    public var device: Int64
    public var inode: UInt64
    public var uid: UInt32
    public var mode: UInt16
    public var linkCount: UInt32
    public var logicalSize: Int64
    public var modificationDate: Date

    public init(device: Int64, inode: UInt64, uid: UInt32, mode: UInt16, linkCount: UInt32, logicalSize: Int64, modificationDate: Date) {
        self.device = device
        self.inode = inode
        self.uid = uid
        self.mode = mode
        self.linkCount = linkCount
        self.logicalSize = logicalSize
        self.modificationDate = modificationDate
    }

    public var isSymlink: Bool { (mode & UInt16(S_IFMT)) == UInt16(S_IFLNK) }
    public var isDirectory: Bool { (mode & UInt16(S_IFMT)) == UInt16(S_IFDIR) }
    public var isRegularFile: Bool { (mode & UInt16(S_IFMT)) == UInt16(S_IFREG) }

    public var identity: FileIdentity { FileIdentity(device: device, inode: inode) }
}

/// `(st_dev, st_ino)` pair captured at scan time and re-checked before acting (SafetyGate check 9).
public struct FileIdentity: Sendable, Codable, Hashable {
    public let device: Int64
    public let inode: UInt64

    public init(device: Int64, inode: UInt64) {
        self.device = device
        self.inode = inode
    }
}

// MARK: - Injectable services

/// Read-only file system access. Every method returns `nil` on error so callers can fail closed.
public protocol FileSystemProbe: Sendable {
    func lstat(_ path: String) -> FileStat?
    func stat(_ path: String) -> FileStat?
    /// `realpath(3)`.
    func realpath(_ path: String) -> String?
    /// `URLResourceKey.canonicalPathKey`.
    func canonicalPath(_ path: String) -> String?
    /// Names (not paths) of the immediate children. Does not follow a symlinked `path`.
    func contentsOfDirectory(_ path: String) -> [String]?
    /// Extended attribute names (`listxattr` with `XATTR_NOFOLLOW`).
    func extendedAttributeNames(_ path: String) -> [String]?
    /// `URLResourceValues.isUbiquitousItem`. `nil` when it cannot be determined.
    func isUbiquitousItem(_ path: String) -> Bool?
    func readFile(_ path: String) -> Data?
}

/// Process inspection via libproc. `nil` means "could not evaluate" → preconditions fail closed.
public protocol ProcessInspecting: Sendable {
    /// Executable names (`proc_name`) of every running process.
    func runningProcessNames() -> [String]?
    /// PIDs holding an open file at or below `path` (`proc_listpidspath`).
    func pidsWithOpenFiles(under path: String) -> [Int32]?
}

/// Running GUI applications (`NSWorkspace.shared.runningApplications`).
public protocol RunningApplicationsProviding: Sendable {
    func runningBundleIdentifiers() -> [String]?
}

/// Installed-application lookups (LaunchServices + Spotlight).
public protocol ApplicationLocating: Sendable {
    /// URLs registered with LaunchServices for the bundle identifier. `nil` on error.
    func applicationURLs(forBundleIdentifier bundleID: String) -> [URL]?
    /// Spotlight `kMDItemCFBundleIdentifier == id` across all mounted volumes. `nil` on error/timeout.
    func spotlightApplicationPaths(forBundleIdentifier bundleID: String) -> [String]?
}

/// Mounted volume information.
public protocol VolumeInspecting: Sendable {
    /// Mount points currently listed under `/Volumes`.
    func mountedVolumes() -> [String]?
    /// `volumeAvailableCapacityForImportantUsage` for the volume containing `path`.
    func availableCapacityForImportantUsage(at path: String) -> Int64?
    /// `volumeAvailableCapacity` for the volume containing `path`.
    func availableCapacity(at path: String) -> Int64?
}

/// Result of a vendor command run without a shell.
public struct CommandResult: Sendable, Equatable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool

    public init(exitCode: Int32, stdout: String, stderr: String, timedOut: Bool = false) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
    }

    public var succeeded: Bool { exitCode == 0 && !timedOut }
}

/// Runs a resolved, trusted executable with an argument array (never a shell string).
/// Read-only callers (preconditions, dry-run sizing) use this too; the implementation is
/// `CommandRunner` in Execution/.
public protocol CommandRunning: Sendable {
    /// Resolves `tool` (e.g. "xcrun", "brew") against the trusted directory list. `nil` if untrusted/missing.
    func resolveExecutable(_ tool: String) -> String?
    func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult
}

/// Code-signature verification (`SecStaticCodeCheckValidity` against a requirement).
public protocol CodeSignatureVerifying: Sendable {
    /// `true` only when the code at `path` is validly signed and satisfies `anchor apple`.
    /// `false` when it is unsigned, invalid or not Apple's; `nil` when it could not be evaluated.
    /// Callers treat `nil` like `false` (fail closed).
    func isAppleSigned(path: String) -> Bool?
}

/// Verifier that can never vouch for anything: every query is "could not evaluate".
public struct UnavailableCodeSignatureVerifier: CodeSignatureVerifying {
    public init() {}
    public func isAppleSigned(path: String) -> Bool? { nil }
}

public protocol Clock: Sendable {
    var now: Date { get }
}

public struct SystemClock: Clock {
    public init() {}
    public var now: Date { Date() }
}

// MARK: - Environment

// Named `SafeCleanEnvironment` (spec: "Environment") to avoid clashing with SwiftUI.Environment.

/// Everything SafeClean needs from the outside world, injected so tests never touch the real home.
public struct SafeCleanEnvironment: Sendable {
    public let homeDirectory: URL
    public let fileSystem: any FileSystemProbe
    public let processes: any ProcessInspecting
    public let runningApplications: any RunningApplicationsProviding
    public let applications: any ApplicationLocating
    public let volumes: any VolumeInspecting
    public let commands: any CommandRunning
    public let codeSignatures: any CodeSignatureVerifying
    public let clock: any Clock
    public let effectiveUserID: UInt32
    public let userID: UInt32

    public init(
        homeDirectory: URL,
        fileSystem: any FileSystemProbe,
        processes: any ProcessInspecting,
        runningApplications: any RunningApplicationsProviding,
        applications: any ApplicationLocating,
        volumes: any VolumeInspecting,
        commands: any CommandRunning,
        clock: any Clock,
        effectiveUserID: UInt32,
        userID: UInt32,
        // SAFETY-DECISION: the default verifier answers `nil` ("cannot evaluate") for every path, so an
        // environment built without an explicit verifier makes `appleSigned` fail closed. The default
        // exists only so environments created before this member was added keep compiling.
        codeSignatures: any CodeSignatureVerifying = UnavailableCodeSignatureVerifier()
    ) {
        self.homeDirectory = homeDirectory
        self.fileSystem = fileSystem
        self.processes = processes
        self.runningApplications = runningApplications
        self.applications = applications
        self.volumes = volumes
        self.commands = commands
        self.codeSignatures = codeSignatures
        self.clock = clock
        self.effectiveUserID = effectiveUserID
        self.userID = userID
    }

    /// Home directory path as a plain string with no trailing slash.
    public var homePath: String { homeDirectory.standardizedFileURL.path }
}

// MARK: - Test-suite guard

/// Hook the test runner installs so that any resolution of a path inside the real home
/// directory aborts the test run (spec §12). Production never installs a hook.
public enum RealHomeGuard {
    nonisolated(unsafe) private static var hook: (@Sendable (String) -> Void)?
    private static let lock = NSLock()

    public static func install(_ newHook: @escaping @Sendable (String) -> Void) {
        lock.lock(); defer { lock.unlock() }
        hook = newHook
    }

    /// Called by the canonicalizer and the live file-system probe with every path they resolve.
    public static func check(_ path: String) {
        lock.lock()
        let current = hook
        lock.unlock()
        current?(path)
    }
}
