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
    /// Spotlight: every item whose `kMDItemCFBundleIdentifier` is `domain` or starts with `domain.`
    /// (case-insensitive), across all mounted volumes. `domain` is a two-label vendor domain such as
    /// `com.vendor`. `nil` on error / timeout / an implausible domain. Used by the OrphanDetector
    /// (spec §6.9 condition 2): any app of the same developer installed anywhere blocks.
    func spotlightApplicationPaths(inVendorDomain domain: String) -> [String]?
}

extension ApplicationLocating {
    /// SAFETY-DECISION (review M6): a locator that cannot answer vendor-domain queries answers "could
    /// not evaluate", so nothing is classified as orphaned through it.
    public func spotlightApplicationPaths(inVendorDomain domain: String) -> [String]? { nil }
}

/// A volume mounted under `/Volumes` and its identity.
public struct MountedVolume: Sendable, Hashable {
    /// Mount point (`/Volumes/<name>`).
    public var path: String
    /// `URLResourceKey.volumeUUIDStringKey`; `nil` when it could not be read (FAT, some network shares).
    public var uuid: String?

    public init(path: String, uuid: String?) {
        self.path = path
        self.uuid = uuid
    }
}

/// Mounted volume information.
public protocol VolumeInspecting: Sendable {
    /// Mount points currently listed under `/Volumes`.
    func mountedVolumes() -> [String]?
    /// The volumes of `mountedVolumes()` with their identity (UUID). `nil` when they cannot be listed.
    func mountedVolumeIdentities() -> [MountedVolume]?
    /// `volumeAvailableCapacityForImportantUsage` for the volume containing `path`.
    func availableCapacityForImportantUsage(at path: String) -> Int64?
    /// `volumeAvailableCapacity` for the volume containing `path`.
    func availableCapacity(at path: String) -> Int64?
}

extension VolumeInspecting {
    /// SAFETY-DECISION (review M6): an inspector that cannot read volume identities reports every
    /// volume WITHOUT a UUID, which the OrphanDetector treats as "cannot tell which drive this is"
    /// (nothing is orphaned while such a volume is mounted).
    public func mountedVolumeIdentities() -> [MountedVolume]? {
        mountedVolumes().map { paths in paths.map { MountedVolume(path: $0, uuid: nil) } }
    }
}

/// Fixed system folders read by the OrphanDetector and the LaunchAgent checks (spec §6.9).
/// Injectable through `SafeCleanEnvironment.systemLocations` so tests read fixture folders, never the
/// real machine's apps. Every value is an absolute path; `{HOME}` is expanded by the readers.
public struct SystemLocations: Sendable, Hashable {
    /// Where installed apps are enumerated (top level plus one folder level).
    public var applicationRoots: [String]
    /// Roots that always exist on macOS: one that is missing or unreadable means "cannot evaluate".
    public var requiredApplicationRoots: [String]
    /// The Setapp subscription-store folder.
    public var setappDirectory: String
    /// Where external volumes are mounted (`<volumesDirectory>/<name>/Applications` is enumerated too).
    public var volumesDirectory: String
    /// System-wide LaunchAgents folders (jobs loaded into every user's GUI domain).
    public var launchAgentDirectories: [String]
    /// LaunchDaemons folders.
    public var launchDaemonDirectories: [String]

    public init(applicationRoots: [String], requiredApplicationRoots: [String], setappDirectory: String,
                volumesDirectory: String, launchAgentDirectories: [String], launchDaemonDirectories: [String]) {
        self.applicationRoots = applicationRoots
        self.requiredApplicationRoots = requiredApplicationRoots
        self.setappDirectory = setappDirectory
        self.volumesDirectory = volumesDirectory
        self.launchAgentDirectories = launchAgentDirectories
        self.launchDaemonDirectories = launchDaemonDirectories
    }

    /// The real macOS locations.
    public static let standard = SystemLocations(
        applicationRoots: ["/Applications", "/Applications/Utilities", "{HOME}/Applications", "/System/Applications"],
        requiredApplicationRoots: ["/Applications", "/System/Applications"],
        setappDirectory: "/Applications/Setapp",
        volumesDirectory: "/Volumes",
        launchAgentDirectories: ["/Library/LaunchAgents"],
        launchDaemonDirectories: ["/Library/LaunchDaemons"])
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

/// Why a vendor command is being run. The live runner only accepts an invocation that exactly
/// matches an entry of `CommandAllowList` for this purpose.
public enum CommandPurpose: String, Sendable, Hashable, CaseIterable {
    /// Dry runs, discovery listings and precondition probes (Discovery/, Safety/).
    case readOnly
    /// A cleanup action (Executor only).
    case action
}

/// Runs a resolved, trusted executable with an argument array (never a shell string).
/// Read-only callers (preconditions, dry-run sizing) use this too; the implementation is
/// `CommandRunner` in Execution/.
public protocol CommandRunning: Sendable {
    /// Resolves `tool` (e.g. "xcrun", "brew") against the trusted directory list. `nil` if untrusted/missing.
    func resolveExecutable(_ tool: String) -> String?
    /// Legacy form; means `purpose: .readOnly` (see the default implementation below).
    func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult
    func run(executable: String, arguments: [String], timeout: TimeInterval, purpose: CommandPurpose) async -> CommandResult
    /// A user-facing reason why `tool` is unavailable when the user can change it in Settings (e.g. it
    /// is in a Homebrew folder other accounts can change and "Trust Homebrew tools" is OFF); `nil`
    /// otherwise. Callers keep their own generic message for `nil`.
    func unavailableReason(for tool: String) -> String?
    /// This runner with the user's command trust settings applied (fakes and disabled runners ignore it).
    func applying(_ policy: CommandTrustPolicy) -> any CommandRunning
}

extension CommandRunning {
    public func unavailableReason(for tool: String) -> String? { nil }
    public func applying(_ policy: CommandTrustPolicy) -> any CommandRunning { self }

    /// SAFETY-DECISION: the purpose-less call is always a READ-ONLY request; only an explicit
    /// `.action` may ever run a cleanup command.
    public func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult {
        await run(executable: executable, arguments: arguments, timeout: timeout, purpose: .readOnly)
    }
    // SAFETY-DECISION (M4): there is deliberately NO default for the purpose-taking `run`. Every
    // conformer must implement it and so decide what to do with `.action`; a default that silently
    // dropped the purpose would let an action reach a runner that only meant to serve read-only
    // queries (and two defaults calling each other would recurse forever).
}

/// Code-signature verification (`SecStaticCodeCheckValidity` against a requirement).
public protocol CodeSignatureVerifying: Sendable {
    /// `true` only when the code at `path` is validly signed and satisfies `anchor apple`.
    /// `false` when it is unsigned, invalid or not Apple's; `nil` when it could not be evaluated.
    /// Callers treat `nil` like `false` (fail closed).
    func isAppleSigned(path: String) -> Bool?
    /// Signing information of the code at `path` (`SecCodeCopySigningInformation` with
    /// `kSecCSSigningInformation`): its Team ID (`nil` when unsigned, ad-hoc signed or platform code)
    /// and the `com.apple.security.application-groups` it declares (empty when none). `nil` when the
    /// information could not be read or parsed. Used by the OrphanDetector (spec §6.9 condition 5),
    /// where `nil` for ANY installed app means no Group Container is orphaned (fail closed).
    func signingInfo(path: String) -> (teamID: String?, appGroups: [String])?
}

extension CodeSignatureVerifying {
    /// SAFETY-DECISION (M6): a verifier that does not implement `signingInfo` can never read anything
    /// ("could not evaluate"), so Group Containers are never classified as orphaned through it.
    public func signingInfo(path: String) -> (teamID: String?, appGroups: [String])? { nil }
}

/// Verifier that can never vouch for anything: every query is "could not evaluate".
public struct UnavailableCodeSignatureVerifier: CodeSignatureVerifying {
    public init() {}
    public func isAppleSigned(path: String) -> Bool? { nil }
    public func signingInfo(path: String) -> (teamID: String?, appGroups: [String])? { nil }
}

/// Optional Spotlight file search (used by `lightroom.previews` to find `.lrcat` catalogs).
public protocol SpotlightSearching: Sendable {
    /// Paths of items whose file name ends in `.<ext>`, limited to `roots` when given (all
    /// indexed volumes when `nil`). `nil` on error, timeout or when Spotlight is unavailable.
    /// Callers must re-validate every returned path; Spotlight results are hints, not facts.
    func paths(withExtension ext: String, under roots: [String]?) -> [String]?
}

/// Spotlight that can never answer: every query is "could not evaluate" (`nil`).
public struct UnavailableSpotlightSearch: SpotlightSearching {
    public init() {}
    public func paths(withExtension ext: String, under roots: [String]?) -> [String]? { nil }
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
    /// Always configured with the trust policy of `scanSettings` (see `with(scanSettings:)`).
    public private(set) var commands: any CommandRunning
    public let codeSignatures: any CodeSignatureVerifying
    public let clock: any Clock
    public let effectiveUserID: UInt32
    public let userID: UInt32
    /// User settings (project roots, archives to keep, overrides, exclusions …).
    public var scanSettings: ScanSettings
    /// Spotlight file search; unavailable (always `nil`) unless injected.
    public var spotlight: any SpotlightSearching
    /// Fixed system folders (the real ones unless a test injects fixture folders).
    public var systemLocations: SystemLocations = .standard

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
        codeSignatures: any CodeSignatureVerifying = UnavailableCodeSignatureVerifier(),
        // SAFETY-DECISION: the defaults configure NO project roots and an unavailable Spotlight, so an
        // environment built without them discovers nothing through those features.
        scanSettings: ScanSettings = .default,
        spotlight: any SpotlightSearching = UnavailableSpotlightSearch()
    ) {
        self.homeDirectory = homeDirectory
        self.fileSystem = fileSystem
        self.processes = processes
        self.runningApplications = runningApplications
        self.applications = applications
        self.volumes = volumes
        // SAFETY-DECISION: the runner always follows the settings' command trust policy, so the
        // opt-in Homebrew relaxation is ON only while the settings say so (default OFF).
        self.commands = commands.applying(CommandTrustPolicy(settings: scanSettings))
        self.codeSignatures = codeSignatures
        self.clock = clock
        self.effectiveUserID = effectiveUserID
        self.userID = userID
        self.scanSettings = scanSettings
        self.spotlight = spotlight
    }

    /// A copy of this environment with different settings.
    public func with(scanSettings: ScanSettings) -> SafeCleanEnvironment {
        var copy = self
        copy.scanSettings = scanSettings
        copy.commands = commands.applying(CommandTrustPolicy(settings: scanSettings))
        return copy
    }

    /// A copy of this environment with different system folders (tests: fixture folders).
    public func with(systemLocations: SystemLocations) -> SafeCleanEnvironment {
        var copy = self
        copy.systemLocations = systemLocations
        return copy
    }

    /// A copy of this environment with a different Spotlight implementation.
    public func with(spotlight: any SpotlightSearching) -> SafeCleanEnvironment {
        var copy = self
        copy.spotlight = spotlight
        return copy
    }

    /// Home directory path as a plain string with no trailing slash, in the same `/private/...`
    /// form the canonicalizer produces for `/var`, `/tmp` and `/etc` (so every module agrees on
    /// one spelling of the home).
    public var homePath: String {
        let path = homeDirectory.standardizedFileURL.path
        for alias in ["/var", "/tmp", "/etc"] where path == alias || path.hasPrefix(alias + "/") {
            return "/private" + path
        }
        return path
    }
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

    /// `true` while a hook is installed (test runs only). Lets the live probe perform extra
    /// resolution for the guard without costing anything in production.
    public static var isActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return hook != nil
    }

    /// Called by the canonicalizer and the live file-system probe with every path they resolve.
    public static func check(_ path: String) {
        lock.lock()
        let current = hook
        lock.unlock()
        current?(path)
    }
}
