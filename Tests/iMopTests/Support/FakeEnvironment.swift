import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

// Test-only fakes. Classes holding mutable overrides are `final` + `NSLock` + `@unchecked Sendable`
// (acceptable in test support only).

private func fakeKey(_ path: String) -> String {
    var p = path
    while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
    return p.precomposedStringWithCanonicalMapping.lowercased()
}

private func fakeComponents(_ path: String) -> [String] {
    path.split(separator: "/", omittingEmptySubsequences: true)
        .map { $0.precomposedStringWithCanonicalMapping.lowercased() }
}

private func fakeIsInsideOrEqual(_ candidate: String, _ root: String) -> Bool {
    let c = fakeComponents(candidate), r = fakeComponents(root)
    return c.count >= r.count && Array(c.prefix(r.count)) == r
}

// MARK: - File system

/// Wraps `LiveFileSystemProbe` (real fixture files) and lets tests override per-path metadata or
/// force any call to fail (`nil`). Keys are compared case/Unicode-insensitively.
final class FakeFileSystemProbe: FileSystemProbe, @unchecked Sendable {
    enum Method: Sendable, Hashable, CaseIterable {
        case lstat, stat, realpath, canonicalPath, contentsOfDirectory, extendedAttributeNames, isUbiquitousItem, readFile
    }

    enum StatScope: Sendable { case lstat, stat, both }

    struct StatOverride: Sendable {
        var device: Int64?
        var uid: UInt32?
        var inode: UInt64?
        var mode: UInt16?
        var modificationDate: Date?
    }

    let live: LiveFileSystemProbe
    private let lock = NSLock()
    private var lstatOverrides: [String: StatOverride] = [:]
    private var statOverrides: [String: StatOverride] = [:]
    private var xattrOverrides: [String: [String]] = [:]
    private var ubiquitousOverrides: [String: Bool?] = [:]
    private var realpathOverrides: [String: String?] = [:]
    private var canonicalPathOverrides: [String: String?] = [:]
    /// Method → paths forced to `nil`. A `nil` path entry (stored as "*") fails every path.
    private var failures: [Method: Set<String>] = [:]
    private var calls: [(Method, String)] = []

    init(live: LiveFileSystemProbe = LiveFileSystemProbe()) {
        self.live = live
    }

    // MARK: Configuration

    func overrideStat(_ path: String, device: Int64? = nil, uid: UInt32? = nil, inode: UInt64? = nil,
                      mode: UInt16? = nil, modificationDate: Date? = nil, scope: StatScope = .both) {
        let override = StatOverride(device: device, uid: uid, inode: inode, mode: mode, modificationDate: modificationDate)
        withLock {
            if scope != .stat { lstatOverrides[fakeKey(path)] = override }
            if scope != .lstat { statOverrides[fakeKey(path)] = override }
        }
    }

    /// Replaces the extended attribute list reported for `path`.
    func setExtendedAttributes(_ names: [String], for path: String) {
        withLock { xattrOverrides[fakeKey(path)] = names }
    }

    /// Overrides `isUbiquitousItem` for `path` (`nil` = "could not be determined").
    func setUbiquitous(_ value: Bool?, for path: String) {
        withLock { ubiquitousOverrides[fakeKey(path)] = .some(value) }
    }

    /// Overrides `realpath` for `path` (`nil` = failure).
    func setRealpath(_ value: String?, for path: String) {
        withLock { realpathOverrides[fakeKey(path)] = .some(value) }
    }

    /// Overrides `canonicalPath` for `path` (`nil` = failure).
    func setCanonicalPath(_ value: String?, for path: String) {
        withLock { canonicalPathOverrides[fakeKey(path)] = .some(value) }
    }

    /// Forces `method` to return `nil` for `path`, or for every path when `path` is nil.
    func fail(_ method: Method, path: String? = nil) {
        withLock { failures[method, default: []].insert(path.map(fakeKey) ?? "*") }
    }

    func clearOverrides() {
        withLock {
            lstatOverrides = [:]; statOverrides = [:]; xattrOverrides = [:]; ubiquitousOverrides = [:]
            realpathOverrides = [:]; canonicalPathOverrides = [:]; failures = [:]
        }
    }

    /// Every (method, path) the code under test asked for, in order.
    var recordedCalls: [(Method, String)] { withLock { calls } }

    // MARK: FileSystemProbe

    func lstat(_ path: String) -> FileStat? {
        guard begin(.lstat, path) else { return nil }
        return apply(withLock { lstatOverrides[fakeKey(path)] }, to: live.lstat(path))
    }

    func stat(_ path: String) -> FileStat? {
        guard begin(.stat, path) else { return nil }
        return apply(withLock { statOverrides[fakeKey(path)] }, to: live.stat(path))
    }

    func realpath(_ path: String) -> String? {
        guard begin(.realpath, path) else { return nil }
        if let override = withLock({ realpathOverrides[fakeKey(path)] }) { return override }
        return live.realpath(path)
    }

    func canonicalPath(_ path: String) -> String? {
        guard begin(.canonicalPath, path) else { return nil }
        if let override = withLock({ canonicalPathOverrides[fakeKey(path)] }) { return override }
        return live.canonicalPath(path)
    }

    func contentsOfDirectory(_ path: String) -> [String]? {
        guard begin(.contentsOfDirectory, path) else { return nil }
        return live.contentsOfDirectory(path)
    }

    func extendedAttributeNames(_ path: String) -> [String]? {
        guard begin(.extendedAttributeNames, path) else { return nil }
        if let override = withLock({ xattrOverrides[fakeKey(path)] }) { return override }
        return live.extendedAttributeNames(path)
    }

    func isUbiquitousItem(_ path: String) -> Bool? {
        guard begin(.isUbiquitousItem, path) else { return nil }
        if let override = withLock({ ubiquitousOverrides[fakeKey(path)] }) { return override }
        return live.isUbiquitousItem(path)
    }

    func readFile(_ path: String) -> Data? {
        guard begin(.readFile, path) else { return nil }
        return live.readFile(path)
    }

    // MARK: Private

    /// Records the call; returns false when the call is forced to fail.
    private func begin(_ method: Method, _ path: String) -> Bool {
        RealHomeGuard.check(path)
        return withLock {
            calls.append((method, path))
            guard let failing = failures[method] else { return true }
            return !(failing.contains("*") || failing.contains(fakeKey(path)))
        }
    }

    private func apply(_ override: StatOverride?, to base: FileStat?) -> FileStat? {
        guard var result = base else { return nil }
        guard let override else { return result }
        if let device = override.device { result.device = device }
        if let uid = override.uid { result.uid = uid }
        if let inode = override.inode { result.inode = inode }
        if let mode = override.mode { result.mode = mode }
        if let date = override.modificationDate { result.modificationDate = date }
        return result
    }

    @discardableResult
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }
}

// MARK: - Processes

final class FakeProcessInspector: ProcessInspecting, @unchecked Sendable {
    private let lock = NSLock()
    private var _names: [String]
    private var _openFiles: [String: [Int32]]
    private var _failing: Bool

    /// - Parameters:
    ///   - names: running executable names.
    ///   - openFiles: path → PIDs holding it open; a query for `p` returns PIDs of every entry at or below `p`.
    ///   - failing: every query returns `nil`.
    init(names: [String] = ["launchd", "iMopTests"], openFiles: [String: [Int32]] = [:], failing: Bool = false) {
        _names = names
        _openFiles = openFiles
        _failing = failing
    }

    var names: [String] {
        get { lock.lock(); defer { lock.unlock() }; return _names }
        set { lock.lock(); _names = newValue; lock.unlock() }
    }

    var openFiles: [String: [Int32]] {
        get { lock.lock(); defer { lock.unlock() }; return _openFiles }
        set { lock.lock(); _openFiles = newValue; lock.unlock() }
    }

    var failing: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failing }
        set { lock.lock(); _failing = newValue; lock.unlock() }
    }

    func runningProcessNames() -> [String]? {
        failing ? nil : names
    }

    func pidsWithOpenFiles(under path: String) -> [Int32]? {
        if failing { return nil }
        var pids = Set<Int32>()
        for (open, holders) in openFiles where fakeIsInsideOrEqual(open, path) {
            pids.formUnion(holders)
        }
        return pids.sorted()
    }
}

// MARK: - Running applications

final class FakeRunningApplications: RunningApplicationsProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var _ids: [String]
    private var _failing: Bool

    init(ids: [String] = ["com.apple.finder", "com.apple.dock"], failing: Bool = false) {
        _ids = ids
        _failing = failing
    }

    var ids: [String] {
        get { lock.lock(); defer { lock.unlock() }; return _ids }
        set { lock.lock(); _ids = newValue; lock.unlock() }
    }

    var failing: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failing }
        set { lock.lock(); _failing = newValue; lock.unlock() }
    }

    func runningBundleIdentifiers() -> [String]? {
        failing ? nil : ids
    }
}

// MARK: - Installed applications

final class FakeApplicationLocator: ApplicationLocating, @unchecked Sendable {
    private let lock = NSLock()
    private var _applicationURLs: [String: [URL]]
    private var _spotlightPaths: [String: [String]]
    private var _failing: Bool
    private var _spotlightFailing: Bool

    init(applicationURLs: [String: [URL]] = [:], spotlightPaths: [String: [String]] = [:],
         failing: Bool = false, spotlightFailing: Bool = false) {
        _applicationURLs = applicationURLs
        _spotlightPaths = spotlightPaths
        _failing = failing
        _spotlightFailing = spotlightFailing
    }

    var applicationURLs: [String: [URL]] {
        get { lock.lock(); defer { lock.unlock() }; return _applicationURLs }
        set { lock.lock(); _applicationURLs = newValue; lock.unlock() }
    }

    var spotlightPaths: [String: [String]] {
        get { lock.lock(); defer { lock.unlock() }; return _spotlightPaths }
        set { lock.lock(); _spotlightPaths = newValue; lock.unlock() }
    }

    var failing: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failing }
        set { lock.lock(); _failing = newValue; lock.unlock() }
    }

    var spotlightFailing: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _spotlightFailing }
        set { lock.lock(); _spotlightFailing = newValue; lock.unlock() }
    }

    func applicationURLs(forBundleIdentifier bundleID: String) -> [URL]? {
        if failing { return nil }
        return applicationURLs.first { $0.key.lowercased() == bundleID.lowercased() }?.value ?? []
    }

    func spotlightApplicationPaths(forBundleIdentifier bundleID: String) -> [String]? {
        if failing || spotlightFailing { return nil }
        return spotlightPaths.first { $0.key.lowercased() == bundleID.lowercased() }?.value ?? []
    }
}

// MARK: - Spotlight

/// Spotlight file search fake: extension → paths; `failing` answers `nil` (error / timeout).
final class FakeSpotlightSearch: SpotlightSearching, @unchecked Sendable {
    private let lock = NSLock()
    private var _results: [String: [String]]
    private var _failing: Bool
    private var _queries: [(String, [String]?)] = []

    init(results: [String: [String]] = [:], failing: Bool = false) {
        _results = results
        _failing = failing
    }

    var results: [String: [String]] {
        get { lock.lock(); defer { lock.unlock() }; return _results }
        set { lock.lock(); _results = newValue; lock.unlock() }
    }

    var failing: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failing }
        set { lock.lock(); _failing = newValue; lock.unlock() }
    }

    var queries: [(String, [String]?)] { lock.lock(); defer { lock.unlock() }; return _queries }

    func paths(withExtension ext: String, under roots: [String]?) -> [String]? {
        lock.lock(); defer { lock.unlock() }
        _queries.append((ext, roots))
        if _failing { return nil }
        return _results[ext.lowercased()] ?? []
    }
}

// MARK: - Volumes

final class FakeVolumeInspector: VolumeInspecting, @unchecked Sendable {
    private let lock = NSLock()
    private var _volumes: [String]?
    private var _importantCapacity: Int64?
    private var _capacity: Int64?

    init(volumes: [String]? = [], importantCapacity: Int64? = 100_000_000_000, capacity: Int64? = 100_000_000_000) {
        _volumes = volumes
        _importantCapacity = importantCapacity
        _capacity = capacity
    }

    var volumes: [String]? {
        get { lock.lock(); defer { lock.unlock() }; return _volumes }
        set { lock.lock(); _volumes = newValue; lock.unlock() }
    }

    var importantCapacity: Int64? {
        get { lock.lock(); defer { lock.unlock() }; return _importantCapacity }
        set { lock.lock(); _importantCapacity = newValue; lock.unlock() }
    }

    var capacity: Int64? {
        get { lock.lock(); defer { lock.unlock() }; return _capacity }
        set { lock.lock(); _capacity = newValue; lock.unlock() }
    }

    private var _importantCapacityQueue: [Int64?] = []

    /// Successive `availableCapacityForImportantUsage` answers (one per call); once drained, the
    /// fixed `importantCapacity` is returned again. Lets tests simulate before/after measurements.
    func queueImportantCapacities(_ values: [Int64?]) {
        lock.lock(); _importantCapacityQueue = values; lock.unlock()
    }

    func mountedVolumes() -> [String]? { volumes }
    func availableCapacityForImportantUsage(at path: String) -> Int64? {
        lock.lock(); defer { lock.unlock() }
        if !_importantCapacityQueue.isEmpty { return _importantCapacityQueue.removeFirst() }
        return _importantCapacity
    }
    func availableCapacity(at path: String) -> Int64? { capacity }
}

// MARK: - Commands

final class FakeCommandRunner: CommandRunning, @unchecked Sendable {
    struct Invocation: Sendable, Equatable {
        let executable: String
        let arguments: [String]
        let timeout: TimeInterval
        let purpose: CommandPurpose

        init(executable: String, arguments: [String], timeout: TimeInterval, purpose: CommandPurpose = .readOnly) {
            self.executable = executable
            self.arguments = arguments
            self.timeout = timeout
            self.purpose = purpose
        }
    }

    private let lock = NSLock()
    private var _executables: [String: String]
    private var _responses: [String: CommandResult]
    private var _defaultResult: CommandResult
    private var _invocations: [Invocation] = []

    /// - Parameters:
    ///   - executables: tool name → resolved absolute path; unknown tools resolve to `nil`.
    ///   - responses: keyed by `arguments.joined(separator: " ")`.
    ///   - defaultResult: returned for any unlisted argument list (a failure by default).
    init(executables: [String: String] = [:], responses: [String: CommandResult] = [:],
         defaultResult: CommandResult = CommandResult(exitCode: 1, stdout: "", stderr: "no fake response")) {
        _executables = executables
        _responses = responses
        _defaultResult = defaultResult
    }

    static func key(_ arguments: [String]) -> String { arguments.joined(separator: " ") }

    var executables: [String: String] {
        get { lock.lock(); defer { lock.unlock() }; return _executables }
        set { lock.lock(); _executables = newValue; lock.unlock() }
    }

    var responses: [String: CommandResult] {
        get { lock.lock(); defer { lock.unlock() }; return _responses }
        set { lock.lock(); _responses = newValue; lock.unlock() }
    }

    func setResponse(_ result: CommandResult, for arguments: [String]) {
        lock.lock(); _responses[Self.key(arguments)] = result; lock.unlock()
    }

    var invocations: [Invocation] {
        lock.lock(); defer { lock.unlock() }; return _invocations
    }

    func resolveExecutable(_ tool: String) -> String? {
        executables[tool]
    }

    /// The purpose-less form means `.readOnly` (same as the protocol default).
    func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult {
        record(Invocation(executable: executable, arguments: arguments, timeout: timeout, purpose: .readOnly))
    }

    func run(executable: String, arguments: [String], timeout: TimeInterval, purpose: CommandPurpose) async -> CommandResult {
        record(Invocation(executable: executable, arguments: arguments, timeout: timeout, purpose: purpose))
    }

    /// Every recorded purpose, in order (tests assert Discovery/Safety only ever use `.readOnly`).
    var purposes: [CommandPurpose] { invocations.map(\.purpose) }

    private func record(_ invocation: Invocation) -> CommandResult {
        lock.lock(); defer { lock.unlock() }
        _invocations.append(invocation)
        return _responses[Self.key(invocation.arguments)] ?? _defaultResult
    }
}

// MARK: - Code signatures

final class FakeCodeSignatureVerifier: CodeSignatureVerifying, @unchecked Sendable {
    private let lock = NSLock()
    private var _results: [String: Bool?]
    private var _defaultResult: Bool?

    /// `results` maps paths to the verdict; unlisted paths return `defaultResult` (`nil` = cannot evaluate).
    init(results: [String: Bool?] = [:], defaultResult: Bool? = nil) {
        _results = Dictionary(results.map { (fakeKey($0.key), $0.value) }, uniquingKeysWith: { _, last in last })
        _defaultResult = defaultResult
    }

    func set(_ value: Bool?, for path: String) {
        lock.lock(); _results[fakeKey(path)] = .some(value); lock.unlock()
    }

    func isAppleSigned(path: String) -> Bool? {
        lock.lock(); defer { lock.unlock() }
        if let result = _results[fakeKey(path)] { return result }
        return _defaultResult
    }

    // MARK: Signing information (Milestone 6, OrphanDetector condition 5)

    struct SigningInfo: Sendable, Equatable {
        var teamID: String?
        var appGroups: [String]
    }

    private var _signingInfos: [String: SigningInfo?] = [:]
    /// Answer for paths without an explicit entry (`nil` = cannot be read, the protocol default).
    private var _defaultSigningInfo: SigningInfo?
    private var _signingInfoQueries: [String] = []

    /// Sets the signing info of `path` (`nil` = reading it fails).
    func setSigningInfo(_ info: SigningInfo?, for path: String) {
        lock.lock(); _signingInfos[fakeKey(path)] = .some(info); lock.unlock()
    }

    var defaultSigningInfo: SigningInfo? {
        get { lock.lock(); defer { lock.unlock() }; return _defaultSigningInfo }
        set { lock.lock(); _defaultSigningInfo = newValue; lock.unlock() }
    }

    var signingInfoQueries: [String] { lock.lock(); defer { lock.unlock() }; return _signingInfoQueries }

    func signingInfo(path: String) -> (teamID: String?, appGroups: [String])? {
        lock.lock(); defer { lock.unlock() }
        _signingInfoQueries.append(path)
        let info: SigningInfo?
        if let explicit = _signingInfos[fakeKey(path)] { info = explicit } else { info = _defaultSigningInfo }
        return info.map { ($0.teamID, $0.appGroups) }
    }
}

// MARK: - Clock

/// A clock that stays put unless a test moves it.
final class FixedClock: iMopCore.Clock, @unchecked Sendable {
    private let lock = NSLock()
    private var _now: Date

    init(now: Date = Date()) { _now = now }

    var now: Date {
        get { lock.lock(); defer { lock.unlock() }; return _now }
        set { lock.lock(); _now = newValue; lock.unlock() }
    }

    func advance(days: Double) {
        lock.lock(); _now = _now.addingTimeInterval(days * 86_400); lock.unlock()
    }
}

// MARK: - Environment

/// Builds a `SafeCleanEnvironment` rooted at a `FixtureBuilder`'s fake home with fully controllable fakes.
/// All fakes are reference types, so tests can mutate them after the environment is built.
final class FakeEnvironment: @unchecked Sendable {
    let fixture: FixtureBuilder
    let fileSystem: FakeFileSystemProbe
    let processes: FakeProcessInspector
    let runningApplications: FakeRunningApplications
    let applications: FakeApplicationLocator
    let volumes: FakeVolumeInspector
    let commands: FakeCommandRunner
    let codeSignatures: FakeCodeSignatureVerifier
    let clock: FixedClock

    let spotlight: FakeSpotlightSearch

    private let lock = NSLock()
    private var _effectiveUserID: UInt32
    private var _userID: UInt32
    private var _scanSettings: ScanSettings = .default

    init(
        fixture: FixtureBuilder,
        fileSystem: FakeFileSystemProbe = FakeFileSystemProbe(),
        processes: FakeProcessInspector = FakeProcessInspector(),
        runningApplications: FakeRunningApplications = FakeRunningApplications(),
        applications: FakeApplicationLocator = FakeApplicationLocator(),
        volumes: FakeVolumeInspector = FakeVolumeInspector(),
        commands: FakeCommandRunner = FakeCommandRunner(),
        codeSignatures: FakeCodeSignatureVerifier = FakeCodeSignatureVerifier(),
        clock: FixedClock = FixedClock(),
        spotlight: FakeSpotlightSearch = FakeSpotlightSearch(),
        effectiveUserID: UInt32 = geteuid(),
        userID: UInt32 = getuid()
    ) {
        self.fixture = fixture
        self.fileSystem = fileSystem
        self.processes = processes
        self.runningApplications = runningApplications
        self.applications = applications
        self.volumes = volumes
        self.commands = commands
        self.codeSignatures = codeSignatures
        self.clock = clock
        self.spotlight = spotlight
        _effectiveUserID = effectiveUserID
        _userID = userID
    }

    /// Simulate `geteuid()` (0 = running as root).
    var effectiveUserID: UInt32 {
        get { lock.lock(); defer { lock.unlock() }; return _effectiveUserID }
        set { lock.lock(); _effectiveUserID = newValue; lock.unlock() }
    }

    /// Simulate `getuid()`; defaults to the real uid so fixture files are "owned by the user".
    var userID: UInt32 {
        get { lock.lock(); defer { lock.unlock() }; return _userID }
        set { lock.lock(); _userID = newValue; lock.unlock() }
    }

    /// Milestone 5: the scan settings every new `environment` value carries (project roots, archives
    /// to keep, overrides). Defaults to `ScanSettings.default` (no project roots).
    var scanSettings: ScanSettings {
        get { lock.lock(); defer { lock.unlock() }; return _scanSettings }
        set { lock.lock(); _scanSettings = newValue; lock.unlock() }
    }

    /// A fresh `SafeCleanEnvironment` value sharing these fakes.
    var environment: SafeCleanEnvironment {
        SafeCleanEnvironment(
            homeDirectory: URL(fileURLWithPath: fixture.home, isDirectory: true),
            fileSystem: fileSystem,
            processes: processes,
            runningApplications: runningApplications,
            applications: applications,
            volumes: volumes,
            commands: commands,
            clock: clock,
            effectiveUserID: effectiveUserID,
            userID: userID,
            codeSignatures: codeSignatures,
            scanSettings: scanSettings,
            spotlight: spotlight
        )
    }

    /// SafetyGate whose system deny-list entries are waived for the fixture root (it lives under
    /// /private/var/folders, which is deny-listed). Home-relative entries still apply.
    func makeGate(userExclusions: [String] = [], ageThresholdOverrides: [String: Int] = [:]) -> SafetyGate {
        SafetyGate(environment: environment, userExclusions: userExclusions,
                   ageThresholdOverrides: ageThresholdOverrides, waivedSystemRoots: [fixture.root])
    }

    func makeDenyList() -> DenyList {
        DenyList(homeDirectory: fixture.home, waivedSystemRoots: [fixture.root])
    }

    func makeCanonicalizer() -> PathCanonicalizer {
        PathCanonicalizer(environment: environment)
    }

    func makePreconditionEvaluator(ageThresholdOverrides: [String: Int] = [:]) -> PreconditionEvaluator {
        PreconditionEvaluator(environment: environment, ageThresholdOverrides: ageThresholdOverrides)
    }

    /// A filesystem `ScanTarget` for an existing fixture path, with identity captured via `lstat` now
    /// (as the scanner would). `path` may be absolute or relative to the fake home.
    func scanTarget(
        ruleID: String,
        path: String,
        kind: TargetKind = .filesystem,
        allocatedBytes: Int64 = 1_024,
        itemCount: Int = 1,
        owningBundleID: String? = nil,
        captureIdentity: Bool = true
    ) -> ScanTarget {
        let absolute = path.hasPrefix("/") ? path : fixture.path(path)
        let identity = captureIdentity ? fileSystem.lstat(absolute)?.identity : nil
        return ScanTarget(
            ruleID: ruleID,
            kind: kind,
            path: absolute,
            displayName: (absolute as NSString).lastPathComponent,
            identity: identity,
            allocatedBytes: allocatedBytes,
            reclaimableBytes: allocatedBytes,
            itemCount: itemCount,
            lastUsed: nil,
            owningBundleID: owningBundleID
        )
    }
}
