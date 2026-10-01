import AppKit
import CoreServices
import Darwin
import Foundation
import Security

// MARK: - Live environment

/// Builds the production `SafeCleanEnvironment`. Every service here is read-only: nothing in this
/// file mutates the file system.
public enum LiveEnvironment {
    public static func make() -> SafeCleanEnvironment {
        SafeCleanEnvironment(
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            fileSystem: LiveFileSystemProbe(),
            processes: LiveProcessInspector(),
            runningApplications: LiveRunningApplications(),
            applications: LiveApplicationLocator(),
            volumes: LiveVolumeInspector(),
            // SAFETY-DECISION (Milestone 1): no vendor command can run yet, so every command-based
            // precondition (simulatorIdle, dockerDaemonReachable, notMounted, notSelectedXcode) fails closed.
            commands: DisabledCommandRunner(),
            clock: SystemClock(),
            effectiveUserID: geteuid(),
            userID: getuid(),
            codeSignatures: LiveCodeSignatureVerifier()
        )
    }
}

// MARK: - Shared helpers

// File-scope wrappers so the probe's own `lstat`/`stat` methods do not shadow the Darwin calls.
private func darwinLstat(_ path: String, _ buffer: inout Darwin.stat) -> Int32 { lstat(path, &buffer) }
private func darwinStat(_ path: String, _ buffer: inout Darwin.stat) -> Int32 { stat(path, &buffer) }

/// Path helpers private to the live services (kept local so this file has no dependency on Safety/).
enum LivePathSupport {
    /// Components of an absolute path, mapped to the logical form used by SafeClean:
    /// `/System/Volumes/Data/...` → `/...`, `/var|tmp|etc/...` → `/private/...`, normalized for
    /// case- and Unicode-insensitive comparison. `nil` for non-absolute paths or paths with `..`.
    static func logicalComparableComponents(_ path: String) -> [String]? {
        guard path.hasPrefix("/") else { return nil }
        var parts = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init).filter { $0 != "." }
        if parts.contains("..") { return nil }
        let lowered = parts.map(normalize)
        if lowered.count >= 3, lowered[0] == "system", lowered[1] == "volumes", lowered[2] == "data" {
            parts.removeFirst(3)
        }
        if let first = parts.first.map(normalize), ["var", "tmp", "etc"].contains(first) {
            parts.insert("private", at: 0)
        }
        return parts.map(normalize)
    }

    static func normalize(_ component: String) -> String {
        component.precomposedStringWithCanonicalMapping.lowercased()
    }

    static func isInsideOrEqual(_ candidate: [String], _ root: [String]) -> Bool {
        candidate.count >= root.count && Array(candidate.prefix(root.count)) == root
    }

    /// Decodes a NUL-terminated C char buffer.
    static func string(fromCChars buffer: [CChar]) -> String {
        let length = buffer.firstIndex(of: 0) ?? buffer.count
        return String(decoding: buffer.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// Decodes a fixed-size, NUL-terminated C char tuple (e.g. `vip_path`).
    static func string<T>(fromCTuple tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw -> String in
            let bytes = raw.bindMemory(to: UInt8.self)
            let length = bytes.firstIndex(of: 0) ?? bytes.count
            return String(decoding: bytes.prefix(length), as: UTF8.self)
        }
    }
}

// MARK: - File system

/// Read-only Darwin-backed file-system probe. Every method returns `nil` on any error.
public struct LiveFileSystemProbe: FileSystemProbe {
    /// SAFETY-DECISION: `readFile` refuses files larger than this (default 32 MiB) rather than loading
    /// arbitrarily large data; callers treat `nil` as "could not evaluate".
    public let maxReadFileBytes: Int

    public init(maxReadFileBytes: Int = 32 * 1024 * 1024) {
        self.maxReadFileBytes = maxReadFileBytes
    }

    public func lstat(_ path: String) -> FileStat? {
        guard Self.admit(path, followsFinalLink: false) else { return nil }
        var st = Darwin.stat()
        guard darwinLstat(path, &st) == 0 else { return nil }
        return Self.fileStat(st)
    }

    public func stat(_ path: String) -> FileStat? {
        guard Self.admit(path, followsFinalLink: true) else { return nil }
        var st = Darwin.stat()
        guard darwinStat(path, &st) == 0 else { return nil }
        return Self.fileStat(st)
    }

    public func realpath(_ path: String) -> String? {
        guard Self.admit(path, followsFinalLink: true) else { return nil }
        guard let resolved = Darwin.realpath(path, nil) else { return nil }
        defer { free(resolved) }
        let result = String(cString: resolved)
        RealHomeGuard.check(result)
        return result
    }

    public func canonicalPath(_ path: String) -> String? {
        guard Self.admit(path, followsFinalLink: true) else { return nil }
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(forKeys: [.canonicalPathKey]),
              let canonical = values.canonicalPath else { return nil }
        RealHomeGuard.check(canonical)
        return canonical
    }

    public func contentsOfDirectory(_ path: String) -> [String]? {
        guard Self.admit(path, followsFinalLink: false) else { return nil }
        // Never list through a symlinked `path`: lstat first, then open with O_NOFOLLOW so a swap
        // between the two calls is also refused.
        guard let info = lstat(path), info.isDirectory, !info.isSymlink else { return nil }
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        var opened = Darwin.stat()
        guard fstat(fd, &opened) == 0,
              Int64(opened.st_dev) == info.device, UInt64(opened.st_ino) == info.inode else {
            close(fd)
            return nil
        }
        guard let dir = fdopendir(fd) else {
            close(fd)
            return nil
        }
        defer { closedir(dir) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(dir) else {
                if errno != 0 { return nil }
                break
            }
            let length = Int(entry.pointee.d_namlen)
            let name = withUnsafeBytes(of: entry.pointee.d_name) { raw in
                String(decoding: raw.bindMemory(to: UInt8.self).prefix(length), as: UTF8.self)
            }
            if name == "." || name == ".." || name.isEmpty { continue }
            names.append(name)
        }
        return names
    }

    public func extendedAttributeNames(_ path: String) -> [String]? {
        guard Self.admit(path, followsFinalLink: false) else { return nil }
        for _ in 0..<4 {
            let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
            guard size >= 0 else { return nil }
            if size == 0 { return [] }
            var buffer = [CChar](repeating: 0, count: size)
            let read = listxattr(path, &buffer, size, XATTR_NOFOLLOW)
            if read < 0 {
                if errno == ERANGE { continue } // attributes grew between the two calls; retry
                return nil
            }
            let bytes = buffer.prefix(read).map { UInt8(bitPattern: $0) }
            return bytes.split(separator: 0, omittingEmptySubsequences: true)
                .map { String(decoding: $0, as: UTF8.self) }
        }
        return nil
    }

    public func isUbiquitousItem(_ path: String) -> Bool? {
        guard Self.admit(path, followsFinalLink: true) else { return nil }
        // Foundation answers "not ubiquitous" even for a missing path; that is not an evaluation.
        var st = Darwin.stat()
        guard darwinLstat(path, &st) == 0 else { return nil }
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(forKeys: [
            .isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey, .ubiquitousItemIsUploadedKey,
        ]) else { return nil }
        if values.isUbiquitousItem == true { return true }
        // SAFETY-DECISION: any ubiquity-only attribute being present means iCloud manages the item,
        // even if `isUbiquitousItem` itself was not reported.
        if values.ubiquitousItemDownloadingStatus != nil || values.ubiquitousItemIsUploaded != nil {
            return true
        }
        // SAFETY-DECISION: Foundation reports no value (rather than `false`) for ordinary local
        // files. A successful lookup with no ubiquity attributes is therefore treated as "not
        // ubiquitous"; a failed lookup is `nil` (fail closed). The path-based cloud-root check and
        // the File Provider xattr check still apply independently.
        return values.isUbiquitousItem ?? false
    }

    public func readFile(_ path: String) -> Data? {
        guard Self.admit(path, followsFinalLink: false) else { return nil }
        // SAFETY-DECISION: never read through a symlinked final component.
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = Darwin.stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
              st.st_size >= 0, st.st_size <= Int64(maxReadFileBytes) else { return nil }
        var data = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if n == 0 { break }
            data.append(contentsOf: chunk.prefix(n))
            if data.count > maxReadFileBytes { return nil }
        }
        return data
    }

    /// Gate in front of every syscall.
    ///
    /// SAFETY-DECISION: only absolute, NUL-free paths without a ".." component ever reach the file
    /// system; anything else answers `nil` ("cannot evaluate"). A relative path would be resolved
    /// against the process's working directory, and ".." defeats every lexical containment check.
    /// The real-home guard sees the path as given and — while a guard is installed (test runs only,
    /// so production pays nothing) — also where the call really lands: realpath of the whole path for
    /// calls that follow the final link, realpath of the parent plus the final name otherwise.
    static func admit(_ path: String, followsFinalLink: Bool) -> Bool {
        guard path.hasPrefix("/"), !path.contains("\0") else { return false }
        guard !path.split(separator: "/", omittingEmptySubsequences: true).contains("..") else { return false }
        RealHomeGuard.check(path)
        guard RealHomeGuard.isActive else { return true }
        if followsFinalLink, let resolved = resolvedString(path) {
            RealHomeGuard.check(resolved)
            return true
        }
        let ns = path as NSString
        let parent = ns.deletingLastPathComponent
        if let resolvedParent = resolvedString(parent.isEmpty ? "/" : parent) {
            let name = ns.lastPathComponent
            RealHomeGuard.check(name.isEmpty || name == "/" ? resolvedParent : resolvedParent + "/" + name)
        }
        return true
    }

    private static func resolvedString(_ path: String) -> String? {
        guard let resolved = Darwin.realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    static func fileStat(_ st: Darwin.stat) -> FileStat {
        FileStat(
            device: Int64(st.st_dev),
            inode: UInt64(st.st_ino),
            uid: UInt32(st.st_uid),
            mode: UInt16(st.st_mode),
            linkCount: UInt32(st.st_nlink),
            logicalSize: Int64(st.st_size),
            modificationDate: Date(
                timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec)
                    + TimeInterval(st.st_mtimespec.tv_nsec) / 1_000_000_000
            )
        )
    }
}

// MARK: - Processes

/// libproc-backed process inspection. `nil` whenever the answer cannot be trusted.
public struct LiveProcessInspector: ProcessInspecting {
    public init() {}

    public func runningProcessNames() -> [String]? {
        guard let pids = Self.allPIDs() else { return nil }
        var names = Set<String>()
        for pid in pids where pid > 0 {
            // proc_name truncates to MAXCOMLEN (16) characters; the buffer must hold 2 * MAXCOMLEN.
            var nameBuffer = [CChar](repeating: 0, count: 2 * Int(MAXCOMLEN) + 1)
            if proc_name(pid, &nameBuffer, UInt32(nameBuffer.count)) > 0 {
                let name = LivePathSupport.string(fromCChars: nameBuffer)
                if !name.isEmpty { names.insert(name) }
            }
            // SAFETY-DECISION: also report the untruncated executable file name when readable, so a
            // long name (e.g. "com.apple.dt.SKAgent…") matches exactly. Extra names can only make
            // processNotRunning stricter, never looser.
            if let path = Self.executablePath(pid) {
                let base = (path as NSString).lastPathComponent
                if !base.isEmpty { names.insert(base) }
            }
        }
        // SAFETY-DECISION: our own process is always running, so an empty list means the query failed.
        guard !names.isEmpty else { return nil }
        return Array(names).sorted()
    }

    public func pidsWithOpenFiles(under path: String) -> [Int32]? {
        RealHomeGuard.check(path)
        guard path.hasPrefix("/") else { return nil }
        var st = Darwin.stat()
        guard darwinLstat(path, &st) == 0 else { return nil }
        guard let pids = Self.allPIDs() else { return nil }

        var found = Set<Int32>()

        // 1. Kernel-side exact match on the target vnode (fds, cwd/root and mapped text), all processes
        //    this user may inspect.
        var buffer = [Int32](repeating: 0, count: pids.count + 256)
        let bytes = proc_listpidspath(
            UInt32(PROC_ALL_PIDS), 0, path, UInt32(PROC_LISTPIDSPATH_EXCLUDE_EVTONLY),
            &buffer, Int32(buffer.count * MemoryLayout<Int32>.size)
        )
        guard bytes >= 0 else { return nil }
        let count = min(Int(bytes) / MemoryLayout<Int32>.size, buffer.count)
        // SAFETY-DECISION: a completely filled buffer may be truncated → cannot evaluate.
        guard count < buffer.count else { return nil }
        for pid in buffer.prefix(count) where pid > 0 { found.insert(pid) }

        // 2. proc_listpidspath only matches the exact inode, so a directory target would miss files
        //    open *below* it. Walk every inspectable process's vnode fds, cwd and executable path and
        //    match them component-wise against the target.
        var roots: [[String]] = []
        if let logical = LivePathSupport.logicalComparableComponents(path) { roots.append(logical) }
        if let resolved = Darwin.realpath(path, nil) {
            let resolvedString = String(cString: resolved)
            free(resolved)
            RealHomeGuard.check(resolvedString)
            if let logical = LivePathSupport.logicalComparableComponents(resolvedString) { roots.append(logical) }
        }
        guard !roots.isEmpty else { return nil }

        func matches(_ candidate: String) -> Bool {
            guard let parts = LivePathSupport.logicalComparableComponents(candidate) else { return false }
            return roots.contains { LivePathSupport.isInsideOrEqual(parts, $0) }
        }

        // SAFETY-DECISION: processes this user may not inspect (other users / root, EPERM) and processes
        // that exit mid-walk (ESRCH) are skipped, exactly like an unprivileged `lsof +D`. iMop never runs
        // as root, the target must be owned by the user (SafetyGate check 8), and step 1 still covers
        // the target itself. Memory-mapped libraries below the target are not enumerated (cost); the
        // executable path of every process is.
        let myUID = getuid()
        for pid in pids where pid > 0 && !found.contains(pid) {
            if let exe = Self.executablePath(pid), matches(exe) { found.insert(pid); continue }

            var vnodeInfo = proc_vnodepathinfo()
            let vnodeSize = Int32(MemoryLayout<proc_vnodepathinfo>.size)
            errno = 0
            if proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vnodeInfo, vnodeSize) == vnodeSize {
                let cwd = LivePathSupport.string(fromCTuple: vnodeInfo.pvi_cdir.vip_path)
                let root = LivePathSupport.string(fromCTuple: vnodeInfo.pvi_rdir.vip_path)
                if (!cwd.isEmpty && matches(cwd)) || (!root.isEmpty && matches(root)) {
                    found.insert(pid)
                    continue
                }
            } else {
                switch Self.classifyFailure(pid: pid, errno: errno, myUID: myUID) {
                case .skip: continue
                case .cannotEvaluate: return nil
                }
            }

            switch Self.openVnodes(of: pid, myUID: myUID, where: matches) {
            case .match: found.insert(pid)
            case .noMatch, .skip: continue
            case .cannotEvaluate: return nil
            }
        }
        return found.sorted()
    }

    // MARK: libproc plumbing

    static func allPIDs() -> [pid_t]? {
        for _ in 0..<4 {
            let estimate = proc_listallpids(nil, 0)
            guard estimate > 0 else { return nil }
            let capacity = Int(estimate) + 128
            var pids = [pid_t](repeating: 0, count: capacity)
            let n = proc_listallpids(&pids, Int32(capacity * MemoryLayout<pid_t>.size))
            guard n > 0 else { return nil }
            if Int(n) >= capacity { continue } // possibly truncated; retry with a fresh estimate
            return Array(pids.prefix(Int(n)))
        }
        return nil
    }

    static func executablePath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN)) // PROC_PIDPATHINFO_MAXSIZE
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        let path = LivePathSupport.string(fromCChars: buffer)
        return path.isEmpty ? nil : path
    }

    @_spi(FixtureTesting)
    public enum FDScan: Equatable, Sendable {
        case match
        case noMatch
        /// Process exited, is a zombie, or belongs to another user (EPERM): skipped.
        case skip
        /// A same-user process could not be inspected: the whole answer is untrustworthy.
        case cannotEvaluate
    }

    @_spi(FixtureTesting)
    public enum FailureClass: Equatable, Sendable {
        case skip
        case cannotEvaluate
    }

    /// SAFETY-DECISION (spec §3.6 "treat errors as open"): a libproc failure is only ignored when the
    /// process is gone (ESRCH, or no longer listed), is a zombie (no open files), or is owned by another
    /// user and refused with EPERM — exactly like an unprivileged `lsof +D`. Any other failure, in
    /// particular for a live process of this user, makes the whole query "cannot evaluate" (nil).
    @_spi(FixtureTesting)
    public static func classifyFailure(pid: pid_t, errno code: Int32, myUID: uid_t) -> FailureClass {
        if code == ESRCH { return .skip }
        guard let info = kinfo(pid) else { return .skip } // no longer exists
        if info.kp_proc.p_stat == CChar(SZOMB) { return .skip }
        if code == EPERM && info.kp_eproc.e_ucred.cr_uid != myUID { return .skip }
        return .cannotEvaluate
    }

    /// `sysctl(KERN_PROC_PID)` — works for every process without privileges; nil if it is gone.
    static func kinfo(_ pid: pid_t) -> kinfo_proc? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0, size > 0 else { return nil }
        guard info.kp_proc.p_pid == pid else { return nil }
        return info
    }

    /// Scans every vnode fd of `pid`. A listing that fills the buffer completely may be truncated; it
    /// is retried with a larger buffer and, if it still fills up, the process is reported as holding
    /// the target open (fail closed).
    @_spi(FixtureTesting)
    public static func openVnodes(of pid: pid_t, myUID: uid_t, where predicate: (String) -> Bool) -> FDScan {
        let fdInfoSize = MemoryLayout<proc_fdinfo>.stride
        errno = 0
        let needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        if needed <= 0 {
            if needed == 0 && errno == 0 { return .noMatch } // no file descriptors at all
            return classifyFailure(pid: pid, errno: errno, myUID: myUID) == .skip ? .skip : .cannotEvaluate
        }
        var capacity = Int(needed) / fdInfoSize + 32
        for _ in 0..<4 {
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
            errno = 0
            let used = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(capacity * fdInfoSize))
            if used <= 0 {
                if used == 0 && errno == 0 { return .noMatch }
                return classifyFailure(pid: pid, errno: errno, myUID: myUID) == .skip ? .skip : .cannotEvaluate
            }
            let count = Int(used) / fdInfoSize
            if count >= capacity {
                capacity *= 2 // possibly truncated; retry with room to spare
                continue
            }
            for fd in fds.prefix(count) where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
                var info = vnode_fdinfowithpath()
                let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
                // An fd closed between listing and lookup is gone; nothing to report for it.
                guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &info, size) == size else { continue }
                let path = LivePathSupport.string(fromCTuple: info.pvip.vip_path)
                if !path.isEmpty && predicate(path) { return .match }
            }
            return .noMatch
        }
        // SAFETY-DECISION: still possibly truncated after retries → assume it holds the target open.
        return .match
    }
}

// MARK: - Running applications

public struct LiveRunningApplications: RunningApplicationsProviding {
    public init() {}

    public func runningBundleIdentifiers() -> [String]? {
        let ids = NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier)
        // SAFETY-DECISION: a logged-in session always has running applications (Finder, Dock, …);
        // an empty list means the snapshot is unavailable, so report "cannot evaluate".
        guard !ids.isEmpty else { return nil }
        return ids
    }
}

// MARK: - Installed applications

public struct LiveApplicationLocator: ApplicationLocating {
    /// Upper bound for a Spotlight query; on timeout the lookup returns `nil` (fail closed).
    public let spotlightTimeout: TimeInterval

    public init(spotlightTimeout: TimeInterval = 15) {
        self.spotlightTimeout = spotlightTimeout
    }

    public func applicationURLs(forBundleIdentifier bundleID: String) -> [URL]? {
        guard Self.isPlausibleBundleID(bundleID) else { return nil }
        return NSWorkspace.shared.urlsForApplications(withBundleIdentifier: bundleID)
    }

    public func spotlightApplicationPaths(forBundleIdentifier bundleID: String) -> [String]? {
        // SAFETY-DECISION: only plain reverse-DNS identifiers are queried, so the identifier can never
        // alter the Spotlight query syntax.
        guard let queryString = Self.spotlightQueryString(forBundleIdentifier: bundleID) else { return nil }

        // SAFETY-DECISION: every MDQuery call (create, execute, read, release) happens on ONE serial
        // queue inside one work item; the caller never touches the query. On timeout the caller only
        // flags the request as abandoned (under the box's lock) and answers nil (fail closed). The
        // serial queue bounds Spotlight to one blocked thread: requests queued behind a hung query
        // time out on their own and are skipped without running once they are dequeued.
        let box = SpotlightRequest()
        let done = DispatchSemaphore(value: 0)
        Self.spotlightQueue.async {
            defer { done.signal() }
            guard !box.isAbandoned else { return }
            box.finish(Self.runSpotlightQuery(queryString, shouldContinue: { !box.isAbandoned }))
        }
        guard done.wait(timeout: .now() + spotlightTimeout) == .success else {
            box.abandon()
            return nil
        }
        return box.paths
    }

    /// The Spotlight query for `bundleID`, or nil for an implausible identifier.
    ///
    /// SAFETY-DECISION: bundle identifiers are case-insensitive (LaunchServices matches them that
    /// way), so the comparison uses Spotlight's `c` (case-insensitive) modifier. Without it a
    /// case-variant identifier gets a successful EMPTY answer, which reads as "not installed"
    /// (fail open).
    @_spi(FixtureTesting)
    public static func spotlightQueryString(forBundleIdentifier bundleID: String) -> String? {
        guard isPlausibleBundleID(bundleID) else { return nil }
        return "kMDItemCFBundleIdentifier == \"\(bundleID)\"c"
    }

    /// Serializes every Spotlight lookup.
    private static let spotlightQueue = DispatchQueue(label: "iMop.LiveApplicationLocator.spotlight", qos: .utility)

    /// Runs one synchronous query entirely on the calling thread. nil on any failure.
    private static func runSpotlightQuery(_ queryString: String, shouldContinue: () -> Bool) -> [String]? {
        guard let query = MDQueryCreate(kCFAllocatorDefault, queryString as CFString, nil, nil) else { return nil }
        let scopes = [kMDQueryScopeComputer as String, kMDQueryScopeNetwork as String] as CFArray
        MDQuerySetSearchScope(query, scopes, 0)
        guard MDQueryExecute(query, CFOptionFlags(kMDQuerySynchronous.rawValue)) else { return nil }
        MDQueryDisableUpdates(query)
        defer { MDQueryStop(query) }
        guard shouldContinue() else { return nil }
        var paths: [String] = []
        let count = MDQueryGetResultCount(query)
        for index in 0..<count {
            guard let raw = MDQueryGetResultAtIndex(query, index) else { continue }
            let item = Unmanaged<MDItem>.fromOpaque(raw).takeUnretainedValue()
            if let path = MDItemCopyAttribute(item, kMDItemPath) as? String { paths.append(path) }
        }
        return paths
    }

    static func isPlausibleBundleID(_ id: String) -> Bool {
        guard !id.isEmpty, id.count <= 255 else { return false }
        return id.unicodeScalars.allSatisfy { scalar in
            (scalar.value < 128) && (CharacterSet.alphanumerics.contains(scalar) || scalar == "." || scalar == "-" || scalar == "_")
        }
    }
}

/// Hand-off between a caller and the Spotlight work item. Holds only plain values (never the
/// MDQuery), and every access goes through the lock.
private final class SpotlightRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var abandoned = false
    private var result: [String]?

    var isAbandoned: Bool {
        lock.lock(); defer { lock.unlock() }
        return abandoned
    }

    func abandon() {
        lock.lock(); abandoned = true; lock.unlock()
    }

    func finish(_ paths: [String]?) {
        lock.lock(); result = paths; lock.unlock()
    }

    var paths: [String]? {
        lock.lock(); defer { lock.unlock() }
        return abandoned ? nil : result
    }
}

// MARK: - Volumes

public struct LiveVolumeInspector: VolumeInspecting {
    public init() {}

    public func mountedVolumes() -> [String]? {
        guard let urls = FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: nil, options: []) else {
            return nil
        }
        return urls.map { $0.standardizedFileURL.path }.filter { path in
            let parts = path.split(separator: "/", omittingEmptySubsequences: true)
            return parts.count >= 2 && LivePathSupport.normalize(String(parts[0])) == "volumes"
        }
    }

    public func availableCapacityForImportantUsage(at path: String) -> Int64? {
        RealHomeGuard.check(path)
        guard path.hasPrefix("/") else { return nil }
        let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values?.volumeAvailableCapacityForImportantUsage
    }

    public func availableCapacity(at path: String) -> Int64? {
        RealHomeGuard.check(path)
        guard path.hasPrefix("/") else { return nil }
        let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeAvailableCapacityKey])
        return values?.volumeAvailableCapacity.map(Int64.init)
    }
}

// MARK: - Code signatures

public struct LiveCodeSignatureVerifier: CodeSignatureVerifying {
    public init() {}

    public func isAppleSigned(path: String) -> Bool? {
        RealHomeGuard.check(path)
        guard path.hasPrefix("/") else { return nil }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return nil }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let anchorApple = requirement else { return nil }
        // SAFETY-DECISION: default flags perform full validation including sealed resources, so a
        // tampered Apple bundle fails. Slower than kSecCSDoNotValidateResources, but only used for the
        // few Red-tier bundle rules.
        let status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), anchorApple)
        switch status {
        case errSecSuccess:
            return true
        case errSecCSReqFailed, errSecCSUnsigned, errSecCSSignatureFailed, errSecCSBadResource,
             errSecCSResourcesNotSealed, errSecCSResourcesInvalid, errSecCSSignatureInvalid:
            return false
        default:
            return nil
        }
    }
}

// MARK: - Commands (Milestone 1 placeholder)

/// Milestone 1 placeholder: no executable resolves and nothing ever runs, so command-based
/// preconditions fail closed. Replaced by `CommandRunner` in Milestone 4.
public struct DisabledCommandRunner: CommandRunning {
    public init() {}

    public func resolveExecutable(_ tool: String) -> String? { nil }

    public func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult {
        CommandResult(exitCode: -1, stdout: "", stderr: "command execution is disabled in this build")
    }
}
