import Darwin
import Foundation

/// Runs vendor cleanup and query commands (spec §5.3).
///
/// - Executables are resolved only from a fixed list of trusted directories and verified: every
///   directory on the way to the file (each ancestor, each symlink hop) is owned by the user or root
///   and not group/world-writable; every symlink is owned by the user or root; the final file is a
///   regular, executable file owned by the user or root and not group/world-writable; its real path
///   is inside a trusted root; and when it is a `#!` script its interpreter passes the same checks.
/// - `Process` is started with the ABSOLUTE, fully resolved executable path and an ARGUMENT ARRAY.
///   There is no shell, no shell flag, no C-library shell helpers, no privilege escalation.
/// - Every invocation must exactly match an entry of `CommandAllowList` for its purpose.
/// - The child gets a sanitized environment (`PATH` = trusted directories that pass the directory
///   checks at run time plus SIP-protected `/usr/bin` and `/bin`, `HOME`, `USER`, `LANG`),
///   `/dev/null` as stdin and `HOME` as working directory.
/// - stdout/stderr are drained concurrently and truncated at 64 KB each (on a UTF-8 boundary); a
///   hard timeout terminates the child's whole process group (SIGTERM, then SIGKILL after a grace
///   period) and the result is delivered only after that.
/// - `run` never throws: every failure is a `CommandResult` with exit code -1 and an explanation.
public struct CommandRunner: CommandRunning {
    /// One directory searched for executables, in order.
    public struct SearchDirectory: Sendable, Hashable {
        public let path: String
        /// When non-nil, only these tool names may be resolved from this directory.
        public let allowedTools: Set<String>?

        public init(path: String, allowedTools: Set<String>? = nil) {
            self.path = path
            self.allowedTools = allowedTools
        }
    }

    /// SAFETY-DECISION: the only system tools ever taken from /usr/bin.
    public static let systemTools: Set<String> = ["xcrun", "xcode-select", "hdiutil", "tmutil", "pkgutil", "launchctl", "git"]

    /// SAFETY-DECISION (M6): system tools that are resolved ONLY from this exact, SIP-protected path
    /// (never from any search directory): `pkgutil --pkgs` (read-only, OrphanDetector condition 4),
    /// `tmutil listlocalsnapshots /` (read-only, Time Machine advisory) and `launchctl bootout …`
    /// (the Executor's `bootoutAndTrash` only). The file must still pass every trust check, and its
    /// real path must be exactly this path.
    public static let systemToolPaths: [String: String] = [
        "pkgutil": "/usr/sbin/pkgutil",
        "launchctl": CommandAllowList.launchctlPath,
        "tmutil": "/usr/bin/tmutil",
    ]

    /// SAFETY-DECISION: SIP-protected system directories. They are always on the child's PATH (after
    /// the trusted search directories) so `#!/usr/bin/env bash` and system helpers resolve
    /// to the system copies, and a `#!` interpreter may live in them.
    public static let systemDirectories = ["/usr/bin", "/bin"]

    /// Per-stream capture limit (spec §5.3). The "[truncated N bytes]" marker is appended after it.
    public static let outputLimit = 64 * 1024
    /// Grace period between SIGTERM and SIGKILL on timeout.
    public static let terminationGrace: TimeInterval = 5
    /// SAFETY-DECISION: no caller may run a command longer than the longest spec timeout (30 min,
    /// `simctl runtime delete`); a non-positive or non-finite timeout means the 10-minute default.
    public static let maximumTimeout: TimeInterval = 1800

    public static let notAllowedMessage = "command not allowed"
    public static let cancelledMessage = "cancelled"

    /// Longest `#!` line the kernel honours (and the most we read of a script).
    static let shebangLimit = 512
    /// Nested interpreters (`script → /usr/bin/env → node`) followed at most this deep.
    static let maximumInterpreterDepth = 3
    /// Symlink hops followed at most (like `MAXSYMLINKS`).
    static let maximumSymlinkHops = 32

    let homePath: String
    let searchDirectories: [SearchDirectory]
    /// Directories the REAL path of a resolved executable must be inside.
    let trustedRoots: [String]
    let allowList: CommandAllowList
    let userID: uid_t
    let grace: TimeInterval
    let captureLimit: Int
    /// Tool → the only path it may be resolved from (`systemToolPaths` in production; empty for the
    /// fixture runner unless a test passes its own table).
    let exactToolPaths: [String: String]

    /// Production runner for the user whose home is `homeDirectory`.
    public init(homeDirectory: URL) {
        let home = Self.cleanHome(homeDirectory)
        self.init(home: home,
                  searchDirectories: Self.standardSearchDirectories(home: home),
                  trustedRoots: Self.standardTrustedRoots(home: home),
                  allowList: .standard,
                  userID: getuid(),
                  grace: Self.terminationGrace,
                  captureLimit: Self.outputLimit,
                  exactToolPaths: Self.systemToolPaths)
    }

    /// Test-only runner: custom trusted directories and allow-list so fixtures can run fake
    /// executable scripts. Never used by the app.
    ///
    /// `userID` lets a test simulate "owned by another user" (a non-root process cannot chown a
    /// fixture file to another uid): files owned by the real uid then count as someone else's.
    @_spi(FixtureTesting)
    public init(homeDirectory: URL, searchDirectories: [SearchDirectory], trustedRoots: [String],
                allowList: CommandAllowList, terminationGrace: TimeInterval = CommandRunner.terminationGrace,
                outputLimit: Int = CommandRunner.outputLimit, userID: uid_t = getuid(),
                exactToolPaths: [String: String] = [:]) {
        self.init(home: Self.cleanHome(homeDirectory), searchDirectories: searchDirectories, trustedRoots: trustedRoots,
                  allowList: allowList, userID: userID, grace: terminationGrace, captureLimit: outputLimit,
                  exactToolPaths: exactToolPaths)
    }

    private init(home: String, searchDirectories: [SearchDirectory], trustedRoots: [String], allowList: CommandAllowList,
                 userID: uid_t, grace: TimeInterval, captureLimit: Int, exactToolPaths: [String: String]) {
        self.homePath = home
        self.searchDirectories = searchDirectories
        self.trustedRoots = trustedRoots
        self.allowList = allowList
        self.userID = userID
        self.grace = grace
        self.captureLimit = max(0, captureLimit)
        self.exactToolPaths = exactToolPaths
    }

    private static func cleanHome(_ url: URL) -> String {
        var path = url.standardizedFileURL.path
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        return path
    }

    /// Spec §5.3 search order.
    public static func standardSearchDirectories(home: String) -> [SearchDirectory] {
        [
            SearchDirectory(path: "/usr/bin", allowedTools: systemTools),
            SearchDirectory(path: "/opt/homebrew/bin"),
            SearchDirectory(path: "/usr/local/bin"),
            SearchDirectory(path: home + "/.cargo/bin"),
            SearchDirectory(path: home + "/go/bin"),
            SearchDirectory(path: home + "/.bun/bin"),
            SearchDirectory(path: home + "/.local/bin"),
        ]
    }

    /// SAFETY-DECISION: a symlinked executable is accepted only when its real path is ALSO inside
    /// one of these roots (e.g. Homebrew's `bin/brew` → `/opt/homebrew/Library/...`). A link into
    /// `/Applications`, `~/Downloads`, `/tmp` etc. is not trusted.
    public static func standardTrustedRoots(home: String) -> [String] {
        ["/usr/bin", "/opt/homebrew", "/usr/local",
         home + "/.cargo/bin", home + "/go/bin", home + "/.bun/bin", home + "/.local/bin"]
    }

    // MARK: - Resolution

    /// A fully verified executable.
    struct VerifiedExecutable: Sendable, Equatable {
        /// What `resolveExecutable` returns: `<search directory>/<tool>`.
        let candidate: String
        /// The fully resolved file that is launched.
        let realPath: String
        let device: dev_t
        let inode: ino_t
    }

    public func resolveExecutable(_ tool: String) -> String? {
        verifiedResolution(tool)?.candidate
    }

    func verifiedResolution(_ tool: String) -> VerifiedExecutable? {
        guard Self.isBareToolName(tool) else { return nil }
        if let exact = exactToolPaths[tool] {
            // SAFETY-DECISION (M6): only the exact path; its real path must be that same file.
            RealHomeGuard.check(exact)
            var info = Darwin.stat()
            guard exact.hasPrefix("/"), Darwin.lstat(exact, &info) == 0,
                  let verified = verifiedFile(exact, roots: [exact], depth: 0), verified.path == exact else { return nil }
            return VerifiedExecutable(candidate: exact, realPath: verified.path,
                                      device: verified.info.st_dev, inode: verified.info.st_ino)
        }
        for directory in searchDirectories {
            if let allowed = directory.allowedTools, !allowed.contains(tool) { continue }
            let candidate = directory.path + "/" + tool
            RealHomeGuard.check(candidate)
            var info = Darwin.stat()
            // Not present here: keep searching. Present but untrusted: stop (fail closed) rather than
            // falling through to a later directory, so a bad file can never be silently bypassed.
            guard Darwin.lstat(candidate, &info) == 0 else { continue }
            guard let verified = verifiedFile(candidate, roots: trustedRoots, depth: 0) else { return nil }
            return VerifiedExecutable(candidate: candidate, realPath: verified.path,
                                      device: verified.info.st_dev, inode: verified.info.st_ino)
        }
        return nil
    }

    /// `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, at most 255 characters.
    static func isBareToolName(_ tool: String) -> Bool {
        let scalars = Array(tool.unicodeScalars)
        guard let first = scalars.first, scalars.count <= 255, isAlphanumeric(first) else { return false }
        return scalars.allSatisfy { isAlphanumeric($0) || $0 == "." || $0 == "_" || $0 == "+" || $0 == "-" }
    }

    private static func isAlphanumeric(_ scalar: Unicode.Scalar) -> Bool {
        scalar.isASCII && (("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar) || ("0"..."9").contains(scalar))
    }

    /// The resolved file and its `lstat` when `path` passes every trust check, else `nil`.
    ///
    /// - `roots`: the resolved path must be inside one of them.
    /// - `depth`: interpreter nesting (a `#!` interpreter is verified with `depth + 1`).
    private func verifiedFile(_ path: String, roots: [String], depth: Int) -> (path: String, info: Darwin.stat)? {
        guard depth <= Self.maximumInterpreterDepth else { return nil }
        // SAFETY-DECISION (review M4): resolve the path component by component, checking EVERY
        // directory passed through (all ancestors up to "/", each symlink hop's directory) and every
        // symlink, so nobody but the user or root can swap anything between the check and the launch.
        guard let resolved = secureResolve(path) else { return nil }
        RealHomeGuard.check(resolved.path)
        guard isInside(resolved.path, roots: roots) else { return nil }

        // The real file: regular, executable by us, owned by us or root, not group/world-writable.
        let file = resolved.info
        guard (file.st_mode & S_IFMT) == S_IFREG else { return nil }
        guard file.st_uid == userID || file.st_uid == 0 else { return nil }
        guard (file.st_mode & (S_IWGRP | S_IWOTH)) == 0 else { return nil }
        guard (file.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0, Darwin.access(resolved.path, X_OK) == 0 else { return nil }

        // SAFETY-DECISION (review M4): a `#!` script runs its interpreter, so the interpreter must
        // pass the same checks (inside a trusted root or SIP-protected /bin, /usr/bin).
        guard interpreterIsTrusted(of: resolved.path, depth: depth) else { return nil }
        return resolved
    }

    /// Like `realpath(3)`, but returns `nil` unless every directory traversed (including "/" and every
    /// directory a symlink is read from) is owned by the user or root and not group/world-writable,
    /// and every symlink is owned by the user or root. The sticky, world-writable `/tmp` does NOT
    /// qualify. Returns the resolved path and the `lstat` of its final component.
    func secureResolve(_ path: String) -> (path: String, info: Darwin.stat)? {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { return nil }
        var root = Darwin.stat()
        guard Darwin.lstat("/", &root) == 0, isSafeDirectory(root) else { return nil }
        var pending = Array(path.split(separator: "/").map(String.init).reversed())
        var current = "/"
        var currentInfo = root
        var hops = 0
        while let component = pending.popLast() {
            if component.isEmpty || component == "." { continue }
            if component == ".." {
                // `current` is resolved, and all its ancestors were verified on the way in.
                current = current == "/" ? "/" : (current as NSString).deletingLastPathComponent
                guard Darwin.lstat(current, &currentInfo) == 0 else { return nil }
                continue
            }
            // `current` must be a safe directory to look inside it.
            guard (currentInfo.st_mode & S_IFMT) == S_IFDIR, isSafeDirectory(currentInfo) else { return nil }
            let next = current == "/" ? "/" + component : current + "/" + component
            var info = Darwin.stat()
            guard Darwin.lstat(next, &info) == 0 else { return nil }
            switch info.st_mode & S_IFMT {
            case S_IFLNK:
                hops += 1
                guard hops <= Self.maximumSymlinkHops, info.st_uid == userID || info.st_uid == 0,
                      let target = Self.readLink(next), !target.isEmpty else { return nil }
                if target.hasPrefix("/") {
                    current = "/"
                    currentInfo = root
                }
                pending.append(contentsOf: target.split(separator: "/").map(String.init).reversed())
            case S_IFDIR:
                current = next
                currentInfo = info
            default:
                // A file: nothing may follow it.
                guard pending.allSatisfy({ $0.isEmpty || $0 == "." }) else { return nil }
                return (next, info)
            }
        }
        // Ended on a directory: it must be safe too.
        guard (currentInfo.st_mode & S_IFMT) == S_IFDIR, isSafeDirectory(currentInfo) else { return nil }
        return (current, currentInfo)
    }

    private static func readLink(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = Darwin.readlink(path, &buffer, Int(PATH_MAX))
        guard count > 0, count <= Int(PATH_MAX) else { return nil }
        let bytes = buffer[0..<count].map { UInt8(bitPattern: $0) }
        guard !bytes.contains(0) else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }

    private func isSafeDirectory(_ info: Darwin.stat) -> Bool {
        guard (info.st_mode & S_IFMT) == S_IFDIR else { return false }
        guard info.st_uid == userID || info.st_uid == 0 else { return false }
        return (info.st_mode & (S_IWGRP | S_IWOTH)) == 0
    }

    /// `true` when `path` is not a `#!` script, or when its interpreter passes every check.
    private func interpreterIsTrusted(of path: String, depth: Int) -> Bool {
        guard let header = Self.readHeader(path) else {
            // SAFETY-DECISION: a file whose first bytes cannot be read cannot be checked → refused.
            return false
        }
        guard header.starts(with: [UInt8(ascii: "#"), UInt8(ascii: "!")]) else { return true }
        guard let newline = header.firstIndex(of: UInt8(ascii: "\n")) else {
            // The kernel would truncate an over-long line; never guess what it would run.
            return false
        }
        let line = header[2..<newline]
        guard line.allSatisfy({ $0 >= 0x20 && $0 < 0x7F || $0 == UInt8(ascii: "\t") }) else { return false }
        let tokens = String(decoding: line, as: UTF8.self)
            .split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let interpreter = tokens.first, interpreter.hasPrefix("/") else { return false }
        let interpreterRoots = trustedRoots + Self.systemDirectories
        guard let resolved = verifiedFile(interpreter, roots: interpreterRoots, depth: depth + 1) else { return false }

        if resolved.path == "/usr/bin/env" {
            // SAFETY-DECISION: `#!/usr/bin/env NAME` — exactly one bare program name (no `-S`, no
            // options, no assignments), resolved exactly like `env` will: the first directory of the
            // sanitized PATH that has an entry of that name decides, and that entry must pass every
            // check. An untrusted first match is refused, never skipped.
            guard tokens.count == 2, Self.isBareToolName(tokens[1]) else { return false }
            let name = tokens[1]
            for directory in sanitizedPathDirectories() {
                let candidate = directory + "/" + name
                RealHomeGuard.check(candidate)
                var info = Darwin.stat()
                guard Darwin.lstat(candidate, &info) == 0 else { continue }
                return verifiedFile(candidate, roots: interpreterRoots, depth: depth + 1) != nil
            }
            return false
        }
        return true
    }

    /// The first `shebangLimit` bytes of a regular file (never through a final symlink).
    private static func readHeader(_ path: String) -> [UInt8]? {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }
        var info = Darwin.stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        var buffer = [UInt8](repeating: 0, count: shebangLimit)
        var filled = 0
        while filled < buffer.count {
            let count = buffer.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress! + filled, raw.count - filled)
            }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if count == 0 { break }
            filled += count
        }
        return Array(buffer[0..<filled])
    }

    private func isInside(_ real: String, roots: [String]) -> Bool {
        // Lexical roots first, then their real paths (e.g. a fixture home under /var → /private/var),
        // computed only when needed so a /usr/bin hit never inspects the home directory.
        if roots.contains(where: { Self.isInside(real, root: $0) }) { return true }
        for root in roots {
            RealHomeGuard.check(root)
            if let resolved = Self.realpath(root), Self.isInside(real, root: resolved) { return true }
        }
        return false
    }

    /// Component-wise, case-sensitive containment (case-sensitive is the conservative choice).
    static func isInside(_ path: String, root: String) -> Bool {
        guard root.hasPrefix("/"), path.hasPrefix("/") else { return false }
        var trimmedRoot = root
        while trimmedRoot.count > 1 && trimmedRoot.hasSuffix("/") { trimmedRoot.removeLast() }
        guard trimmedRoot != "/" else { return false }
        return path == trimmedRoot || path.hasPrefix(trimmedRoot + "/")
    }

    private static func realpath(_ path: String) -> String? {
        guard let resolved = Darwin.realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    // MARK: - Environment

    /// SAFETY-DECISION (review M4): the child's PATH lists only the trusted search directories that
    /// pass the directory checks NOW (every directory on the way owned by the user or root, none
    /// group/world-writable — e.g. a 0775 `/opt/homebrew/bin` is left out), followed by the
    /// SIP-protected `/usr/bin` and `/bin`. A directory whose contents `resolveExecutable` would refuse
    /// is never on PATH, so neither `env` nor a vendor tool can pick a program from it.
    @_spi(FixtureTesting)
    public func sanitizedPathDirectories() -> [String] {
        var result: [String] = []
        for directory in searchDirectories.map(\.path) where !result.contains(directory) {
            if Self.systemDirectories.contains(directory) {
                result.append(directory)
                continue
            }
            RealHomeGuard.check(directory)
            if let resolved = secureResolve(directory), (resolved.info.st_mode & S_IFMT) == S_IFDIR {
                result.append(directory)
            }
        }
        for directory in Self.systemDirectories where !result.contains(directory) {
            result.append(directory)
        }
        return result
    }

    var sanitizedPath: String { sanitizedPathDirectories().joined(separator: ":") }

    /// SAFETY-DECISION: the child sees only PATH (trusted directories), HOME, USER and LANG.
    func sanitizedEnvironment() -> [String: String] {
        var environment: [String: String] = ["PATH": sanitizedPath, "HOME": homePath]
        let inherited = ProcessInfo.processInfo.environment
        if let user = inherited["USER"].flatMap(Self.safeEnvironmentValue) ?? Self.loginName() {
            environment["USER"] = user
        }
        if let lang = inherited["LANG"].flatMap(Self.safeEnvironmentValue) {
            environment["LANG"] = lang
        }
        return environment
    }

    private static func safeEnvironmentValue(_ value: String) -> String? {
        guard !value.isEmpty, value.utf8.count <= 256,
              !value.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
        return value
    }

    private static func loginName() -> String? {
        guard let entry = getpwuid(getuid()), let name = entry.pointee.pw_name else { return nil }
        return safeEnvironmentValue(String(cString: name))
    }

    // MARK: - Running

    public func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult {
        // SAFETY-DECISION: the purpose-less form is read-only.
        await run(executable: executable, arguments: arguments, timeout: timeout, purpose: .readOnly)
    }

    public func run(executable: String, arguments: [String], timeout: TimeInterval, purpose: CommandPurpose) async -> CommandResult {
        guard executable.hasPrefix("/") else { return Self.failure("executable must be an absolute path") }
        let tool = (executable as NSString).lastPathComponent
        guard Self.isBareToolName(tool) else { return Self.failure("executable name is not a bare tool name") }
        guard allowList.matches(tool: tool, arguments: arguments, purpose: purpose) else {
            return Self.failure(Self.notAllowedMessage)
        }
        // SAFETY-DECISION (M6): the launchctl bootout must name THIS user's GUI domain and a plist
        // directly in THIS user's ~/Library/LaunchAgents (the static table cannot know either).
        if tool == CommandAllowList.launchctlTool {
            var homes = [homePath]
            RealHomeGuard.check(homePath)
            if let resolved = Self.realpath(homePath), resolved != homePath { homes.append(resolved) }
            guard purpose == .action,
                  CommandAllowList.launchAgentBootoutAllowed(arguments: arguments, userID: UInt32(userID), homeDirectories: homes) else {
                return Self.failure(Self.notAllowedMessage)
            }
        }
        // SAFETY-DECISION: the path is re-resolved and re-verified right before launch; a caller can
        // never run an executable that `resolveExecutable` would not return for that tool now.
        guard let verified = verifiedResolution(tool), verified.candidate == executable else {
            return Self.failure("executable is not in a trusted location")
        }
        let effectiveTimeout = (timeout.isFinite && timeout > 0) ? min(timeout, Self.maximumTimeout) : CommandSpec.defaultTimeout
        guard FileManager.default.fileExists(atPath: homePath) else {
            return Self.failure("home directory is not available")
        }

        // SAFETY-DECISION (review M4): launch the fully resolved, verified file (not the symlink in the
        // search directory), and only if it is still the same inode right before the launch.
        let session = CommandSession(executable: verified, arguments: arguments, environment: sanitizedEnvironment(),
                                     workingDirectory: homePath, timeout: effectiveTimeout, grace: grace,
                                     captureLimit: captureLimit)
        // SAFETY-DECISION (review M4): a cancelled task stops a READ-ONLY probe (process group
        // SIGTERM → grace → SIGKILL, result "cancelled"). An `.action` command is never interrupted
        // half-way: the Executor cancels between items, and the command's own timeout still applies.
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                session.start { continuation.resume(returning: $0) }
            }
        } onCancel: {
            if purpose == .readOnly { session.cancel() }
        }
    }

    static func failure(_ message: String) -> CommandResult {
        CommandResult(exitCode: -1, stdout: "", stderr: message)
    }
}

// MARK: - One process run

/// Drains one pipe on its own (a dispatch read source) until EOF, keeping at most `limit` bytes and
/// discarding the rest. The read end is closed by the source's cancel handler, so it is never closed
/// while a read is in flight.
private final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var droppedBytes = 0
    private var finished = false
    private let limit: Int
    private let fd: Int32
    private let source: DispatchSourceRead
    let done = DispatchGroup()

    init(readEnd fd: Int32, limit: Int) {
        self.fd = fd
        self.limit = limit
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "com.imop.cleaner.CommandRunner.output"))
        done.enter()
        let group = done
        source.setEventHandler { [weak self] in self?.readAvailable() }
        // Captures only the fd and the group: it always runs (once) after `cancel()`, even if the
        // collector is gone, so the fd is always closed and the group always balanced.
        source.setCancelHandler {
            Darwin.close(fd)
            group.leave()
        }
    }

    /// Starts reading. Must be called exactly once (a dispatch source must be resumed before it is
    /// cancelled or released).
    func start() {
        source.resume()
    }

    private func readAvailable() {
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
        if count < 0, errno == EINTR || errno == EAGAIN { return }
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return }
        guard count > 0 else {
            // EOF (or a read error): stop.
            finished = true
            source.cancel()
            return
        }
        let room = max(0, limit - data.count)
        if room > 0 { data.append(contentsOf: buffer[0..<min(room, count)]) }
        droppedBytes += max(0, count - room)
    }

    /// Stops reading (abandoned after the child exited and the grace ran out). The fd is closed by
    /// the cancel handler.
    func finish() {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return }
        finished = true
        source.cancel()
    }

    var text: String {
        lock.lock()
        defer { lock.unlock() }
        var kept = data
        var dropped = droppedBytes
        if dropped > 0 {
            // Cut on a UTF-8 scalar boundary: a sequence split by the limit is dropped whole rather
            // than decoded as U+FFFD.
            let incomplete = Self.incompleteUTF8SuffixLength(kept)
            kept.removeLast(incomplete)
            dropped += incomplete
        }
        var result = String(decoding: kept, as: UTF8.self)
        if dropped > 0 { result += "\n[truncated \(dropped) bytes]" }
        return result
    }

    /// Number of trailing bytes forming an incomplete UTF-8 sequence (0 when the data ends cleanly).
    static func incompleteUTF8SuffixLength(_ data: Data) -> Int {
        let bytes = [UInt8](data.suffix(4))
        guard let leadIndex = bytes.lastIndex(where: { $0 & 0xC0 != 0x80 }) else { return 0 }
        let lead = bytes[leadIndex]
        let expected: Int
        switch lead {
        case 0xF0...0xF7: expected = 4
        case 0xE0...0xEF: expected = 3
        case 0xC0...0xDF: expected = 2
        default: expected = 1
        }
        let available = bytes.count - leadIndex
        return available < expected ? available : 0
    }
}

private final class CommandSession: @unchecked Sendable {
    private enum StopReason { case timeout, cancel }

    private let process = Process()
    private let executable: CommandRunner.VerifiedExecutable
    private let timeout: TimeInterval
    private let grace: TimeInterval
    private let timerQueue = DispatchQueue(label: "com.imop.cleaner.CommandRunner.timers")
    private let lock = NSLock()

    private var stdout: OutputCollector?
    private var stderr: OutputCollector?
    private var writeEnds: [FileHandle] = []
    private var setupError: String?

    // Guarded by `lock`.
    private var started = false
    private var exited = false
    private var completed = false
    private var stopReason: StopReason?
    private var terminationBegun = false
    private var groupID: pid_t = 0
    private var timeoutItem: DispatchWorkItem?
    private var killItem: DispatchWorkItem?
    private var completion: (@Sendable (CommandResult) -> Void)?
    private let killSent = DispatchSemaphore(value: 0)

    init(executable: CommandRunner.VerifiedExecutable, arguments: [String], environment: [String: String],
         workingDirectory: String, timeout: TimeInterval, grace: TimeInterval, captureLimit: Int) {
        self.executable = executable
        self.timeout = timeout
        self.grace = grace
        process.executableURL = URL(fileURLWithPath: executable.realPath, isDirectory: false)
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = URL(fileURLWithPath: workingDirectory, isDirectory: true)
        process.standardInput = FileHandle.nullDevice
        guard let out = Self.makePipe() else {
            setupError = "could not create pipes: \(String(cString: strerror(errno)))"
            return
        }
        guard let err = Self.makePipe() else {
            setupError = "could not create pipes: \(String(cString: strerror(errno)))"
            Darwin.close(out.read)
            Darwin.close(out.write)
            return
        }
        let outWrite = FileHandle(fileDescriptor: out.write, closeOnDealloc: true)
        let errWrite = FileHandle(fileDescriptor: err.write, closeOnDealloc: true)
        writeEnds = [outWrite, errWrite]
        process.standardOutput = outWrite
        process.standardError = errWrite
        stdout = OutputCollector(readEnd: out.read, limit: captureLimit)
        stderr = OutputCollector(readEnd: err.read, limit: captureLimit)
    }

    /// A pipe whose ends are close-on-exec (the child gets its own copies through `Process`), so a
    /// concurrently started command never inherits another command's pipe.
    private static func makePipe() -> (read: Int32, write: Int32)? {
        var fds: [Int32] = [-1, -1]
        guard Darwin.pipe(&fds) == 0 else { return nil }
        for fd in fds { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
        return (fds[0], fds[1])
    }

    func start(_ completion: @escaping @Sendable (CommandResult) -> Void) {
        lock.lock()
        self.completion = completion
        let cancelledEarly = stopReason == .cancel
        lock.unlock()

        guard let stdout, let stderr, setupError == nil else {
            closeWriteEnds()
            deliver(CommandRunner.failure(setupError ?? "could not set up the command"))
            return
        }
        stdout.start()
        stderr.start()
        if cancelledEarly {
            abandonBeforeLaunch(CommandResult(exitCode: -1, stdout: "", stderr: CommandRunner.cancelledMessage))
            return
        }
        // SAFETY-DECISION (review M4): the verified file must still be the same inode right before
        // the launch; anything else fails closed.
        var info = Darwin.stat()
        guard Darwin.lstat(executable.realPath, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_dev == executable.device, info.st_ino == executable.inode else {
            abandonBeforeLaunch(CommandRunner.failure("executable changed before launch"))
            return
        }

        // Strong capture on purpose: the session stays alive while the child runs; the cycle is
        // broken in `collectAndFinish`.
        process.terminationHandler = { [self] _ in
            DispatchQueue.global(qos: .utility).async { self.collectAndFinish() }
        }
        do {
            try process.run()
        } catch {
            process.terminationHandler = nil
            abandonBeforeLaunch(CommandRunner.failure("could not start \(process.executableURL?.lastPathComponent ?? "command"): \(error.localizedDescription)"))
            return
        }
        // The parent's copies of the write ends are not needed; closing them lets EOF arrive.
        closeWriteEnds()

        let pid = process.processIdentifier
        let item = DispatchWorkItem { [weak self] in self?.requestStop(.timeout) }
        lock.lock()
        started = true
        // Foundation starts the child as the leader of its own process group; signal the whole group
        // only when that is verifiably so (never our own group).
        if pid > 0, getpgid(pid) == pid, pid != getpgrp() { groupID = pid }
        let alreadyExited = exited || completed
        if !alreadyExited { timeoutItem = item }
        let pendingStop = stopReason != nil && !alreadyExited
        lock.unlock()
        if !alreadyExited { timerQueue.asyncAfter(deadline: .now() + timeout, execute: item) }
        if pendingStop { beginTermination() }
    }

    private func abandonBeforeLaunch(_ result: CommandResult) {
        closeWriteEnds()
        stdout?.finish()
        stderr?.finish()
        deliver(result)
    }

    private func closeWriteEnds() {
        for handle in writeEnds { try? handle.close() }
        writeEnds = []
    }

    /// Task cancellation (read-only probes only; see `CommandRunner.run`).
    func cancel() {
        requestStop(.cancel)
    }

    private func requestStop(_ reason: StopReason) {
        lock.lock()
        guard !completed, !exited, stopReason == nil else { lock.unlock(); return }
        stopReason = reason
        let launched = started
        lock.unlock()
        // Before the launch, `start` sees the reason and acts on it.
        if launched { beginTermination() }
    }

    /// SIGTERM to the child's process group now, SIGKILL to the group after the grace period.
    private func beginTermination() {
        lock.lock()
        guard !terminationBegun, !completed else { lock.unlock(); return }
        terminationBegun = true
        let item = DispatchWorkItem { [weak self] in self?.escalate() }
        killItem = item
        lock.unlock()
        sendSignal(SIGTERM)
        timerQueue.asyncAfter(deadline: .now() + grace, execute: item)
    }

    private func escalate() {
        sendSignal(SIGKILL)
        killSent.signal()
    }

    /// SAFETY-DECISION (review M4): signals go to the whole process group of the child (a grandchild
    /// that ignores SIGTERM is still killed), even after the direct child has exited — the group id
    /// cannot be reused while any member is alive, and nothing is sent once the result is delivered.
    /// Without a verified group, only the direct child is signalled, and only while it runs.
    private func sendSignal(_ signal: Int32) {
        lock.lock()
        let done = completed
        let group = groupID
        lock.unlock()
        guard !done else { return }
        if group > 0 {
            _ = killpg(group, signal)
        } else if process.isRunning {
            let pid = process.processIdentifier
            if pid > 0 { _ = kill(pid, signal) }
        }
    }

    /// `true` when no member of the child's process group is left.
    private func groupIsGone() -> Bool {
        lock.lock()
        let group = groupID
        lock.unlock()
        guard group > 0 else { return true }
        return killpg(group, 0) == -1 && errno == ESRCH
    }

    private func collectAndFinish() {
        process.terminationHandler = nil
        lock.lock()
        exited = true
        // The child is gone: no timeout may fire for it any more.
        timeoutItem?.cancel()
        timeoutItem = nil
        let reason = stopReason
        lock.unlock()

        if reason != nil {
            // SAFETY-DECISION (review M4): a stopped command's result is delivered only after the
            // SIGKILL went to its process group, or once no member of the group is left. (Idempotent:
            // covers a stop requested just as the child exited.)
            beginTermination()
            let deadline = Date().addingTimeInterval(grace + 2)
            while Date() < deadline {
                if killSent.wait(timeout: .now() + 0.05) == .success { break }
                if groupIsGone() { break }
            }
        }
        // A grandchild may keep a pipe open after the child exited; wait a bounded time for EOF.
        let eofDeadline = DispatchTime.now() + max(1, grace)
        if let stdout, stdout.done.wait(timeout: eofDeadline) == .timedOut { stdout.finish() }
        if let stderr, stderr.done.wait(timeout: eofDeadline) == .timedOut { stderr.finish() }

        let outputText = stdout?.text ?? ""
        var errorText = stderr?.text ?? ""
        var exitCode = process.terminationStatus
        if process.terminationReason == .uncaughtSignal {
            errorText += (errorText.isEmpty ? "" : "\n") + "terminated by signal \(exitCode)"
            exitCode = 128 + exitCode
        }
        switch reason {
        case .cancel?:
            deliver(CommandResult(exitCode: -1, stdout: outputText, stderr: CommandRunner.cancelledMessage))
        case .timeout?:
            errorText += (errorText.isEmpty ? "" : "\n") + "timed out after \(Int(timeout)) s"
            deliver(CommandResult(exitCode: exitCode, stdout: outputText, stderr: errorText, timedOut: true))
        case nil:
            deliver(CommandResult(exitCode: exitCode, stdout: outputText, stderr: errorText, timedOut: false))
        }
    }

    private func deliver(_ result: CommandResult) {
        lock.lock()
        guard !completed, let completion else { lock.unlock(); return }
        completed = true
        self.completion = nil
        // Release every pending timer (they only hold the session weakly, but need not linger).
        timeoutItem?.cancel()
        timeoutItem = nil
        killItem?.cancel()
        killItem = nil
        lock.unlock()
        completion(result)
    }
}
