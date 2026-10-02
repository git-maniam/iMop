import Darwin
import Foundation

// MARK: - Event

/// One audit-log line (spec §5.5). Carries metadata only — NEVER file contents.
public struct AuditEvent: Sendable, Codable, Hashable {
    /// Upper bound for `detail` (vendor command stdout/stderr, spec §5.3).
    public static let maxDetailBytes = 64 * 1024

    public let timestamp: Date
    public let sessionID: UUID?
    public let ruleID: String?
    public let path: String?
    public let action: String
    public let bytes: Int64?
    public let verdict: String
    public let rejectionReason: String?
    public let commandExitCode: Int32?
    /// Free-form diagnostic text (e.g. command stdout/stderr), truncated to `maxDetailBytes` UTF-8 bytes.
    public let detail: String?

    public init(
        timestamp: Date,
        sessionID: UUID? = nil,
        ruleID: String? = nil,
        path: String? = nil,
        action: String,
        bytes: Int64? = nil,
        verdict: String,
        rejectionReason: String? = nil,
        commandExitCode: Int32? = nil,
        detail: String? = nil
    ) {
        self.timestamp = timestamp
        self.sessionID = sessionID
        self.ruleID = ruleID
        self.path = path
        self.action = action
        self.bytes = bytes
        self.verdict = verdict
        self.rejectionReason = rejectionReason
        self.commandExitCode = commandExitCode
        self.detail = detail.map { Self.truncated($0) }
    }

    static let truncationMarker = "\n… [truncated]"

    /// `text` cut (on a Character boundary) so that its UTF-8 encoding, marker included, fits in `limit` bytes.
    public static func truncated(_ text: String, limit: Int = maxDetailBytes) -> String {
        guard text.utf8.count > limit else { return text }
        let marker = truncationMarker
        let budget = max(0, limit - marker.utf8.count)
        var used = 0
        var end = text.startIndex
        for index in text.indices {
            let size = String(text[index]).utf8.count
            if used + size > budget { break }
            used += size
            end = text.index(after: index)
        }
        return String(text[text.startIndex..<end]) + (marker.utf8.count <= limit ? marker : "")
    }
}

// MARK: - Errors

public enum AuditLogError: Error, Sendable, Equatable {
    /// The export destination is not an absolute file URL or could not be resolved.
    case invalidDestination(String)
    /// The export destination is inside the Quarantine, iMop's own folders, or a deny-listed location.
    case destinationRefused(String)
    /// A file already exists at the export destination (never overwritten).
    case destinationExists
    /// `{HOME}/Library/Logs/iMop` is missing, a symlink, or not owned by the user.
    case logDirectoryUnavailable
    case io(String)
}

// MARK: - Audit log

/// Append-only JSONL audit log at `{HOME}/Library/Logs/iMop/audit-YYYY-MM.jsonl` (UTC month).
///
/// SAFETY-DECISION: the audit log is iMop's own bookkeeping, not a cleanup mutation, so it is written
/// even in builds without IMOP_ALLOW_MUTATION (dry runs are auditable). It writes only under
/// `{homePath}/Library/Logs/iMop`, walks there with `openat(O_NOFOLLOW)` from the home directory so a
/// symlinked directory anywhere on the way is refused, creates the folder 0700 and files 0600, and
/// opens the file with `O_APPEND|O_CREAT|O_WRONLY|O_NOFOLLOW|O_CLOEXEC`.
public actor AuditLog {
    /// Location of the log folder relative to the home directory.
    public static let relativeDirectoryComponents = ["Library", "Logs", "iMop"]

    private let environment: SafeCleanEnvironment
    private let exportWaivedSystemRoots: [String]

    /// `{homePath}/Library/Logs/iMop`.
    public nonisolated let directoryPath: String

    /// Number of events that could not be written. Logging failures never crash.
    public private(set) var failedWrites: Int = 0

    public init(environment: SafeCleanEnvironment) {
        self.init(environment: environment, exportWaivedSystemRoots: [])
    }

    /// Test-only: system deny-list entries that are ancestors of these roots are not applied to an
    /// export destination inside them (fixtures live under the deny-listed /private/var/folders).
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, exportWaivedSystemRoots: [String]) {
        self.environment = environment
        self.exportWaivedSystemRoots = exportWaivedSystemRoots
        self.directoryPath = ([environment.homePath] + Self.relativeDirectoryComponents).joined(separator: "/")
    }

    // MARK: Recording

    public func record(_ event: AuditEvent) {
        guard let line = Self.encode(event) else {
            failedWrites += 1
            return
        }
        guard let dirFD = openLogDirectory(create: true) else {
            failedWrites += 1
            return
        }
        defer { close(dirFD) }

        let name = Self.fileName(for: environment.clock.now)
        // SAFETY-DECISION: O_NONBLOCK so a FIFO planted at the log name fails (ENXIO) instead of
        // blocking the actor — and with it every Executor run — forever. O_NOFOLLOW alone does not
        // reject FIFOs. Blocking mode is restored once the file is proven to be a regular file.
        let fd = openat(dirFD, name, O_APPEND | O_CREAT | O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, mode_t(0o600))
        guard fd >= 0 else {
            failedWrites += 1
            return
        }
        defer { close(fd) }

        var st = Darwin.stat()
        // SAFETY-DECISION: only append to a regular, single-link file owned by the user; a hard link
        // planted at the log name could otherwise make us append to some other file.
        guard fstat(fd, &st) == 0,
              (st.st_mode & S_IFMT) == S_IFREG,
              st.st_nlink == 1,
              st.st_uid == environment.userID else {
            failedWrites += 1
            return
        }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0 else {
            failedWrites += 1
            return
        }
        if (st.st_mode & 0o077) != 0 { _ = fchmod(fd, mode_t(0o600)) }

        if !Self.writeAll(fd: fd, data: line) {
            failedWrites += 1
        }
    }

    // MARK: Reading

    /// Every `audit-YYYY-MM.jsonl` in the log folder, oldest month first.
    public func logFiles() -> [URL] {
        logFileNames().map { URL(fileURLWithPath: directoryPath).appendingPathComponent($0, isDirectory: false) }
    }

    /// Concatenates every audit file into `destination` (chosen by the user via NSSavePanel).
    ///
    /// SAFETY-DECISION: export writes a NEW file only (`O_CREAT|O_EXCL|O_NOFOLLOW`) — an existing file
    /// is never overwritten, so the UI must pick a fresh name. The destination may not be inside the
    /// Quarantine root, iMop's own folders, or any deny-listed location. Like `record`, export is
    /// bookkeeping and is not gated by IMOP_ALLOW_MUTATION.
    public func export(to destination: URL) throws {
        guard destination.isFileURL else { throw AuditLogError.invalidDestination("not a file URL") }
        let rawPath = destination.path
        let canonicalizer = PathCanonicalizer(environment: environment)

        let lexicalDestination: CanonicalPath
        switch canonicalizer.lexical(rawPath) {
        case .success(let path): lexicalDestination = path
        case .failure(let rejection): throw AuditLogError.invalidDestination(rejection.reason)
        }
        guard let fileName = lexicalDestination.lastComponent, let lexicalParent = lexicalDestination.parent else {
            throw AuditLogError.invalidDestination("no file name")
        }
        let resolvedParent: CanonicalPath
        switch canonicalizer.canonicalize(lexicalParent.path) {
        case .success(let path): resolvedParent = path
        case .failure(let rejection):
            if case .denyListed(let entry) = rejection { throw AuditLogError.destinationRefused(entry) }
            throw AuditLogError.invalidDestination(rejection.reason)
        }
        let resolvedDestination = resolvedParent.appending(fileName)

        try checkExportDestination(lexicalDestination)
        try checkExportDestination(resolvedDestination)

        // Gather the content first so a failure leaves no partial destination file behind.
        var content = Data()
        guard let dirFD = openLogDirectory(create: false) else {
            // Nothing logged yet: export an empty file rather than inventing content.
            guard logDirectoryIsAbsent() else { throw AuditLogError.logDirectoryUnavailable }
            return try writeNewFile(at: resolvedDestination.path, data: content)
        }
        defer { close(dirFD) }
        for name in logFileNames(dirFD: dirFD) {
            // SAFETY-DECISION: a log name that is not a regular, single-link file owned by the user (a
            // FIFO, a hard link to some other file, ...) is skipped: its content is never exported.
            guard let data = try readLogFile(dirFD: dirFD, name: name) else { continue }
            content.append(data)
            if let last = data.last, last != UInt8(ascii: "\n") { content.append(UInt8(ascii: "\n")) }
        }
        try writeNewFile(at: resolvedDestination.path, data: content)
    }

    // MARK: - Internals

    private func checkExportDestination(_ path: CanonicalPath) throws {
        let home = CanonicalPath(validatedPath: environment.homePath)
        let quarantineRoot = home.appending("Library").appending("Application Support")
            .appending("iMop").appending("Quarantine")
        if path.isInsideOrEqual(quarantineRoot) {
            throw AuditLogError.destinationRefused("~/Library/Application Support/iMop/Quarantine")
        }
        let logDirectory = Self.relativeDirectoryComponents.reduce(home) { $0.appending($1) }
        if path.isInsideOrEqual(logDirectory) {
            throw AuditLogError.destinationRefused("~/Library/Logs/iMop")
        }
        let denyList = DenyList(homeDirectory: environment.homePath, waivedSystemRoots: exportWaivedSystemRoots)
        if let entry = denyList.matchingEntry(for: path, ruleID: nil, purpose: .standard) {
            throw AuditLogError.destinationRefused(entry)
        }
    }

    private func writeNewFile(at path: String, data: Data) throws {
        RealHomeGuard.check(path)
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else {
            let code = errno
            if code == EEXIST { throw AuditLogError.destinationExists }
            throw AuditLogError.io(String(cString: strerror(code)))
        }
        defer { close(fd) }
        guard Self.writeAll(fd: fd, data: data) else {
            throw AuditLogError.io("write failed: \(String(cString: strerror(errno)))")
        }
    }

    /// The file's content, or `nil` when it is not a regular, single-link file owned by the user.
    private func readLogFile(dirFD: Int32, name: String) throws -> Data? {
        // O_NONBLOCK: opening a FIFO for reading would otherwise block until a writer appears.
        let fd = openat(dirFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            let code = errno
            if code == ELOOP { return nil } // a symlink at a log name
            throw AuditLogError.io("cannot open \(name): \(String(cString: strerror(code)))")
        }
        defer { close(fd) }
        var st = Darwin.stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_nlink == 1,
              st.st_uid == environment.userID else {
            return nil
        }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0 else {
            throw AuditLogError.io("cannot read \(name)")
        }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw AuditLogError.io("read failed: \(String(cString: strerror(errno)))")
            }
            if count == 0 { break }
            result.append(contentsOf: buffer[0..<count])
        }
        return result
    }

    private func logFileNames() -> [String] {
        guard let dirFD = openLogDirectory(create: false) else { return [] }
        defer { close(dirFD) }
        return logFileNames(dirFD: dirFD)
    }

    /// Names matching `audit-YYYY-MM.jsonl` in the already-verified directory, sorted.
    private func logFileNames(dirFD: Int32) -> [String] {
        let dupFD = dup(dirFD)
        guard dupFD >= 0 else { return [] }
        guard let dir = fdopendir(dupFD) else {
            close(dupFD)
            return []
        }
        defer { closedir(dir) }
        var names: [String] = []
        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) {
                    String(cString: $0)
                }
            }
            if Self.isLogFileName(name) { names.append(name) }
        }
        return names.sorted()
    }

    /// `true` when `{home}/Library/Logs/iMop` simply does not exist yet (nothing to export).
    private func logDirectoryIsAbsent() -> Bool {
        var st = Darwin.stat()
        return lstat(directoryPath, &st) != 0 && errno == ENOENT
    }

    /// Opens `{home}/Library/Logs/iMop` component by component with `O_NOFOLLOW`, refusing symlinks
    /// and directories not owned by the user. With `create`, missing components are created 0700.
    private func openLogDirectory(create: Bool) -> Int32? {
        let home = environment.homePath
        guard home.hasPrefix("/"), home != "/", !home.contains("\0") else { return nil }
        RealHomeGuard.check(directoryPath)

        var fd = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        for component in Self.relativeDirectoryComponents {
            var next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            if next < 0, errno == ENOENT, create {
                if mkdirat(fd, component, mode_t(0o700)) != 0, errno != EEXIST {
                    close(fd)
                    return nil
                }
                next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            }
            close(fd)
            guard next >= 0 else { return nil }
            fd = next
            var st = Darwin.stat()
            guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == environment.userID else {
                close(fd)
                return nil
            }
        }
        // The iMop folder itself is kept private (0700).
        var st = Darwin.stat()
        if fstat(fd, &st) == 0, (st.st_mode & 0o7777) != 0o700 {
            _ = fchmod(fd, mode_t(0o700))
        }
        return fd
    }

    private static func writeAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard var pointer = raw.baseAddress else { return true }
            var remaining = raw.count
            while remaining > 0 {
                let written = write(fd, pointer, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                remaining -= written
                pointer = pointer.advanced(by: written)
            }
            return true
        }
    }

    static func encode(_ event: AuditEvent) -> Data? {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard var data = try? encoder.encode(event) else { return nil }
        // JSONEncoder escapes control characters inside strings, so the object is a single line.
        data.append(UInt8(ascii: "\n"))
        return data
    }

    /// `audit-YYYY-MM.jsonl` for the UTC month containing `date`.
    static func fileName(for date: Date) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0)!
        let parts = calendar.dateComponents([.year, .month], from: date)
        let year = parts.year ?? 1970
        let month = parts.month ?? 1
        return String(format: "audit-%04d-%02d.jsonl", year, month)
    }

    static func isLogFileName(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        // "audit-" + 4 digits + "-" + 2 digits + ".jsonl"
        guard bytes.count == 6 + 4 + 1 + 2 + 6, name.hasPrefix("audit-"), name.hasSuffix(".jsonl") else { return false }
        let digits = Array(bytes[6..<10]) + Array(bytes[11..<13])
        return bytes[10] == UInt8(ascii: "-") && digits.allSatisfy { $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }
    }
}
