import Darwin
import Foundation
import iMopCore

/// Creates a throw-away fixture tree under
/// `FileManager.default.temporaryDirectory/iMopTests-<UUID>/` with a fake home at `<root>/home`.
///
/// Both `root` and `home` are `realpath`-resolved, i.e. the `/private/var/folders/...` form, so
/// they compare equal to what the canonicalizer produces.
///
/// Relative paths passed to the helpers are relative to the fake home unless `base: .root` is given.
/// Helpers that create things refuse absolute paths and `..` components, so a fixture can never be
/// written outside its root.
final class FixtureBuilder: Sendable {
    enum Base: Sendable { case home, root }

    let root: String
    let home: String

    init() throws {
        RealHomeTripwire.install()
        let tmp = FileManager.default.temporaryDirectory.path
        guard let resolvedTmp = Self.realpath(tmp) else { throw TestError("cannot resolve temporary directory \(tmp)") }
        let rootPath = resolvedTmp + "/iMopTests-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: rootPath + "/home", withIntermediateDirectories: true)
        guard let resolvedRoot = Self.realpath(rootPath) else { throw TestError("cannot resolve fixture root \(rootPath)") }
        root = resolvedRoot
        home = resolvedRoot + "/home"
        guard !RealHomeTripwire.isInsideRealHome(home) else {
            throw TestError("fixture home \(home) is inside the real home directory")
        }
    }

    // MARK: Paths

    /// Absolute path for `rel` (string join only; nothing is checked or created).
    func path(_ rel: String, base: Base = .home) -> String {
        let prefix = base == .home ? home : root
        let trimmed = rel.hasPrefix("/") ? String(rel.dropFirst()) : rel
        return trimmed.isEmpty ? prefix : prefix + "/" + trimmed
    }

    // MARK: Creation

    /// Creates the directory (and intermediates). Returns its absolute path.
    @discardableResult
    func dir(_ rel: String, base: Base = .home) throws -> String {
        let target = try checkedPath(rel, base: base)
        try FileManager.default.createDirectory(atPath: target, withIntermediateDirectories: true)
        return target
    }

    /// Creates a regular file of `bytes` bytes (parents created as needed). Returns its absolute path.
    @discardableResult
    func file(_ rel: String, bytes: Int = 0, base: Base = .home) throws -> String {
        let target = try checkedPath(rel, base: base)
        try FileManager.default.createDirectory(
            atPath: (target as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        guard FileManager.default.createFile(atPath: target, contents: Data(repeating: 0x61, count: max(0, bytes))) else {
            throw TestError("could not create fixture file \(target)")
        }
        return target
    }

    /// Creates a regular file with the given contents.
    @discardableResult
    func file(_ rel: String, contents: Data, base: Base = .home) throws -> String {
        let target = try checkedPath(rel, base: base)
        try FileManager.default.createDirectory(
            atPath: (target as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        guard FileManager.default.createFile(atPath: target, contents: contents) else {
            throw TestError("could not create fixture file \(target)")
        }
        return target
    }

    /// Creates a symbolic link at `rel` whose destination is `destination`, verbatim (absolute or
    /// relative). The destination is never created or touched. Returns the link's absolute path.
    @discardableResult
    func symlink(_ rel: String, to destination: String, base: Base = .home) throws -> String {
        let target = try checkedPath(rel, base: base)
        try FileManager.default.createDirectory(
            atPath: (target as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: target, withDestinationPath: destination)
        return target
    }

    /// Sets the modification time of `rel` (not following a final symlink) to `clock.now - daysAgo`.
    func setModificationDate(_ rel: String, daysAgo: Double, clock: any iMopCore.Clock, base: Base = .home) throws {
        let target = try checkedPath(rel, base: base)
        try setModificationDate(atPath: target, to: clock.now.addingTimeInterval(-daysAgo * 86_400))
    }

    func setModificationDate(_ rel: String, daysAgo: Int, clock: any iMopCore.Clock, base: Base = .home) throws {
        try setModificationDate(rel, daysAgo: Double(daysAgo), clock: clock, base: base)
    }

    /// Sets an extended attribute on a fixture item (not following a final symlink).
    func setExtendedAttribute(_ name: String, value: String = "1", on rel: String, base: Base = .home) throws {
        let target = try checkedPath(rel, base: base)
        let data = Array(value.utf8)
        let status = data.withUnsafeBytes { raw in
            setxattr(target, name, raw.baseAddress, raw.count, 0, XATTR_NOFOLLOW)
        }
        guard status == 0 else { throw TestError("setxattr \(name) on \(target) failed: errno \(errno)") }
    }

    /// Removes the whole fixture tree. Refuses anything that is not an `iMopTests-*` directory
    /// directly inside the temporary directory.
    func cleanup() {
        guard let resolvedTmp = Self.realpath(FileManager.default.temporaryDirectory.path) else { return }
        let parent = (root as NSString).deletingLastPathComponent
        let name = (root as NSString).lastPathComponent
        guard parent == resolvedTmp, name.hasPrefix("iMopTests-"), name.count > "iMopTests-".count,
              !RealHomeTripwire.isInsideRealHome(root) else {
            print("  [FixtureBuilder] refusing to clean up unexpected path \(root)")
            return
        }
        makeOwnerWritable(root)
        try? FileManager.default.removeItem(atPath: root)
    }

    // MARK: Private

    private func checkedPath(_ rel: String, base: Base) throws -> String {
        guard !rel.hasPrefix("/") else { throw TestError("fixture paths must be relative: \(rel)") }
        let parts = rel.split(separator: "/", omittingEmptySubsequences: true)
        guard !parts.contains("..") else { throw TestError("fixture paths must not contain '..': \(rel)") }
        return path(rel, base: base)
    }

    private func setModificationDate(atPath target: String, to date: Date) throws {
        let seconds = date.timeIntervalSince1970
        let whole = floor(seconds)
        var times = [
            timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)), // atime: leave untouched
            timespec(tv_sec: Int(whole), tv_nsec: Int((seconds - whole) * 1_000_000_000)),
        ]
        guard utimensat(AT_FDCWD, target, &times, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw TestError("utimensat on \(target) failed: errno \(errno)")
        }
    }

    /// Tests may chmod fixture directories read-only; restore u+w (directories only, no symlink
    /// following) so the tree can be removed.
    private func makeOwnerWritable(_ top: String) {
        var st = Darwin.stat()
        guard lstat(top, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return }
        _ = chmod(top, st.st_mode | S_IRWXU)
        guard let children = try? FileManager.default.contentsOfDirectory(atPath: top) else { return }
        for child in children { makeOwnerWritable(top + "/" + child) }
    }

    static func realpath(_ path: String) -> String? {
        guard let resolved = Darwin.realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}

/// Spec §12: the test run aborts if any code path resolves a path inside the real home directory.
/// Installed automatically by `FixtureBuilder.init`; safe to call repeatedly.
enum RealHomeTripwire {
    /// Normalized component lists of every spelling of the real home directory.
    static let realHomes: [[String]] = {
        var candidates: [String] = [NSHomeDirectory(), FileManager.default.homeDirectoryForCurrentUser.path]
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            candidates.append(String(cString: dir))
        }
        candidates += candidates.compactMap { FixtureBuilder.realpath($0) }
        var result: [[String]] = []
        for candidate in candidates {
            let parts = logicalComponents(candidate)
            // Never treat "/" (or a non-absolute value) as the home: that would trip on everything.
            if !parts.isEmpty, candidate.hasPrefix("/"), !result.contains(parts) { result.append(parts) }
        }
        return result
    }()

    static func install() {
        _ = realHomes
        RealHomeGuard.install { path in
            if RealHomeTripwire.isInsideRealHome(path) {
                FileHandle.standardError.write(Data("\nRealHomeGuard: ABORTING — path inside the real home directory: \(path)\n".utf8))
                fflush(stdout)
                fatalError("RealHomeGuard: test code resolved a path inside the real home directory: \(path)")
            }
        }
    }

    static func isInsideRealHome(_ path: String) -> Bool {
        var expanded = path.hasPrefix("~") ? NSHomeDirectory() + path.dropFirst() : path
        // A relative path resolves against the working directory (the repo, inside the real home).
        if !expanded.hasPrefix("/") {
            expanded = FileManager.default.currentDirectoryPath + "/" + expanded
        }
        // ".." cannot be resolved lexically (symlinks), so any path containing it is a violation.
        if expanded.split(separator: "/", omittingEmptySubsequences: true).contains("..") { return true }
        let parts = logicalComponents(expanded)
        return realHomes.contains { home in parts.count >= home.count && Array(parts.prefix(home.count)) == home }
    }

    /// Lexical, normalized components with firmlink and /private mapping (mirrors the canonicalizer).
    static func logicalComponents(_ path: String) -> [String] {
        var parts = path.split(separator: "/", omittingEmptySubsequences: true)
            .map { $0.precomposedStringWithCanonicalMapping.lowercased() }
            .filter { $0 != "." }
        if parts.count >= 3, parts[0] == "system", parts[1] == "volumes", parts[2] == "data" {
            parts.removeFirst(3)
        }
        if let first = parts.first, ["var", "tmp", "etc"].contains(first) { parts.insert("private", at: 0) }
        return parts
    }
}
