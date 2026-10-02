import Darwin
import Foundation

/// File-descriptor-relative helpers shared by the mutating primitives (Quarantine, Trash, permanent
/// removal). Review M3: a path-based check followed by a path-based action leaves a window in which
/// the path can be redirected. These helpers let a caller pin the item's PARENT directory as an open
/// descriptor (reached without following any symlink) and inspect / act on the item relative to it.
enum SecureFS {
    struct Errno: Error, Sendable, Equatable {
        let code: Int32
        init(_ code: Int32) { self.code = code }
    }

    /// Opens the directory at the absolute, canonical `path` by walking from "/" one component at a
    /// time with `O_NOFOLLOW`, so no component (the last one included) may be a symlink. Returns the
    /// descriptor or the `errno` of the first failure (`ELOOP`/`ENOTDIR` for a symlink).
    static func openDirectory(_ path: String) -> Result<Int32, Errno> {
        RealHomeGuard.check(path)
        guard path.hasPrefix("/"), !path.contains("\0") else { return .failure(Errno(EINVAL)) }
        var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { return .failure(Errno(errno)) }
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            let name = String(component)
            guard name != ".", name != ".." else {
                Darwin.close(fd)
                return .failure(Errno(EINVAL))
            }
            // O_NONBLOCK: never block on a FIFO planted where a directory is expected.
            let next = Darwin.openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            let code = errno
            Darwin.close(fd)
            guard next >= 0 else { return .failure(Errno(code == 0 ? EIO : code)) }
            fd = next
        }
        return .success(fd)
    }

    /// `fstatat(dirFD, name, AT_SYMLINK_NOFOLLOW)`.
    static func lstat(at dirFD: Int32, _ name: String) -> QuarantineFS.LstatResult {
        var st = Darwin.stat()
        errno = 0
        guard Darwin.fstatat(dirFD, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else {
            let code = errno
            return code == ENOENT ? .missing : .failed(code == 0 ? EIO : code)
        }
        return .ok(QuarantineFS.Info(st))
    }

    /// `fstat(fd)`.
    static func fstat(_ fd: Int32) -> QuarantineFS.Info? {
        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else { return nil }
        return QuarantineFS.Info(st)
    }

    /// Persistent identifier of the volume holding `path` (`URLResourceKey.volumeUUIDStringKey`).
    /// Unlike `st_dev`, it does not change when the volume is mounted again.
    static func volumeUUID(_ path: String) -> String? {
        RealHomeGuard.check(path)
        guard let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeUUIDStringKey]) else { return nil }
        guard let uuid = values.volumeUUIDString, !uuid.isEmpty else { return nil }
        return uuid
    }

    /// Splits a canonical absolute path into (parent path, last component).
    static func split(_ path: String) -> (parent: String, name: String)? {
        guard case .success(let canonical) = PathCanonicalizer.clean(path, home: nil), canonical.path == path,
              let name = canonical.lastComponent, let parent = canonical.parent, !parent.components.isEmpty else {
            return nil
        }
        return (parent.path, name)
    }
}
