import Darwin
import Foundation

// Spec §7.1 / §7.2 — read-only sizing.
//
// This file must stay strictly read-only: the only system calls it makes are
// getattrlist(2), getattrlistbulk(2), open(2)/openat(2) with O_RDONLY, fstat(2) and close(2).

/// Size of one target as it would be reported to the user ("Estimated reclaimable: X (Y on disk)").
public struct SizeEstimate: Sendable, Hashable {
    /// Bytes allocated on disk (`ATTR_FILE_ALLOCSIZE`), each inode counted once. Never logical size.
    public let allocatedBytes: Int64
    /// Bytes that would actually be freed: APFS private size (clone/snapshot-shared blocks excluded),
    /// hard-linked files excluded unless every link is inside the measured tree.
    public let reclaimableBytes: Int64
    /// Number of file-system objects measured. For a directory root this is every object *below*
    /// the root (files, directories, symlinks, others); for a non-directory root it is 1.
    public let itemCount: Int
    /// Newest `ATTR_CMN_MODTIME` seen (root included).
    public let newestModification: Date?
    /// Allocated bytes of hard-linked files that are *not* counted as reclaimable because at least
    /// one link lives outside the measured tree (or the link count could not be read).
    public let hardLinkedBytesExcluded: Int64
    /// Directories not descended into because they are mount points / on a different device.
    public let crossedMountPointsSkipped: Int
    /// `false` when the walk was cancelled or any part of the tree could not be read; the numbers
    /// are then a lower bound.
    public let complete: Bool
    /// Deny-list label (`".git"`, `".photoslibrary"`, …) of the first entry found BELOW the measured
    /// root whose name is protected by spec §3.5 ("any git repository's .git directory", "any path
    /// with extension …"). `nil` when none was seen (in the part of the tree that could be read).
    public let protectedDescendantEntry: String?

    /// `true` when an entry below the root carries a deny-listed name (see `protectedDescendantEntry`).
    public var containsProtectedDescendant: Bool { protectedDescendantEntry != nil }

    public init(
        allocatedBytes: Int64,
        reclaimableBytes: Int64,
        itemCount: Int,
        newestModification: Date?,
        hardLinkedBytesExcluded: Int64,
        crossedMountPointsSkipped: Int,
        complete: Bool,
        protectedDescendantEntry: String? = nil
    ) {
        self.allocatedBytes = allocatedBytes
        self.reclaimableBytes = reclaimableBytes
        self.itemCount = itemCount
        self.newestModification = newestModification
        self.hardLinkedBytesExcluded = hardLinkedBytesExcluded
        self.crossedMountPointsSkipped = crossedMountPointsSkipped
        self.complete = complete
        self.protectedDescendantEntry = protectedDescendantEntry
    }
}

/// Measures allocated and reclaimable bytes of a file or directory tree with `getattrlistbulk(2)`.
///
/// Never follows symlinks, never crosses onto another device, never recurses (explicit stack),
/// bounded number of simultaneously open descriptors, honours `Task.isCancelled`.
public struct SizeCalculator: Sendable {
    private let environment: SafeCleanEnvironment

    /// Maximum directory descriptors held open at once (root included). Deeper levels are closed
    /// and re-opened on demand (identity re-verified), so very deep trees cannot exhaust the
    /// process descriptor table.
    private static let maxOpenDirectoryDescriptors = 32
    /// Size of the getattrlistbulk buffer.
    private static let bulkBufferSize = 128 * 1024

    public init(environment: SafeCleanEnvironment) {
        self.environment = environment
    }

    /// Measures `path`. Returns `nil` when the root itself cannot be examined or opened, or when
    /// `path` is not an absolute path in normal form.
    ///
    /// SAFETY-DECISION (review M2): symlinks are never followed at ANY level of `path`:
    /// - a path that is not in normal form (trailing "/", "." / ".." / empty components, or "/"
    ///   itself) is refused, because POSIX resolves a final symlink for "link/" and "link/.";
    /// - the root's PARENT directory is opened with `O_NOFOLLOW_ANY`, so a symlink in any ancestor
    ///   component (/tmp, /var, or a link swapped in after canonicalization) makes the measurement
    ///   fail (`nil`) instead of measuring the link's destination;
    /// - the root itself is examined relative to that descriptor with getattrlistat(FSOPT_NOFOLLOW)
    ///   and opened with openat(O_NOFOLLOW): a symlink root is measured as itself (1 item, 0 bytes);
    /// - the real-home guard sees both the input and where the opened directories really are
    ///   (F_GETPATH).
    public func measure(path: String) -> SizeEstimate? {
        // Refused before anything else (no system call, no guard lookup) when not in normal form.
        guard Self.isNormalAbsolutePath(path) else { return nil }
        RealHomeGuard.check(path)
        let parts = path.dropFirst().split(separator: "/").map(String.init)
        guard let last = parts.last else { return nil }
        let parentPath = "/" + parts.dropLast().joined(separator: "/")
        guard let parentFD = Self.openAncestor(path: parentPath) else { return nil }
        defer { _ = Darwin.close(parentFD) }
        if let opened = Self.openedPath(parentFD) {
            RealHomeGuard.check(opened == "/" ? "/" + last : opened + "/" + last)
        }
        let rootName = Array(last.utf8CString)
        guard let root = Self.attributes(of: rootName, in: parentFD) else { return nil }
        guard let rootType = root.objectType else { return nil }

        var walk = SizingWalk()
        walk.noteModification(root.modificationDate)

        if rootType != SizingVnodeType.directory {
            // Single object (regular file, symlink, or anything that is not a directory).
            walk.itemCount = 1
            walk.account(entry: root)
            return walk.finish()
        }

        let rootFD = Self.openDirectory(at: parentFD, name: rootName)
        guard rootFD >= 0 else { return nil }
        if let opened = Self.openedPath(rootFD) {
            RealHomeGuard.check(opened)
        }
        var stack: [SizingFrame] = []
        defer {
            for frame in stack where frame.fd >= 0 { _ = Darwin.close(frame.fd) }
        }

        var rootStat = Darwin.stat()
        guard Self.retryingFstat(rootFD, &rootStat), (rootStat.st_mode & S_IFMT) == S_IFDIR else {
            _ = Darwin.close(rootFD)
            return nil
        }
        // SAFETY-DECISION: the directory we opened must be the very object getattrlist described;
        // if it was swapped in between we refuse to measure rather than report someone else's tree.
        if let expected = root.fileID, UInt64(rootStat.st_ino) != expected {
            _ = Darwin.close(rootFD)
            return nil
        }
        let rootDevice = rootStat.st_dev
        walk.visitedDirectories.insert(SizingLinkKey(device: Int64(rootDevice), fileID: UInt64(rootStat.st_ino)))

        let buffer = UnsafeMutableRawPointer.allocate(byteCount: Self.bulkBufferSize, alignment: 8)
        defer { buffer.deallocate() }

        stack.append(SizingFrame(fd: rootFD, name: [], inode: UInt64(rootStat.st_ino), pending: []))
        guard let rootChildren = Self.enumerate(fd: rootFD, buffer: buffer, walk: &walk) else {
            walk.complete = false
            return walk.finish()
        }
        stack[0].pending = rootChildren

        while !stack.isEmpty {
            if Task.isCancelled {
                walk.complete = false
                break
            }
            let top = stack.count - 1
            guard let child = stack[top].pending.popLast() else {
                let finished = stack.removeLast()
                if finished.fd >= 0 { _ = Darwin.close(finished.fd) }
                continue
            }
            if stack[top].fd < 0 && !Self.reopen(frameAt: top, in: &stack, device: rootDevice) {
                // Could not get back into this directory safely: give up on its remaining children.
                walk.complete = false
                stack[top].pending.removeAll()
                continue
            }

            let childFD = Self.openDirectory(at: stack[top].fd, name: child.name)
            guard childFD >= 0 else {
                // EACCES, ENOENT/ENOTDIR/ELOOP (changed since enumeration), EMFILE, …
                walk.complete = false
                continue
            }
            var st = Darwin.stat()
            guard Self.retryingFstat(childFD, &st), (st.st_mode & S_IFMT) == S_IFDIR else {
                _ = Darwin.close(childFD)
                walk.complete = false
                continue
            }
            if st.st_dev != rootDevice {
                // A mount point (or firmlink onto another volume) not flagged by ATTR_DIR_MOUNTSTATUS.
                _ = Darwin.close(childFD)
                walk.crossedMountPointsSkipped += 1
                continue
            }
            if UInt64(st.st_ino) != child.fileID {
                // Replaced between enumeration and open: do not measure an unknown object.
                _ = Darwin.close(childFD)
                walk.complete = false
                continue
            }
            let key = SizingLinkKey(device: Int64(st.st_dev), fileID: UInt64(st.st_ino))
            guard walk.visitedDirectories.insert(key).inserted else {
                // Directory hard link / loop: already measured.
                _ = Darwin.close(childFD)
                continue
            }
            guard let grandChildren = Self.enumerate(fd: childFD, buffer: buffer, walk: &walk) else {
                _ = Darwin.close(childFD)
                walk.complete = false
                continue
            }
            if grandChildren.isEmpty {
                _ = Darwin.close(childFD)
                continue
            }
            stack.append(SizingFrame(fd: childFD, name: child.name, inode: UInt64(st.st_ino), pending: grandChildren))
            Self.enforceDescriptorLimit(&stack)
        }

        return walk.finish()
    }

    /// Absolute, non-root, and already in normal form: no empty, "." or ".." component, no trailing
    /// "/", no NUL.
    static func isNormalAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), path.count > 1, !path.contains("\0") else { return false }
        let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        return components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    /// Spec §3.5 deny-list label carried by an entry NAME (normalized), or nil.
    static func protectedNameLabel(_ name: String) -> String? {
        let normalized = PathComparison.normalize(name)
        if normalized == ".git" { return ".git" }
        for ext in DenyList.protectedExtensions where normalized.hasSuffix("." + ext) {
            return "." + ext
        }
        return nil
    }
}

// MARK: - Internals

/// `enum vtype` values from <sys/vnode.h>.
private enum SizingVnodeType {
    static let regular: UInt32 = 1
    static let directory: UInt32 = 2
    static let symlink: UInt32 = 5
}

/// Attribute bit masks from <sys/attr.h>, as `attrgroup_t`.
private enum SizingAttrBit {
    static let cmnName = attrgroup_t(truncatingIfNeeded: ATTR_CMN_NAME)
    static let cmnDevID = attrgroup_t(truncatingIfNeeded: ATTR_CMN_DEVID)
    static let cmnObjType = attrgroup_t(truncatingIfNeeded: ATTR_CMN_OBJTYPE)
    static let cmnModTime = attrgroup_t(truncatingIfNeeded: ATTR_CMN_MODTIME)
    static let cmnFileID = attrgroup_t(truncatingIfNeeded: ATTR_CMN_FILEID)
    static let cmnFlags = attrgroup_t(truncatingIfNeeded: ATTR_CMN_FLAGS)
    static let cmnError = attrgroup_t(truncatingIfNeeded: ATTR_CMN_ERROR)
    static let cmnReturnedAttrs = attrgroup_t(truncatingIfNeeded: ATTR_CMN_RETURNED_ATTRS)
    static let dirMountStatus = attrgroup_t(truncatingIfNeeded: ATTR_DIR_MOUNTSTATUS)
    static let fileLinkCount = attrgroup_t(truncatingIfNeeded: ATTR_FILE_LINKCOUNT)
    static let fileAllocSize = attrgroup_t(truncatingIfNeeded: ATTR_FILE_ALLOCSIZE)
    static let cmnextPrivateSize = attrgroup_t(truncatingIfNeeded: ATTR_CMNEXT_PRIVATESIZE)
    static let cmnextExtFlags = attrgroup_t(truncatingIfNeeded: ATTR_CMNEXT_EXT_FLAGS)
    /// `UF_COMPRESSED` (decmpfs-compressed file) from <sys/stat.h>.
    static let compressedFlag = UInt32(truncatingIfNeeded: UF_COMPRESSED)
    /// `EF_MAY_SHARE_BLOCKS` from <sys/attr.h>: the file may share blocks with another file (clone).
    static let mayShareBlocks: UInt64 = 0x0000_0001
    static let mountPointFlag = UInt32(truncatingIfNeeded: DIR_MNTSTATUS_MNTPOINT)
}

/// (device, file id) — hard links and directory loops are detected with this key.
private struct SizingLinkKey: Hashable {
    let device: Int64
    let fileID: UInt64
}

/// Attributes of one object as parsed from a getattrlist / getattrlistbulk record.
/// `nil` fields were not returned (invalid for the object or the file system).
private struct SizingAttributes {
    var name: [CChar]?
    var error: UInt32 = 0
    var device: Int32?
    var objectType: UInt32?
    var modificationDate: Date?
    /// `ATTR_CMN_FLAGS` (st_flags).
    var flags: UInt32?
    var fileID: UInt64?
    var mountStatus: UInt32?
    var linkCount: UInt32?
    var allocatedSize: Int64?
    var privateSize: Int64?
    /// `ATTR_CMNEXT_EXT_FLAGS` (EF_* bits).
    var extendedFlags: UInt64?
}

private struct SizingPendingDirectory {
    /// NUL-terminated entry name exactly as returned by the file system (no re-encoding).
    let name: [CChar]
    let fileID: UInt64
}

private struct SizingFrame {
    /// Open directory descriptor, or -1 while temporarily closed by the descriptor limit.
    var fd: Int32
    /// NUL-terminated name relative to the parent frame (empty for the root).
    let name: [CChar]
    let inode: UInt64
    var pending: [SizingPendingDirectory]
}

private struct SizingLinkRecord {
    var linkCount: UInt32
    var occurrences: UInt32
    var allocated: Int64
    var reclaimable: Int64
}

private struct SizingWalk {
    var allocated: Int64 = 0
    var reclaimable: Int64 = 0
    var itemCount = 0
    var newest: Date?
    var hardLinkedExcluded: Int64 = 0
    var crossedMountPointsSkipped = 0
    var complete = true
    var links: [SizingLinkKey: SizingLinkRecord] = [:]
    var visitedDirectories: Set<SizingLinkKey> = []
    var protectedDescendant: String?

    mutating func noteModification(_ date: Date?) {
        guard let date else { return }
        if let current = newest, current >= date { return }
        newest = date
    }

    /// Accounts the bytes of a non-directory object.
    mutating func account(entry: SizingAttributes) {
        if entry.objectType == SizingVnodeType.symlink {
            return // Symlinks are items with 0 bytes; never follow them.
        }
        guard let rawAllocated = entry.allocatedSize else {
            // Not reported for this object: count nothing, but say the number is a lower bound.
            complete = false
            return
        }
        let allocatedBytes = max(0, rawAllocated)
        // SAFETY-DECISION: per-file private size under-reports when two clones of the same blocks are
        // both inside the tree (deleting both would free the shared blocks). We accept that: the
        // estimate must never promise more than is freed (spec §7.1, "accuracy is part of honesty").
        // SAFETY-DECISION: private size is clamped to [0, allocated] so a file system quirk can
        // never make us promise more than is on disk. Fallback to allocated only when the private
        // size attribute is not available (non-APFS volumes).
        // SAFETY-DECISION (review M2): APFS reports a private size of 0 for decmpfs-compressed files
        // (UF_COMPRESSED) even when they share no blocks with anything. Only when the file system
        // positively says the file cannot share blocks (EXT_FLAGS returned with EF_MAY_SHARE_BLOCKS
        // clear) is the private size treated as unavailable and the allocated size used instead
        // (still subject to the hard-link rules below). If the may-share bit is set, or the flags
        // were not returned, the private size stands: never promise more than is freed.
        let privateSizeUsable: Bool = {
            guard entry.privateSize != nil else { return false }
            if let flags = entry.flags, flags & SizingAttrBit.compressedFlag != 0,
               let ext = entry.extendedFlags, ext & SizingAttrBit.mayShareBlocks == 0 {
                return false
            }
            return true
        }()
        let reclaimableBytes: Int64
        if privateSizeUsable, let rawPrivate = entry.privateSize {
            reclaimableBytes = min(max(0, rawPrivate), allocatedBytes)
        } else {
            reclaimableBytes = allocatedBytes
        }

        guard let linkCount = entry.linkCount else {
            // SAFETY-DECISION: unknown link count → assume it may be hard-linked elsewhere:
            // on disk, but not reclaimable.
            allocated = Self.add(allocated, allocatedBytes)
            hardLinkedExcluded = Self.add(hardLinkedExcluded, allocatedBytes)
            complete = false
            return
        }
        if linkCount <= 1 {
            allocated = Self.add(allocated, allocatedBytes)
            reclaimable = Self.add(reclaimable, reclaimableBytes)
            return
        }
        guard let fileID = entry.fileID, let device = entry.device else {
            // SAFETY-DECISION: a hard-linked file we cannot identify cannot be proven to have all
            // its links inside the tree → not reclaimable.
            allocated = Self.add(allocated, allocatedBytes)
            hardLinkedExcluded = Self.add(hardLinkedExcluded, allocatedBytes)
            complete = false
            return
        }
        let key = SizingLinkKey(device: Int64(device), fileID: fileID)
        if var record = links[key] {
            record.occurrences &+= 1
            record.linkCount = max(record.linkCount, linkCount)
            record.allocated = max(record.allocated, allocatedBytes)
            record.reclaimable = min(record.reclaimable, reclaimableBytes)
            links[key] = record
        } else {
            links[key] = SizingLinkRecord(linkCount: linkCount, occurrences: 1, allocated: allocatedBytes, reclaimable: reclaimableBytes)
        }
    }

    mutating func finish() -> SizeEstimate {
        for record in links.values {
            // Each inode is on disk once, however many of its links we saw.
            allocated = Self.add(allocated, record.allocated)
            if record.occurrences >= record.linkCount {
                reclaimable = Self.add(reclaimable, record.reclaimable)
            } else {
                hardLinkedExcluded = Self.add(hardLinkedExcluded, record.allocated)
            }
        }
        links.removeAll()
        return SizeEstimate(
            allocatedBytes: allocated,
            reclaimableBytes: min(reclaimable, allocated),
            itemCount: itemCount,
            newestModification: newest,
            hardLinkedBytesExcluded: hardLinkedExcluded,
            crossedMountPointsSkipped: crossedMountPointsSkipped,
            complete: complete,
            protectedDescendantEntry: protectedDescendant
        )
    }

    private static func add(_ a: Int64, _ b: Int64) -> Int64 {
        let (sum, overflow) = a.addingReportingOverflow(b)
        return overflow ? Int64.max : sum
    }
}

extension SizeCalculator {
    // MARK: Attribute requests

    /// Attributes requested for every object. FSOPT_PACK_INVAL_ATTRS is deliberately NOT used: per
    /// getattrlist(2) only attributes whose bit is set in the returned attribute_set_t are packed,
    /// which makes the record self-describing (the getattrlistbulk(2) man page sample relies on this).
    private static func makeAttrList(bulk: Bool) -> attrlist {
        var list = attrlist()
        list.bitmapcount = u_short(ATTR_BIT_MAP_COUNT)
        list.reserved = 0
        var common = SizingAttrBit.cmnReturnedAttrs | SizingAttrBit.cmnDevID | SizingAttrBit.cmnObjType
            | SizingAttrBit.cmnModTime | SizingAttrBit.cmnFlags | SizingAttrBit.cmnFileID
        if bulk {
            common |= SizingAttrBit.cmnName | SizingAttrBit.cmnError
        }
        list.commonattr = common
        list.volattr = 0
        list.dirattr = bulk ? SizingAttrBit.dirMountStatus : 0
        list.fileattr = SizingAttrBit.fileLinkCount | SizingAttrBit.fileAllocSize
        // With FSOPT_ATTR_CMN_EXTENDED, forkattr carries the ATTR_CMNEXT_* bits.
        list.forkattr = SizingAttrBit.cmnextPrivateSize | SizingAttrBit.cmnextExtFlags
        return list
    }

    private static var bulkOptions: UInt64 { UInt64(FSOPT_ATTR_CMN_EXTENDED) }
    /// The root is a single name relative to its (no-follow-opened) parent; FSOPT_NOFOLLOW keeps a
    /// final symlink from being followed.
    private static var singleOptions: UInt32 { UInt32(FSOPT_NOFOLLOW) | UInt32(FSOPT_ATTR_CMN_EXTENDED) }

    /// getattrlistat(2) on `name` inside `parentFD` itself (never following a final symlink).
    private static func attributes(of name: [CChar], in parentFD: Int32) -> SizingAttributes? {
        var list = makeAttrList(bulk: false)
        let size = 512
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
        defer { buffer.deallocate() }
        var attempts = 0
        while true {
            let rc = name.withUnsafeBufferPointer { getattrlistat(parentFD, $0.baseAddress!, &list, buffer, size, UInt(singleOptions)) }
            if rc == 0 { break }
            if errno == EINTR && attempts < 64 { attempts += 1; continue }
            return nil
        }
        let reported = Int(buffer.loadUnaligned(as: UInt32.self))
        guard reported >= 4 + MemoryLayout<attribute_set_t>.size, reported <= size else { return nil }
        let raw = UnsafeRawBufferPointer(start: UnsafeRawPointer(buffer), count: size)
        return parseRecord(raw, start: 0, length: reported, expectName: false)
    }

    // MARK: Record parsing (bounds-checked)

    /// Parses one record that starts with its uint32_t length at `start`. Returns `nil` when the
    /// record is malformed (any read would leave `[start, start+length)`).
    private static func parseRecord(_ buffer: UnsafeRawBufferPointer, start: Int, length: Int, expectName: Bool) -> SizingAttributes? {
        guard start >= 0, length >= 4, start <= buffer.count, length <= buffer.count - start,
              let base = buffer.baseAddress else { return nil }
        var cursor = Cursor(base: base, offset: start + 4, end: start + length)
        guard let returnedCommon: UInt32 = cursor.read(),
              let _: UInt32 = cursor.read(),            // volattr
              let returnedDir: UInt32 = cursor.read(),
              let returnedFile: UInt32 = cursor.read(),
              let returnedFork: UInt32 = cursor.read() else { return nil }

        var result = SizingAttributes()
        // ATTR_CMN_ERROR is packed immediately after ATTR_CMN_RETURNED_ATTRS (getattrlistbulk(2)).
        if returnedCommon & SizingAttrBit.cmnError != 0 {
            guard let error: UInt32 = cursor.read() else { return nil }
            result.error = error
        }
        if returnedCommon & SizingAttrBit.cmnName != 0 {
            let referenceOffset = cursor.offset
            guard let dataOffset: Int32 = cursor.read(), let dataLength: UInt32 = cursor.read() else { return nil }
            result.name = readName(base: base, referenceOffset: referenceOffset, dataOffset: Int(dataOffset),
                                   dataLength: Int(dataLength), recordStart: start, recordEnd: start + length)
            if result.name == nil { return nil }
        } else if expectName {
            return result // no name: caller treats as unusable
        }
        if returnedCommon & SizingAttrBit.cmnDevID != 0 {
            guard let dev: Int32 = cursor.read() else { return nil }
            result.device = dev
        }
        if returnedCommon & SizingAttrBit.cmnObjType != 0 {
            guard let type: UInt32 = cursor.read() else { return nil }
            result.objectType = type
        }
        if returnedCommon & SizingAttrBit.cmnModTime != 0 {
            // struct timespec: two 64-bit fields, 4-byte aligned in the buffer.
            guard let seconds: Int64 = cursor.read(), let nanoseconds: Int64 = cursor.read() else { return nil }
            result.modificationDate = Date(timeIntervalSince1970: Double(seconds) + Double(nanoseconds) / 1_000_000_000)
        }
        // Packed in attribute bit order: ATTR_CMN_FLAGS (0x40000) comes before ATTR_CMN_FILEID.
        if returnedCommon & SizingAttrBit.cmnFlags != 0 {
            guard let flags: UInt32 = cursor.read() else { return nil }
            result.flags = flags
        }
        if returnedCommon & SizingAttrBit.cmnFileID != 0 {
            guard let fileID: UInt64 = cursor.read() else { return nil }
            result.fileID = fileID
        }
        if returnedDir & SizingAttrBit.dirMountStatus != 0 {
            guard let status: UInt32 = cursor.read() else { return nil }
            result.mountStatus = status
        }
        if returnedFile & SizingAttrBit.fileLinkCount != 0 {
            guard let links: UInt32 = cursor.read() else { return nil }
            result.linkCount = links
        }
        if returnedFile & SizingAttrBit.fileAllocSize != 0 {
            guard let allocated: Int64 = cursor.read() else { return nil }
            result.allocatedSize = allocated
        }
        if returnedFork & SizingAttrBit.cmnextPrivateSize != 0 {
            guard let privateSize: Int64 = cursor.read() else { return nil }
            result.privateSize = privateSize
        }
        // ATTR_CMNEXT_EXT_FLAGS (0x200) is packed after ATTR_CMNEXT_PRIVATESIZE (0x8).
        if returnedFork & SizingAttrBit.cmnextExtFlags != 0 {
            guard let extFlags: UInt64 = cursor.read() else { return nil }
            result.extendedFlags = extFlags
        }
        return result
    }

    /// Validates an attrreference_t name: data must lie inside the record, be NUL-terminated,
    /// non-empty, contain no "/" or interior NUL, and not be "." or "..".
    private static func readName(base: UnsafeRawPointer, referenceOffset: Int, dataOffset: Int, dataLength: Int,
                                 recordStart: Int, recordEnd: Int) -> [CChar]? {
        let (nameStart, overflow) = referenceOffset.addingReportingOverflow(dataOffset)
        guard !overflow, nameStart >= recordStart, dataLength >= 2, dataLength <= 4096,
              nameStart <= recordEnd, dataLength <= recordEnd - nameStart else { return nil }
        let bytes = UnsafeRawBufferPointer(start: base + nameStart, count: dataLength)
        guard bytes[dataLength - 1] == 0 else { return nil }
        let body = bytes[0..<(dataLength - 1)]
        guard !body.contains(0), !body.contains(UInt8(ascii: "/")) else { return nil }
        if body.count == 1 && body.first == UInt8(ascii: ".") { return nil }
        if body.count == 2 && body.allSatisfy({ $0 == UInt8(ascii: ".") }) { return nil }
        return bytes.map { CChar(bitPattern: $0) }
    }

    private struct Cursor {
        let base: UnsafeRawPointer
        var offset: Int
        let end: Int

        /// Reads a fixed-size value and advances by its size rounded up to 4 bytes
        /// (getattrlist(2): every attribute is 4-byte aligned, including 64-bit types).
        mutating func read<T: FixedWidthInteger>() -> T? {
            let size = MemoryLayout<T>.size
            guard offset >= 0, offset <= end, size <= end - offset else { return nil }
            let value = base.loadUnaligned(fromByteOffset: offset, as: T.self)
            offset += (size + 3) & ~3
            return value
        }
    }

    // MARK: Enumeration

    /// Enumerates one directory, accounting every entry. Returns the subdirectories to descend
    /// into, or `nil` if the directory could not be read at all.
    private static func enumerate(fd: Int32, buffer: UnsafeMutableRawPointer, walk: inout SizingWalk) -> [SizingPendingDirectory]? {
        var list = makeAttrList(bulk: true)
        var children: [SizingPendingDirectory] = []
        let raw = UnsafeRawBufferPointer(start: UnsafeRawPointer(buffer), count: bulkBufferSize)
        var readAnything = false
        var interrupts = 0

        while true {
            if Task.isCancelled {
                walk.complete = false
                return children
            }
            let count = getattrlistbulk(fd, &list, buffer, bulkBufferSize, bulkOptions)
            if count < 0 {
                if errno == EINTR && interrupts < 64 { interrupts += 1; continue }
                walk.complete = false
                return readAnything ? children : nil
            }
            if count == 0 { return children }
            readAnything = true

            var offset = 0
            for _ in 0..<Int(count) {
                // Each record starts 8-byte aligned with a uint32_t length (getattrlistbulk(2)).
                guard offset % 8 == 0, offset >= 0, offset <= bulkBufferSize - 4 else {
                    walk.complete = false
                    return children
                }
                let length = Int(raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
                guard length >= 4 + MemoryLayout<attribute_set_t>.size, length <= bulkBufferSize - offset else {
                    // SAFETY-DECISION: a malformed buffer means we cannot trust anything after it;
                    // stop reading this directory and report the estimate as incomplete.
                    walk.complete = false
                    return children
                }
                defer { offset += length }

                guard let entry = parseRecord(raw, start: offset, length: length, expectName: true) else {
                    walk.complete = false
                    return children
                }
                guard entry.error == 0, entry.name != nil, let type = entry.objectType else {
                    walk.complete = false
                    continue
                }
                walk.itemCount += 1
                walk.noteModification(entry.modificationDate)
                if walk.protectedDescendant == nil, let name = entry.name {
                    // SAFETY-DECISION (review M2): spec §3.5 protects a .git directory or a protected
                    // extension ANYWHERE; a target that contains one must never be acted on.
                    let length = name.firstIndex(of: 0) ?? name.count
                    let text = String(decoding: name.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
                    walk.protectedDescendant = SizeCalculator.protectedNameLabel(text)
                }

                if type == SizingVnodeType.directory {
                    if let status = entry.mountStatus, status & SizingAttrBit.mountPointFlag != 0 {
                        walk.crossedMountPointsSkipped += 1
                        continue
                    }
                    guard let fileID = entry.fileID, let name = entry.name else {
                        walk.complete = false
                        continue
                    }
                    children.append(SizingPendingDirectory(name: name, fileID: fileID))
                } else {
                    walk.account(entry: entry)
                }
            }
        }
    }

    // MARK: Descriptors

    private static let directoryFlags: Int32 = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK

    /// Opens the root's parent directory. O_NOFOLLOW_ANY (which cannot be combined with O_NOFOLLOW):
    /// a symlink in ANY component fails with ELOOP.
    /// SAFETY-DECISION: O_NONBLOCK so a FIFO swapped in for a directory can never block the scan.
    private static func openAncestor(path: String) -> Int32? {
        var attempts = 0
        while true {
            let fd = path.withCString { Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW_ANY) }
            if fd >= 0 { return fd }
            if errno == EINTR && attempts < 64 { attempts += 1; continue }
            return nil // ENOTDIR, ELOOP (symlink), EACCES, ENOENT, …
        }
    }

    private static func openDirectory(at parent: Int32, name: [CChar]) -> Int32 {
        var attempts = 0
        while true {
            let fd = name.withUnsafeBufferPointer { openat(parent, $0.baseAddress!, directoryFlags) }
            if fd >= 0 { return fd }
            if errno == EINTR && attempts < 64 { attempts += 1; continue }
            return -1
        }
    }

    /// Where the opened descriptor really is (F_GETPATH), for the real-home guard.
    private static func openedPath(_ fd: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) + 1)
        let rc = buffer.withUnsafeMutableBufferPointer { fcntl(fd, F_GETPATH, $0.baseAddress!) }
        guard rc != -1 else { return nil }
        let length = buffer.firstIndex(of: 0) ?? buffer.count
        return String(decoding: buffer.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func retryingFstat(_ fd: Int32, _ st: inout Darwin.stat) -> Bool {
        var attempts = 0
        while true {
            if fstat(fd, &st) == 0 { return true }
            if errno == EINTR && attempts < 64 { attempts += 1; continue }
            return false
        }
    }

    /// Keeps at most `maxOpenDirectoryDescriptors` frames open. Never closes the root (index 0) or
    /// the top frame; closes the shallowest other open frames first.
    private static func enforceDescriptorLimit(_ stack: inout [SizingFrame]) {
        var open = stack.reduce(0) { $0 + ($1.fd >= 0 ? 1 : 0) }
        guard open > maxOpenDirectoryDescriptors else { return }
        var index = 1
        while open > maxOpenDirectoryDescriptors && index < stack.count - 1 {
            if stack[index].fd >= 0 {
                _ = Darwin.close(stack[index].fd)
                stack[index].fd = -1
                open -= 1
            }
            index += 1
        }
    }

    /// Re-opens a frame closed by the descriptor limit by walking down from its nearest open
    /// ancestor with openat(O_NOFOLLOW), verifying device and inode of every component.
    ///
    /// Each step only needs its parent's descriptor, so the intermediate descriptor is closed as soon
    /// as the next one is open: at most the ancestor, one intermediate and the new descriptor are open
    /// at any moment (review M2: re-opening a deep chain must not burst past RLIMIT_NOFILE).
    private static func reopen(frameAt target: Int, in stack: inout [SizingFrame], device: dev_t) -> Bool {
        var ancestor = target - 1
        while ancestor > 0 && stack[ancestor].fd < 0 { ancestor -= 1 }
        guard ancestor >= 0, stack[ancestor].fd >= 0 else { return false }
        for index in (ancestor + 1)...target {
            let fd = openDirectory(at: stack[index - 1].fd, name: stack[index].name)
            let previous = index - 1
            func releasePrevious() {
                if previous != ancestor, previous != 0, stack[previous].fd >= 0 {
                    _ = Darwin.close(stack[previous].fd)
                    stack[previous].fd = -1
                }
            }
            guard fd >= 0 else {
                releasePrevious()
                return false
            }
            var st = Darwin.stat()
            guard retryingFstat(fd, &st), (st.st_mode & S_IFMT) == S_IFDIR,
                  st.st_dev == device, UInt64(st.st_ino) == stack[index].inode else {
                _ = Darwin.close(fd)
                releasePrevious()
                return false
            }
            stack[index].fd = fd
            releasePrevious()
        }
        enforceDescriptorLimit(&stack)
        return stack[target].fd >= 0
    }
}
