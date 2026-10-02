import Darwin
import Foundation
import OpenDirectory

// Settings → "Trust Homebrew tools" (opt-in, OFF by default). See SAFETY.md › Command trust.
//
// A standard Homebrew install makes its folders (`/opt/homebrew/bin`, `Cellar`, `lib`, …) writable by
// the installing user AND by the `admin` group (drwxrwxr-x, group admin). By default `CommandRunner`
// refuses every group-writable directory, so Homebrew-installed tools never run. With this setting
// ON, such a Homebrew directory is accepted as well — but only under the narrow rule documented on
// `CommandRunner.isTrustedHomebrewDirectory`. Everything else in the trust model is unchanged.

/// How strictly `CommandRunner` treats the folders vendor tools live in.
public struct CommandTrustPolicy: Sendable, Hashable {
    /// Settings → "Trust Homebrew tools": accept Homebrew folders that the `admin` group may write to.
    /// SAFETY-DECISION: OFF unless the user turned it on (after seeing who else could change the tools).
    public var trustsHomebrewAdminWritableDirectories: Bool
    /// When set and revoked, the relaxation is OFF even though `trustsHomebrewAdminWritableDirectories`
    /// says ON: turning the setting off withdraws it from runners already handed to a running scan or
    /// cleanup (see `CommandTrustRevocation`).
    public var revocation: CommandTrustRevocation?

    public init(trustsHomebrewAdminWritableDirectories: Bool = false, revocation: CommandTrustRevocation? = nil) {
        self.trustsHomebrewAdminWritableDirectories = trustsHomebrewAdminWritableDirectories
        self.revocation = revocation
    }

    /// The policy the user's settings ask for.
    public init(settings: ScanSettings, revocation: CommandTrustRevocation? = nil) {
        self.init(trustsHomebrewAdminWritableDirectories: settings.trustHomebrewAdminWritableDirectories,
                  revocation: revocation)
    }

    /// `true` while the Homebrew relaxation applies right now (ON and not revoked since).
    public var relaxesHomebrewDirectories: Bool {
        trustsHomebrewAdminWritableDirectories && !(revocation?.isRevoked ?? false)
    }

    public static func == (lhs: CommandTrustPolicy, rhs: CommandTrustPolicy) -> Bool {
        lhs.trustsHomebrewAdminWritableDirectories == rhs.trustsHomebrewAdminWritableDirectories
            && lhs.revocation.map(ObjectIdentifier.init) == rhs.revocation.map(ObjectIdentifier.init)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(trustsHomebrewAdminWritableDirectories)
        hasher.combine(revocation.map(ObjectIdentifier.init))
    }

    /// Today's (and the default) behaviour: no group- or world-writable folder is ever trusted.
    public static let strict = CommandTrustPolicy()

    /// SAFETY-DECISION: the exact Homebrew locations the relaxation may ever apply to — nothing else.
    /// Apple silicon: the whole `/opt/homebrew` prefix. Intel: the folders Homebrew owns inside
    /// `/usr/local` (never `/usr/local` itself). Only the list for the architecture iMop runs on is
    /// used, so an Intel-style `/usr/local` install on an Apple silicon Mac is not relaxed.
    public static let appleSiliconHomebrewPrefixes = ["/opt/homebrew"]
    public static let intelHomebrewPrefixes = ["/usr/local/Homebrew", "/usr/local/Cellar", "/usr/local/opt", "/usr/local/lib",
                                               "/usr/local/bin", "/usr/local/share", "/usr/local/Caskroom"]

    public static var standardHomebrewPrefixes: [String] {
        #if arch(arm64)
        return appleSiliconHomebrewPrefixes
        #else
        return intelHomebrewPrefixes
        #endif
    }

    /// Where Homebrew lives on this Mac, for the Settings text ("/opt/homebrew" or "/usr/local").
    public static var homebrewLocationDescription: String {
        #if arch(arm64)
        return "/opt/homebrew"
        #else
        return "/usr/local"
        #endif
    }

    /// The `admin` group's id (`getgrnam_r("admin")`), or `nil` when it cannot be determined — the
    /// relaxation is then disabled (fail closed).
    public static func lookUpAdminGroupID() -> gid_t? {
        AdminGroupMembers.lookUpGroup(named: AdminGroupMembers.adminGroupName)?.gid
    }

    /// Unavailable reason when a tool exists but sits in a Homebrew folder other accounts can change.
    public static func homebrewTrustRequiredMessage(tool: String, folder: String) -> String {
        "\(tool) is in \(folder), a folder other accounts can change. " + homebrewTrustRequiredSuffix
    }

    /// Unavailable reason when the tool's own folder is fine but something it needs (its `#!`
    /// interpreter, a symlink target, a program `env` finds on PATH) is in such a Homebrew folder.
    public static func homebrewTrustRequiredMessage(tool: String, uses folder: String) -> String {
        "\(tool) uses \(folder), a folder other accounts can change. " + homebrewTrustRequiredSuffix
    }

    static let homebrewTrustRequiredSuffix = "Turn on “Trust Homebrew tools” in Settings to allow it."

    /// `true` for a message made by `homebrewTrustRequiredMessage` (lets a client keep its own
    /// generic "not installed" text for every other failure).
    public static func isHomebrewTrustRequiredMessage(_ message: String) -> Bool {
        message.hasSuffix(homebrewTrustRequiredSuffix)
    }
}

/// One-way switch shared by the runners built while "Trust Homebrew tools" is ON. Turning the
/// setting OFF revokes it, so a scan or cleanup that is already running stops trusting the Homebrew
/// folders at its next command (like `LiveExclusions` for exclusions added during a run).
public final class CommandTrustRevocation: @unchecked Sendable {
    private let lock = NSLock()
    private var revoked = false

    public init() {}

    public var isRevoked: Bool {
        lock.lock(); defer { lock.unlock() }
        return revoked
    }

    /// SAFETY-DECISION: there is deliberately no way back: a revoked switch stays revoked (turning the
    /// setting ON again starts a NEW switch that only runners built afterwards use).
    public func revoke() {
        lock.lock(); defer { lock.unlock() }
        revoked = true
    }
}

/// Who, besides the user, could change tools in an `admin`-group-writable Homebrew folder (shown before
/// the user turns on "Trust Homebrew tools"). Read-only: only the group and account databases are read.
public enum AdminGroupMembers {
    public static let adminGroupName = "admin"

    /// The `admin` group's directory record: what `getgrnam` does not show.
    public struct DirectoryRecord: Sendable, Equatable {
        /// `PrimaryGroupID` (must be the id `getgrnam` returned).
        public var groupID: gid_t?
        /// `NestedGroups`: groups whose members are admins too (e.g. a directory-bound "Allow
        /// administration by" group or an MDM admin group).
        public var nestedGroups: [String]
        /// `GroupMembers`: member accounts by their generated UUID.
        public var memberUUIDs: [String]

        public init(groupID: gid_t?, nestedGroups: [String], memberUUIDs: [String]) {
            self.groupID = groupID
            self.nestedGroups = nestedGroups
            self.memberUUIDs = memberUUIDs
        }
    }

    /// What the disclosure is computed from (the live databases in the app; fakes in tests).
    @_spi(FixtureTesting)
    public struct Source: Sendable {
        /// The admin group's id and explicit member names, or `nil` when it cannot be read.
        public var adminGroup: @Sendable () -> (gid: gid_t, members: [String])?
        /// Every account's name and primary group id, or `nil` when the accounts cannot be listed.
        public var accounts: @Sendable () -> [(name: String, primaryGroupID: gid_t)]?
        /// The current user's account name (`nil` when unknown).
        public var currentUserName: @Sendable () -> String?
        /// The admin group's directory record, or `nil` when it cannot be read.
        public var directoryRecord: @Sendable () -> DirectoryRecord?
        /// The short name of the user account with this generated UUID (`nil` when there is no such
        /// user account, e.g. the UUID is a group's, or it cannot be looked up).
        public var accountName: @Sendable (_ uuid: String) -> String?

        public init(adminGroup: @escaping @Sendable () -> (gid: gid_t, members: [String])?,
                    accounts: @escaping @Sendable () -> [(name: String, primaryGroupID: gid_t)]?,
                    currentUserName: @escaping @Sendable () -> String?,
                    directoryRecord: @escaping @Sendable () -> DirectoryRecord?,
                    accountName: @escaping @Sendable (_ uuid: String) -> String?) {
            self.adminGroup = adminGroup
            self.accounts = accounts
            self.currentUserName = currentUserName
            self.directoryRecord = directoryRecord
            self.accountName = accountName
        }
    }

    /// Account names in the `admin` group (explicit members, members listed by UUID, and accounts
    /// whose primary group is `admin`), de-duplicated and sorted, without the current user and `root`.
    /// `nil` when this cannot be determined completely.
    public static func current() -> [String]? {
        members(from: liveSource)
    }

    @_spi(FixtureTesting)
    public static func members(from source: Source) -> [String]? {
        guard let group = source.adminGroup() else { return nil }
        guard let accounts = source.accounts() else { return nil }
        // SAFETY-DECISION (review): `getgrnam` shows only the short-name `GroupMembership`. macOS also
        // counts `GroupMembers` (UUIDs) and every member of a `NestedGroups` group as an admin. The
        // list is returned only when it is COMPLETE: a record that cannot be read, a different group
        // id, any nested group (its members cannot be listed reliably, e.g. a directory group) or a
        // member UUID that is not a known user account all mean "could not be determined" (`nil`),
        // which makes Settings show the stronger warning instead of a false "no one else".
        guard let record = source.directoryRecord(), record.groupID == group.gid,
              record.nestedGroups.isEmpty else { return nil }
        var names = Set(group.members.filter { !$0.isEmpty })
        for uuid in record.memberUUIDs {
            guard let name = source.accountName(uuid), !name.isEmpty else { return nil }
            names.insert(name)
        }
        for account in accounts where account.primaryGroupID == group.gid && !account.name.isEmpty {
            names.insert(account.name)
        }
        names.remove("root")
        // SAFETY-DECISION: when the user's own name is unknown nothing else is removed (listing too
        // many accounts is the safe side of a disclosure).
        if let me = source.currentUserName() { names.remove(me) }
        return names.sorted()
    }

    static let liveSource = Source(
        adminGroup: { lookUpGroup(named: adminGroupName) },
        accounts: { allAccounts() },
        currentUserName: {
            var entry = passwd()
            var result: UnsafeMutablePointer<passwd>?
            var buffer = [CChar](repeating: 0, count: 16 * 1024)
            guard getpwuid_r(getuid(), &entry, &buffer, buffer.count, &result) == 0, result != nil,
                  let name = entry.pw_name else { return nil }
            return String(cString: name)
        },
        directoryRecord: { liveDirectoryRecord() },
        accountName: { liveAccountName(uuid: $0) }
    )

    private static let directoryLock = NSLock()

    /// The `admin` record through the directory search policy (read-only Open Directory lookup).
    static func liveDirectoryRecord() -> DirectoryRecord? {
        directoryLock.lock()
        defer { directoryLock.unlock() }
        let attributes = [kODAttributeTypePrimaryGroupID, kODAttributeTypeNestedGroups, kODAttributeTypeGroupMembers]
        guard let node = try? ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication)),
              let record = try? node.record(withRecordType: kODRecordTypeGroups, name: adminGroupName, attributes: attributes),
              let details = try? record.recordDetails(forAttributes: attributes) else { return nil }
        // An attribute that is absent is empty; one that is present but not a list of strings is unreadable.
        func strings(_ attribute: String) -> [String]? {
            guard let value = details[attribute] else { return [] }
            guard let list = value as? [Any] else { return nil }
            var result: [String] = []
            for element in list {
                guard let text = element as? String else { return nil }
                result.append(text)
            }
            return result
        }
        guard let ids = strings(kODAttributeTypePrimaryGroupID), let nested = strings(kODAttributeTypeNestedGroups),
              let members = strings(kODAttributeTypeGroupMembers) else { return nil }
        let groupID: gid_t? = ids.count == 1 ? gid_t(ids[0]) : nil
        return DirectoryRecord(groupID: groupID, nestedGroups: nested, memberUUIDs: members)
    }

    /// The one user account whose `GeneratedUID` is `uuid` (read-only Open Directory query).
    static func liveAccountName(uuid: String) -> String? {
        directoryLock.lock()
        defer { directoryLock.unlock() }
        guard let node = try? ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication)),
              let query = try? ODQuery(node: node, forRecordTypes: kODRecordTypeUsers, attribute: kODAttributeTypeGUID,
                                       matchType: ODMatchType(kODMatchEqualTo), queryValues: uuid,
                                       returnAttributes: [kODAttributeTypeRecordName], maximumResults: 2),
              let results = try? query.resultsAllowingPartial(false),
              results.count == 1, let record = results.first as? ODRecord else { return nil }
        return record.recordName
    }

    /// `getgrnam_r`: the group's id and explicit members.
    static func lookUpGroup(named name: String) -> (gid: gid_t, members: [String])? {
        var group = Darwin.group()
        var result: UnsafeMutablePointer<Darwin.group>?
        var size = 16 * 1024
        while size <= 1024 * 1024 {
            var buffer = [CChar](repeating: 0, count: size)
            let status = getgrnam_r(name, &group, &buffer, buffer.count, &result)
            if status == ERANGE { size *= 4; continue }
            guard status == 0, result != nil else { return nil }
            var members: [String] = []
            if var cursor = group.gr_mem {
                while let member = cursor.pointee {
                    members.append(String(cString: member))
                    cursor += 1
                }
            }
            return (group.gr_gid, members)
        }
        return nil
    }

    private static let accountsLock = NSLock()

    /// Every account (`getpwent`, which is not thread-safe, so serialized here).
    static func allAccounts() -> [(name: String, primaryGroupID: gid_t)]? {
        accountsLock.lock()
        defer { accountsLock.unlock() }
        setpwent()
        defer { endpwent() }
        var accounts: [(name: String, primaryGroupID: gid_t)] = []
        while let entry = getpwent() {
            guard let name = entry.pointee.pw_name else { continue }
            accounts.append((String(cString: name), entry.pointee.pw_gid))
            if accounts.count > 100_000 { return nil }
        }
        return accounts
    }
}
