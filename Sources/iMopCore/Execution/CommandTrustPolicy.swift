import Darwin
import Foundation

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

    public init(trustsHomebrewAdminWritableDirectories: Bool = false) {
        self.trustsHomebrewAdminWritableDirectories = trustsHomebrewAdminWritableDirectories
    }

    /// The policy the user's settings ask for.
    public init(settings: ScanSettings) {
        self.init(trustsHomebrewAdminWritableDirectories: settings.trustHomebrewAdminWritableDirectories)
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

    static let homebrewTrustRequiredSuffix = "Turn on “Trust Homebrew tools” in Settings to allow it."

    /// `true` for a message made by `homebrewTrustRequiredMessage` (lets a client keep its own
    /// generic "not installed" text for every other failure).
    public static func isHomebrewTrustRequiredMessage(_ message: String) -> Bool {
        message.hasSuffix(homebrewTrustRequiredSuffix)
    }
}

/// Who, besides the user, could change tools in an `admin`-group-writable Homebrew folder (shown before
/// the user turns on "Trust Homebrew tools"). Read-only: only the group and account databases are read.
public enum AdminGroupMembers {
    public static let adminGroupName = "admin"

    /// What the disclosure is computed from (the live databases in the app; fakes in tests).
    @_spi(FixtureTesting)
    public struct Source: Sendable {
        /// The admin group's id and explicit member names, or `nil` when it cannot be read.
        public var adminGroup: @Sendable () -> (gid: gid_t, members: [String])?
        /// Every account's name and primary group id, or `nil` when the accounts cannot be listed.
        public var accounts: @Sendable () -> [(name: String, primaryGroupID: gid_t)]?
        /// The current user's account name (`nil` when unknown).
        public var currentUserName: @Sendable () -> String?

        public init(adminGroup: @escaping @Sendable () -> (gid: gid_t, members: [String])?,
                    accounts: @escaping @Sendable () -> [(name: String, primaryGroupID: gid_t)]?,
                    currentUserName: @escaping @Sendable () -> String?) {
            self.adminGroup = adminGroup
            self.accounts = accounts
            self.currentUserName = currentUserName
        }
    }

    /// Account names in the `admin` group (explicit members plus accounts whose primary group is
    /// `admin`), de-duplicated and sorted, without the current user and `root`. `nil` when this cannot
    /// be determined.
    public static func current() -> [String]? {
        members(from: liveSource)
    }

    @_spi(FixtureTesting)
    public static func members(from source: Source) -> [String]? {
        guard let group = source.adminGroup() else { return nil }
        guard let accounts = source.accounts() else { return nil }
        var names = Set(group.members.filter { !$0.isEmpty })
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
        }
    )

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
