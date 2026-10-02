import Foundation

/// Why the deny-list is being consulted.
public enum DenyListPurpose: Sendable {
    /// Every rule-driven action.
    case standard
    /// Reserved for the Quarantine module: may reach `{HOME}/Library/Application Support/iMop/Quarantine/**`.
    case quarantine
}

/// Spec §3.5 absolute deny-list. Hard-coded in Swift (never in Rules.json); it always wins over any
/// rule, user setting or allow-root.
public struct DenyList: Sendable {

    // MARK: Constants (every entry of spec §3.5)

    /// Absolute system locations. Matched component-wise against the logical canonical path.
    public static let systemEntries: [String] = [
        "/System",
        "/bin",
        "/sbin",
        "/usr",
        "/opt",
        "/private/etc",
        "/private/var/db",
        "/private/var/vm",
        "/private/var/folders",
        "/private/var/root",
        "/private/var/log",
        "/private/var/run",
        "/private/tmp",
        "/Library",
        "/Applications/Utilities",
        "/Volumes",
        "/cores",
        "/.Spotlight-V100",
        "/.fseventsd",
        "/.DocumentRevisions-V100",
        "/.MobileBackups",
        "/.vol",
    ]

    /// Locations relative to the home directory. A trailing `*` on the last component means
    /// "a component that starts with" the text before it; `*text*` means "a component that contains".
    public static let homeRelativeEntries: [String] = [
        "Library/Keychains",
        "Library/Mobile Documents",
        "Library/CloudStorage",
        "Library/Mail",
        "Library/Messages",
        "Library/Photos",
        "Library/Accounts",
        "Library/Cookies",
        "Library/HTTPStorages",
        "Library/Safari",
        "Library/Calendars",
        "Library/Reminders",
        // SAFETY-DECISION: the spec lists "~/Library/Contacts (Application Support/AddressBook)"; both
        // the literal ~/Library/Contacts and the AddressBook store are denied.
        "Library/Contacts",
        "Library/Application Support/AddressBook",
        "Library/Application Support/MobileSync",
        "Library/Application Support/com.apple.TCC",
        "Library/Application Support/iMop",
        // SAFETY-DECISION (review M2): iMop's own audit log folder (spec §5.5,
        // {HOME}/Library/Logs/iMop/audit-YYYY-MM.jsonl). Written only by the audit-log module, never
        // by a rule; `logs.user` additionally lists "iMop" in its excludedNames.
        "Library/Logs/iMop",
        "Library/Group Containers/group.com.apple.*",
        // SAFETY-DECISION: beyond the spec's literal "group.com.apple.*", any Group Container whose
        // name contains "com.apple." is Apple-managed too ("<TeamID>.groups.com.apple.podcasts",
        // "<TeamID>.com.apple.…"). A leading-and-trailing "*" means "component contains".
        "Library/Group Containers/*com.apple.*",
        "Library/Containers/com.apple.*",
        "Library/Preferences/com.apple.*",
        // SAFETY-DECISION: per-host Apple preferences live one level deeper and are just as Apple-owned.
        "Library/Preferences/ByHost/com.apple.*",
        "Library/LaunchAgents/com.apple.*",
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        ".docker/config.json",
        ".config/gh",
        ".netrc",
        "Documents",
        "Desktop",
        "Pictures",
        "Movies",
        "Music",
    ]

    /// Any path with a component carrying one of these extensions is denied.
    public static let protectedExtensions: [String] = [
        "photoslibrary",
        "musiclibrary",
        "tvlibrary",
        "lrcat",
        "fcpbundle",
        "logicx",
        "band",
        "sparsebundle",
        "keychain-db",
    ]

    /// Cloud-sync roots (iCloud Drive, File Provider storage), relative to the home directory.
    public static let cloudRootsRelativeToHome: [String] = [
        "Library/Mobile Documents",
        "Library/CloudStorage",
    ]

    // MARK: Compiled matchers

    /// How the last component of a wildcard entry is matched.
    enum Wildcard: Sendable, Hashable {
        /// `name*`: a component that starts with the text.
        case prefix(String)
        /// `*name*`: a component that contains the text.
        case contains(String)

        func matches(_ normalizedComponent: String) -> Bool {
            switch self {
            case .prefix(let text): return normalizedComponent.hasPrefix(text)
            case .contains(let text): return normalizedComponent.contains(text)
            }
        }
    }

    /// One home-relative entry split into its fixed part and optional wildcard (raw spelling).
    struct HomeEntrySpec: Sendable {
        let label: String
        /// Fixed components below the home directory (raw spelling, not normalized).
        let fixedComponents: [String]
        let wildcard: Wildcard?
    }

    /// An extra location protected under an entry's label: where a home-relative entry (or the
    /// directory holding its wildcard children) really lives when it is reached through a symlink.
    struct Alias: Sendable {
        let label: String
        let path: CanonicalPath
        let wildcard: Wildcard?
    }

    /// Parses `homeRelativeEntries` (trailing `*` = prefix, leading-and-trailing `*` = contains).
    static let homeEntrySpecs: [HomeEntrySpec] = homeRelativeEntries.map { entry in
        var parts = entry.split(separator: "/").map(String.init)
        var wildcard: Wildcard?
        if let last = parts.last, last.hasSuffix("*") {
            let body = String(last.dropLast())
            if body.hasPrefix("*") {
                wildcard = .contains(PathComparison.normalize(String(body.dropFirst())))
            } else {
                wildcard = .prefix(PathComparison.normalize(body))
            }
            parts.removeLast()
        }
        return HomeEntrySpec(label: "~/" + entry, fixedComponents: parts, wildcard: wildcard)
    }

    private struct Entry: Sendable {
        /// Human-readable entry, e.g. "/System" or "~/Library/Keychains".
        let label: String
        /// Normalized fixed components.
        let components: [String]
        /// How the next component must match (wildcard entries).
        let wildcard: Wildcard?

        /// The path is the entry or lies beneath it.
        func covers(_ path: [String]) -> Bool {
            if let wildcard {
                guard path.count > components.count,
                      Array(path.prefix(components.count)) == components else { return false }
                return wildcard.matches(path[components.count])
            }
            guard path.count >= components.count else { return false }
            return Array(path.prefix(components.count)) == components
        }

        /// The path is a strict ancestor of something this entry protects (removing it would remove
        /// protected content too).
        func isProtectedDescendant(of path: [String]) -> Bool {
            if wildcard != nil {
                // Anything at or above the directory holding the wildcard children.
                guard path.count <= components.count else { return false }
            } else {
                guard path.count < components.count else { return false }
            }
            return Array(components.prefix(path.count)) == path
        }
    }

    private let systemMatchers: [Entry]
    private let homeMatchers: [Entry]
    /// Resolved locations of home-relative entries reached through symlinks (see `adding(aliases:)`).
    private var aliasMatchers: [Entry] = []
    private let waivedRoots: [CanonicalPath]
    /// nil when the home directory was unusable; every path is then denied.
    private let home: CanonicalPath?
    private let mailDownloads: CanonicalPath?
    private let quarantineRoot: CanonicalPath?
    private let containersAppleEntryLabel = "~/Library/Containers/com.apple.*"
    private let iMopSupportEntryLabel = "~/Library/Application Support/iMop"

    // MARK: Init

    public init(homeDirectory: String) {
        self.init(homeDirectory: homeDirectory, waived: [])
    }

    /// Test-only: system entries that are ancestors of these roots are NOT applied to paths inside
    /// them (`FileManager.temporaryDirectory` lives under /private/var/folders, which is deny-listed).
    /// Home-relative entries, extensions and `.git` still apply inside waived roots.
    @_spi(FixtureTesting)
    public init(homeDirectory: String, waivedSystemRoots: [String]) {
        self.init(homeDirectory: homeDirectory, waived: waivedSystemRoots)
    }

    private init(homeDirectory: String, waived: [String]) {
        systemMatchers = Self.systemEntries.map { entry in
            Entry(label: entry,
                  components: entry.split(separator: "/").map { PathComparison.normalize(String($0)) },
                  wildcard: nil)
        }

        waivedRoots = Self.acceptedWaivedRoots(waived)

        if let homeString = PathCanonicalizer.validHome(homeDirectory) {
            let homePath = CanonicalPath(validatedPath: homeString)
            home = homePath
            let homeNorm = homePath.comparisonComponents
            homeMatchers = Self.homeEntrySpecs.map { spec in
                Entry(label: spec.label,
                      components: homeNorm + spec.fixedComponents.map(PathComparison.normalize),
                      wildcard: spec.wildcard)
            }
            mailDownloads = homePath
                .appending("Library").appending("Containers").appending("com.apple.mail")
                .appending("Data").appending("Library").appending("Mail Downloads")
            quarantineRoot = homePath
                .appending("Library").appending("Application Support").appending("iMop").appending("Quarantine")
        } else {
            // SAFETY-DECISION: an unusable home directory makes the deny-list deny everything.
            home = nil
            homeMatchers = []
            mailDownloads = nil
            quarantineRoot = nil
        }
    }

    /// A copy that also protects `aliases` (each under its entry's label, with the same "contains"
    /// rule). Used by SafetyGate for home-relative entries that are, or are reached through, symlinks:
    /// §3.5 requires that a link to a protected folder is not a bypass, so the folder's real location
    /// is protected as well.
    func adding(aliases: [Alias]) -> DenyList {
        var copy = self
        for alias in aliases {
            copy.aliasMatchers.append(Entry(label: alias.label, components: alias.path.comparisonComponents,
                                            wildcard: alias.wildcard))
        }
        return copy
    }

    // MARK: Matching

    /// Returns the matching deny entry (human readable) or `nil` if the path is not deny-listed.
    public func matchingEntry(for path: CanonicalPath, ruleID: String?, purpose: DenyListPurpose) -> String? {
        guard home != nil else { return "invalid home directory" }

        // SAFETY-DECISION: defense in depth — re-apply the lexical text rules to the path in case it was
        // built with `CanonicalPath(validatedPath:)` from a non-logical form (/tmp, /var, firmlink).
        // Both the given form and the re-cleaned form are checked.
        let recleaned: CanonicalPath
        switch PathCanonicalizer.clean(path.path, home: nil) {
        case .success(let p): recleaned = p
        case .failure(.denyListed(let entry)): return entry
        case .failure: return "unresolvable path"
        }

        if let hit = match(path, ruleID: ruleID, purpose: purpose) { return hit }
        if recleaned != path, let hit = match(recleaned, ruleID: ruleID, purpose: purpose) { return hit }
        return nil
    }

    private func match(_ path: CanonicalPath, ruleID: String?, purpose: DenyListPurpose) -> String? {
        let comps = path.comparisonComponents

        // 1. System entries (component-wise prefix).
        for entry in systemMatchers where entry.covers(comps) {
            if isWaived(path, systemEntry: entry) { continue }
            if entry.label == "/cores", ruleID == "system.coreDumps", isCoreDump(comps) { continue }
            return entry.label
        }

        // 2. Home-relative entries.
        for entry in homeMatchers where entry.covers(comps) {
            if entry.label == containersAppleEntryLabel, ruleID == "mail.downloads",
               let mailDownloads, path.isStrictlyInside(mailDownloads),
               path.components.count == mailDownloads.components.count + 1 {
                // SAFETY-DECISION: the only Apple-container exception is a DIRECT child of Mail Downloads
                // ("Mail Downloads/*"), for rule "mail.downloads" only — exactly like /cores/core.*.
                // Deeper paths stay denied (removing the direct child already covers them). Every other
                // entry still applies.
                continue
            }
            if entry.label == iMopSupportEntryLabel, purpose == .quarantine,
               let quarantineRoot, path.isStrictlyInside(quarantineRoot) {
                // Reserved for the Quarantine module; the Quarantine folder itself stays denied.
                continue
            }
            return entry.label
        }

        // 2b. Resolved symlink destinations of home-relative entries. No rule or purpose exception
        //     ever applies to them.
        for entry in aliasMatchers where entry.covers(comps) {
            return entry.label
        }

        // 3. Protected extensions and .git, on any component.
        for component in comps {
            if component == ".git" { return ".git" }
            for ext in Self.protectedExtensions where component.hasSuffix("." + ext) {
                return "." + ext
            }
        }

        // 4. SAFETY-DECISION: a path that CONTAINS a protected location (e.g. ~/Library, the home
        //    directory itself, ~/.docker, /Applications, /) is denied too: acting on it would act on the
        //    protected content beneath it. The spec's prefix match alone would not catch this.
        //    Waivers never apply to this check.
        for entry in systemMatchers where entry.isProtectedDescendant(of: comps) {
            return "contains \(entry.label)"
        }
        for entry in homeMatchers where entry.isProtectedDescendant(of: comps) {
            return "contains \(entry.label)"
        }
        for entry in aliasMatchers where entry.isProtectedDescendant(of: comps) {
            return "contains \(entry.label)"
        }

        return nil
    }

    /// The only system entries a fixture waiver can ever lift: the ones that hold the per-user
    /// temporary directory.
    static let waivableSystemEntries: Set<String> = ["/private/var/folders", "/private/tmp"]

    /// Prefix every accepted waived root must carry directly below the temporary directory.
    static let fixtureRootPrefix = "imoptests-"

    /// SAFETY-DECISION: the fixture waiver exists only so test fixtures under
    /// `FileManager.temporaryDirectory` can be validated. A waived root is accepted only if it lies
    /// strictly inside the temporary directory (lexical or resolved form) and its first component
    /// below it starts with "iMopTests-"; every other root ("/", "/usr", "/Library", "/Volumes/X", a
    /// sibling folder in the temp dir, a malformed path) is ignored, i.e. gives no waiver at all.
    static func acceptedWaivedRoots(_ raw: [String]) -> [CanonicalPath] {
        guard !raw.isEmpty else { return [] }
        var tempForms: [CanonicalPath] = []
        let tmp = NSTemporaryDirectory()
        if case .success(let lexical) = PathCanonicalizer.clean(tmp, home: nil), !lexical.components.isEmpty {
            tempForms.append(lexical)
        }
        if let resolved = Darwin.realpath(tmp, nil) {
            let resolvedString = String(cString: resolved)
            free(resolved)
            if case .success(let p) = PathCanonicalizer.clean(resolvedString, home: nil),
               !p.components.isEmpty, !tempForms.contains(p) {
                tempForms.append(p)
            }
        }
        return raw.compactMap { candidate in
            guard case .success(let root) = PathCanonicalizer.clean(candidate, home: nil) else { return nil }
            for temp in tempForms where root.isStrictlyInside(temp) {
                let first = root.comparisonComponents[temp.components.count]
                if first.hasPrefix(fixtureRootPrefix) && first.count > fixtureRootPrefix.count { return root }
            }
            return nil
        }
    }

    /// A system entry is waived for `path` when the entry is an ancestor-or-equal of a waived root that
    /// contains `path`. Only `waivableSystemEntries` can be waived ("/System" never).
    private func isWaived(_ path: CanonicalPath, systemEntry entry: Entry) -> Bool {
        // SAFETY-DECISION: "/System" can never be waived, even in tests; neither can any entry other
        // than the temporary-directory holders.
        guard entry.label != "/System", Self.waivableSystemEntries.contains(entry.label) else { return false }
        return waivedRoots.contains { root in
            path.isInsideOrEqual(root) && entry.covers(root.comparisonComponents)
        }
    }

    /// `/cores/core.*` — direct children only.
    private func isCoreDump(_ comps: [String]) -> Bool {
        comps.count == 2 && comps[0] == "cores" && comps[1].hasPrefix("core.") && comps[1].count > "core.".count
    }
}
