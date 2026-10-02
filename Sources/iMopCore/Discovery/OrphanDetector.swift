import Foundation

// Read-only OrphanDetector (spec §6.9 `leftovers.appData`, Red).
//
// Proposes `{HOME}/Library/{Application Support, Preferences (<id>.plist), Containers, Group Containers,
// Caches, HTTPStorages, WebKit}/<identifier>` ONLY when all eight conditions of spec §6.9 hold. Every
// condition is a separate function returning an `OrphanBlock` (the reason it blocks orphan status) and
// FAILS CLOSED: an error, timeout or unknown answer blocks. The same `OrphanEvaluator` re-checks
// conditions 1–4 (and the volume part of 8) at execute time for `Precondition.stillOrphaned`.
//
// It only reads: the file system through `SafeCleanEnvironment.fileSystem`, LaunchServices / Spotlight,
// running apps / processes, code-signing information, and the read-only `pkgutil --pkgs` listing. It
// never modifies anything. The Scanner and SafetyGate re-validate every candidate (deny-list wins:
// HTTPStorages and com.apple.* are never offered).

// MARK: - Public model

/// The `{HOME}/Library/<folder>` areas searched for leftovers.
public enum OrphanLocation: String, Sendable, CaseIterable, Hashable {
    case applicationSupport = "Application Support"
    case preferences = "Preferences"
    case containers = "Containers"
    case groupContainers = "Group Containers"
    case caches = "Caches"
    case httpStorages = "HTTPStorages"
    case webKit = "WebKit"

    /// Folder name directly inside `{HOME}/Library`.
    public var directoryName: String { rawValue }

    /// Components below the home directory.
    public var components: [String] { ["Library", rawValue] }

    public var displayName: String {
        switch self {
        case .applicationSupport: return "Application Support"
        case .preferences: return "Preferences"
        case .containers: return "Container"
        case .groupContainers: return "Group Container"
        case .caches: return "Caches"
        case .httpStorages: return "HTTP storage"
        case .webKit: return "WebKit data"
        }
    }

    /// `Preferences` holds `<identifier>.plist` files; every other location holds folders.
    public var holdsFiles: Bool { self == .preferences }

    /// The location whose directory name is `name` (case-insensitive).
    public static func named(_ name: String) -> OrphanLocation? {
        let wanted = PathComparison.normalize(name)
        return allCases.first { PathComparison.normalize($0.rawValue) == wanted }
    }
}

/// The eight conditions of spec §6.9, numbered as in the spec.
public enum OrphanCondition: Int, Sendable, CaseIterable, Hashable, Comparable {
    /// 1. Not `com.apple.*` (also `group.com.apple.*`), not deny-listed.
    case notAppleOrDenied = 1
    /// 2. No app registered with LaunchServices AND Spotlight finds none on any mounted volume.
    case notInstalled = 2
    /// 3. No running app / process related to the identifier.
    case notRunning = 3
    /// 4. Not referenced by a package receipt (`pkgutil --pkgs`).
    case noPackageReceipt = 4
    /// 5. Group Containers: no installed app declares the group or has the Team ID prefix.
    case groupContainerUnclaimed = 5
    /// 6. A reverse-DNS identifier that is not a known CLI / tool / other rule's directory.
    case notKnownTool = 6
    /// 7. `olderThan(30)`.
    case olderThan = 7
    /// 8. Not a subscription-store (Setapp) app, and no drive that held apps is disconnected.
    case noMissingAppLocation = 8

    public static func < (lhs: OrphanCondition, rhs: OrphanCondition) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Why an identifier is NOT orphaned.
public struct OrphanBlock: Sendable, Hashable, CustomStringConvertible {
    public let condition: OrphanCondition
    /// User-facing explanation.
    public let reason: String

    public init(_ condition: OrphanCondition, _ reason: String) {
        self.condition = condition
        self.reason = reason
    }

    public var description: String { "condition \(condition.rawValue): \(reason)" }
}

/// One `{HOME}/Library/<location>/<name>` entry being evaluated.
public struct OrphanCandidate: Sendable, Hashable {
    /// The identifier (folder name, or the plist name without `.plist` for Preferences).
    public let identifier: String
    public let location: OrphanLocation
    /// Absolute path of the entry.
    public let path: String
    /// Directory-entry name (`<identifier>` or `<identifier>.plist`).
    public let name: String

    public init(identifier: String, location: OrphanLocation, path: String, name: String) {
        self.identifier = identifier
        self.location = location
        self.path = path
        self.name = name
    }

    /// The candidate for directory entry `name` of `location` (inside `directory`), or `nil` when the
    /// name has the wrong form (a Preferences entry that is not `<id>.plist`).
    public static func make(name: String, location: OrphanLocation, directory: String) -> OrphanCandidate? {
        guard InspectorWalker.isPlainName(name) else { return nil }
        let identifier: String
        if location.holdsFiles {
            let suffix = ".plist"
            // SAFETY-DECISION: only exactly `<id>.plist` (lowercase extension); lock files, `.plist.lockfile`,
            // backups and anything else are not offered.
            guard name.hasSuffix(suffix), name.count > suffix.count else { return nil }
            identifier = String(name.dropLast(suffix.count))
        } else {
            identifier = name
        }
        return OrphanCandidate(identifier: identifier, location: location, path: directory + "/" + name, name: name)
    }
}

// MARK: - Evaluator

/// Evaluates the eight orphan conditions of spec §6.9. Each `check…` function returns `nil` when its
/// condition holds and an `OrphanBlock` when it blocks orphan status (fail closed).
///
/// An evaluator caches expensive lookups (LaunchServices / Spotlight answers, the package receipt list,
/// the installed apps' signing information, the Setapp state, the catalog exclusions) for its own
/// lifetime, so create one per scan (the inspector does) and a fresh one per execute-time re-check.
public struct OrphanEvaluator: Sendable {
    public static let ruleID = "leftovers.appData"
    /// Condition 7: never less than 30 days, whatever the rule declares.
    public static let minimumAgeDays = 30
    /// Condition 4: the only package-receipt tool ever run (read-only).
    public static let pkgutilPath = "/usr/sbin/pkgutil"
    public static let pkgutilArguments = ["--pkgs"]
    static let pkgutilTimeout: TimeInterval = 30
    /// Condition 5: where installed apps are enumerated (`{HOME}` is expanded).
    public static let defaultApplicationRoots = ["/Applications", "/Applications/Utilities", "{HOME}/Applications", "/System/Applications"]
    /// Roots that always exist on macOS: one that is missing or unreadable means "cannot evaluate".
    public static let defaultRequiredApplicationRoots = ["/Applications", "/System/Applications"]
    /// Condition 8: the Setapp subscription-store folder.
    public static let defaultSetappDirectory = "/Applications/Setapp"
    /// Condition 5: SAFETY-DECISION — more installed apps than this cannot be evaluated (fail closed).
    public static let maximumInstalledApps = 3_000
    /// Condition 2: at most this many identifier forms are looked up per identifier.
    static let maximumLookupForms = 8
    /// Processes / labels shorter than this are only compared for equality (condition 3).
    static let minimumPrefixMatchLength = 4

    /// Condition 6: known CLI / tool / vendor directory names (compared case-insensitively with the
    /// identifier, the entry name and EVERY dot-separated label of the identifier).
    public static let knownToolNames: [String] = [
        "Homebrew", "pip", "node-gyp", "typescript", "Jupyter", "jupyter", "npm", "yarn", "pnpm", "Code", "Cursor",
        "JetBrains", "Google", "Microsoft", "Adobe", "Mozilla", "Firefox", "Docker", "iMop", "CrashReporter",
        "AddressBook", "CallHistoryDB", "Knowledge", "Dock",
        "Setapp", "VSCodium", "Electron", "CocoaPods", "Carthage", "SwiftPM", "Xcode", "Python", "pypoetry", "pipenv",
        "Rustup", "Cargo", "Ollama", "OrbStack", "Colima",
    ] + UnknownOwnerCachesInspector.knownToolCacheNames

    let environment: SafeCleanEnvironment
    let catalog: RuleCatalog?
    let applicationRoots: [String]
    let requiredApplicationRoots: Set<String>
    let setappDirectory: String
    private let denyFilter: InspectorDenyFilter
    private let cache = OrphanEvaluationCache()

    /// - Parameter catalog: the catalog whose other rules' directories are excluded (condition 6).
    ///   SAFETY-DECISION: without a catalog condition 6 always blocks (the overlap cannot be ruled out).
    public init(environment: SafeCleanEnvironment, catalog: RuleCatalog? = nil) {
        self.init(environment: environment, catalog: catalog, applicationRoots: Self.defaultApplicationRoots,
                  requiredApplicationRoots: Self.defaultRequiredApplicationRoots, setappDirectory: Self.defaultSetappDirectory)
    }

    /// Test-only: fixture application folders instead of the real `/Applications` etc.
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, catalog: RuleCatalog?, applicationRoots: [String],
                requiredApplicationRoots: [String] = [], setappDirectory: String) {
        self.environment = environment
        self.catalog = catalog
        let home = environment.homePath
        self.applicationRoots = applicationRoots.map { $0.replacingOccurrences(of: "{HOME}", with: home) }
        self.requiredApplicationRoots = Set(requiredApplicationRoots.map { $0.replacingOccurrences(of: "{HOME}", with: home) })
        self.setappDirectory = setappDirectory.replacingOccurrences(of: "{HOME}", with: home)
        self.denyFilter = InspectorDenyFilter(environment: environment)
    }

    // MARK: All conditions

    /// First condition that blocks `candidate` (cheap checks first), or `nil` when it is orphaned.
    public func evaluate(_ candidate: OrphanCandidate, olderThanDays days: Int = OrphanEvaluator.minimumAgeDays) async -> OrphanBlock? {
        if let block = checkNotKnownTool(candidate) { return block }
        if let block = checkNotAppleOrDenied(candidate) { return block }
        if let block = checkOlderThan(candidate, days: days) { return block }
        if let block = checkGroupContainerUnclaimed(candidate) { return block }
        if let block = checkNoMissingAppLocation(identifier: candidate.identifier) { return block }
        if let block = checkNotRunning(identifier: candidate.identifier) { return block }
        if let block = checkNotInstalled(identifier: candidate.identifier) { return block }
        if let block = await checkNoPackageReceipt(identifier: candidate.identifier) { return block }
        return nil
    }

    /// Execute-time re-check for `Precondition.stillOrphaned`: identifier shape, condition 1 (Apple),
    /// the volume part of condition 8, and conditions 3, 2 and 4. `nil` when still orphaned.
    ///
    /// SAFETY-DECISION: more than the agreed 2, 3, 4 is re-checked (Apple prefix, identifier shape,
    /// disconnected drives) because they are cheap and can only make the result more conservative.
    public func stillOrphaned(identifier: String) async -> OrphanBlock? {
        let trimmed = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed == identifier else {
            return OrphanBlock(.notKnownTool, "The app this item belonged to is unknown")
        }
        guard Self.isReverseDNSIdentifier(identifier) else {
            return OrphanBlock(.notKnownTool, "“\(identifier)” is not an app identifier")
        }
        if let block = checkNotApple(identifier: identifier) { return block }
        if let block = checkVolumesConnected() { return block }
        if let block = checkNotRunning(identifier: identifier) { return block }
        if let block = checkNotInstalled(identifier: identifier) { return block }
        if let block = await checkNoPackageReceipt(identifier: identifier) { return block }
        return nil
    }

    /// `Precondition.stillOrphaned` outcome for a target's owning identifier (fail closed: `nil` /
    /// empty fails).
    public static func preconditionOutcome(owningBundleID: String?, environment: SafeCleanEnvironment) async -> (passed: Bool, detail: String) {
        guard let owner = owningBundleID, !owner.isEmpty else {
            return (false, "The app this item belonged to is unknown")
        }
        if let block = await OrphanEvaluator(environment: environment).stillOrphaned(identifier: owner) {
            return (false, block.reason)
        }
        return (true, "Still not installed, not running and not referenced by an installer receipt")
    }

    // MARK: Condition 1 — not Apple, not deny-listed

    public func checkNotAppleOrDenied(_ candidate: OrphanCandidate) -> OrphanBlock? {
        if let block = checkNotApple(identifier: candidate.identifier) { return block }
        if Self.isAppleIdentifier(candidate.name) { return OrphanBlock(.notAppleOrDenied, "Apple data is never removed") }
        if denyFilter.isDenied(candidate.path, ruleID: Self.ruleID) {
            return OrphanBlock(.notAppleOrDenied, "This location is protected")
        }
        return nil
    }

    public func checkNotApple(identifier: String) -> OrphanBlock? {
        Self.isAppleIdentifier(identifier) ? OrphanBlock(.notAppleOrDenied, "Apple data is never removed") : nil
    }

    /// SAFETY-DECISION: any identifier with a label `apple` (case-insensitive) is Apple's: covers
    /// `com.apple.*`, `group.com.apple.*` and `<TEAMID>.com.apple.*`.
    public static func isAppleIdentifier(_ identifier: String) -> Bool {
        if BundleIdentifierHeuristics.isApple(identifier) { return true }
        return labels(identifier).contains("apple")
    }

    // MARK: Condition 2 — not installed (LaunchServices AND Spotlight)

    /// Looks up the identifier, its Group-Container core (`group.` / Team ID removed) and their
    /// reverse-DNS prefixes of at least three labels (`com.vendor.app.helper` → `com.vendor.app`).
    /// Every lookup must succeed and find nothing.
    public func checkNotInstalled(identifier: String) -> OrphanBlock? {
        for form in Self.lookupForms(identifier) {
            switch installLookup(form) {
            case .absent: continue
            case .installed(let where_):
                return OrphanBlock(.notInstalled, "An app with the identifier \(form) is installed (\(where_))")
            case .unknown(let why):
                return OrphanBlock(.notInstalled, why)
            }
        }
        return nil
    }

    enum InstallLookup: Sendable, Equatable {
        case absent
        case installed(String)
        case unknown(String)
    }

    private func installLookup(_ bundleID: String) -> InstallLookup {
        let key = PathComparison.normalize(bundleID)
        if let cached = cache.read({ $0.installLookups[key] }) { return cached }
        let result: InstallLookup
        if let urls = environment.applications.applicationURLs(forBundleIdentifier: bundleID) {
            if let first = urls.first {
                result = .installed(first.standardizedFileURL.path)
            } else if let paths = environment.applications.spotlightApplicationPaths(forBundleIdentifier: bundleID) {
                result = paths.first.map { .installed($0) } ?? .absent
            } else {
                result = .unknown("Spotlight could not confirm that no app with this identifier exists on any drive")
            }
        } else {
            result = .unknown("Could not check which apps are installed")
        }
        cache.write { $0.installLookups[key] = result }
        return result
    }

    // MARK: Condition 3 — not running

    /// Blocks when a running app's bundle identifier equals, extends or is extended by the identifier
    /// (or its core), or shares its vendor domain; or when a running process is named like the
    /// identifier's last label, its vendor label or `appName`.
    ///
    /// SAFETY-DECISION: the related-identifier and vendor-domain matches go beyond exact equality —
    /// a running sibling app of the same vendor may still read this data.
    public func checkNotRunning(identifier: String, appName: String? = nil) -> OrphanBlock? {
        guard let running = environment.runningApplications.runningBundleIdentifiers() else {
            return OrphanBlock(.notRunning, "Could not check which apps are running")
        }
        let forms = [identifier, Self.coreIdentifier(identifier)]
        let vendors = Set(forms.compactMap(Self.vendorDomain))
        for app in running {
            if forms.contains(where: { Self.areRelated(app, $0) }) {
                return OrphanBlock(.notRunning, "\(app) is running")
            }
            if let vendor = Self.vendorDomain(app), vendors.contains(vendor) {
                return OrphanBlock(.notRunning, "\(app), from the same developer, is running")
            }
        }
        guard let processes = environment.processes.runningProcessNames() else {
            return OrphanBlock(.notRunning, "Could not check which processes are running")
        }
        var names: [String] = []
        let coreLabels = Self.labels(Self.coreIdentifier(identifier))
        if let last = coreLabels.last { names.append(last) }
        if coreLabels.count >= 2 { names.append(coreLabels[1]) }
        if let appName { names.append(PathComparison.normalize(appName)) }
        names = names.filter { !$0.isEmpty }
        guard !names.isEmpty else { return OrphanBlock(.notRunning, "Could not tell which process would use this data") }
        for process in processes {
            let running = PathComparison.normalize(process)
            guard !running.isEmpty else { continue }
            for name in names {
                let matches = running == name
                    // proc_name truncates long names.
                    || (running.count >= 15 && name.hasPrefix(running))
                    || (name.count >= Self.minimumPrefixMatchLength && running.hasPrefix(name))
                if matches { return OrphanBlock(.notRunning, "A process named “\(process)” is running") }
            }
        }
        return nil
    }

    // MARK: Condition 4 — no package receipt

    public func checkNoPackageReceipt(identifier: String) async -> OrphanBlock? {
        guard let packages = await packageReceiptIDs() else {
            return OrphanBlock(.noPackageReceipt, "Could not read the installer receipts")
        }
        return Self.packageReceiptBlock(identifier: identifier, packageIDs: packages)
    }

    /// Pure part of condition 4: blocks when any receipt id equals, starts with or contains the
    /// identifier (or its core) or vice versa, or shares its vendor domain (case-insensitive).
    ///
    /// SAFETY-DECISION: the vendor-domain match is stricter than the spec's "references" (an
    /// installer of the same developer may own this data under a different identifier).
    public static func packageReceiptBlock(identifier: String, packageIDs: [String]) -> OrphanBlock? {
        let forms = Set([identifier, coreIdentifier(identifier)].map(PathComparison.normalize))
        let vendors = Set(forms.compactMap(vendorDomain))
        for raw in packageIDs {
            let package = PathComparison.normalize(raw.trimmingCharacters(in: .whitespacesAndNewlines))
            guard !package.isEmpty else { continue }
            for form in forms where package == form || package.hasPrefix(form) || package.contains(form) || form.contains(package) {
                return OrphanBlock(.noPackageReceipt, "Installed by the package \(raw)")
            }
            if let vendor = vendorDomain(package), vendors.contains(vendor) {
                return OrphanBlock(.noPackageReceipt, "The developer's package \(raw) is installed")
            }
        }
        return nil
    }

    /// Receipt ids from `/usr/sbin/pkgutil --pkgs` (read-only; once per evaluator). `nil` on any failure.
    func packageReceiptIDs() async -> [String]? {
        if let cached = cache.read({ $0.packageIDs }) { return cached }
        let result = await fetchPackageReceiptIDs()
        cache.write { $0.packageIDs = .some(result) }
        return result
    }

    private func fetchPackageReceiptIDs() async -> [String]? {
        // SAFETY-DECISION: only the SIP-protected system pkgutil, and only the read-only listing.
        guard let tool = environment.commands.resolveExecutable("pkgutil"), tool == Self.pkgutilPath else { return nil }
        let result = await environment.commands.run(executable: tool, arguments: Self.pkgutilArguments,
                                                    timeout: Self.pkgutilTimeout, purpose: .readOnly)
        guard result.succeeded else { return nil }
        // SAFETY-DECISION: a truncated listing may be missing the receipt that matters → unknown.
        guard !result.stdout.contains("[truncated ") else { return nil }
        let ids = result.stdout.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // SAFETY-DECISION: every Mac has Apple receipts; an empty listing is not trustworthy.
        guard !ids.isEmpty else { return nil }
        return ids
    }

    // MARK: Condition 5 — Group Containers

    /// Group Containers only (other locations pass). `<TEAMID>.<rest>`: blocked if any installed app
    /// has that Team ID. `group.<rest>`: blocked if any installed app declares it (or a related group)
    /// in `com.apple.security.application-groups`. Both checks apply to both forms.
    public func checkGroupContainerUnclaimed(_ candidate: OrphanCandidate) -> OrphanBlock? {
        guard candidate.location == .groupContainers else { return nil }
        let identifier = candidate.identifier
        let team = Self.teamIDPrefix(identifier)
        // SAFETY-DECISION: a Group Container name that is neither `group.…` nor `<TEAMID>.…` is not
        // understood and is never orphaned.
        guard team != nil || PathComparison.normalize(identifier).hasPrefix("group.") else {
            return OrphanBlock(.groupContainerUnclaimed, "Unrecognised app group name")
        }
        let apps: [InstalledAppSignature]
        switch installedSignatures() {
        case .failed(let why): return OrphanBlock(.groupContainerUnclaimed, why)
        case .known(let list): apps = list
        }
        let wantedTeam = team.map(PathComparison.normalize)
        for app in apps {
            if let wantedTeam, let appTeam = app.teamID, PathComparison.normalize(appTeam) == wantedTeam {
                return OrphanBlock(.groupContainerUnclaimed, "\(app.name) from the same developer (Team ID \(appTeam)) is installed")
            }
            if app.appGroups.contains(where: { Self.areRelated($0, identifier) }) {
                return OrphanBlock(.groupContainerUnclaimed, "\(app.name) uses this app group")
            }
        }
        return nil
    }

    struct InstalledAppSignature: Sendable, Equatable {
        let path: String
        let name: String
        let teamID: String?
        let appGroups: [String]
    }

    enum InstalledSignatures: Sendable, Equatable {
        case known([InstalledAppSignature])
        case failed(String)
    }

    private func installedSignatures() -> InstalledSignatures {
        if let cached = cache.read({ $0.signatures }) { return cached }
        let result = readInstalledSignatures()
        cache.write { $0.signatures = result }
        return result
    }

    /// SAFETY-DECISION: if ANY installed app's signing information cannot be read (or the apps cannot
    /// be enumerated completely), no Group Container is orphaned.
    private func readInstalledSignatures() -> InstalledSignatures {
        let failure = InstalledSignatures.failed("Could not check which installed apps use app groups")
        guard let paths = installedAppPaths() else { return failure }
        var apps: [InstalledAppSignature] = []
        for path in paths {
            guard let info = environment.codeSignatures.signingInfo(path: path) else { return failure }
            let name = (path as NSString).lastPathComponent
            apps.append(InstalledAppSignature(path: path, name: (name as NSString).deletingPathExtension,
                                              teamID: info.teamID, appGroups: info.appGroups))
        }
        return .known(apps)
    }

    /// Top-level `.app` bundles of every application root, plus those one folder level down
    /// (`/Applications/Setapp/*.app`). `nil` when a required root is missing, a root cannot be listed,
    /// or there are more than `maximumInstalledApps`.
    func installedAppPaths() -> [String]? {
        let fs = environment.fileSystem
        var found: [String] = []
        var seen = Set<String>()
        func add(_ path: String) -> Bool {
            if seen.insert(PathComparison.normalize(path)).inserted { found.append(path) }
            return found.count <= Self.maximumInstalledApps
        }
        for root in applicationRoots {
            guard let info = fs.lstat(root) else {
                if requiredApplicationRoots.contains(root) { return nil }
                continue
            }
            guard info.isDirectory, !info.isSymlink, let names = fs.contentsOfDirectory(root) else { return nil }
            for name in names.sorted() where InspectorWalker.isPlainName(name) && !name.hasPrefix(".") {
                let child = root + "/" + name
                if Self.isAppBundleName(name) {
                    guard add(child) else { return nil }
                    continue
                }
                guard let childInfo = fs.lstat(child), childInfo.isDirectory, !childInfo.isSymlink,
                      !SafetyGate.isBundleComponent(name) else { continue }
                guard let inner = fs.contentsOfDirectory(child) else { return nil }
                for innerName in inner.sorted() where InspectorWalker.isPlainName(innerName) && Self.isAppBundleName(innerName) {
                    guard add(child + "/" + innerName) else { return nil }
                }
            }
        }
        return found
    }

    static func isAppBundleName(_ name: String) -> Bool {
        PathComparison.normalize(name).hasSuffix(".app") && name.count > 4
    }

    // MARK: Condition 6 — identifier shape, known tools, other rules

    /// Blocks plain folder names (only reverse-DNS identifiers with at least two dots are ever
    /// candidates), known tool / vendor names, bundle-looking names, and anything another rule of the
    /// catalog targets.
    public func checkNotKnownTool(_ candidate: OrphanCandidate) -> OrphanBlock? {
        // SAFETY-DECISION: plain folder names are never orphan candidates.
        guard Self.isReverseDNSIdentifier(candidate.identifier) else {
            return OrphanBlock(.notKnownTool, "“\(candidate.identifier)” is not an app identifier")
        }
        // SAFETY-DECISION: a folder named like a bundle (`com.vendor.app` reads as `*.app`) is never proposed.
        if !candidate.location.holdsFiles, SafetyGate.isBundleComponent(candidate.name) {
            return OrphanBlock(.notKnownTool, "Named like an app bundle")
        }
        if let tool = Self.knownToolMatch(candidate.identifier) ?? Self.knownToolMatch(candidate.name) {
            return OrphanBlock(.notKnownTool, "Belongs to \(tool), which iMop does not treat as a deleted app")
        }
        guard let catalog else {
            return OrphanBlock(.notKnownTool, "Could not check which other cleanup rules use this folder")
        }
        let exclusions: CatalogExclusions
        if let cached = cache.read({ $0.exclusions }) {
            exclusions = cached
        } else {
            exclusions = Self.catalogExclusions(catalog: catalog, ownRuleID: Self.ruleID, environment: environment)
            cache.write { $0.exclusions = exclusions }
        }
        if exclusions.isExcluded(candidate.name, in: candidate.location) || exclusions.isExcluded(candidate.identifier, in: candidate.location) {
            return OrphanBlock(.notKnownTool, "Another cleanup rule handles this folder")
        }
        return nil
    }

    /// The known tool name matching `name` itself or any of its labels, or `nil`.
    static func knownToolMatch(_ name: String) -> String? {
        let whole = PathComparison.normalize(name)
        let parts = Set(labels(name))
        return knownToolNames.first { tool in
            let normalized = PathComparison.normalize(tool)
            return normalized == whole || parts.contains(normalized)
        }
    }

    /// At least three dot-separated labels (≥ 2 dots), each 1–63 ASCII letters / digits / `-`, not
    /// starting or ending with `-`; at most 255 characters.
    public static func isReverseDNSIdentifier(_ identifier: String) -> Bool {
        guard !identifier.isEmpty, identifier.count <= 255 else { return false }
        let parts = identifier.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3 else { return false }
        return parts.allSatisfy { label in
            guard !label.isEmpty, label.count <= 63, !label.hasPrefix("-"), !label.hasSuffix("-") else { return false }
            return label.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-") }
        }
    }

    /// Names (and single-segment wildcard patterns) of location children other rules may target.
    struct CatalogExclusions: Sendable {
        var names: [OrphanLocation: Set<String>] = [:]
        var childPatterns: [OrphanLocation: [GlobPattern]] = [:]

        func isExcluded(_ name: String, in location: OrphanLocation) -> Bool {
            if names[location]?.contains(PathComparison.normalize(name)) == true { return true }
            return childPatterns[location]?.contains { $0.matches(segment: name, at: 2) } ?? false
        }
    }

    /// Every child of a location that another rule's allow-root or glob reaches (mirrors
    /// `UnknownOwnerCachesInspector.exclusions`, for all leftover locations).
    static func catalogExclusions(catalog: RuleCatalog, ownRuleID: String, environment: SafeCleanEnvironment) -> CatalogExclusions {
        var exclusions = CatalogExclusions()
        let home = environment.homePath
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let homePath) = canonicalizer.lexical(home) else { return exclusions }
        let library = homePath.appending("Library")
        let expander = GlobExpander(environment: environment)

        func excludeChild(of raw: String) {
            guard case .success(let path) = canonicalizer.lexical(raw) else { return }
            for location in OrphanLocation.allCases {
                let directory = library.appending(location.directoryName)
                guard path.isStrictlyInside(directory) else { continue }
                exclusions.names[location, default: []].insert(PathComparison.normalize(path.components[directory.components.count]))
            }
        }

        for other in catalog.rules where other.id != ownRuleID {
            for raw in other.resolvedAllowRoots(home: home) { excludeChild(of: raw) }
            guard case .glob(let patterns) = other.discovery else { continue }
            for raw in patterns {
                guard let pattern = GlobPattern(raw), pattern.anchor == .home, pattern.segments.count >= 3,
                      pattern.matches(segment: "Library", at: 0) else { continue }
                for location in OrphanLocation.allCases where pattern.matches(segment: location.directoryName, at: 1) {
                    if !pattern.isWildcard(at: 2) {
                        exclusions.names[location, default: []].insert(PathComparison.normalize(pattern.segments[2]))
                    } else if pattern.segments.count == 3 {
                        exclusions.childPatterns[location, default: []].append(pattern)
                    } else {
                        for match in expander.expand(pattern, excludedNames: other.excludedNames) { excludeChild(of: match) }
                    }
                }
            }
        }
        return exclusions
    }

    // MARK: Condition 7 — olderThan(30)

    /// `lastUsed = max(mtime(entry), mtime(each immediate child))` via `lstat` must be more than
    /// `days` (never less than 30; a user override may only raise it) days ago.
    public func checkOlderThan(_ candidate: OrphanCandidate, days: Int = OrphanEvaluator.minimumAgeDays) -> OrphanBlock? {
        let declared = max(days, Self.minimumAgeDays)
        let threshold = environment.scanSettings.effectiveAgeThreshold(ruleID: Self.ruleID, declared: declared)
        let fs = environment.fileSystem
        let unknown = OrphanBlock(.olderThan, "Could not determine when this was last used")
        guard let info = fs.lstat(candidate.path) else { return unknown }
        var latest = info.modificationDate
        if info.isDirectory {
            guard let children = fs.contentsOfDirectory(candidate.path) else { return unknown }
            for child in children {
                guard InspectorWalker.isPlainName(child), let childInfo = fs.lstat(candidate.path + "/" + child) else { return unknown }
                latest = max(latest, childInfo.modificationDate)
            }
        }
        let age = environment.clock.now.timeIntervalSince(latest)
        guard age > TimeInterval(threshold) * PreconditionEvaluator.secondsPerDay else {
            return OrphanBlock(.olderThan, "Used within the last \(threshold) days")
        }
        return nil
    }

    // MARK: Condition 8 — app locations

    public func checkNoMissingAppLocation(identifier: String) -> OrphanBlock? {
        if let block = checkVolumesConnected() { return block }
        return checkSetapp(identifier: identifier)
    }

    /// Message of the scan status when a drive is missing.
    public static let disconnectedVolumeMessage = "A drive that may contain apps is not connected"

    /// Blocks when the mounted volumes cannot be listed, or any volume of
    /// `scanSettings.lastSeenVolumes` is not mounted now (or fewer volumes are mounted).
    public func checkVolumesConnected() -> OrphanBlock? {
        guard let mounted = environment.volumes.mountedVolumes() else {
            return OrphanBlock(.noMissingAppLocation, "Could not check which drives are connected, so apps on them cannot be ruled out")
        }
        let previous = environment.scanSettings.lastSeenVolumes.filter { !$0.isEmpty }
        let current = Set(mounted.map(Self.volumeKey))
        let missing = previous.filter { !current.contains(Self.volumeKey($0)) }
        if !missing.isEmpty || mounted.count < Set(previous.map(Self.volumeKey)).count {
            let names = missing.map { ($0 as NSString).lastPathComponent }.filter { !$0.isEmpty }
            let list = names.isEmpty ? "" : " (\(names.joined(separator: ", ")))"
            return OrphanBlock(.noMissingAppLocation,
                               "\(Self.disconnectedVolumeMessage)\(list). Connect it and scan again — apps on it would otherwise look deleted.")
        }
        return nil
    }

    static func volumeKey(_ path: String) -> String {
        var trimmed = path
        while trimmed.count > 1 && trimmed.hasSuffix("/") { trimmed.removeLast() }
        return PathComparison.normalize(trimmed)
    }

    /// `lastSeenVolumes` to persist after a scan (delegates to `ScanSettings.lastSeenVolumesAfterScan`,
    /// which only ever adds volumes, so a disconnected drive keeps blocking until it is reconnected).
    public static func lastSeenVolumesAfterScan(environment: SafeCleanEnvironment) -> [String] {
        environment.scanSettings.lastSeenVolumesAfterScan(mounted: environment.volumes.mountedVolumes())
    }

    enum SetappState: Sendable, Equatable {
        case inactive
        case active([String])
        case unknown(String)
    }

    /// When the Setapp folder holds apps: blocks `com.setapp.*`, identifiers related to an installed
    /// Setapp app (also with `-setapp` added or removed), and requires LaunchServices + Spotlight to
    /// confirm the `-setapp` variant is absent too. A Setapp folder that cannot be read blocks.
    public func checkSetapp(identifier: String) -> OrphanBlock? {
        let bundleIDs: [String]
        switch setappState() {
        case .inactive: return nil
        case .unknown(let why): return OrphanBlock(.noMissingAppLocation, why)
        case .active(let ids): bundleIDs = ids
        }
        let core = Self.coreIdentifier(identifier)
        if Self.vendorDomain(core) == "com.setapp" {
            return OrphanBlock(.noMissingAppLocation, "Belongs to Setapp")
        }
        let suffix = "-setapp"
        var variants = [identifier, core]
        let normalizedCore = PathComparison.normalize(core)
        if normalizedCore.hasSuffix(suffix) {
            variants.append(String(core.dropLast(suffix.count)))
        } else {
            variants.append(core + suffix)
        }
        for app in bundleIDs where variants.contains(where: { Self.areRelated(app, $0) }) {
            return OrphanBlock(.noMissingAppLocation, "\(app) is installed through Setapp")
        }
        for variant in variants.dropFirst(2) {
            switch installLookup(variant) {
            case .absent: continue
            case .installed(let where_): return OrphanBlock(.noMissingAppLocation, "The Setapp edition is installed (\(where_))")
            case .unknown(let why): return OrphanBlock(.noMissingAppLocation, why)
            }
        }
        return nil
    }

    private func setappState() -> SetappState {
        if let cached = cache.read({ $0.setapp }) { return cached }
        let state = readSetappState()
        cache.write { $0.setapp = state }
        return state
    }

    private func readSetappState() -> SetappState {
        let fs = environment.fileSystem
        let unreadable = SetappState.unknown("Could not check the apps installed through Setapp")
        switch XcodeDerivedDataInspector.existence(of: setappDirectory, fileSystem: fs) {
        case .absent: return .inactive
        case .unknown: return unreadable
        case .exists: break
        }
        guard let info = fs.lstat(setappDirectory), info.isDirectory, !info.isSymlink,
              let names = fs.contentsOfDirectory(setappDirectory) else { return unreadable }
        var ids: [String] = []
        for name in names.sorted() where InspectorWalker.isPlainName(name) && Self.isAppBundleName(name) {
            guard let plist = DevToolsFileReader.readPlistDictionary(setappDirectory + "/" + name + "/Contents/Info.plist", fileSystem: fs),
                  let id = plist["CFBundleIdentifier"] as? String, !id.isEmpty else { return unreadable }
            ids.append(id)
        }
        return ids.isEmpty ? .inactive : .active(ids)
    }

    // MARK: Identifier helpers

    /// Lowercased, NFC-normalized dot-separated labels.
    static func labels(_ identifier: String) -> [String] {
        PathComparison.normalize(identifier).split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    }

    /// The first label when it looks like an Apple Team ID (10 uppercase ASCII letters / digits).
    public static func teamIDPrefix(_ identifier: String) -> String? {
        guard let first = identifier.split(separator: ".", omittingEmptySubsequences: false).first,
              first.count == 10,
              first.unicodeScalars.allSatisfy({ $0.isASCII && (CharacterSet.uppercaseLetters.contains($0) || CharacterSet.decimalDigits.contains($0)) }),
              identifier.count > first.count + 1 else { return nil }
        return String(first)
    }

    /// `group.<rest>` / `<TEAMID>.<rest>` → `<rest>` (when it still has two labels); otherwise the
    /// identifier itself.
    public static func coreIdentifier(_ identifier: String) -> String {
        let parts = identifier.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 3 else { return identifier }
        if PathComparison.normalize(parts[0]) == "group" || teamIDPrefix(identifier) != nil {
            return parts.dropFirst().joined(separator: ".")
        }
        return identifier
    }

    /// First two labels of `identifier` (e.g. `com.vendor`), or `nil` when it has fewer than two.
    static func vendorDomain(_ identifier: String) -> String? {
        let parts = labels(coreIdentifier(identifier))
        guard parts.count >= 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        return parts[0] + "." + parts[1]
    }

    /// Equal, or one extends the other at a label boundary (case-insensitive).
    static func areRelated(_ lhs: String, _ rhs: String) -> Bool {
        let a = PathComparison.normalize(lhs), b = PathComparison.normalize(rhs)
        guard !a.isEmpty, !b.isEmpty else { return false }
        return a == b || a.hasPrefix(b + ".") || b.hasPrefix(a + ".")
    }

    /// Identifier forms looked up for condition 2 (unique, at most `maximumLookupForms`).
    static func lookupForms(_ identifier: String) -> [String] {
        var forms: [String] = []
        func add(_ form: String) {
            guard !form.isEmpty, !forms.contains(where: { PathComparison.normalize($0) == PathComparison.normalize(form) }) else { return }
            forms.append(form)
        }
        let core = coreIdentifier(identifier)
        add(identifier)
        add(core)
        for base in [identifier, core] {
            var parts = base.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            while parts.count > 3 {
                parts.removeLast()
                add(parts.joined(separator: "."))
            }
        }
        return Array(forms.prefix(maximumLookupForms))
    }
}

// MARK: - Per-evaluator cache

final class OrphanEvaluationCache: @unchecked Sendable {
    struct State {
        var installLookups: [String: OrphanEvaluator.InstallLookup] = [:]
        /// Outer `nil`: not fetched yet; inner `nil`: the fetch failed.
        var packageIDs: [String]?? = nil
        var signatures: OrphanEvaluator.InstalledSignatures?
        var setapp: OrphanEvaluator.SetappState?
        var exclusions: OrphanEvaluator.CatalogExclusions?
    }

    private let lock = NSLock()
    private var state = State()

    func read<T>(_ body: (State) -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body(state)
    }

    func write(_ body: (inout State) -> Void) {
        lock.lock(); defer { lock.unlock() }
        body(&state)
    }
}

// MARK: - leftovers.appData inspector

/// `leftovers.appData` (Red): leftover data of deleted apps (spec §6.9). Only entries for which every
/// one of the eight conditions holds are proposed; the Scanner and SafetyGate re-validate them, and the
/// rule's preconditions (`owningAppNotRunning`, `olderThan(30)`, `notOpenByAnyProcess`,
/// `stillOrphaned`) are re-checked at execute time.
public struct OrphanedAppDataInspector: Inspector {
    public static let ruleID = OrphanEvaluator.ruleID

    private let catalog: RuleCatalog?
    private let applicationRoots: [String]
    private let requiredApplicationRoots: [String]
    private let setappDirectory: String

    /// - Parameter catalog: the catalog whose other rules' folders are excluded (condition 6). `nil`
    ///   loads the bundled catalog at discovery time.
    public init(catalog: RuleCatalog? = nil) {
        self.catalog = catalog
        self.applicationRoots = OrphanEvaluator.defaultApplicationRoots
        self.requiredApplicationRoots = OrphanEvaluator.defaultRequiredApplicationRoots
        self.setappDirectory = OrphanEvaluator.defaultSetappDirectory
    }

    /// Test-only: fixture application folders instead of the real `/Applications` etc.
    @_spi(FixtureTesting)
    public init(catalog: RuleCatalog?, applicationRoots: [String], requiredApplicationRoots: [String] = [], setappDirectory: String) {
        self.catalog = catalog
        self.applicationRoots = applicationRoots
        self.requiredApplicationRoots = requiredApplicationRoots
        self.setappDirectory = setappDirectory
    }

    /// `true` when a catalog was injected at init (otherwise the bundled one is loaded).
    var hasInjectedCatalog: Bool { catalog != nil }

    /// A copy bound to `catalog` (keeps the application roots).
    func with(catalog: RuleCatalog) -> OrphanedAppDataInspector {
        OrphanedAppDataInspector(catalog: catalog, applicationRoots: applicationRoots,
                                 requiredApplicationRoots: requiredApplicationRoots, setappDirectory: setappDirectory)
    }

    public var id: InspectorID { .orphanedAppData }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        // SAFETY-DECISION: an unknown rule id bound to this inspector gets nothing.
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not the leftovers rule"))
        }
        let catalog = self.catalog ?? RuleCatalog.loadBundled(environment: environment)
        // SAFETY-DECISION: without a catalog the folders of other rules cannot be excluded.
        guard !catalog.rules.isEmpty else {
            return InspectorOutput(candidates: [], status: .unavailable("The rule catalog could not be loaded"))
        }
        let evaluator = OrphanEvaluator(environment: environment, catalog: catalog, applicationRoots: applicationRoots,
                                        requiredApplicationRoots: requiredApplicationRoots, setappDirectory: setappDirectory)
        // SAFETY-DECISION: with a drive missing that may hold apps, NOTHING is proposed.
        if let block = evaluator.checkVolumesConnected() {
            return InspectorOutput(candidates: [], status: .unavailable(block.reason))
        }
        let declaredDays = rule.preconditions.compactMap { precondition -> Int? in
            if case .olderThan(let days) = precondition { return days }
            return nil
        }.max() ?? OrphanEvaluator.minimumAgeDays
        let days = max(declaredDays, OrphanEvaluator.minimumAgeDays)

        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home) else { return InspectorOutput(candidates: [], status: .ok) }
        let device = homeStat.device
        let denyFilter = InspectorDenyFilter(environment: environment)
        let ruleExcluded = Set(rule.excludedNames.map(PathComparison.normalize))

        var candidates: [DiscoveredCandidate] = []
        for location in OrphanLocation.allCases {
            guard let directory = walker.descend(from: home, through: location.components, device: device) else { continue }
            // SAFETY-DECISION: a deny-listed location (HTTPStorages) is not even listed.
            if denyFilter.isDenied(directory, ruleID: rule.id) || denyFilter.isDenied(directory + "/imop-orphan-probe", ruleID: rule.id) {
                continue
            }
            guard case .entries(let entries) = walker.list(directory, device: device) else { continue }
            for entry in entries {
                if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage)) }
                guard !entry.name.hasPrefix("."), !entry.stat.isSymlink, entry.stat.device == device,
                      !ruleExcluded.contains(PathComparison.normalize(entry.name)) else { continue }
                if location.holdsFiles {
                    guard entry.stat.isRegularFile else { continue }
                } else {
                    guard InspectorWalker.isDescendable(entry, device: device) else { continue }
                }
                guard let candidate = OrphanCandidate.make(name: entry.name, location: location, directory: directory) else { continue }
                if await evaluator.evaluate(candidate, olderThanDays: days) != nil { continue }
                let threshold = environment.scanSettings.effectiveAgeThreshold(ruleID: rule.id, declared: days)
                var notes = [
                    "No installed app with the identifier \(candidate.identifier) was found (LaunchServices and Spotlight, all connected drives).",
                    "It is not used by a running app or process, not referenced by an installer receipt, and has not changed in over \(threshold) days.",
                ]
                if location == .groupContainers {
                    notes.append("No installed app uses this app group or its developer's Team ID.")
                }
                notes.append("It is moved to the Trash, so you can put it back from there.")
                candidates.append(DiscoveredCandidate(
                    path: candidate.path,
                    displayName: "\(candidate.identifier) (\(location.displayName))",
                    owningBundleID: candidate.identifier,
                    notes: notes
                ))
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Target shape for `RuleTargetMatcher`: `Library/<location>/<identifier>` (Preferences:
    /// `<identifier>.plist`) with a reverse-DNS, non-Apple identifier equal to `owner`.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        guard relative.count == 3, PathComparison.normalize(relative[0]) == "library",
              let location = OrphanLocation.named(relative[1]),
              !relative[2].hasPrefix("."),
              let candidate = OrphanCandidate.make(name: relative[2], location: location, directory: "/"),
              OrphanEvaluator.isReverseDNSIdentifier(candidate.identifier),
              !OrphanEvaluator.isAppleIdentifier(candidate.identifier),
              location.holdsFiles || !SafetyGate.isBundleComponent(relative[2]),
              let owner else { return false }
        return PathComparison.normalize(owner) == PathComparison.normalize(candidate.identifier)
    }
}
