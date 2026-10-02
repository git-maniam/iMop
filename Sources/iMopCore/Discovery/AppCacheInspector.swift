import Foundation

// Read-only inspectors for app, container, Electron and Chromium caches (spec §6.6).
//
// Every inspector walks the file system ONLY through `SafeCleanEnvironment.fileSystem`
// (`contentsOfDirectory` + `lstat`). It never descends through a symlink, never crosses a volume
// boundary, and never modifies anything. The Scanner re-checks every candidate (canonicalization,
// deny-list, allow-root containment, symlinks) and SafetyGate validates it again before any action.

// MARK: - Shared read-only walking helpers

/// Minimal read-only directory walker shared by the inspectors.
struct InspectorWalker: Sendable {
    let fileSystem: any FileSystemProbe

    init(environment: SafeCleanEnvironment) {
        self.fileSystem = environment.fileSystem
    }

    /// `lstat` of `path` if it is a real directory (not a symlink). `nil` otherwise.
    func realDirectory(_ path: String) -> FileStat? {
        guard let info = fileSystem.lstat(path), info.isDirectory, !info.isSymlink else { return nil }
        return info
    }

    /// Follows `components` below `base`, one real directory at a time. Each step must be a real
    /// directory (never a symlink) on `device`. Returns the final path or `nil`.
    func descend(from base: String, through components: [String], device: Int64) -> String? {
        var current = base
        for component in components {
            guard InspectorWalker.isPlainName(component) else { return nil }
            current += "/" + component
            // SAFETY-DECISION: a symlinked or cross-volume intermediate directory ends the walk.
            guard let info = realDirectory(current), info.device == device else { return nil }
        }
        return current
    }

    /// Entry of a directory listing with its `lstat` result.
    struct Entry: Sendable {
        let name: String
        let path: String
        let stat: FileStat
    }

    enum Listing: Sendable {
        /// The directory does not exist (or is not a real directory on the expected volume).
        case absent
        /// The directory exists but could not be listed (TCC / app-data protection denial, I/O error).
        case declined
        case entries([Entry])
    }

    /// Lists the immediate children of `directory` (which must be a real directory on `device`).
    /// Children whose `lstat` fails or whose names are not plain are skipped.
    func list(_ directory: String, device: Int64) -> Listing {
        guard let info = realDirectory(directory), info.device == device else { return .absent }
        guard let names = fileSystem.contentsOfDirectory(directory) else { return .declined }
        var entries: [Entry] = []
        for name in names.sorted() where InspectorWalker.isPlainName(name) {
            let child = directory + "/" + name
            guard let childStat = fileSystem.lstat(child) else { continue }
            entries.append(Entry(name: name, path: child, stat: childStat))
        }
        return .entries(entries)
    }

    /// A single, non-empty path component without separators, NUL, `.` or `..`.
    static func isPlainName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
    }

    /// `true` for an entry that may be descended into: a real directory on `device`.
    static func isDescendable(_ entry: Entry, device: Int64) -> Bool {
        entry.stat.isDirectory && !entry.stat.isSymlink && entry.stat.device == device
    }
}

/// Bundle-identifier helpers shared by the inspectors.
enum BundleIdentifierHeuristics {
    /// Reverse-DNS look: at least two dot-separated, non-empty labels of ASCII letters, digits,
    /// `-` and `_`; the first label starts with a letter.
    static func looksReverseDNS(_ name: String) -> Bool {
        guard name.count <= 255 else { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }) else { return false }
        guard let first = labels.first?.unicodeScalars.first,
              first.isASCII, CharacterSet.letters.contains(first) else { return false }
        return name.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar) || scalar == "." || scalar == "-" || scalar == "_")
        }
    }

    /// `com.apple` or `com.apple.*`, compared case- and normalization-insensitively.
    static func isApple(_ bundleID: String) -> Bool {
        let normalized = PathComparison.normalize(bundleID)
        return normalized == "com.apple" || normalized.hasPrefix("com.apple.")
    }

    /// The display name of the installed app (from its bundle file name), when it is installed.
    /// Returns `nil` when the app is not installed OR the lookup failed.
    ///
    /// SAFETY-DECISION: a failed LaunchServices lookup (`nil`) is treated exactly like "not
    /// installed": the folder is not attributed to an installed app, so it is not offered as Green.
    static func installedAppName(_ bundleID: String, environment: SafeCleanEnvironment) -> String? {
        guard let urls = environment.applications.applicationURLs(forBundleIdentifier: bundleID),
              let first = urls.first else { return nil }
        let name = first.deletingPathExtension().lastPathComponent
        return name.isEmpty ? bundleID : name
    }
}

// MARK: - apps.userCaches

/// `{HOME}/Library/Caches/<bundleID>` for installed, non-Apple apps (spec §6.6 `apps.userCaches`).
///
/// Folders that do not resolve to an installed app are NOT emitted here: they belong to the Yellow rule
/// `apps.userCaches.unknownOwner` (a later milestone).
public struct AppUserCachesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .appUserCaches }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let base = environment.homePath
        guard let homeStat = walker.realDirectory(base),
              let caches = walker.descend(from: base, through: ["Library", "Caches"], device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let entries: [InspectorWalker.Entry]
        switch walker.list(caches, device: homeStat.device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        case .entries(let list): entries = list
        }

        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if Task.isCancelled { break }
            // SAFETY-DECISION: only real directories on the home volume; a symlink, a plain file or a
            // mount point named like a bundle ID is never treated as an app's cache folder.
            guard InspectorWalker.isDescendable(entry, device: homeStat.device) else { continue }
            guard BundleIdentifierHeuristics.looksReverseDNS(entry.name),
                  !BundleIdentifierHeuristics.isApple(entry.name) else { continue }
            guard let appName = BundleIdentifierHeuristics.installedAppName(entry.name, environment: environment) else {
                continue
            }
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: "\(appName) cache",
                owningBundleID: entry.name,
                notes: ["Cache folder of \(appName) (\(entry.name))"]
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}

// MARK: - apps.containerCaches

/// `{HOME}/Library/Containers/<id>/Data/Library/Caches/*` for installed, non-Apple apps
/// (spec §6.6 `apps.containerCaches`). App-data protection denials are reported, never crashed on.
public struct AppContainerCachesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .appContainerCaches }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let base = environment.homePath
        guard let homeStat = walker.realDirectory(base),
              let containers = walker.descend(from: base, through: ["Library", "Containers"], device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let containerEntries: [InspectorWalker.Entry]
        switch walker.list(containers, device: device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        case .entries(let list): containerEntries = list
        }

        var candidates: [DiscoveredCandidate] = []
        var declined = 0
        for container in containerEntries {
            if Task.isCancelled { break }
            guard InspectorWalker.isDescendable(container, device: device) else { continue }
            guard BundleIdentifierHeuristics.looksReverseDNS(container.name),
                  !BundleIdentifierHeuristics.isApple(container.name) else { continue }
            guard let appName = BundleIdentifierHeuristics.installedAppName(container.name, environment: environment) else {
                continue
            }
            guard let cachesDir = walker.descend(from: container.path, through: ["Data", "Library", "Caches"], device: device) else {
                // Either absent or a symlink / other volume; a denied lstat looks the same: nothing offered.
                continue
            }
            switch walker.list(cachesDir, device: device) {
            case .absent:
                continue
            case .declined:
                // SAFETY-DECISION: a container whose Caches cannot be listed (macOS app-data
                // protection) is skipped, never retried with other APIs.
                declined += 1
                continue
            case .entries(let entries):
                for entry in entries {
                    candidates.append(DiscoveredCandidate(
                        path: entry.path,
                        displayName: "\(appName) — \(entry.name)",
                        owningBundleID: container.name,
                        notes: ["Cache inside the sandbox container of \(appName) (\(container.name))"]
                    ))
                }
            }
        }
        if candidates.isEmpty && declined > 0 {
            return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}

// MARK: - apps.electronCaches

/// Known Electron apps: ONLY the Chromium cache subfolders directly under
/// `{HOME}/Library/Application Support/<App>/` (spec §6.6 `apps.electronCaches`).
public struct ElectronCachesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .electronCaches }

    struct KnownApp: Sendable {
        let bundleID: String
        let folder: String
        let displayName: String
    }

    // SAFETY-DECISION: explicit allow-list only. Microsoft Teams is deliberately absent: classic Teams
    // is retired and new Teams (com.microsoft.teams2) is not an Electron app storing caches under
    // Application Support/<App>/, so no folder mapping can be stated with certainty.
    static let knownApps: [KnownApp] = [
        KnownApp(bundleID: "com.tinyspeck.slackmacgap", folder: "Slack", displayName: "Slack"),
        KnownApp(bundleID: "com.hnc.Discord", folder: "discord", displayName: "Discord"),
        KnownApp(bundleID: "notion.id", folder: "Notion", displayName: "Notion"),
        KnownApp(bundleID: "com.figma.Desktop", folder: "Figma", displayName: "Figma"),
        // Spotify keeps most of its cache under ~/Library/Caches; only the exact-named Chromium
        // cache folders are taken, and only if its Application Support folder exists.
        KnownApp(bundleID: "com.spotify.client", folder: "Spotify", displayName: "Spotify"),
    ]

    // SAFETY-DECISION: exact folder names only. Never Local Storage, IndexedDB, Session Storage,
    // Cookies, databases, Service Worker or anything else.
    static let cacheFolderNames: [String] = [
        "Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache",
    ]

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let base = environment.homePath
        guard let homeStat = walker.realDirectory(base),
              let support = walker.descend(from: base, through: ["Library", "Application Support"], device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let allowed = Set(Self.cacheFolderNames.map(PathComparison.normalize))

        var candidates: [DiscoveredCandidate] = []
        for app in Self.knownApps {
            if Task.isCancelled { break }
            // SAFETY-DECISION: only for apps that are installed. Caches of uninstalled apps are
            // leftovers, handled by the (Red) OrphanDetector in a later milestone.
            guard BundleIdentifierHeuristics.installedAppName(app.bundleID, environment: environment) != nil else { continue }
            guard let appDir = walker.descend(from: support, through: [app.folder], device: device) else { continue }
            guard case .entries(let entries) = walker.list(appDir, device: device) else { continue }
            for entry in entries where allowed.contains(PathComparison.normalize(entry.name)) {
                candidates.append(DiscoveredCandidate(
                    path: entry.path,
                    displayName: "\(app.displayName) — \(entry.name)",
                    owningBundleID: app.bundleID,
                    notes: ["\(app.displayName) (\(app.bundleID)) web-content cache"]
                ))
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}

// MARK: - browser.chromium.cache

/// Chrome / Edge / Brave / Arc / Vivaldi profile caches (spec §6.6 `browser.chromium.cache`):
/// in each profile (`Default`, `Profile *`) under Application Support only `Cache`, `Code Cache` and
/// `GPUCache`; plus `{HOME}/Library/Caches/<Vendor>/<Browser>/<Profile>/Cache`.
public struct ChromiumCachesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .chromiumCaches }

    struct KnownBrowser: Sendable {
        let bundleID: String
        let displayName: String
        /// Components below `{HOME}/Library/Application Support` (user-data directory).
        let supportComponents: [String]
        /// Components below `{HOME}/Library/Caches`.
        let cachesComponents: [String]
    }

    static let knownBrowsers: [KnownBrowser] = [
        KnownBrowser(bundleID: "com.google.Chrome", displayName: "Google Chrome",
                     supportComponents: ["Google", "Chrome"], cachesComponents: ["Google", "Chrome"]),
        KnownBrowser(bundleID: "com.microsoft.edgemac", displayName: "Microsoft Edge",
                     supportComponents: ["Microsoft Edge"], cachesComponents: ["Microsoft Edge"]),
        KnownBrowser(bundleID: "com.brave.Browser", displayName: "Brave",
                     supportComponents: ["BraveSoftware", "Brave-Browser"], cachesComponents: ["BraveSoftware", "Brave-Browser"]),
        KnownBrowser(bundleID: "company.thebrowser.Browser", displayName: "Arc",
                     supportComponents: ["Arc", "User Data"], cachesComponents: ["Arc", "User Data"]),
        KnownBrowser(bundleID: "com.vivaldi.Vivaldi", displayName: "Vivaldi",
                     supportComponents: ["Vivaldi"], cachesComponents: ["Vivaldi"]),
    ]

    // SAFETY-DECISION: exact names only. Never Service Worker, Local Storage, IndexedDB, Cookies,
    // Session Storage, databases, History, Login Data or any other profile content.
    static let profileCacheNames: [String] = ["Cache", "Code Cache", "GPUCache"]
    static let cachesRootCacheNames: [String] = ["Cache"]

    /// `Default` or `Profile <something>`. Guest / System profiles are not included.
    static func isProfileName(_ name: String) -> Bool {
        let normalized = PathComparison.normalize(name)
        if normalized == "default" { return true }
        let prefix = "profile "
        return normalized.hasPrefix(prefix) && normalized.count > prefix.count
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let base = environment.homePath
        guard let homeStat = walker.realDirectory(base) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let support = walker.descend(from: base, through: ["Library", "Application Support"], device: device)
        let caches = walker.descend(from: base, through: ["Library", "Caches"], device: device)

        var candidates: [DiscoveredCandidate] = []
        for browser in Self.knownBrowsers {
            if Task.isCancelled { break }
            // SAFETY-DECISION: only for installed browsers (see ElectronCachesInspector).
            guard BundleIdentifierHeuristics.installedAppName(browser.bundleID, environment: environment) != nil else { continue }
            if let support, let userData = walker.descend(from: support, through: browser.supportComponents, device: device) {
                candidates += profileCaches(in: userData, names: Self.profileCacheNames, browser: browser,
                                            walker: walker, device: device)
            }
            if let caches, let cacheData = walker.descend(from: caches, through: browser.cachesComponents, device: device) {
                candidates += profileCaches(in: cacheData, names: Self.cachesRootCacheNames, browser: browser,
                                            walker: walker, device: device)
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    private func profileCaches(in userData: String, names: [String], browser: KnownBrowser,
                               walker: InspectorWalker, device: Int64) -> [DiscoveredCandidate] {
        guard case .entries(let profiles) = walker.list(userData, device: device) else { return [] }
        let allowed = Set(names.map(PathComparison.normalize))
        var result: [DiscoveredCandidate] = []
        for profile in profiles where Self.isProfileName(profile.name) {
            guard InspectorWalker.isDescendable(profile, device: device) else { continue }
            guard case .entries(let entries) = walker.list(profile.path, device: device) else { continue }
            for entry in entries where allowed.contains(PathComparison.normalize(entry.name)) {
                result.append(DiscoveredCandidate(
                    path: entry.path,
                    displayName: "\(browser.displayName) — \(profile.name) — \(entry.name)",
                    owningBundleID: browser.bundleID,
                    notes: ["\(browser.displayName) profile “\(profile.name)”"]
                ))
            }
        }
        return result
    }
}

// MARK: - Deny-list pre-filter (Milestone 5)

/// Read-only deny-list pre-filter used by inspectors so they never even PROPOSE a protected path or
/// walk into one. It is defence in depth only: the Scanner and SafetyGate apply the full deny-list
/// again (both spellings of the home directory) before anything is offered or acted on.
struct InspectorDenyFilter: Sendable {
    private let canonicalizer: PathCanonicalizer
    private let denyLists: [DenyList]

    init(environment: SafeCleanEnvironment) {
        let canonicalizer = PathCanonicalizer(environment: environment)
        self.canonicalizer = canonicalizer
        var homes = [environment.homePath]
        for form in PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        where !homes.contains(form.path) {
            homes.append(form.path)
        }
        // SAFETY-DECISION: one deny-list per spelling of the home directory, like the Scanner. The
        // fixture waiver is requested for the home directory itself: `DenyList` accepts it ONLY for a
        // test fixture root (strictly inside the temporary directory and named "iMopTests-…"), so for
        // a real home it is ignored and the complete deny-list applies. Without it, every path of a
        // fixture home would be denied by "/private/var/folders" before the home-relative entries,
        // extensions and `.git` are even looked at, and the pre-filter could not be tested.
        self.denyLists = homes.map { DenyList(homeDirectory: $0, waivedSystemRoots: [$0]) }
    }

    /// `true` when `path` is deny-listed (or cannot be cleaned, which also counts as denied).
    func isDenied(_ path: String, ruleID: String) -> Bool {
        guard case .success(let lexical) = canonicalizer.lexical(path) else { return true }
        return isDenied(lexical, ruleID: ruleID)
    }

    func isDenied(_ path: CanonicalPath, ruleID: String) -> Bool {
        denyLists.contains { $0.matchingEntry(for: path, ruleID: ruleID, purpose: .standard) != nil }
    }
}

// MARK: - apps.userCaches.unknownOwner

/// Folders directly in `{HOME}/Library/Caches` that cannot be attributed to an installed app
/// (spec §6.6 `apps.userCaches.unknownOwner`, Yellow).
///
/// A folder is proposed only when ALL of these hold:
/// - it is a real directory on the home volume (no symlink, file or mount point) with a plain,
///   non-hidden name;
/// - it is not `com.apple.*` and not deny-listed;
/// - its name (or a reverse-DNS prefix of it) does not resolve to an installed app — and every
///   lookup succeeded;
/// - it is not the ancestor-or-equal of anything another rule of the catalog may target (allow-roots
///   and glob bases inside `Library/Caches`, expanded wildcard globs), and not one of the known
///   tool / browser cache folders (`knownToolCacheNames`). The Scanner's overlap resolution keeps the
///   MORE cautious tier, so without this a Yellow folder here would swallow Green targets of other
///   rules (pip, Homebrew, Firefox, …) and they would silently stop being preselected.
///
/// The catalog is the one injected at init; when none is injected the bundled catalog is loaded.
public struct UnknownOwnerCachesInspector: Inspector {
    private let catalog: RuleCatalog?

    /// - Parameter catalog: the catalog whose other rules' roots are excluded. `nil` loads the
    ///   bundled catalog at discovery time.
    public init(catalog: RuleCatalog? = nil) {
        self.catalog = catalog
    }

    /// `true` when a catalog was injected at init (otherwise the bundled one is loaded).
    var hasInjectedCatalog: Bool { catalog != nil }

    public var id: InspectorID { .appUserCachesUnknownOwner }

    /// Known tool, browser and vendor cache folders directly in `{HOME}/Library/Caches` that are never
    /// proposed here, whether or not a rule for them is currently enabled (compared case- and
    /// Unicode-insensitively). The catalog-derived exclusions are added on top.
    public static let knownToolCacheNames: [String] = [
        // Package managers and toolchains (§6.2).
        "Homebrew", "pip", "pip-tools", "pipenv", "CocoaPods", "org.swift.swiftpm", "org.carthage.CarthageKit",
        "pypoetry", "ms-playwright", "Yarn", "go-build", "golangci-lint", "node-gyp", "typescript", "pnpm",
        "deno", "bun", "uv", "Jupyter", "electron", "electron-builder",
        // Editors and IDEs (§6.3).
        "JetBrains", "Google", "Microsoft",
        // Browsers (§6.6).
        "Firefox", "Mozilla", "Microsoft Edge", "BraveSoftware", "Vivaldi", "Arc", "com.apple.Safari",
        // Adobe (§6.7): owned by Creative Cloud apps whose bundle ids differ from the folder name.
        "Adobe",
        // iMop itself.
        "com.imop.cleaner", "iMop",
    ] + appleSystemCacheNames

    /// SAFETY-DECISION (review M5): plain-named caches of always-installed macOS components (no
    /// `com.apple.` prefix, and LaunchServices resolves none of them to an app). Apple-owned caches
    /// are never "unknown owner". Also reserved in `RuleTargetMatcher.unknownOwnerReservedCacheNames`.
    public static let appleSystemCacheNames: [String] = [
        "CloudKit", "GeoServices", "PassKit", "FamilyCircle", "familycircled", "GameKit", "SiriTTS", "Siri",
        "Metadata", "Maps", "AMSDataMigratorTool", "akd", "assetsd", "storeassetd", "storedownloadd", "storeaccountd",
        "SpeechRecognitionCore", "CrashReporter", "ColorSync", "FontRegistry", "TemporaryItems", "WeatherKit",
        "Safari", "SafariTechnologyPreview", "MobileAsset", "PhotosUI", "Photos", "AddressBook", "Calendar",
        "CallHistory", "Messages", "Mail", "Notes", "Reminders", "Spotlight", "Siri Suggestions", "Translation",
        "AppleMediaServices", "AppStore", "StoreKit", "News", "Stocks", "Weather", "Home", "Music", "TV",
        "Podcasts", "Books", "iBooks", "FaceTime", "Shortcuts", "Wallet", "Accessibility",
    ]

    /// SafetyGate / discovery re-check (review M5): `target` can be listed and holds no `com.apple.*`
    /// entry directly inside it (e.g. `CloudKit` holds `com.apple.*` folders), which marks it as an
    /// Apple component's cache. `nil` when it may be offered.
    public static func contentsProblem(target: CanonicalPath, fileSystem: any FileSystemProbe) -> String? {
        guard let names = fileSystem.contentsOfDirectory(target.path) else { return "its contents cannot be listed" }
        if names.contains(where: BundleIdentifierHeuristics.isApple) { return "it holds Apple (com.apple.*) data" }
        return nil
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let base = environment.homePath
        guard let homeStat = walker.realDirectory(base),
              let caches = walker.descend(from: base, through: ["Library", "Caches"], device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device

        let catalog = self.catalog ?? RuleCatalog.loadBundled(environment: environment)
        // SAFETY-DECISION: without a catalog the folders of other rules cannot be known, so nothing
        // is proposed rather than risking a Yellow folder that hides Green targets.
        guard !catalog.rules.isEmpty else {
            return InspectorOutput(candidates: [], status: .unavailable("The rule catalog could not be loaded"))
        }

        let entries: [InspectorWalker.Entry]
        switch walker.list(caches, device: device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        case .entries(let list): entries = list
        }

        let exclusions = Self.exclusions(catalog: catalog, ownRuleID: rule.id, environment: environment)
        let ruleExcluded = Set(rule.excludedNames.map(PathComparison.normalize))
        let denyFilter = InspectorDenyFilter(environment: environment)

        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage)) }
            guard InspectorWalker.isDescendable(entry, device: device), !entry.name.hasPrefix(".") else { continue }
            let normalized = PathComparison.normalize(entry.name)
            guard !BundleIdentifierHeuristics.isApple(entry.name),
                  !ruleExcluded.contains(normalized),
                  !exclusions.isExcluded(entry.name) else { continue }
            guard !denyFilter.isDenied(entry.path, ruleID: rule.id) else { continue }
            // SAFETY-DECISION: a folder named like a bundle (".app", ".bundle", …) is never proposed.
            if SafetyGate.isBundleComponent(entry.name) { continue }
            // SAFETY-DECISION (review M5): a folder holding com.apple.* entries (or that cannot be
            // listed) is treated as an Apple component's cache and never proposed.
            guard case .success(let entryPath) = PathCanonicalizer.clean(entry.path, home: nil),
                  Self.contentsProblem(target: entryPath, fileSystem: environment.fileSystem) == nil else { continue }
            switch Self.ownerResolution(entry.name, environment: environment) {
            case .installed, .lookupFailed:
                // Installed → `apps.userCaches` (Green) owns it. Lookup failed → unknown, never guessed.
                continue
            case .notInstalled:
                break
            }
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: entry.name,
                owningBundleID: nil,
                notes: [
                    "No installed app could be matched to this cache folder (\(entry.name)).",
                    "iMop cannot tell which program uses it; it may be re-created the next time that program runs.",
                ]
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    // MARK: Owner resolution

    enum OwnerResolution: Sendable, Equatable {
        case installed
        case notInstalled
        case lookupFailed
    }

    /// Whether `name` belongs to an installed app. A reverse-DNS name is looked up as is and through
    /// each of its reverse-DNS prefixes with at least three labels (`com.vendor.app.helper` →
    /// `com.vendor.app`), so helper / updater folders of installed apps are attributed to them.
    ///
    /// SAFETY-DECISION: any failed lookup (`nil`) means the owner is unknown, so the folder is not
    /// proposed as "unknown owner" (it might belong to an installed app).
    static func ownerResolution(_ name: String, environment: SafeCleanEnvironment) -> OwnerResolution {
        guard BundleIdentifierHeuristics.looksReverseDNS(name) else {
            // SAFETY-DECISION (M5 integration): a plain name is still asked about (as an identifier),
            // so that a failing app lookup also withholds plain-named folders instead of offering them
            // while it is unknown which apps are installed.
            guard let urls = environment.applications.applicationURLs(forBundleIdentifier: name) else { return .lookupFailed }
            return urls.isEmpty ? .notInstalled : .installed
        }
        var labels = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var first = true
        while first || labels.count >= 3 {
            first = false
            let candidate = labels.joined(separator: ".")
            guard let urls = environment.applications.applicationURLs(forBundleIdentifier: candidate) else {
                return .lookupFailed
            }
            if !urls.isEmpty { return .installed }
            labels.removeLast()
        }
        return .notInstalled
    }

    // MARK: Exclusions

    /// Names (and single-segment wildcard patterns) of `Library/Caches` children never proposed.
    struct Exclusions: Sendable {
        let names: Set<String>
        /// Patterns whose segment right below `Library/Caches` is a wildcard and which target that
        /// child itself (e.g. `{HOME}/Library/Caches/*.ShipIt`).
        let childPatterns: [GlobPattern]

        func isExcluded(_ name: String) -> Bool {
            if names.contains(PathComparison.normalize(name)) { return true }
            return childPatterns.contains { $0.matches(segment: name, at: 2) }
        }
    }

    /// Exclusions derived from every other rule of `catalog` plus `knownToolCacheNames` and the
    /// Chromium browsers' cache folders.
    static func exclusions(catalog: RuleCatalog, ownRuleID: String, environment: SafeCleanEnvironment) -> Exclusions {
        var names = Set(knownToolCacheNames.map(PathComparison.normalize))
        for browser in ChromiumCachesInspector.knownBrowsers {
            if let first = browser.cachesComponents.first { names.insert(PathComparison.normalize(first)) }
        }
        var childPatterns: [GlobPattern] = []

        let home = environment.homePath
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let homePath) = canonicalizer.lexical(home) else {
            return Exclusions(names: names, childPatterns: childPatterns)
        }
        let caches = homePath.appending("Library").appending("Caches")
        let cachesDepth = caches.components.count

        func excludeChild(of raw: String) {
            guard case .success(let path) = canonicalizer.lexical(raw), path.isStrictlyInside(caches) else { return }
            names.insert(PathComparison.normalize(path.components[cachesDepth]))
        }

        let expander = GlobExpander(environment: environment)
        for other in catalog.rules where other.id != ownRuleID {
            // Allow-roots inside Library/Caches (`{PROJECT_ROOTS}` and other tokens do not clean to an
            // absolute path and are ignored here).
            for raw in other.resolvedAllowRoots(home: home) { excludeChild(of: raw) }
            guard case .glob(let patterns) = other.discovery else { continue }
            for raw in patterns {
                guard let pattern = GlobPattern(raw), pattern.anchor == .home, pattern.segments.count >= 3,
                      pattern.matches(segment: "Library", at: 0), pattern.matches(segment: "Caches", at: 1) else { continue }
                if !pattern.isWildcard(at: 2) {
                    names.insert(PathComparison.normalize(pattern.segments[2]))
                } else if pattern.segments.count == 3 {
                    childPatterns.append(pattern)
                } else {
                    // e.g. `{HOME}/Library/Caches/*/org.sparkle-project.Sparkle`: exclude exactly the
                    // children that currently hold a match (read-only expansion).
                    for match in expander.expand(pattern, excludedNames: other.excludedNames) { excludeChild(of: match) }
                }
            }
        }
        return Exclusions(names: names, childPatterns: childPatterns)
    }

    /// Pure shape check for `RuleTargetMatcher`: `relative` are the components below the home
    /// directory. The catalog-derived exclusions and the owner lookup need context and are applied by
    /// discovery only.
    public static func shapeMatches(relative: [String]) -> Bool {
        guard relative.count == 3,
              PathComparison.normalize(relative[0]) == "library",
              PathComparison.normalize(relative[1]) == "caches" else { return false }
        let name = relative[2]
        guard InspectorWalker.isPlainName(name), !name.hasPrefix("."),
              !BundleIdentifierHeuristics.isApple(name), !SafetyGate.isBundleComponent(name) else { return false }
        let known = Set(knownToolCacheNames.map(PathComparison.normalize))
        return !known.contains(PathComparison.normalize(name))
    }
}

// MARK: - browser.chromium.serviceWorkerCache

/// `<profile>/Service Worker/CacheStorage` of the Chromium browsers (spec §6.6
/// `browser.chromium.serviceWorkerCache`, Yellow): same browsers and profiles as
/// `browser.chromium.cache`, and ONLY the `CacheStorage` folder — never `Service Worker/Database`,
/// `ScriptCache` or anything else in the profile.
public struct ChromiumServiceWorkerInspector: Inspector {
    public init() {}

    public var id: InspectorID { .chromiumServiceWorkerCaches }

    /// Components below a profile folder.
    static let componentsBelowProfile: [String] = ["Service Worker", "CacheStorage"]

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let base = environment.homePath
        guard let homeStat = walker.realDirectory(base),
              let support = walker.descend(from: base, through: ["Library", "Application Support"], device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let denyFilter = InspectorDenyFilter(environment: environment)

        var candidates: [DiscoveredCandidate] = []
        for browser in ChromiumCachesInspector.knownBrowsers {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage)) }
            // SAFETY-DECISION: only for installed browsers (see ElectronCachesInspector).
            guard BundleIdentifierHeuristics.installedAppName(browser.bundleID, environment: environment) != nil else { continue }
            guard let userData = walker.descend(from: support, through: browser.supportComponents, device: device),
                  case .entries(let profiles) = walker.list(userData, device: device) else { continue }
            for profile in profiles where ChromiumCachesInspector.isProfileName(profile.name) {
                guard InspectorWalker.isDescendable(profile, device: device) else { continue }
                // Every step (Service Worker, CacheStorage) must be a real directory on the home volume.
                guard let path = walker.descend(from: profile.path, through: Self.componentsBelowProfile, device: device),
                      !denyFilter.isDenied(path, ruleID: rule.id) else { continue }
                candidates.append(DiscoveredCandidate(
                    path: path,
                    displayName: "\(browser.displayName) — \(profile.name) — Service Worker cache",
                    owningBundleID: browser.bundleID,
                    notes: [
                        "\(browser.displayName) profile “\(profile.name)”",
                        "Web apps may keep offline data here; they download it again the next time you open them online.",
                    ]
                ))
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Pure shape check for `RuleTargetMatcher`: `relative` are the components below the home
    /// directory; `owner` must be the bundle id of the browser whose user-data folder it is in.
    public static func shapeMatches(relative: [String], owner: String?) -> Bool {
        guard let owner, !owner.isEmpty else { return false }
        let rel = relative.map(PathComparison.normalize)
        let normalizedOwner = PathComparison.normalize(owner)
        for browser in ChromiumCachesInspector.knownBrowsers where PathComparison.normalize(browser.bundleID) == normalizedOwner {
            let base = (["Library", "Application Support"] + browser.supportComponents).map(PathComparison.normalize)
            let tail = componentsBelowProfile.map(PathComparison.normalize)
            guard rel.count == base.count + 1 + tail.count, Array(rel.prefix(base.count)) == base,
                  Array(rel.suffix(tail.count)) == tail else { continue }
            if ChromiumCachesInspector.isProfileName(relative[base.count]) { return true }
        }
        return false
    }
}
