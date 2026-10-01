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
        case .declined: return InspectorOutput(candidates: [], status: .unavailable("Access was declined"))
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
        case .declined: return InspectorOutput(candidates: [], status: .unavailable("Access was declined"))
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
            return InspectorOutput(candidates: [], status: .unavailable("Access was declined"))
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
