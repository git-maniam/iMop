import Foundation

// Read-only JetBrains cache inspector (spec §6.3 `jetbrains.caches.orphanedVersion` / `.current`).
//
// Walks `{HOME}/Library/Caches/JetBrains` through `SafeCleanEnvironment.fileSystem` only
// (`contentsOfDirectory` + `lstat`), never through a symlink or across a volume, and reads the
// installed apps' `Contents/Info.plist` (a single bounded file read, no walk inside the bundle) to
// learn their versions. It never modifies anything.

/// `{HOME}/Library/Caches/JetBrains/<Product><Version>` (e.g. `IntelliJIdea2024.1`).
///
/// - `jetbrains.caches.orphanedVersion` (Green): only folders of a KNOWN product for which every
///   installed app of that product (any channel: release, EAP, …) was found, read and parsed, at
///   least one such app exists, and none has that major.minor version.
/// - `jetbrains.caches.current` (Yellow): every other parsable folder (that version is installed,
///   the product is unknown, or the lookup / any app plist failed).
public struct JetBrainsCachesInspector: Inspector {
    public static let orphanedRuleID = "jetbrains.caches.orphanedVersion"
    public static let currentRuleID = "jetbrains.caches.current"
    static let cachesComponents = ["Library", "Caches", "JetBrains"]

    /// Cache-folder product name → bundle identifier of that product's app.
    ///
    /// SAFETY-DECISION: only products whose folder name and bundle identifier are certain. Anything
    /// else is never classified as orphaned.
    public static let productBundleIDs: [String: String] = [
        "IntelliJIdea": "com.jetbrains.intellij",
        "IdeaIC": "com.jetbrains.intellij.ce",
        "PyCharm": "com.jetbrains.pycharm",
        "PyCharmCE": "com.jetbrains.pycharm.ce",
        "WebStorm": "com.jetbrains.WebStorm",
        "GoLand": "com.jetbrains.goland",
        "CLion": "com.jetbrains.CLion",
        "Rider": "com.jetbrains.rider",
        "PhpStorm": "com.jetbrains.PhpStorm",
        "RubyMine": "com.jetbrains.rubymine",
        "DataGrip": "com.jetbrains.datagrip",
        "AndroidStudio": "com.google.android.studio",
    ]

    public init() {}

    public var id: InspectorID { .jetbrainsCaches }

    /// A `<Product><major>.<minor>` folder name.
    public struct ParsedName: Sendable, Equatable {
        public let product: String
        public let version: [Int]
    }

    /// `"IntelliJIdea2024.1"` → (`IntelliJIdea`, [2024, 1]). The product is ASCII letters only and the
    /// version exactly `<digits>.<digits>`; anything else (e.g. `Toolbox`) is `nil`.
    public static func parseFolderName(_ name: String) -> ParsedName? {
        guard let firstDigit = name.firstIndex(where: { $0.isASCII && $0.isNumber }) else { return nil }
        let product = name[..<firstDigit]
        let versionText = name[firstDigit...]
        guard !product.isEmpty, product.unicodeScalars.allSatisfy({ $0.isASCII && CharacterSet.letters.contains($0) }) else { return nil }
        let groups = versionText.split(separator: ".", omittingEmptySubsequences: false)
        guard groups.count == 2, DevToolsFileReader.isDottedVersion(versionText) else { return nil }
        let version = groups.compactMap { Int($0) }
        guard version.count == 2 else { return nil }
        return ParsedName(product: String(product), version: version)
    }

    /// Bundle identifier of a product name (case-insensitive), or `nil` when unknown.
    public static func bundleID(forProduct product: String) -> String? {
        let wanted = PathComparison.normalize(product)
        return productBundleIDs.first { PathComparison.normalize($0.key) == wanted }?.value
    }

    /// Result of looking up which versions of a product are installed.
    enum InstalledVersions {
        /// Every installed app was found and parsed: their major.minor versions (possibly none).
        case known(Set<[Int]>)
        /// The lookup failed or some app's version could not be read.
        case unknown
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let wantOrphaned: Bool
        switch rule.id {
        case Self.orphanedRuleID: wantOrphaned = true
        case Self.currentRuleID: wantOrphaned = false
        // SAFETY-DECISION: an unknown rule id bound to this inspector gets nothing.
        default: return InspectorOutput(candidates: [], status: .unavailable("Not a JetBrains caches rule"))
        }
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let caches = walker.descend(from: home, through: Self.cachesComponents, device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let entries: [InspectorWalker.Entry]
        switch walker.list(caches, device: device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        case .entries(let list): entries = list
        }

        var lookups: [String: InstalledVersions] = [:]
        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed("Scan cancelled")) }
            guard InspectorWalker.isDescendable(entry, device: device) else { continue }
            // SAFETY-DECISION: folders that are not `<Product><major>.<minor>` (Toolbox, logs, …) are
            // not something this rule understands and are not offered at all.
            guard let parsed = Self.parseFolderName(entry.name) else { continue }
            let versionText = DevToolsFileReader.versionString(parsed.version)
            let owner = Self.bundleID(forProduct: parsed.product)

            var orphaned = false
            var notes: [String] = []
            if let owner {
                let installed: InstalledVersions
                if let cached = lookups[owner] {
                    installed = cached
                } else {
                    installed = Self.installedVersions(of: owner, environment: environment)
                    lookups[owner] = installed
                }
                switch installed {
                case .known(let versions):
                    if versions.contains(parsed.version) {
                        notes.append("\(parsed.product) \(versionText) is installed.")
                    } else if versions.isEmpty {
                        // SAFETY-DECISION (review M5): no copy of the product found at all cannot be told
                        // apart from "installed but not registered with LaunchServices" (a Toolbox
                        // install never opened from Finder, an unusual channel): CURRENT, never orphaned.
                        notes.append("No \(parsed.product) app was found; it may still be installed somewhere iMop cannot see.")
                    } else {
                        orphaned = true
                        let list = versions.sorted { DevToolsFileReader.compareVersions($0, $1) == .orderedAscending }
                            .map(DevToolsFileReader.versionString).joined(separator: ", ")
                        notes.append("\(parsed.product) \(versionText) is no longer installed (installed: \(list)).")
                    }
                case .unknown:
                    // SAFETY-DECISION: a failed lookup or an unreadable app plist means "maybe still
                    // installed": CURRENT (Yellow), never orphaned.
                    notes.append("Could not confirm which \(parsed.product) versions are installed.")
                }
            } else {
                // SAFETY-DECISION: an unknown product is never classified as orphaned.
                notes.append("Unrecognised JetBrains product “\(parsed.product)”; treated as installed.")
            }
            guard orphaned == wantOrphaned else { continue }
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: "\(parsed.product) \(versionText) caches",
                owningBundleID: owner,
                notes: notes
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Release-channel suffixes JetBrains appends to a product's bundle identifier (EAP / preview
    /// builds share the release's `<Product><major.minor>` cache folder).
    public static let channelSuffixes = ["-EAP", ".EAP", "-eap", "-Preview", "-RC", "-Nightly"]

    /// Every bundle identifier of `bundleID`'s product family: the release id plus its channel ids.
    public static func bundleIDFamily(_ bundleID: String) -> [String] {
        [bundleID] + channelSuffixes.map { bundleID + $0 }
    }

    /// major.minor versions of every installed app of `bundleID`'s product FAMILY (release and EAP /
    /// preview channels; LaunchServices, plus Spotlight when it answers). `.unknown` when any
    /// LaunchServices lookup fails or any app's version cannot be read.
    ///
    /// SAFETY-DECISION (review M5): a cache folder is orphaned only when no app of ANY channel of the
    /// product has that major.minor version.
    static func installedVersions(of bundleID: String, environment: SafeCleanEnvironment) -> InstalledVersions {
        var appPaths: [String] = []
        for id in bundleIDFamily(bundleID) {
            guard let urls = environment.applications.applicationURLs(forBundleIdentifier: id) else { return .unknown }
            appPaths += urls.map { $0.standardizedFileURL.path }
            // Spotlight is additive only: it can reveal more installed copies, never fewer.
            if let more = environment.applications.spotlightApplicationPaths(forBundleIdentifier: id) {
                appPaths += more
            }
        }
        var seen = Set<String>()
        var versions = Set<[Int]>()
        for path in appPaths {
            var trimmed = path
            while trimmed.count > 1 && trimmed.hasSuffix("/") { trimmed.removeLast() }
            guard trimmed.hasPrefix("/"), seen.insert(PathComparison.normalize(trimmed)).inserted else { continue }
            guard let plist = DevToolsFileReader.readPlistDictionary(trimmed + "/Contents/Info.plist", fileSystem: environment.fileSystem),
                  let short = plist["CFBundleShortVersionString"] as? String,
                  let numbers = DevToolsFileReader.numericVersionPrefix(short), numbers.count >= 2 else {
                return .unknown
            }
            versions.insert(Array(numbers.prefix(2)))
        }
        return .known(versions)
    }

    /// Target shape for `RuleTargetMatcher`: `Library/Caches/JetBrains/<Product><major>.<minor>` of a
    /// known product, owned by that product's bundle identifier.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        guard relative.count == cachesComponents.count + 1,
              XcodeInspectorSupport.hasPrefix(relative, cachesComponents),
              let owner, let parsed = parseFolderName(relative[relative.count - 1]),
              let expected = bundleID(forProduct: parsed.product) else { return false }
        return PathComparison.normalize(owner) == PathComparison.normalize(expected)
    }
}
