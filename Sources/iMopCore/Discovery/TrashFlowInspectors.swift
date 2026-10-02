import Foundation

// Read-only inspectors for the Milestone 6 Trash-action rules (spec §6.1 `xcode.extraInstalls`,
// §6.3 `jetbrains.config.orphanedVersion`, §6.6 `installers.macOS`, `trash.empty`).
//
// Like every inspector they read the file system ONLY through `SafeCleanEnvironment.fileSystem`
// (`contentsOfDirectory` + `lstat` + bounded `readFile`), run vendor tools only through
// `environment.commands` with purpose `.readOnly`, never descend through a symlink, never cross a
// volume boundary and never modify anything. The Scanner re-checks every candidate (canonicalization,
// deny-list, allow-root containment, target shape) and SafetyGate validates it again before acting.

// MARK: - Shared helpers

/// Bounded, read-only reads of an application bundle's metadata.
enum AppBundleReader {
    /// `Contents/Info.plist` of the `.app` at `appPath`, read only when `Contents` is a real directory
    /// (never a symlink) and the plist is a small regular file. `nil` on any error.
    static func infoPlist(_ appPath: String, fileSystem: any FileSystemProbe) -> [String: Any]? {
        let contents = appPath + "/Contents"
        guard let info = fileSystem.lstat(contents), info.isDirectory, !info.isSymlink else { return nil }
        return DevToolsFileReader.readPlistDictionary(contents + "/Info.plist", fileSystem: fileSystem)
    }

    /// `CFBundleIdentifier` of a parsed Info.plist (non-empty string), or `nil`.
    static func bundleIdentifier(_ plist: [String: Any]) -> String? {
        guard let id = plist["CFBundleIdentifier"] as? String, !id.isEmpty, id.utf8.count <= 255 else { return nil }
        return id
    }

    /// `true` when the name ends in `.app` (case-insensitive).
    static func isAppBundleName(_ name: String) -> Bool {
        name.count > 4 && name.lowercased().hasSuffix(".app")
    }

    /// A printable, single-line metadata value (at most 128 bytes), or `nil`.
    static func displayValue(_ value: Any?) -> String? {
        guard let text = value as? String else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= 128,
              !trimmed.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
        return trimmed
    }
}

// MARK: - xcode.extraInstalls

/// Additional copies of Xcode (`.app` bundles whose `CFBundleIdentifier` is `com.apple.dt.Xcode`)
/// directly inside `/Applications` or `{HOME}/Applications` (spec §6.1 `xcode.extraInstalls`, Red, Trash).
///
/// Bundles are found through LaunchServices, Spotlight and a direct listing of both folders; every
/// result is re-validated (exact parent folder, real directory on the parent's volume, no symlink in
/// the path, Info.plist bundle identifier). The copy holding the active developer directory
/// (`xcode-select -p`) is NEVER offered.
public struct XcodeExtraInstallsInspector: Inspector {
    public static let ruleID = "xcode.extraInstalls"
    public static let xcodeBundleID = XcodeInspectorSupport.xcodeBundleID
    static let xcodeSelectTimeout: TimeInterval = 30
    /// SAFETY-DECISION: at most this many Xcode bundles are examined; more is not a normal setup.
    static let maxBundles = 20

    private let systemApplicationsDirectory: String

    public init() {
        self.systemApplicationsDirectory = "/Applications"
    }

    /// Test-only: replaces `/Applications` with a fixture folder.
    @_spi(FixtureTesting)
    public init(systemApplicationsDirectory: String) {
        self.systemApplicationsDirectory = systemApplicationsDirectory
    }

    public var id: InspectorID { .xcodeExtraInstalls }

    /// A validated Xcode bundle.
    struct XcodeBundle {
        let path: CanonicalPath
        let version: String?
        let build: String?
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        // SAFETY-DECISION: an unknown rule id bound to this inspector gets nothing.
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not the Xcode extra installs rule"))
        }
        let canonicalizer = PathCanonicalizer(environment: environment)
        // SAFETY-DECISION: without a definite active developer directory nothing is offered: any
        // copy could be the one in use.
        guard let developerForms = await Self.activeDeveloperDirectoryForms(environment: environment, canonicalizer: canonicalizer) else {
            return InspectorOutput(candidates: [], status: .unavailable("Could not determine the active Xcode (xcode-select), so no copy of Xcode is offered"))
        }
        if Task.isCancelled { return XcodeInspectorSupport.cancelled }

        let bundles = Self.xcodeBundles(environment: environment, canonicalizer: canonicalizer,
                                        parents: [systemApplicationsDirectory, environment.homePath + "/Applications"])
        if Task.isCancelled { return XcodeInspectorSupport.cancelled }

        // SAFETY-DECISION: a bundle is "the selected Xcode" when the developer directory is inside it
        // OR it is inside the developer directory (both spellings of each).
        func isSelected(_ bundle: XcodeBundle) -> Bool {
            developerForms.contains { $0.isInsideOrEqual(bundle.path) || bundle.path.isInsideOrEqual($0) }
        }
        let selected = bundles.filter(isSelected)
        // SAFETY-DECISION: "extra" means "not the one in use". When the active developer directory is
        // not inside one of the Xcode copies found (Command Line Tools selected, Xcode elsewhere, a
        // copy iMop could not read), iMop cannot tell which copy is the user's main Xcode and offers
        // none.
        guard let kept = selected.first else {
            return InspectorOutput(candidates: [], status: .unavailable(
                "The active developer directory is not inside a copy of Xcode in Applications; choose your Xcode with xcode-select first"))
        }

        var candidates: [DiscoveredCandidate] = []
        for bundle in bundles where !isSelected(bundle) {
            var notes: [String] = []
            let versionText = [bundle.version.map { "version \($0)" }, bundle.build.map { "build \($0)" }]
                .compactMap { $0 }.joined(separator: ", ")
            if !versionText.isEmpty { notes.append("Xcode \(versionText).") }
            notes.append("The active Xcode (\(kept.path.path)) is kept.")
            notes.append("Moving an app to the Trash needs the App Management permission.")
            let name = bundle.path.lastComponent ?? "Xcode"
            let display = bundle.version.map { "Xcode \($0) (\(name))" } ?? name
            candidates.append(DiscoveredCandidate(path: bundle.path.path, displayName: display,
                                                  owningBundleID: Self.xcodeBundleID, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Both spellings (lexical and resolved) of the active developer directory, or `nil` when
    /// `xcode-select -p` cannot be run or its output is not one absolute path.
    static func activeDeveloperDirectoryForms(environment: SafeCleanEnvironment,
                                              canonicalizer: PathCanonicalizer) async -> [CanonicalPath]? {
        guard let tool = environment.commands.resolveExecutable("xcode-select") else { return nil }
        let result = await environment.commands.run(executable: tool, arguments: ["-p"], timeout: xcodeSelectTimeout,
                                                    purpose: .readOnly)
        guard result.succeeded else { return nil }
        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !output.isEmpty, !output.contains("\n"), output.hasPrefix("/") else { return nil }
        var forms: [CanonicalPath] = []
        if case .success(let lexical) = canonicalizer.lexical(output), !lexical.components.isEmpty { forms.append(lexical) }
        if case .success(let resolved) = canonicalizer.canonicalize(output), !resolved.components.isEmpty,
           !forms.contains(resolved) {
            forms.append(resolved)
        }
        return forms.isEmpty ? nil : forms
    }

    /// Every validated Xcode bundle directly inside one of `parents`.
    static func xcodeBundles(environment: SafeCleanEnvironment, canonicalizer: PathCanonicalizer,
                             parents: [String]) -> [XcodeBundle] {
        let fs = environment.fileSystem
        let walker = InspectorWalker(environment: environment)

        // Allowed parent folders: real directories whose lexical and resolved spellings agree.
        var allowedParents: [(path: CanonicalPath, device: Int64)] = []
        for raw in parents {
            guard case .success(let lexical) = canonicalizer.lexical(raw),
                  case .success(let resolved) = canonicalizer.canonicalize(raw), resolved == lexical,
                  let info = walker.realDirectory(lexical.path),
                  !allowedParents.contains(where: { $0.path == lexical }) else { continue }
            allowedParents.append((lexical, info.device))
        }
        guard !allowedParents.isEmpty else { return [] }

        // Raw candidates: direct listing (names mentioning Xcode) + LaunchServices + Spotlight.
        var raw: [String] = []
        for parent in allowedParents {
            guard case .entries(let entries) = walker.list(parent.path.path, device: parent.device) else { continue }
            for entry in entries where AppBundleReader.isAppBundleName(entry.name)
                && entry.name.lowercased().contains("xcode") {
                raw.append(entry.path)
            }
        }
        if let urls = environment.applications.applicationURLs(forBundleIdentifier: xcodeBundleID) {
            raw += urls.filter(\.isFileURL).map { $0.standardizedFileURL.path }
        }
        if let paths = environment.applications.spotlightApplicationPaths(forBundleIdentifier: xcodeBundleID) {
            raw += paths
        }

        var bundles: [XcodeBundle] = []
        var seen = Set<CanonicalPath>()
        for path in raw {
            if bundles.count >= maxBundles || Task.isCancelled { break }
            var trimmed = path
            while trimmed.count > 1 && trimmed.hasSuffix("/") { trimmed.removeLast() }
            guard trimmed.hasPrefix("/"), case .success(let lexical) = canonicalizer.lexical(trimmed),
                  let name = lexical.lastComponent, AppBundleReader.isAppBundleName(name),
                  !seen.contains(lexical) else { continue }
            // SAFETY-DECISION: exactly one level below an allowed parent (no nested or external copies).
            guard let parent = allowedParents.first(where: { lexical.depth(below: $0.path) == 1 }) else { continue }
            // SAFETY-DECISION: no symlink anywhere in the path, a real directory on the parent's volume.
            guard case .success(let resolved) = canonicalizer.canonicalize(lexical.path), resolved == lexical,
                  let info = fs.lstat(lexical.path), info.isDirectory, !info.isSymlink,
                  info.device == parent.device else { continue }
            guard let plist = AppBundleReader.infoPlist(lexical.path, fileSystem: fs),
                  let id = AppBundleReader.bundleIdentifier(plist),
                  PathComparison.normalize(id) == PathComparison.normalize(xcodeBundleID) else { continue }
            seen.insert(lexical)
            let versionPlist = DevToolsFileReader.readPlistDictionary(lexical.path + "/Contents/version.plist", fileSystem: fs)
            bundles.append(XcodeBundle(
                path: lexical,
                version: AppBundleReader.displayValue(plist["CFBundleShortVersionString"]),
                build: AppBundleReader.displayValue(versionPlist?["ProductBuildVersion"])))
        }
        return bundles.sorted { $0.path.path < $1.path.path }
    }
}

// MARK: - installers.macOS

/// `/Applications/Install macOS *.app` (spec §6.6 `installers.macOS`, Yellow, Trash).
///
/// Only real `.app` directories directly in `/Applications` whose Info.plist identifies Apple's
/// installer (`com.apple.InstallAssistant…`) are offered; the bundle identifier becomes the owner so
/// `owningAppNotRunning` re-checks it before acting.
public struct MacOSInstallersInspector: Inspector {
    public static let ruleID = "installers.macOS"
    static let namePrefix = "Install macOS "
    /// SAFETY-DECISION: only Apple's installer apps (their bundle identifiers all start with this).
    static let installerBundleIDPrefix = "com.apple.InstallAssistant"
    static let maxInstallers = 20

    private let applicationsDirectory: String

    public init() {
        self.applicationsDirectory = "/Applications"
    }

    /// Test-only: replaces `/Applications` with a fixture folder.
    @_spi(FixtureTesting)
    public init(applicationsDirectory: String) {
        self.applicationsDirectory = applicationsDirectory
    }

    public var id: InspectorID { .macOSInstallers }

    /// `true` for `Install macOS <something>.app` (the glob `Install macOS *.app`).
    public static func isInstallerName(_ name: String) -> Bool {
        name.hasPrefix(namePrefix) && name.hasSuffix(".app") && name.count > namePrefix.count + 4
            && InspectorWalker.isPlainName(name)
    }

    /// `true` for an Apple installer bundle identifier.
    public static func isInstallerBundleID(_ id: String) -> Bool {
        let normalized = PathComparison.normalize(id)
        let prefix = PathComparison.normalize(installerBundleIDPrefix)
        return normalized.hasPrefix(prefix + ".") || normalized == prefix
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not the macOS installers rule"))
        }
        let walker = InspectorWalker(environment: environment)
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let lexical) = canonicalizer.lexical(applicationsDirectory),
              case .success(let resolved) = canonicalizer.canonicalize(applicationsDirectory), resolved == lexical,
              let info = walker.realDirectory(lexical.path) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let entries: [InspectorWalker.Entry]
        switch walker.list(lexical.path, device: info.device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return XcodeInspectorSupport.declined
        case .entries(let list): entries = list
        }
        var candidates: [DiscoveredCandidate] = []
        for entry in entries where Self.isInstallerName(entry.name) {
            if Task.isCancelled { return XcodeInspectorSupport.cancelled }
            if candidates.count >= Self.maxInstallers { break }
            guard InspectorWalker.isDescendable(entry, device: info.device) else { continue }
            // SAFETY-DECISION: an installer whose Info.plist cannot be read, or that is not Apple's
            // installer, is not offered.
            guard let plist = AppBundleReader.infoPlist(entry.path, fileSystem: environment.fileSystem),
                  let bundleID = AppBundleReader.bundleIdentifier(plist), Self.isInstallerBundleID(bundleID) else { continue }
            var notes: [String] = []
            if let version = AppBundleReader.displayValue(plist["DTPlatformVersion"])
                ?? AppBundleReader.displayValue(plist["CFBundleShortVersionString"]) {
                notes.append("Installer version \(version).")
            }
            notes.append("You can download this installer again from Software Update or the App Store.")
            notes.append("Moving an app to the Trash needs the App Management permission.")
            let display = String(entry.name.dropLast(4))
            candidates.append(DiscoveredCandidate(path: entry.path, displayName: display, owningBundleID: bundleID, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}

// MARK: - jetbrains.config.orphanedVersion

/// `{HOME}/Library/Application Support/JetBrains/<Product><major>.<minor>` for product versions that
/// are no longer installed (spec §6.3 `jetbrains.config.orphanedVersion`, Red, Trash).
///
/// Uses exactly the fail-closed classification of `JetBrainsCachesInspector`: a folder is offered only
/// for a KNOWN product for which every installed app of that product family was found and read, at
/// least one such app exists, and none has that major.minor version. Everything else (unknown
/// product, failed lookup, unreadable plist, no app found, version installed) is never offered.
public struct JetBrainsConfigInspector: Inspector {
    public static let ruleID = "jetbrains.config.orphanedVersion"
    static let configComponents = ["Library", "Application Support", "JetBrains"]

    public init() {}

    public var id: InspectorID { .jetbrainsConfig }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not the JetBrains settings rule"))
        }
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let config = walker.descend(from: home, through: Self.configComponents, device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let entries: [InspectorWalker.Entry]
        switch walker.list(config, device: device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return XcodeInspectorSupport.declined
        case .entries(let list): entries = list
        }

        var lookups: [String: JetBrainsCachesInspector.InstalledVersions] = [:]
        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if Task.isCancelled { return XcodeInspectorSupport.cancelled }
            guard InspectorWalker.isDescendable(entry, device: device),
                  let parsed = JetBrainsCachesInspector.parseFolderName(entry.name),
                  // SAFETY-DECISION: an unknown product is never classified as orphaned.
                  let owner = JetBrainsCachesInspector.bundleID(forProduct: parsed.product) else { continue }
            let installed: JetBrainsCachesInspector.InstalledVersions
            if let cached = lookups[owner] {
                installed = cached
            } else {
                installed = JetBrainsCachesInspector.installedVersions(of: owner, environment: environment)
                lookups[owner] = installed
            }
            // SAFETY-DECISION: same fail-closed rules as the caches inspector — `.unknown` and "no app
            // of the product found at all" are both treated as "maybe still installed".
            guard case .known(let versions) = installed, !versions.isEmpty, !versions.contains(parsed.version) else { continue }
            let versionText = DevToolsFileReader.versionString(parsed.version)
            let list = versions.sorted { DevToolsFileReader.compareVersions($0, $1) == .orderedAscending }
                .map(DevToolsFileReader.versionString).joined(separator: ", ")
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: "\(parsed.product) \(versionText) settings",
                owningBundleID: owner,
                notes: [
                    "\(parsed.product) \(versionText) is no longer installed (installed: \(list)).",
                    "This folder contains that version's IDE settings (keymaps, code styles, plugins and other preferences).",
                ]))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Target shape for `RuleTargetMatcher`: `Library/Application Support/JetBrains/<Product><major>.<minor>`
    /// of a known product, owned by that product's bundle identifier.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        guard relative.count == configComponents.count + 1,
              XcodeInspectorSupport.hasPrefix(relative, configComponents),
              let owner, let parsed = JetBrainsCachesInspector.parseFolderName(relative[relative.count - 1]),
              let expected = JetBrainsCachesInspector.bundleID(forProduct: parsed.product) else { return false }
        return PathComparison.normalize(owner) == PathComparison.normalize(expected)
    }
}

// MARK: - trash.empty

/// The immediate children of `{HOME}/.Trash` (spec §6.6 `trash.empty`, Yellow, permanent removal
/// behind an explicit "Empty Trash" confirmation). The UI groups them into one choice; every child
/// is still its own target so SafetyGate checks each one.
public struct TrashContentsInspector: Inspector {
    public static let ruleID = "trash.empty"
    static let trashComponents = [".Trash"]

    public init() {}

    public var id: InspectorID { .trashContents }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not the Empty Trash rule"))
        }
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let trash = walker.descend(from: home, through: Self.trashComponents, device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let entries: [InspectorWalker.Entry]
        switch walker.list(trash, device: homeStat.device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        // The Trash is protected by Full Disk Access: a refused listing means it is not granted.
        case .declined: return InspectorOutput(candidates: [], status: .lockedNeedsFullDiskAccess)
        case .entries(let list): entries = list
        }
        // SAFETY-DECISION: symlinks and anything on another volume are left in the Trash (never
        // offered), so a permanent removal can never reach outside the Trash folder.
        let usable = entries.filter { !$0.stat.isSymlink && $0.stat.device == homeStat.device }
        guard !usable.isEmpty else { return InspectorOutput(candidates: [], status: .ok) }

        var summary = "Part of Empty Trash: \(usable.count) item\(usable.count == 1 ? "" : "s") in the Trash"
        if let estimate = SizeCalculator(environment: environment).measure(path: trash) {
            summary += ", \(CommandDiscovery.formatBytes(estimate.allocatedBytes)) on disk"
            if !estimate.complete { summary += " (some items could not be measured)" }
        }
        summary += "."
        var notes = [summary, "Emptying the Trash cannot be undone."]
        let skipped = entries.count - usable.count
        if skipped > 0 {
            notes.append("\(skipped) item\(skipped == 1 ? " is" : "s are") left in the Trash (symbolic links or items on another volume).")
        }
        var candidates: [DiscoveredCandidate] = []
        for entry in usable {
            if Task.isCancelled { return XcodeInspectorSupport.cancelled }
            candidates.append(DiscoveredCandidate(path: entry.path, displayName: entry.name, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Target shape for `RuleTargetMatcher`: exactly one level below `.Trash`.
    public static func matchesTargetShape(relative: [String]) -> Bool {
        relative.count == trashComponents.count + 1 && XcodeInspectorSupport.hasPrefix(relative, trashComponents)
    }
}
