import Foundation

// Read-only Xcode inspectors (spec §6.1): DerivedData (orphaned / active), Archives (keep newest N
// per bundle identifier) and DeviceSupport.
//
// Like every inspector they walk the file system ONLY through `SafeCleanEnvironment.fileSystem`
// (`contentsOfDirectory` + `lstat` + `readFile`), never through a symlink, never across a volume
// boundary, and never modify anything. The Scanner re-checks every candidate (canonicalization,
// deny-list, allow-root containment, target shape) and SafetyGate validates it again before acting.

// MARK: - Shared read-only helpers (Xcode, JetBrains, VS Code inspectors)

/// Bounded, read-only reads of small metadata files (plists, JSON) through the injected probe.
enum DevToolsFileReader {
    /// SAFETY-DECISION: metadata files larger than this are not parsed (the item is skipped).
    static let maxMetadataBytes: Int64 = 4 * 1024 * 1024

    /// Contents of `path` when it is a real (non-symlink) regular file of at most `maxMetadataBytes`.
    static func readSmallFile(_ path: String, fileSystem: any FileSystemProbe) -> Data? {
        guard let info = fileSystem.lstat(path), info.isRegularFile, !info.isSymlink,
              info.logicalSize >= 0, info.logicalSize <= maxMetadataBytes else { return nil }
        guard let data = fileSystem.readFile(path), Int64(data.count) <= maxMetadataBytes else { return nil }
        return data
    }

    /// Top-level dictionary of the property list at `path`, or `nil` on any error.
    static func readPlistDictionary(_ path: String, fileSystem: any FileSystemProbe) -> [String: Any]? {
        guard let data = readSmallFile(path, fileSystem: fileSystem) else { return nil }
        guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else { return nil }
        return object as? [String: Any]
    }

    /// Top-level JSON value of the file at `path`, or `nil` on any error.
    static func readJSON(_ path: String, fileSystem: any FileSystemProbe) -> Any? {
        guard let data = readSmallFile(path, fileSystem: fileSystem) else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [])
    }

    /// Dotted numeric version prefix ("2024.1.4 EAP" → [2024, 1, 4]); `nil` when it does not start
    /// with a digit.
    static func numericVersionPrefix(_ text: String) -> [Int]? {
        var parts: [Int] = []
        var current = ""
        for character in text {
            if let digit = character.wholeNumberValue, character.isASCII {
                current.append(Character(String(digit)))
                guard current.count <= 9 else { return nil }
            } else if character == "." && !current.isEmpty {
                parts.append(Int(current)!)
                current = ""
            } else {
                break
            }
        }
        if !current.isEmpty { parts.append(Int(current)!) }
        return parts.isEmpty ? nil : parts
    }

    /// `true` for "1", "17.5", "17.5.1", "10.15.7.1": 1…4 dot-separated ASCII digit groups.
    static func isDottedVersion(_ token: Substring) -> Bool {
        let groups = token.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(groups.count) else { return false }
        return groups.allSatisfy { group in
            !group.isEmpty && group.count <= 9 && group.unicodeScalars.allSatisfy { $0.isASCII && CharacterSet.decimalDigits.contains($0) }
        }
    }

    /// Lexicographic comparison of numeric version arrays (missing groups count as 0).
    static func compareVersions(_ lhs: [Int], _ rhs: [Int]) -> ComparisonResult {
        for index in 0..<max(lhs.count, rhs.count) {
            let a = index < lhs.count ? lhs[index] : 0
            let b = index < rhs.count ? rhs[index] : 0
            if a < b { return .orderedAscending }
            if a > b { return .orderedDescending }
        }
        return .orderedSame
    }

    static func versionString(_ version: [Int]) -> String {
        version.map(String.init).joined(separator: ".")
    }

    static func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }
}

/// Common start of the Xcode inspectors: the home volume and `{HOME}/Library/Developer/Xcode`.
enum XcodeInspectorSupport {
    static let xcodeBundleID = "com.apple.dt.Xcode"
    static let xcodeComponents = ["Library", "Developer", "Xcode"]
    static let cancelled = InspectorOutput(candidates: [], status: .failed("Scan cancelled"))
    static let declined = InspectorOutput(candidates: [], status: .unavailable("Access was declined"))
    static let nothing = InspectorOutput(candidates: [], status: .ok)

    /// `(walker, home device, Xcode directory)`, or `nil` when the Xcode directory is absent.
    static func xcodeDirectory(_ environment: SafeCleanEnvironment) -> (InspectorWalker, Int64, String)? {
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let xcode = walker.descend(from: home, through: xcodeComponents, device: homeStat.device) else { return nil }
        return (walker, homeStat.device, xcode)
    }

    /// `true` when `relative` (components below the home directory) starts with `prefix` (normalized).
    static func hasPrefix(_ relative: [String], _ prefix: [String]) -> Bool {
        relative.count >= prefix.count
            && zip(relative, prefix).allSatisfy { PathComparison.normalize($0) == PathComparison.normalize($1) }
    }

    static func ownerIsXcode(_ owner: String?) -> Bool {
        guard let owner else { return false }
        return PathComparison.normalize(owner) == PathComparison.normalize(xcodeBundleID)
    }
}

// MARK: - xcode.derivedData.orphaned / xcode.derivedData.active

/// `{HOME}/Library/Developer/Xcode/DerivedData/*`, split by whether the project named in each
/// folder's `info.plist` (`WorkspacePath`) still exists.
///
/// - `xcode.derivedData.orphaned` (Green): only folders whose `WorkspacePath` is PROVEN absent.
/// - `xcode.derivedData.active` (Yellow): every other folder (project exists, or unknown).
public struct XcodeDerivedDataInspector: Inspector {
    public static let orphanedRuleID = "xcode.derivedData.orphaned"
    public static let activeRuleID = "xcode.derivedData.active"
    static let derivedDataComponents = XcodeInspectorSupport.xcodeComponents + ["DerivedData"]

    public init() {}

    public var id: InspectorID { .xcodeDerivedData }

    /// Whether the project a DerivedData folder belongs to still exists.
    enum ProjectState: Equatable {
        case exists(String)
        /// Proven absent: the nearest existing ancestor was listed and the next component is missing.
        case absent(String)
        /// `info.plist` missing / unreadable / unparsable, or existence could not be proven either way.
        case unknown(String?)
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let wantOrphaned: Bool
        switch rule.id {
        case Self.orphanedRuleID: wantOrphaned = true
        case Self.activeRuleID: wantOrphaned = false
        // SAFETY-DECISION: an unknown rule id bound to this inspector gets nothing.
        default: return InspectorOutput(candidates: [], status: .unavailable("Not a DerivedData rule"))
        }
        guard let (walker, device, xcode) = XcodeInspectorSupport.xcodeDirectory(environment),
              let derivedData = walker.descend(from: xcode, through: ["DerivedData"], device: device) else {
            return XcodeInspectorSupport.nothing
        }
        let entries: [InspectorWalker.Entry]
        switch walker.list(derivedData, device: device) {
        case .absent: return XcodeInspectorSupport.nothing
        case .declined: return XcodeInspectorSupport.declined
        case .entries(let list): entries = list
        }

        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if Task.isCancelled { return XcodeInspectorSupport.cancelled }
            guard InspectorWalker.isDescendable(entry, device: device) else { continue }
            let state = Self.projectState(of: entry.path, fileSystem: environment.fileSystem)
            var notes: [String] = []
            switch state {
            case .absent(let workspace):
                guard wantOrphaned else { continue }
                notes.append("The project this build data belongs to no longer exists: \(workspace)")
            case .exists(let workspace):
                guard !wantOrphaned else { continue }
                notes.append("Project: \(workspace)")
            case .unknown(let workspace):
                // SAFETY-DECISION: a folder whose project cannot be PROVEN gone is treated as ACTIVE
                // (Yellow, never preselected, age-gated), never as orphaned.
                guard !wantOrphaned else { continue }
                if let workspace {
                    notes.append("Project: \(workspace) (could not confirm whether it still exists)")
                } else {
                    notes.append("The project this build data belongs to could not be determined.")
                }
            }
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: "DerivedData — \(entry.name)",
                owningBundleID: XcodeInspectorSupport.xcodeBundleID,
                notes: notes
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Reads `<folder>/info.plist → WorkspacePath` and decides whether that path exists.
    static func projectState(of folder: String, fileSystem: any FileSystemProbe) -> ProjectState {
        guard let plist = DevToolsFileReader.readPlistDictionary(folder + "/info.plist", fileSystem: fileSystem),
              let workspace = plist["WorkspacePath"] as? String, !workspace.isEmpty else {
            return .unknown(nil)
        }
        return existence(of: workspace, fileSystem: fileSystem)
    }

    /// Decides whether `rawPath` exists without ever following a symlink.
    ///
    /// SAFETY-DECISION: `lstat` returning nothing is NOT proof of absence (a TCC-protected folder or
    /// an I/O error looks the same). A path is only "absent" when its nearest existing ancestor is a
    /// real directory that could be listed and the next component is not in that listing. Anything
    /// passing through a symlink, a relative or unclean path, a path below a mount area (`/Volumes`,
    /// `/net`, …: an external disk that may simply not be mounted right now), or a listing of a mount
    /// point or of an empty folder is `unknown`.
    static func existence(of rawPath: String, fileSystem: any FileSystemProbe) -> ProjectState {
        guard rawPath.hasPrefix("/"), !rawPath.contains("\0") else { return .unknown(rawPath) }
        var components = rawPath.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(String.init)
        if components.last == "" { components.removeLast() } // one trailing slash is tolerated
        guard !components.isEmpty, components.allSatisfy(InspectorWalker.isPlainName) else { return .unknown(rawPath) }
        // `/var`, `/tmp` and `/etc` are symlinks into `/private`; use the resolved spelling.
        if ["var", "tmp", "etc"].contains(components[0]) { components.insert("private", at: 0) }
        if isMountArea(components) { return .unknown(rawPath) }

        var current = ""
        // Devices of "/" and of every directory lstat'ed so far (index i = device of the path made of
        // the first i components).
        guard let rootInfo = fileSystem.lstat("/") else { return .unknown(rawPath) }
        var devices: [Int64] = [rootInfo.device]
        for (index, component) in components.enumerated() {
            let parent = current.isEmpty ? "/" : current
            current += "/" + component
            if let info = fileSystem.lstat(current) {
                if index == components.count - 1 { return .exists(rawPath) }
                guard info.isDirectory, !info.isSymlink else { return .unknown(rawPath) }
                devices.append(info.device)
                continue
            }
            guard let names = fileSystem.contentsOfDirectory(parent) else { return .unknown(rawPath) }
            let wanted = PathComparison.normalize(component)
            if names.contains(where: { PathComparison.normalize($0) == wanted }) {
                // Listed but not lstat-able: cannot decide.
                return .unknown(rawPath)
            }
            // SAFETY-DECISION (review M5): a listing is only proof of absence when the listed folder is
            // an ordinary folder. A mount point (device differs from its parent's: the volume may be a
            // different one than the project's) and an EMPTY folder (what an unmounted mount point —
            // sshfs / macFUSE under ~, `hdiutil -mountpoint`, autofs — looks like) are not: the project
            // may only be temporarily unavailable → unknown (active, Yellow), never orphaned.
            if index >= 1, devices[index] != devices[index - 1] { return .unknown(rawPath) }
            if !names.contains(where: { InspectorWalker.isPlainName($0) && !$0.hasPrefix(".") }) { return .unknown(rawPath) }
            return .absent(rawPath)
        }
        return .unknown(rawPath)
    }

    /// Top-level areas where volumes are mounted (and may simply not be mounted right now):
    /// `/Volumes`, `/System/Volumes`, autofs `/net`, `/Network`, `/private/var/automount`, `/mnt`.
    static func isMountArea(_ components: [String]) -> Bool {
        let n = components.map(PathComparison.normalize)
        guard let first = n.first else { return true }
        if ["volumes", "net", "network", "mnt", "automount"].contains(first) { return true }
        if first == "system", n.count > 1, n[1] == "volumes" { return true }
        if first == "private", n.count > 2, n[1] == "var", n[2] == "automount" { return true }
        return false
    }

    /// Target shape (components below the home directory) for `RuleTargetMatcher`:
    /// `Library/Developer/Xcode/DerivedData/<folder>`, owned by Xcode.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        relative.count == derivedDataComponents.count + 1
            && XcodeInspectorSupport.hasPrefix(relative, derivedDataComponents)
            && InspectorWalker.isPlainName(relative[relative.count - 1])
            && XcodeInspectorSupport.ownerIsXcode(owner)
    }
}

// MARK: - xcode.archives.old

/// `{HOME}/Library/Developer/Xcode/Archives/*/*.xcarchive` beyond the newest N per bundle identifier
/// (N = `ScanSettings.effectiveArchivesToKeep`).
public struct XcodeArchivesInspector: Inspector {
    public static let ruleID = "xcode.archives.old"
    static let archivesComponents = XcodeInspectorSupport.xcodeComponents + ["Archives"]
    static let archiveExtension = ".xcarchive"

    public init() {}

    public var id: InspectorID { .xcodeArchives }

    struct ArchiveInfo {
        let path: String
        let name: String
        let bundleID: String
        let created: Date
        let version: String?
        let appName: String?
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not an Xcode archives rule"))
        }
        guard let (walker, device, xcode) = XcodeInspectorSupport.xcodeDirectory(environment),
              let archives = walker.descend(from: xcode, through: ["Archives"], device: device) else {
            return XcodeInspectorSupport.nothing
        }
        let dateFolders: [InspectorWalker.Entry]
        switch walker.list(archives, device: device) {
        case .absent: return XcodeInspectorSupport.nothing
        case .declined: return XcodeInspectorSupport.declined
        case .entries(let list): dateFolders = list
        }

        var parsed: [ArchiveInfo] = []
        for folder in dateFolders {
            if Task.isCancelled { return XcodeInspectorSupport.cancelled }
            guard InspectorWalker.isDescendable(folder, device: device) else { continue }
            // A date folder that cannot be listed only hides archives; with fewer archives known the
            // keep-N cut can only offer fewer (never more) of the ones that were seen.
            guard case .entries(let items) = walker.list(folder.path, device: device) else { continue }
            for item in items where Self.isArchiveName(item.name) {
                guard InspectorWalker.isDescendable(item, device: device) else { continue }
                // SAFETY-DECISION: an archive whose Info.plist is missing, unreadable or lacks a bundle
                // identifier or creation date is KEPT (never offered). Only the archive's top-level
                // Info.plist is read; nothing inside the package is listed or walked.
                guard let info = Self.parseArchive(item, fileSystem: environment.fileSystem) else { continue }
                parsed.append(info)
            }
        }

        let keep = environment.scanSettings.effectiveArchivesToKeep
        let old = Self.archivesBeyondKeep(parsed, keep: keep)
        var candidates: [DiscoveredCandidate] = []
        for archive in old {
            var notes = ["Bundle ID: \(archive.bundleID)", "Created \(DevToolsFileReader.formatDate(archive.created))"]
            if let version = archive.version { notes.append("Version \(version)") }
            notes.append("The newest \(keep) archive\(keep == 1 ? "" : "s") of this app \(keep == 1 ? "is" : "are") kept.")
            let label = archive.appName ?? archive.bundleID
            candidates.append(DiscoveredCandidate(
                path: archive.path,
                displayName: "\(label) — \(archive.name)",
                owningBundleID: XcodeInspectorSupport.xcodeBundleID,
                notes: notes
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    static func isArchiveName(_ name: String) -> Bool {
        let normalized = PathComparison.normalize(name)
        return normalized.hasSuffix(archiveExtension) && normalized.count > archiveExtension.count
    }

    static func parseArchive(_ item: InspectorWalker.Entry, fileSystem: any FileSystemProbe) -> ArchiveInfo? {
        guard let plist = DevToolsFileReader.readPlistDictionary(item.path + "/Info.plist", fileSystem: fileSystem),
              let properties = plist["ApplicationProperties"] as? [String: Any],
              let rawID = properties["CFBundleIdentifier"] as? String,
              let created = plist["CreationDate"] as? Date else { return nil }
        let bundleID = rawID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bundleID.isEmpty else { return nil }
        var version: String?
        if let short = properties["CFBundleShortVersionString"] as? String, !short.isEmpty {
            if let build = properties["CFBundleVersion"] as? String, !build.isEmpty, build != short {
                version = "\(short) (\(build))"
            } else {
                version = short
            }
        }
        let appName = (plist["Name"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return ArchiveInfo(path: item.path, name: item.name, bundleID: bundleID, created: created,
                           version: version, appName: appName)
    }

    /// Archives older than the `keep` newest of their bundle identifier.
    ///
    /// SAFETY-DECISION: bundle identifiers are grouped by their exact string (never merged, so a
    /// group can only be larger, never smaller, than intended), and every archive whose creation
    /// date equals the N-th newest date is kept too (ties keep both).
    static func archivesBeyondKeep(_ archives: [ArchiveInfo], keep: Int) -> [ArchiveInfo] {
        let keepCount = max(1, keep)
        var groups: [String: [ArchiveInfo]] = [:]
        for archive in archives { groups[archive.bundleID, default: []].append(archive) }
        var result: [ArchiveInfo] = []
        for bundleID in groups.keys.sorted() {
            let sorted = groups[bundleID]!.sorted { $0.created > $1.created }
            guard sorted.count > keepCount else { continue }
            let cutoff = sorted[keepCount - 1].created
            result += sorted.filter { $0.created < cutoff }
        }
        return result
    }

    /// Target shape for `RuleTargetMatcher`: `Library/Developer/Xcode/Archives/<folder>/<name>.xcarchive`,
    /// owned by Xcode.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        relative.count == archivesComponents.count + 2
            && XcodeInspectorSupport.hasPrefix(relative, archivesComponents)
            && InspectorWalker.isPlainName(relative[relative.count - 2])
            && InspectorWalker.isPlainName(relative[relative.count - 1])
            && isArchiveName(relative[relative.count - 1])
            && XcodeInspectorSupport.ownerIsXcode(owner)
    }
}

// MARK: - xcode.deviceSupport

/// `{HOME}/Library/Developer/Xcode/{iOS,watchOS,tvOS,visionOS} DeviceSupport/*`, with the OS version
/// parsed from each folder name. Versions more than two major releases behind the newest one present
/// for the same platform are highlighted in the notes. Nothing is preselected (Yellow).
public struct XcodeDeviceSupportInspector: Inspector {
    public static let ruleID = "xcode.deviceSupport"
    /// The platform folders, expanded explicitly (spec §6.1).
    public static let platformFolders = ["iOS DeviceSupport", "watchOS DeviceSupport", "tvOS DeviceSupport", "visionOS DeviceSupport"]
    /// How many major releases behind the newest a version must be to be highlighted.
    static let highlightMajorGap = 2

    public init() {}

    public var id: InspectorID { .xcodeDeviceSupport }

    /// OS version and build parsed from a DeviceSupport folder name.
    public struct ParsedName: Sendable, Equatable {
        public let version: [Int]
        public let build: String?
        public let device: String?
    }

    /// Parses "17.5 (21F79)", "17.5.1 (21F90) arm64e", "iPhone15,2 17.5 (21F79)" and
    /// "watchOS 10.5 (21T575)": the OS version is the last dotted-number token before the build in
    /// parentheses (or the last such token when there is no build). `nil` when none is found.
    public static func parseFolderName(_ name: String) -> ParsedName? {
        var head = Substring(name)
        var build: String?
        if let open = name.firstIndex(of: "(") {
            head = name[..<open]
            let rest = name[name.index(after: open)...]
            if let close = rest.firstIndex(of: ")") {
                let value = rest[..<close].trimmingCharacters(in: .whitespaces)
                if !value.isEmpty { build = value }
            }
        }
        let tokens = head.split(separator: " ", omittingEmptySubsequences: true)
        guard let index = tokens.lastIndex(where: { DevToolsFileReader.isDottedVersion($0) }) else { return nil }
        let version = tokens[index].split(separator: ".").compactMap { Int($0) }
        guard !version.isEmpty else { return nil }
        let prefix = tokens[..<index].joined(separator: " ")
        // A leading platform word ("watchOS") is not a device model.
        let device: String? = prefix.isEmpty || prefix.lowercased().hasSuffix("os") ? nil : prefix
        return ParsedName(version: version, build: build, device: device)
    }

    struct Item {
        let entry: InspectorWalker.Entry
        let platform: String
        let parsed: ParsedName
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not a DeviceSupport rule"))
        }
        guard let (walker, device, xcode) = XcodeInspectorSupport.xcodeDirectory(environment) else {
            return XcodeInspectorSupport.nothing
        }

        var items: [Item] = []
        var declined = 0
        for folder in Self.platformFolders {
            if Task.isCancelled { return XcodeInspectorSupport.cancelled }
            guard let platformDir = walker.descend(from: xcode, through: [folder], device: device) else { continue }
            let entries: [InspectorWalker.Entry]
            switch walker.list(platformDir, device: device) {
            case .absent: continue
            case .declined: declined += 1; continue
            case .entries(let list): entries = list
            }
            let platform = String(folder.dropLast(" DeviceSupport".count))
            for entry in entries {
                guard InspectorWalker.isDescendable(entry, device: device) else { continue }
                // SAFETY-DECISION: a folder whose name carries no recognisable OS version is not
                // something we understand, so it is not offered.
                guard let parsed = Self.parseFolderName(entry.name) else { continue }
                items.append(Item(entry: entry, platform: platform, parsed: parsed))
            }
        }
        if items.isEmpty && declined > 0 { return XcodeInspectorSupport.declined }

        var newestMajor: [String: Int] = [:]
        for item in items {
            let major = item.parsed.version[0]
            newestMajor[item.platform] = max(newestMajor[item.platform] ?? major, major)
        }

        var candidates: [DiscoveredCandidate] = []
        for item in items {
            let versionText = DevToolsFileReader.versionString(item.parsed.version)
            var notes = ["\(item.platform) \(versionText)" + (item.parsed.build.map { " (build \($0))" } ?? "")]
            if let model = item.parsed.device { notes.append("Device: \(model)") }
            if let newest = newestMajor[item.platform], item.parsed.version[0] < newest - Self.highlightMajorGap {
                notes.append("Older than \(item.platform) \(newest - Self.highlightMajorGap): only needed to debug a device still running this version.")
            }
            candidates.append(DiscoveredCandidate(
                path: item.entry.path,
                displayName: "\(item.platform) \(versionText) device support",
                owningBundleID: XcodeInspectorSupport.xcodeBundleID,
                notes: notes
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Target shape for `RuleTargetMatcher`: `Library/Developer/Xcode/<Platform> DeviceSupport/<version folder>`,
    /// owned by Xcode.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        let base = XcodeInspectorSupport.xcodeComponents
        guard relative.count == base.count + 2, XcodeInspectorSupport.hasPrefix(relative, base) else { return false }
        let platform = PathComparison.normalize(relative[base.count])
        guard platformFolders.contains(where: { PathComparison.normalize($0) == platform }) else { return false }
        let name = relative[base.count + 1]
        return InspectorWalker.isPlainName(name) && parseFolderName(name) != nil && XcodeInspectorSupport.ownerIsXcode(owner)
    }
}
