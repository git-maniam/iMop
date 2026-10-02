import Foundation

// Read-only VS Code extensions inspector (spec §6.3 `vscode.oldExtensions`).
//
// Lists `{HOME}/.vscode/extensions` through `SafeCleanEnvironment.fileSystem` only
// (`contentsOfDirectory` + `lstat`) and reads `extensions.json` there (one bounded file read).
// It never descends into an extension folder, never follows a symlink, never crosses a volume and
// never modifies anything.

/// `{HOME}/.vscode/extensions/<publisher.name>-<version>[-<target>]` folders for which a NEWER
/// version of the same extension (same target platform) exists, and which VS Code's own
/// `extensions.json` does not reference.
public struct VSCodeExtensionsInspector: Inspector {
    public static let ruleID = "vscode.oldExtensions"
    public static let vscodeBundleID = "com.microsoft.VSCode"
    static let extensionsComponents = [".vscode", "extensions"]
    static let manifestName = "extensions.json"
    /// `{HOME}/Library/Application Support/Code/User/profiles`: one folder per non-default profile,
    /// each with its own `extensions.json` pointing into the shared `~/.vscode/extensions`.
    static let profilesComponents = ["Library", "Application Support", "Code", "User", "profiles"]

    /// Target-platform suffixes VS Code appends to platform-specific extension folders.
    static let targetPlatforms = [
        "darwin-arm64", "darwin-x64", "universal", "web",
        "linux-x64", "linux-arm64", "linux-armhf", "alpine-x64", "alpine-arm64",
        "win32-x64", "win32-arm64", "win32-ia32",
    ]

    public init() {}

    public var id: InspectorID { .vscodeOldExtensions }

    /// A parsed extension folder name.
    public struct ParsedName: Sendable, Equatable {
        /// `publisher.name`, normalized (VS Code extension ids are case-insensitive).
        public let id: String
        public let version: [Int]
        public let target: String?
    }

    /// `"ms-python.vscode-pylance-2024.5.1"` → (`ms-python.vscode-pylance`, [2024, 5, 1], nil);
    /// `"ms-vscode.cpptools-1.20.5-darwin-arm64"` → (…, [1, 20, 5], `darwin-arm64`). The version must be
    /// exactly `major.minor.patch`; anything else is `nil`.
    public static func parseFolderName(_ name: String) -> ParsedName? {
        guard InspectorWalker.isPlainName(name), !name.hasPrefix(".") else { return nil }
        var rest = Substring(name)
        var target: String?
        let lowered = PathComparison.normalize(name)
        for platform in targetPlatforms where lowered.hasSuffix("-" + platform) {
            rest = rest.dropLast(platform.count + 1)
            target = platform
            break
        }
        guard let dash = rest.lastIndex(of: "-") else { return nil }
        let idPart = rest[..<dash]
        let versionPart = rest[rest.index(after: dash)...]
        guard versionPart.split(separator: ".", omittingEmptySubsequences: false).count == 3,
              DevToolsFileReader.isDottedVersion(versionPart) else { return nil }
        let version = versionPart.split(separator: ".").compactMap { Int($0) }
        guard version.count == 3, isExtensionID(idPart) else { return nil }
        return ParsedName(id: PathComparison.normalize(String(idPart)), version: version, target: target)
    }

    /// `publisher.name`: two non-empty parts split at the first ".", ASCII letters, digits, "-", "_"
    /// (the name part may contain further dots).
    static func isExtensionID(_ text: Substring) -> Bool {
        guard let dot = text.firstIndex(of: ".") else { return false }
        let publisher = text[..<dot]
        let name = text[text.index(after: dot)...]
        guard !publisher.isEmpty, !name.isEmpty else { return false }
        return text.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar) || scalar == "-" || scalar == "_" || scalar == ".")
        }
    }

    /// What `extensions.json` references.
    struct References {
        /// Normalized folder names.
        var folderNames = Set<String>()
        /// `id@version` keys (normalized id).
        var idVersions = Set<String>()

        func references(folder name: String, parsed: ParsedName) -> Bool {
            folderNames.contains(PathComparison.normalize(name))
                || idVersions.contains(parsed.id + "@" + DevToolsFileReader.versionString(parsed.version))
        }
    }

    /// Parses `extensions.json`. `nil` when it is missing, unreadable, not a JSON array, or contains
    /// an entry from which no reference can be derived.
    ///
    /// SAFETY-DECISION: if any entry cannot be understood we cannot tell which folder it keeps alive,
    /// so the whole file counts as unparsable and nothing is offered.
    static func parseReferences(_ path: String, fileSystem: any FileSystemProbe) -> References? {
        guard let array = DevToolsFileReader.readJSON(path, fileSystem: fileSystem) as? [Any] else { return nil }
        var refs = References()
        for element in array {
            guard let entry = element as? [String: Any] else { return nil }
            var understood = false
            if let relative = entry["relativeLocation"] as? String, !relative.isEmpty {
                refs.folderNames.insert(PathComparison.normalize(lastComponent(relative)))
                understood = true
            }
            if let location = entry["location"] as? [String: Any] {
                for key in ["fsPath", "path"] {
                    if let value = location[key] as? String, !value.isEmpty {
                        refs.folderNames.insert(PathComparison.normalize(lastComponent(value)))
                        understood = true
                    }
                }
            } else if let location = entry["location"] as? String, !location.isEmpty {
                refs.folderNames.insert(PathComparison.normalize(lastComponent(location)))
                understood = true
            }
            if let identifier = entry["identifier"] as? [String: Any],
               let id = identifier["id"] as? String, !id.isEmpty,
               let version = entry["version"] as? String, !version.isEmpty {
                let numbers = version.split(separator: ".", omittingEmptySubsequences: false)
                if numbers.count == 3, DevToolsFileReader.isDottedVersion(Substring(version)) {
                    let parsed = numbers.compactMap { Int($0) }
                    refs.idVersions.insert(PathComparison.normalize(id) + "@" + DevToolsFileReader.versionString(parsed))
                }
                // The plain spelling too, in case the folder carries the version verbatim.
                refs.folderNames.insert(PathComparison.normalize(id + "-" + version))
                understood = true
            }
            guard understood else { return nil }
        }
        return refs
    }

    /// The references of every non-default VS Code profile, merged into `references`. `false` when
    /// they cannot all be known.
    ///
    /// SAFETY-DECISION (review M5): `~/.vscode/extensions/extensions.json` is only the DEFAULT
    /// profile's list; another profile may use (or pin) an older version in the same folder. If the
    /// profiles folder exists but any step to it is not a real directory on the home volume, it cannot
    /// be listed, holds anything but plain profile directories, or any profile's `extensions.json` is
    /// missing, unreadable or unparsable, nothing is offered.
    static func mergeProfileReferences(into references: inout References, home: String, device: Int64,
                                       fileSystem: any FileSystemProbe) -> Bool {
        var current = home
        for component in profilesComponents {
            current += "/" + component
            guard let info = fileSystem.lstat(current) else { return true } // no profiles at all
            guard info.isDirectory, !info.isSymlink, info.device == device else { return false }
        }
        guard let names = fileSystem.contentsOfDirectory(current) else { return false }
        for name in names.sorted() {
            guard InspectorWalker.isPlainName(name) else { return false }
            let profile = current + "/" + name
            guard let info = fileSystem.lstat(profile) else { return false }
            // Finder litter (`.DS_Store`) beside the profile folders is not a profile.
            if name.hasPrefix("."), info.isRegularFile, !info.isSymlink { continue }
            guard info.isDirectory, !info.isSymlink, info.device == device else { return false }
            let manifest = profile + "/" + manifestName
            guard let manifestInfo = fileSystem.lstat(manifest), manifestInfo.isRegularFile, !manifestInfo.isSymlink,
                  let refs = parseReferences(manifest, fileSystem: fileSystem) else { return false }
            references.folderNames.formUnion(refs.folderNames)
            references.idVersions.formUnion(refs.idVersions)
        }
        return true
    }

    static func lastComponent(_ value: String) -> String {
        var trimmed = Substring(value)
        while trimmed.hasSuffix("/") { trimmed = trimmed.dropLast() }
        return trimmed.split(separator: "/").last.map(String.init) ?? String(trimmed)
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not a VS Code extensions rule"))
        }
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let extensionsDir = walker.descend(from: home, through: Self.extensionsComponents, device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let entries: [InspectorWalker.Entry]
        switch walker.list(extensionsDir, device: device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return InspectorOutput(candidates: [], status: .unavailable("Access was declined"))
        case .entries(let list): entries = list
        }
        // SAFETY-DECISION: without a readable, fully understood extensions.json nothing is offered.
        guard var references = Self.parseReferences(extensionsDir + "/" + Self.manifestName, fileSystem: environment.fileSystem) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        guard Self.mergeProfileReferences(into: &references, home: home, device: device, fileSystem: environment.fileSystem) else {
            return InspectorOutput(candidates: [], status: .unavailable("VS Code profile extension lists could not all be read"))
        }

        struct Folder {
            let entry: InspectorWalker.Entry
            let parsed: ParsedName
        }
        var groups: [String: [Folder]] = [:]
        for entry in entries {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed("Scan cancelled")) }
            guard InspectorWalker.isDescendable(entry, device: device),
                  let parsed = Self.parseFolderName(entry.name) else { continue }
            // SAFETY-DECISION: "same extension" means same id AND same target platform.
            groups[parsed.id + "|" + (parsed.target ?? ""), default: []].append(Folder(entry: entry, parsed: parsed))
        }

        var candidates: [DiscoveredCandidate] = []
        for key in groups.keys.sorted() {
            let folders = groups[key]!
            guard let newest = folders.max(by: { DevToolsFileReader.compareVersions($0.parsed.version, $1.parsed.version) == .orderedAscending }) else { continue }
            for folder in folders {
                guard DevToolsFileReader.compareVersions(folder.parsed.version, newest.parsed.version) == .orderedAscending else { continue }
                guard !references.references(folder: folder.entry.name, parsed: folder.parsed) else { continue }
                let version = DevToolsFileReader.versionString(folder.parsed.version)
                let newer = DevToolsFileReader.versionString(newest.parsed.version)
                candidates.append(DiscoveredCandidate(
                    path: folder.entry.path,
                    displayName: "\(folder.parsed.id) \(version)",
                    owningBundleID: Self.vscodeBundleID,
                    notes: [
                        "Version \(newer) of this extension is also present.",
                        "No VS Code profile's extension list references this version.",
                    ]
                ))
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Target shape for `RuleTargetMatcher`: `.vscode/extensions/<publisher.name>-<version>[-<target>]`,
    /// owned by VS Code.
    public static func matchesTargetShape(relative: [String], owner: String?) -> Bool {
        guard relative.count == extensionsComponents.count + 1,
              XcodeInspectorSupport.hasPrefix(relative, extensionsComponents),
              let owner, parseFolderName(relative[relative.count - 1]) != nil else { return false }
        return PathComparison.normalize(owner) == PathComparison.normalize(vscodeBundleID)
    }
}
