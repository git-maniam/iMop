import Foundation

// Read-only inspector for the package-manager and toolchain caches cleaned by vendor commands
// (spec §6.2): Homebrew, npm, Yarn, pnpm, Bun, uv, Go, CocoaPods (command form), Flutter/Dart and
// Android virtual devices.
//
// It never acts. It only:
// - resolves tools through `environment.commands.resolveExecutable` (trusted locations only),
// - runs the reviewed read-only queries through `environment.commands` with purpose `.readOnly`
//   (`brew cleanup --prune=all -n`, `yarn cache dir`, `pnpm store path`, `uv cache dir`,
//   `go env GOCACHE` / `go env GOMODCACHE`, `npm config get cache`, `bun pm cache`),
// - looks at folders through `environment.fileSystem` (`lstat`, `contentsOfDirectory`).
// Sizes are measured by the Scanner (`DiscoveredCandidate.sizePaths`), which also deny-list-checks
// every folder and refuses any that is protected or contains a protected item.
//
// Every failure (tool not resolvable, query failed, timed out or printed something unexpected)
// fails closed: status `.unavailable(reason)` and NO candidates.

public struct PackageManagerCachesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .packageManagerCaches }

    /// Timeout of the read-only "where is your cache" queries.
    static let queryTimeout: TimeInterval = 60
    /// `brew cleanup -n` walks every installed formula and cask; give it more time.
    static let brewDryRunTimeout: TimeInterval = 300

    /// Where a rule's cache folder is.
    enum CacheLocation: Sendable {
        /// Components below the home folder.
        case home([String])
        /// Printed (one absolute path) by a read-only query of the rule's tool; `suffix` components are
        /// appended (npm keeps its content cache in `<cache>/_cacache`).
        case query([String], suffix: [String])
    }

    struct CacheSpec: Sendable {
        let displayName: String
        let location: CacheLocation
        /// Extra facts shown in the detail view.
        let notes: [String]
        /// The command frees only part of the folder (unreferenced entries), by an amount nobody can
        /// know in advance: the folder size is shown as "up to", never counted as reclaimable.
        var partial: Bool = false
    }

    /// Rules whose single command item is "the tool's cache folder".
    static let cacheSpecs: [String: CacheSpec] = [
        "npm.cache": CacheSpec(displayName: "npm cache",
                               location: .query(["config", "get", "cache"], suffix: ["_cacache"]), notes: []),
        "yarn.cache": CacheSpec(displayName: "Yarn global cache", location: .query(["cache", "dir"], suffix: []),
                                notes: ["Only Yarn's global cache. A project's own .yarn/cache folder is never touched."]),
        "pnpm.store": CacheSpec(displayName: "pnpm store", location: .query(["store", "path"], suffix: []),
                                notes: ["pnpm removes only packages that no project references any more, so the space freed can be much less than the store's size."],
                                partial: true),
        // SAFETY-DECISION (review M4): `bun pm cache rm` deletes the cache folder bun's own config
        // names (`~/.bunfig.toml`), so the folder is the one `bun pm cache` reports, never a guess.
        "bun.cache": CacheSpec(displayName: "Bun package cache", location: .query(["pm", "cache"], suffix: []), notes: []),
        "uv.cache.prune": CacheSpec(displayName: "uv cache — unused entries", location: .query(["cache", "dir"], suffix: []),
                                    notes: ["uv removes only entries it no longer needs, so the space freed can be much less than the cache's size."],
                                    partial: true),
        "uv.cache.clean": CacheSpec(displayName: "uv cache — everything", location: .query(["cache", "dir"], suffix: []), notes: []),
        "go.buildCache": CacheSpec(displayName: "Go build cache", location: .query(["env", "GOCACHE"], suffix: []), notes: []),
        "go.modCache": CacheSpec(displayName: "Go module cache", location: .query(["env", "GOMODCACHE"], suffix: []),
                                 notes: ["Module files are read-only, so only the go command removes them."]),
        // `pod cache clean --all` removes `<cache_root>/Pods` (cache_root defaults to
        // ~/Library/Caches/CocoaPods; a custom one is refused below).
        "cocoapods.cache.command": CacheSpec(displayName: "CocoaPods download cache",
                                             location: .home(["Library", "Caches", "CocoaPods", "Pods"]), notes: []),
        "flutter.pubCache": CacheSpec(displayName: "Dart and Flutter package cache", location: .home([".pub-cache"]),
                                      notes: ["Globally activated Dart tools (dart pub global activate) live here too and must be activated again."]),
    ]

    static let homebrewRuleID = "homebrew.cleanup"
    static let androidAVDRuleID = "android.avd"

    /// Every rule this inspector serves.
    public static var ruleIDs: Set<String> { Set(cacheSpecs.keys).union([homebrewRuleID, androidAVDRuleID]) }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        // SAFETY-DECISION: the rule must be exactly one of the pinned command rules served here, with
        // the reviewed command; anything else yields nothing.
        guard Self.ruleIDs.contains(rule.id),
              let shape = RuleTargetMatcher.commandRuleShapes[rule.id], shape.inspector == id,
              RuleTargetMatcher.commandRuleMismatch(rule) == nil else {
            return Self.unavailable("This rule is not served by the package manager inspector")
        }
        if rule.id == Self.homebrewRuleID {
            return await homebrew(tool: shape.tool, environment: environment)
        }
        if rule.id == Self.androidAVDRuleID {
            return androidAVDs(tool: shape.tool, environment: environment)
        }
        guard let spec = Self.cacheSpecs[rule.id] else {
            return Self.unavailable("This rule is not served by the package manager inspector")
        }
        return await cache(spec, tool: shape.tool, environment: environment)
    }

    // MARK: - Cache-folder rules

    private func cache(_ spec: CacheSpec, tool: String, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard let executable = environment.commands.resolveExecutable(tool) else {
            return Self.unavailable(Self.notInstalled(tool))
        }

        if tool == "pod", let problem = Self.customCocoaPodsCacheRoot(environment: environment) {
            return Self.unavailable(problem)
        }

        let folder: String
        switch spec.location {
        case .home(let components):
            guard components.allSatisfy(InspectorWalker.isPlainName) else { return Self.unavailable("Invalid cache location") }
            folder = ([environment.homePath] + components).joined(separator: "/")
        case .query(let arguments, let suffix):
            let result = await environment.commands.run(executable: executable, arguments: arguments,
                                                        timeout: Self.queryTimeout, purpose: .readOnly)
            if Task.isCancelled { return Self.unavailable("Scan cancelled") }
            guard result.succeeded else {
                return Self.unavailable("Could not ask \(tool) where its cache is (\(Self.describe(result)))")
            }
            guard let reported = Self.singleAbsolutePath(result.stdout) else {
                return Self.unavailable("\(tool) reported an unexpected cache location")
            }
            guard suffix.allSatisfy(InspectorWalker.isPlainName) else { return Self.unavailable("Invalid cache location") }
            folder = ([reported] + suffix).joined(separator: "/")
        }

        guard let canonical = Self.existingDirectory(folder, environment: environment) else {
            switch Self.folderState(folder, environment: environment) {
            case .absent:
                // Nothing cached yet: nothing to offer.
                return InspectorOutput(candidates: [], status: .ok)
            case .unusable(let reason):
                return Self.unavailable(reason)
            }
        }

        // SAFETY-DECISION (spec §6.2 yarn.cache): never a project's `.yarn/cache` (it may be a
        // committed zero-install cache). A Yarn cache folder with a `.yarn` component anywhere in its
        // path (as reported or as resolved) is refused outright.
        let spellings = [canonical.components, folder.split(separator: "/").map(String.init)]
        if tool == "yarn", spellings.contains(where: { $0.contains { PathComparison.normalize($0) == ".yarn" } }) {
            return Self.unavailable("Yarn reported a project cache (.yarn/cache), which iMop never cleans")
        }

        let candidate = DiscoveredCandidate(
            commandItem: nil,
            path: canonical.path,
            displayName: spec.displayName,
            sizePaths: [canonical.path],
            reclaimableUnknown: spec.partial,
            notes: spec.notes + ["Cache folder: \(canonical.path)", Self.notRestorableNote(tool)]
        )
        return InspectorOutput(candidates: [candidate], status: .ok)
    }

    /// Largest `~/.cocoapods/config.yaml` iMop reads.
    static let maximumCocoaPodsConfigBytes: Int64 = 64 * 1024

    /// Why the CocoaPods cache location cannot be trusted to be the default one, or `nil`.
    ///
    /// SAFETY-DECISION (review M4): `pod cache clean --all` deletes `<cache_root>/Pods`, and
    /// `cache_root` can be set in `~/.cocoapods/config.yaml`. iMop has no read-only way to ask pod
    /// for it, so when that file sets `cache_root` (or cannot be read) the rule is unavailable rather
    /// than sizing and checking a folder the command might not touch.
    static func customCocoaPodsCacheRoot(environment: SafeCleanEnvironment) -> String? {
        let configPath = environment.homePath + "/.cocoapods/config.yaml"
        guard let info = environment.fileSystem.lstat(configPath) else { return nil }
        guard info.isRegularFile, info.logicalSize <= maximumCocoaPodsConfigBytes,
              let data = environment.fileSystem.readFile(configPath), Int64(data.count) <= maximumCocoaPodsConfigBytes,
              let text = String(data: data, encoding: .utf8) else {
            return "CocoaPods' configuration file could not be read, so its cache location is unknown"
        }
        if text.range(of: "cache_root", options: .caseInsensitive) != nil {
            return "CocoaPods uses a custom cache location (cache_root), which iMop does not clean"
        }
        return nil
    }

    // MARK: - homebrew.cleanup

    private func homebrew(tool: String, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard let executable = environment.commands.resolveExecutable(tool) else {
            return Self.unavailable(Self.notInstalled(tool))
        }
        let result = await environment.commands.run(executable: executable, arguments: ["cleanup", "--prune=all", "-n"],
                                                    timeout: Self.brewDryRunTimeout, purpose: .readOnly)
        if Task.isCancelled { return Self.unavailable("Scan cancelled") }
        guard result.succeeded else {
            return Self.unavailable("The Homebrew dry run failed (\(Self.describe(result)))")
        }

        var notes = ["Estimate from brew cleanup --prune=all -n. It includes old package versions in Homebrew's own folders."]
        let bytes: Int64
        switch Self.parseBrewDryRun(result.stdout) {
        case .wouldFree(let value):
            bytes = value
        case .nothingToClean:
            return InspectorOutput(candidates: [], status: .ok)
        case .unknownAmount:
            // SAFETY-DECISION: brew listed items but no total; never guess a number.
            bytes = 0
            notes.append("Homebrew did not report how much space would be freed.")
        case .unparsable:
            return Self.unavailable("Homebrew's dry run printed something unexpected")
        }

        // The informational path is Homebrew's download cache, so a user exclusion of that folder
        // also blocks the command (SafetyGate check 14).
        let cachePath = environment.homePath + "/Library/Caches/Homebrew"
        let candidate = DiscoveredCandidate(
            commandItem: nil,
            path: cachePath,
            displayName: "Homebrew old versions and downloads",
            reportedBytes: bytes,
            notes: notes + [Self.notRestorableNote(tool)]
        )
        return InspectorOutput(candidates: [candidate], status: .ok)
    }

    enum BrewDryRun: Equatable {
        case wouldFree(Int64)
        case nothingToClean
        case unknownAmount
        case unparsable
    }

    /// Parses `brew cleanup -n` output: "==> This operation would free approximately 1.2GB of disk space."
    ///
    /// Homebrew prints sizes with binary multiples labelled B, KB, MB, GB (and TB).
    static func parseBrewDryRun(_ output: String) -> BrewDryRun {
        guard !output.contains("\0") else { return .unparsable }
        let lines = output.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        let marker = "would free approximately "
        for line in lines {
            guard let range = line.range(of: marker, options: .caseInsensitive) else { continue }
            let rest = line[range.upperBound...]
            let amount = rest.prefix { $0.isNumber || $0 == "." }
            let unit = rest.dropFirst(amount.count).drop { $0 == " " }.prefix { $0.isLetter }
            guard !amount.isEmpty, amount.filter({ $0 == "." }).count <= 1,
                  let value = Double(amount), value.isFinite, value >= 0 else { return .unparsable }
            let multiplier: Double
            switch unit.uppercased() {
            case "B": multiplier = 1
            case "KB": multiplier = 1024
            case "MB": multiplier = 1024 * 1024
            case "GB": multiplier = 1024 * 1024 * 1024
            case "TB": multiplier = 1024 * 1024 * 1024 * 1024
            default: return .unparsable
            }
            let bytes = value * multiplier
            guard bytes < Double(Int64.max) else { return .unparsable }
            return .wouldFree(Int64(bytes))
        }
        if lines.contains(where: { $0.hasPrefix("Would remove") }) { return .unknownAmount }
        return .nothingToClean
    }

    // MARK: - android.avd

    private func androidAVDs(tool: String, environment: SafeCleanEnvironment) -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let avdDirectory = walker.descend(from: home, through: [".android", "avd"], device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let entries: [InspectorWalker.Entry]
        switch walker.list(avdDirectory, device: homeStat.device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return Self.unavailable("Access was declined")
        case .entries(let list): entries = list
        }

        let executable = environment.commands.resolveExecutable(tool)
        let names = Set(entries.map(\.name))
        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if Task.isCancelled { break }
            guard InspectorWalker.isDescendable(entry, device: homeStat.device),
                  entry.name.count > 4, entry.name.hasSuffix(".avd") else { continue }
            let name = String(entry.name.dropLast(4))
            // SAFETY-DECISION: avdmanager identifies a device by the name of its `<name>.ini` file. Only
            // folders with a matching regular `<name>.ini` beside them and a name of the reviewed
            // shape are offered; anything else is not a device avdmanager would know by that name.
            let iniPath = avdDirectory + "/" + name + ".ini"
            guard CommandItemKind.androidAVDName.accepts(name), names.contains(name + ".ini"),
                  let ini = environment.fileSystem.lstat(iniPath), ini.isRegularFile else { continue }
            // SAFETY-DECISION (review M4): `avdmanager delete avd -n <name>` recursively deletes the
            // folder named by `path=` (or `path.rel`) in `<name>.ini`, not necessarily the
            // `<name>.avd` folder found here. The command is offered only when the .ini names exactly
            // this folder; otherwise the device is explanation only.
            let mismatch = Self.avdDataFolderMismatch(iniPath: iniPath, iniStat: ini, avdFolder: entry.path,
                                                      environment: environment)
            if executable != nil, mismatch == nil {
                candidates.append(DiscoveredCandidate(
                    commandItem: name,
                    path: entry.path,
                    displayName: name,
                    sizePaths: [entry.path],
                    notes: ["Android virtual device \"\(name)\"", "This cannot be undone. The device's apps and data are deleted."]
                ))
            } else {
                // Spec §6.2: "CMD avdmanager delete avd -n <name> if available, else ADV".
                let reason = executable == nil
                    ? "avdmanager was not found in a trusted location, so iMop cannot remove this device."
                    : "iMop could not confirm which folder avdmanager would delete for this device (\(mismatch ?? "unknown")), so it does not offer to remove it."
                candidates.append(DiscoveredCandidate(
                    advisoryPath: entry.path,
                    displayName: name,
                    sizePaths: [entry.path],
                    notes: ["Android virtual device \"\(name)\"",
                            reason + " Delete it in Android Studio's Device Manager instead."]
                ))
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// Largest `<name>.ini` iMop reads (they are a few hundred bytes).
    static let maximumAVDIniBytes: Int64 = 16 * 1024

    /// `nil` when `<name>.ini` names exactly `avdFolder` as the device's data folder; otherwise why not.
    ///
    /// avdmanager uses `path=` and falls back to `path.rel` (relative to `~/.android`). SAFETY-DECISION:
    /// every key that is present must resolve to the same real folder as `avdFolder` (not through a
    /// symlink), at least one must be present, and a duplicated key or an unreadable/odd file is a
    /// mismatch.
    static func avdDataFolderMismatch(iniPath: String, iniStat: FileStat, avdFolder: String,
                                      environment: SafeCleanEnvironment) -> String? {
        guard iniStat.logicalSize <= maximumAVDIniBytes,
              let data = environment.fileSystem.readFile(iniPath), Int64(data.count) <= maximumAVDIniBytes,
              let text = String(data: data, encoding: .utf8) else {
            return "its .ini file could not be read"
        }
        var values: [String: String] = [:]
        for rawLine in text.components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";"),
                  let equals = line.firstIndex(of: "=") else { continue }
            let key = line[..<equals].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            guard key == "path" || key == "path.rel" else { continue }
            guard values[key] == nil else { return "its .ini file names the folder twice" }
            values[key] = value
        }
        guard !values.isEmpty else { return "its .ini file does not name a folder" }

        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let expected) = canonicalizer.canonicalize(avdFolder) else {
            return "its folder could not be resolved"
        }
        for (key, value) in values {
            let raw: String
            if key == "path" {
                guard value.hasPrefix("/") else { return "its .ini file names a relative folder" }
                raw = value
            } else {
                guard !value.hasPrefix("/"), !value.isEmpty else { return "its .ini file names an unexpected folder" }
                raw = environment.homePath + "/.android/" + value
            }
            guard !raw.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }),
                  case .success(let lexical) = canonicalizer.lexical(raw),
                  let info = environment.fileSystem.lstat(lexical.path), info.isDirectory, !info.isSymlink,
                  case .success(let resolved) = canonicalizer.canonicalize(lexical.path) else {
                return "its .ini file names a folder that is missing or a link"
            }
            guard resolved == expected else { return "its .ini file names another folder" }
        }
        return nil
    }

    // MARK: - Helpers

    static func unavailable(_ reason: String) -> InspectorOutput {
        InspectorOutput(candidates: [], status: .unavailable(reason))
    }

    static func notInstalled(_ tool: String) -> String {
        "\(tool) is not installed in a trusted location"
    }

    /// Spec §5.3 wording for whole-cache commands.
    static func notRestorableNote(_ tool: String) -> String {
        "This cannot be undone. \(tool) will re-download what it needs."
    }

    static func describe(_ result: CommandResult) -> String {
        result.timedOut ? "timed out" : "exit code \(result.exitCode)"
    }

    /// The single absolute path a "where is your cache" query printed, or nil.
    ///
    /// SAFETY-DECISION: exactly one non-empty line (surrounding whitespace ignored), starting with "/",
    /// no control characters, no "." / ".." / empty components; anything else (warnings mixed into
    /// stdout, "undefined", "off", relative paths) is refused.
    static func singleAbsolutePath(_ output: String) -> String? {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= 4096, trimmed.hasPrefix("/"), trimmed != "/",
              !trimmed.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
        var path = trimmed
        while path.count > 1, path.hasSuffix("/") { path.removeLast() }
        let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return nil }
        return path
    }

    /// The canonical form of `path` when it is an existing real directory (reached through symlinks or
    /// not; the Scanner measures and gates the canonical form).
    static func existingDirectory(_ path: String, environment: SafeCleanEnvironment) -> CanonicalPath? {
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let canonical) = canonicalizer.canonicalize(path),
              let info = environment.fileSystem.lstat(canonical.path), info.isDirectory, !info.isSymlink else { return nil }
        return canonical
    }

    enum FolderState {
        case absent
        case unusable(String)
    }

    /// Why `path` is not an existing directory: missing (nothing to offer) or something else (fail closed).
    static func folderState(_ path: String, environment: SafeCleanEnvironment) -> FolderState {
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let lexical) = canonicalizer.lexical(path) else {
            return .unusable("The cache location is not a usable path")
        }
        // Missing when nothing exists at the lexical path (a dangling symlink counts as unusable).
        guard let info = environment.fileSystem.lstat(lexical.path) else { return .absent }
        if info.isSymlink { return .unusable("The cache location is a link that could not be followed") }
        if info.isDirectory { return .unusable("The cache location could not be resolved safely") }
        return .unusable("The cache location is not a folder")
    }
}
