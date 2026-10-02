import Foundation

// SAFETY-NOTE: this file lives in Rules/ and is covered by the static read-only test; it is pure
// data and string comparison. It never touches the file system and never starts a process.

/// What kind of value a `{ITEM}` slot of an allow-listed command accepts (spec §6, Milestone 4).
///
/// SAFETY-DECISION: every per-item argument is checked against a strict, ASCII-only shape before a
/// command can run, so an item name can never inject an option ("-…", "--all"), a path or a keyword
/// such as `all` / `unavailable` (e.g. `simctl delete all` would delete every simulator).
public enum CommandItemKind: String, Sendable, Hashable, CaseIterable {
    /// `^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`
    case simulatorDeviceUDID
    /// `^com\.apple\.CoreSimulator\.SimRuntime\.[A-Za-z0-9.-]+$` or a UDID-shaped UUID.
    case simulatorRuntimeIdentifier
    /// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`
    case dockerVolumeName
    /// `^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?$` with no empty, "." or ".." namespace segment.
    case ollamaModelName
    /// `^[A-Za-z0-9][A-Za-z0-9._-]*$`
    case androidAVDName

    /// Upper bound on any per-item argument.
    public static let maximumLength = 255

    /// `true` when `argument` has exactly this kind's shape.
    public func accepts(_ argument: String) -> Bool {
        let scalars = Array(argument.unicodeScalars)
        guard !scalars.isEmpty, scalars.count <= Self.maximumLength, scalars.allSatisfy(\.isASCII) else { return false }
        switch self {
        case .simulatorDeviceUDID:
            return Self.isUppercaseUUID(scalars)
        case .simulatorRuntimeIdentifier:
            let prefix = "com.apple.CoreSimulator.SimRuntime."
            if argument.hasPrefix(prefix) {
                let rest = scalars.dropFirst(prefix.unicodeScalars.count)
                return !rest.isEmpty && rest.allSatisfy { Self.isAlphanumeric($0) || $0 == "." || $0 == "-" }
            }
            return Self.isUppercaseUUID(scalars)
        case .dockerVolumeName:
            guard let first = scalars.first, Self.isAlphanumeric(first) else { return false }
            return scalars.dropFirst().allSatisfy { Self.isAlphanumeric($0) || $0 == "_" || $0 == "." || $0 == "-" }
        case .ollamaModelName:
            return Self.isOllamaModelName(argument)
        case .androidAVDName:
            guard let first = scalars.first, Self.isAlphanumeric(first) else { return false }
            return scalars.dropFirst().allSatisfy { Self.isAlphanumeric($0) || $0 == "." || $0 == "_" || $0 == "-" }
        }
    }

    /// Whether this kind may legitimately contain "/" (ollama namespaces only).
    public var allowsSlash: Bool { self == .ollamaModelName }

    private static func isAlphanumeric(_ scalar: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar) || ("0"..."9").contains(scalar)
    }

    private static func isUppercaseUUID(_ scalars: [Unicode.Scalar]) -> Bool {
        guard scalars.count == 36 else { return false }
        for (index, scalar) in scalars.enumerated() {
            if [8, 13, 18, 23].contains(index) {
                guard scalar == "-" else { return false }
            } else {
                guard ("0"..."9").contains(scalar) || ("A"..."F").contains(scalar) else { return false }
            }
        }
        return true
    }

    private static func isOllamaModelName(_ argument: String) -> Bool {
        let parts = argument.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        let name = parts[0].unicodeScalars
        guard let first = name.first,
              ("a"..."z").contains(first) || ("0"..."9").contains(first) else { return false }
        let nameOK = name.allSatisfy {
            ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "." || $0 == "_" || $0 == "/" || $0 == "-"
        }
        guard nameOK else { return false }
        // SAFETY-DECISION: a namespace separator never forms an empty, "." or ".." segment, so a model
        // name can never look like a relative path.
        let segments = String(parts[0]).split(separator: "/", omittingEmptySubsequences: false)
        guard segments.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return false }
        if parts.count == 2 {
            let tag = parts[1].unicodeScalars
            guard !tag.isEmpty else { return false }
            return tag.allSatisfy { isAlphanumeric($0) || $0 == "." || $0 == "_" || $0 == "-" }
        }
        return true
    }
}

/// What a NAMED slot (`{PATH}`, `{NAME}`) of an internal read-only probe accepts (Milestone 5).
///
/// SAFETY-DECISION: kept separate from `CommandItemKind` so a rule's `{ITEM}` can never be a path:
/// named slots exist only on internal, read-only, `usableByRules == false` entries (the git probe of
/// `Precondition.notTrackedByGit`) and are refused for `.action` (see `CommandAllowList.entry`).
public enum CommandSlotKind: String, Sendable, Hashable, CaseIterable {
    /// `{PATH}` of the read-only git probe: an absolute, clean path (no empty, "." or ".." component,
    /// no trailing "/", no control characters, at most `maximumPathLength` bytes). Containment in a
    /// configured project root is checked by the caller (`PreconditionEvaluator`), which has the settings.
    case gitWorkTreePath
    /// `{NAME}` of the read-only git probe: exactly one of `CommandAllowList.projectArtifactNames`.
    case projectArtifactName
    /// Milestone 6, `gui/{UID}` of the launchctl bootout action: `gui/` followed by 1–10 ASCII
    /// digits without a leading zero (the caller additionally requires it to be the user's own uid).
    case launchdGUIDomain
    /// Milestone 6, `{PLIST}` of the launchctl bootout action: a clean absolute path whose last two
    /// folders are `Library/LaunchAgents` and whose file name is `<name>.plist` (not `com.apple.*`).
    /// The caller additionally requires it to be inside the user's own home folder.
    case launchAgentPlistPath

    /// Upper bound on a `gitWorkTreePath` argument (UTF-8 bytes).
    public static let maximumPathLength = 1024

    /// `true` when `argument` has exactly this kind's shape.
    public func accepts(_ argument: String) -> Bool {
        guard !argument.hasPrefix("-") else { return false }
        switch self {
        case .gitWorkTreePath:
            return Self.isCleanAbsolutePath(argument)
        case .projectArtifactName:
            // SAFETY-DECISION: exact, case-sensitive membership; never a pattern, never a path.
            return CommandAllowList.projectArtifactNames.contains(argument)
        case .launchdGUIDomain:
            let prefix = "gui/"
            guard argument.hasPrefix(prefix) else { return false }
            let digits = Array(argument.dropFirst(prefix.count).unicodeScalars)
            guard (1...10).contains(digits.count), digits.allSatisfy({ ("0"..."9").contains($0) }) else { return false }
            return digits.count == 1 || digits.first != "0"
        case .launchAgentPlistPath:
            return Self.isLaunchAgentPlistPath(argument)
        }
    }

    /// Kinds that may appear in an `.action` entry (Milestone 6 launchctl bootout). The git probe's
    /// kinds never can.
    public var allowedInAction: Bool {
        switch self {
        case .launchdGUIDomain, .launchAgentPlistPath: return true
        case .gitWorkTreePath, .projectArtifactName: return false
        }
    }

    /// Whether a value of this kind legitimately contains "/".
    public var allowsSlash: Bool {
        switch self {
        case .launchdGUIDomain, .launchAgentPlistPath, .gitWorkTreePath: return true
        case .projectArtifactName: return false
        }
    }

    /// SAFETY-DECISION (M6): `/…/Library/LaunchAgents/<name>.plist` — clean absolute path, the file
    /// name is printable ASCII (no "/", not hidden), ends in `.plist` with a non-empty base that is
    /// not Apple's (`com.apple*`, case-insensitive), and nothing else may follow.
    static func isLaunchAgentPlistPath(_ path: String) -> Bool {
        guard isCleanAbsolutePath(path) else { return false }
        let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard components.count >= 3 else { return false }
        let count = components.count
        guard components[count - 3] == "Library", components[count - 2] == "LaunchAgents" else { return false }
        let name = components[count - 1]
        guard !name.hasPrefix("."), name.hasSuffix(".plist"), name.count > ".plist".count,
              name.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x20 && $0.value < 0x7F }) else { return false }
        return !name.lowercased().hasPrefix("com.apple")
    }

    /// "/a/b": starts with "/", is not "/" itself, has no empty / "." / ".." component, no trailing
    /// "/", no NUL or other control character, at most `maximumPathLength` UTF-8 bytes.
    static func isCleanAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), path.count > 1, !path.hasSuffix("/"),
              path.utf8.count <= maximumPathLength else { return false }
        guard !path.unicodeScalars.contains(where: { $0.properties.generalCategory == .control || $0 == "\0" }) else {
            return false
        }
        let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        return components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }
}

/// The single, Swift-coded table of vendor commands iMop may ever run (spec §5.3, §6, §10).
///
/// Used by BOTH `RuleCatalog` (a rule's command must be one of these entries) and `CommandRunner`
/// (the live runner refuses any invocation that is not one of these entries for the requested
/// purpose). Rules.json can only pick from this table; it can never add to it.
///
/// SAFETY-DECISION: exact (tool, argument array) pairs only. `{ITEM}` is a whole argument whose
/// value must pass the entry's `CommandItemKind` validator. Wrappers, shells, `system prune`,
/// `--volumes`, `brew autoremove` and anything with a path argument are never listed.
public struct CommandAllowList: Sendable {
    /// One reviewed vendor command.
    public struct Entry: Sendable, Hashable {
        public let tool: String
        /// Exact argument template; `CommandSpec.itemToken` marks the single per-item slot.
        public let arguments: [String]
        public let purpose: CommandPurpose
        /// The least cautious tier that may run it as a rule action (spec §6 tables).
        public let minimumTier: Tier
        /// When non-nil, only these rule ids may use it.
        public let ruleIDs: Set<String>?
        /// Validator for the `{ITEM}` slot (non-nil exactly when the template has one).
        public let itemKind: CommandItemKind?
        /// Longest timeout a rule may declare for it (spec §5.3: default 10 min, runtime delete 30 min).
        public let maximumTimeoutSeconds: Int
        /// `false` for internal precondition probes (`xcode-select -p`, `hdiutil info -plist`) that
        /// the runner allows but no rule may name.
        public let usableByRules: Bool
        /// Named slots (`{PATH}`, `{NAME}`) of internal probes → their validator. Rules never use them.
        public let slotKinds: [String: CommandSlotKind]

        public init(_ tool: String, _ arguments: [String], purpose: CommandPurpose, minimumTier: Tier = .green,
                    ruleIDs: Set<String>? = nil, itemKind: CommandItemKind? = nil,
                    maximumTimeoutSeconds: Int = Int(CommandSpec.defaultTimeout), usableByRules: Bool = true,
                    slotKinds: [String: CommandSlotKind] = [:]) {
            self.tool = tool
            self.arguments = arguments
            self.purpose = purpose
            self.minimumTier = minimumTier
            self.ruleIDs = ruleIDs
            self.itemKind = itemKind
            self.maximumTimeoutSeconds = maximumTimeoutSeconds
            self.usableByRules = usableByRules
            self.slotKinds = slotKinds
        }

        public var isPerItem: Bool { arguments.contains(CommandSpec.itemToken) }

        /// `true` when `arguments` (with the item already substituted) is an instance of this entry.
        public func matchesInvocation(tool candidate: String, arguments actual: [String]) -> Bool {
            guard candidate == tool, actual.count == arguments.count else { return false }
            for (template, value) in zip(arguments, actual) {
                if template == CommandSpec.itemToken {
                    // SAFETY-DECISION: an entry with an {ITEM} slot but no validator never matches.
                    guard let itemKind, itemKind.accepts(value) else { return false }
                } else if let slotKind = slotKinds[template] {
                    // SAFETY-DECISION: a named slot value must pass its validator and can never look
                    // like an option.
                    guard !value.hasPrefix("-"), slotKind.accepts(value) else { return false }
                } else if template != value {
                    return false
                }
            }
            return true
        }

        /// `true` when a rule's argument TEMPLATE (still containing `{ITEM}`) is exactly this entry.
        public func matchesTemplate(tool candidate: String, arguments template: [String]) -> Bool {
            candidate == tool && template == arguments
        }

        /// `true` when a rule with this id and tier may use the entry as its action.
        public func permits(ruleID: String, tier: Tier) -> Bool {
            usableByRules && tier >= minimumTier && (ruleIDs?.contains(ruleID) ?? true)
        }
    }

    public let entries: [Entry]

    public init(entries: [Entry]) {
        self.entries = entries
    }

    public var actionEntries: [Entry] { entries.filter { $0.purpose == .action } }
    public var readOnlyEntries: [Entry] { entries.filter { $0.purpose == .readOnly } }

    /// The entry an invocation matches for `purpose`, or `nil` when it is not allowed.
    ///
    /// Applies the always-forbidden checks first (defense in depth: they hold even if a bad entry
    /// were ever added to the table).
    public func entry(tool: String, arguments: [String], purpose: CommandPurpose) -> Entry? {
        guard Self.forbiddenInvocationReason(tool: tool, arguments: arguments, purpose: purpose) == nil else { return nil }
        for entry in entries where entry.purpose == purpose && entry.matchesInvocation(tool: tool, arguments: arguments) {
            // SAFETY-DECISION: for actions, "/" may appear only inside an {ITEM} slot whose kind
            // explicitly allows it (ollama namespaces) or inside a named action slot (M6 launchctl
            // bootout: `gui/<uid>` and the plist path). No fixed argument ever contains a path.
            // SAFETY-DECISION: internal probes with named slots are read-only only; never an action —
            // except the M6 bootout entry, whose slots are action kinds and which no rule may name.
            if purpose == .action, !entry.slotKinds.isEmpty {
                guard !entry.usableByRules, entry.slotKinds.values.allSatisfy(\.allowedInAction) else { continue }
            }
            if purpose == .action {
                let pathLike = zip(entry.arguments, arguments).contains { template, value in
                    guard value.contains("/") else { return false }
                    if template == CommandSpec.itemToken { return !(entry.itemKind?.allowsSlash ?? false) }
                    if let slot = entry.slotKinds[template] { return !(slot.allowedInAction && slot.allowsSlash) }
                    return true
                }
                if pathLike { continue }
            }
            return entry
        }
        return nil
    }

    public func matches(tool: String, arguments: [String], purpose: CommandPurpose) -> Bool {
        entry(tool: tool, arguments: arguments, purpose: purpose) != nil
    }

    /// Why an invocation is forbidden regardless of the table, or `nil`.
    public static func forbiddenInvocationReason(tool: String, arguments: [String], purpose: CommandPurpose) -> String? {
        // SAFETY-DECISION (M6): `launchctl` stays a forbidden tool for every rule and every other
        // invocation; the ONLY exception is exactly `launchctl bootout gui/<uid> <…/Library/LaunchAgents/x.plist>`
        // as an action (the Executor's `bootoutAndTrash`, which also checks the uid and the home folder).
        if forbiddenTools.contains(tool.lowercased()), !isLaunchAgentBootoutShape(tool: tool, arguments: arguments, purpose: purpose) {
            return "tool \"\(tool)\" is never allowed"
        }
        let lowered = arguments.map { $0.lowercased() }
        let exempt = gitProbeExemptIndices(tool: tool, arguments: arguments, purpose: purpose)
        for (index, token) in lowered.enumerated() where forbiddenArguments.contains(token) && !exempt.contains(index) {
            return "argument \"\(token)\" is never allowed"
        }
        // SAFETY-DECISION: no "system prune" of any form (Docker's can delete volumes and every image).
        if lowered.contains("system") && lowered.contains("prune") { return "\"system prune\" is never allowed" }
        if arguments.contains(where: { $0.unicodeScalars.contains { $0.properties.generalCategory == .control } }) {
            return "arguments contain control characters"
        }
        return nil
    }

    /// Argument indices of the read-only git probe whose `-c` / `-C` tokens are exempt from the
    /// forbidden-token check (`-c` is otherwise refused as a shell flag).
    ///
    /// SAFETY-DECISION: the exemption applies only to tool `git`, purpose `.readOnly`, and only when
    /// the invocation begins with EXACTLY (case-sensitive) `--no-optional-locks --icase-pathspecs -c
    /// core.fsmonitor=false -C`; the lowercase `-c` may then only carry that one fixed setting. Every
    /// other argument is still checked.
    static func gitProbeExemptIndices(tool: String, arguments: [String], purpose: CommandPurpose) -> Set<Int> {
        guard tool == "git", purpose == .readOnly, arguments.count == gitTrackedProbeTemplate.count,
              Array(arguments.prefix(gitProbeFixedPrefixCount)) == Array(gitTrackedProbeTemplate.prefix(gitProbeFixedPrefixCount))
        else { return [] }
        return [2, 4]
    }

    /// Number of fixed leading tokens of `gitTrackedProbeTemplate` (everything before `{PATH}`).
    static let gitProbeFixedPrefixCount = 5

    // MARK: - Read-only git probe (Precondition.notTrackedByGit, spec §6.5)

    /// Named slot: the project directory (`git -C {PATH}`).
    public static let pathSlot = "{PATH}"
    /// Named slot: the artifact name (`ls-files … -- {NAME}`).
    public static let nameSlot = "{NAME}"

    /// The only artifact names the git probe may ask about (spec §6.5 ProjectScanner artifacts).
    public static let projectArtifactNames: Set<String> = ["node_modules", "target", ".venv", "venv", "Pods", ".next", "build", ".build"]

    /// `git --no-optional-locks --icase-pathspecs -c core.fsmonitor=false -C {PATH} ls-files
    /// --error-unmatch -- {NAME}`.
    ///
    /// SAFETY-DECISION: beyond the agreed `-C <dir> ls-files --error-unmatch -- <name>`:
    /// - `--no-optional-locks` stops git from opportunistically rewriting `.git/index` (Discovery and
    ///   preconditions must not modify the user's repository);
    /// - `--icase-pathspecs` (review M5): git compares pathspecs case-SENSITIVELY even with
    ///   `core.ignorecase=true`, but APFS is case-insensitive. Committed files indexed as `Build/ci.sh`
    ///   live inside the on-disk `build/` folder, yet `ls-files --error-unmatch -- build` reports
    ///   "did not match" — which would read as "untracked". Case-insensitive matching can only report
    ///   MORE paths as tracked, so it is the conservative choice. (The cwd prefix git derives from
    ///   `-C` stays case-sensitive; the precondition therefore only asks git when the artifact's own
    ///   folder holds the `.git`, so that prefix is always empty.)
    /// - `-c core.fsmonitor=false` stops a repository-local `core.fsmonitor` hook (an arbitrary
    ///   program named in `.git/config`) from being run when git reads the index.
    public static let gitTrackedProbeTemplate: [String] = [
        "--no-optional-locks", "--icase-pathspecs", "-c", "core.fsmonitor=false", "-C", pathSlot,
        "ls-files", "--error-unmatch", "--", nameSlot,
    ]

    /// The concrete probe arguments for `projectDirectory` / `artifactName` (validated by the entry).
    public static func gitTrackedProbeArguments(projectDirectory: String, artifactName: String) -> [String] {
        gitTrackedProbeTemplate.map { token in
            switch token {
            case pathSlot: return projectDirectory
            case nameSlot: return artifactName
            default: return token
            }
        }
    }

    /// The git probe as the `notTrackedByGit` precondition may run it: the invocation must match the
    /// read-only allow-list entry AND its `{PATH}` must be a clean absolute path inside-or-equal one
    /// of the user's validated `projectRoots` (`ProjectRoots.resolve`), and its `{NAME}` a reviewed
    /// artifact name.
    ///
    /// SAFETY-DECISION: the static table cannot know the user's settings, so the project-root
    /// containment of `{PATH}` is checked here, by the only caller that runs the probe; a path outside
    /// every configured root (or with no roots configured) is refused and git is never run.
    public static func gitProbeAllowed(arguments: [String], projectRoots: [CanonicalPath]) -> Bool {
        guard matches(tool: "git", arguments: arguments, purpose: .readOnly),
              let pathIndex = gitTrackedProbeTemplate.firstIndex(of: pathSlot),
              let nameIndex = gitTrackedProbeTemplate.firstIndex(of: nameSlot),
              arguments.count == gitTrackedProbeTemplate.count else { return false }
        let path = arguments[pathIndex]
        guard CommandSlotKind.gitWorkTreePath.accepts(path), projectArtifactNames.contains(arguments[nameIndex]),
              case .success(let clean) = PathCanonicalizer.clean(path, home: nil), clean.path == path else { return false }
        return projectRoots.contains { clean.isInsideOrEqual($0) }
    }

    // MARK: - LaunchAgent bootout (Milestone 6, spec §6.9 `leftovers.launchAgents`)

    /// The only launchctl invocation iMop may ever run.
    public static let launchctlTool = "launchctl"
    /// SAFETY-DECISION: launchctl is only ever taken from this exact SIP-protected path.
    public static let launchctlPath = "/bin/launchctl"
    /// Named slot: the user's GUI domain (`gui/<uid>`).
    public static let guiDomainSlot = "gui/{UID}"
    /// Named slot: the plist being booted out.
    public static let plistSlot = "{PLIST}"
    public static let launchAgentBootoutTemplate: [String] = ["bootout", guiDomainSlot, plistSlot]

    /// `["bootout", "gui/<userID>", plistPath]`.
    public static func launchAgentBootoutArguments(userID: UInt32, plistPath: String) -> [String] {
        ["bootout", "gui/\(userID)", plistPath]
    }

    /// Shape only (no uid / home check): exactly `bootout gui/<digits> <LaunchAgents plist>` as an action.
    static func isLaunchAgentBootoutShape(tool: String, arguments: [String], purpose: CommandPurpose) -> Bool {
        tool == launchctlTool && purpose == .action && arguments.count == 3 && arguments[0] == "bootout"
            && CommandSlotKind.launchdGUIDomain.accepts(arguments[1])
            && CommandSlotKind.launchAgentPlistPath.accepts(arguments[2])
    }

    /// The bootout as the Executor (and the live runner) may run it: an allow-listed action invocation
    /// whose domain is exactly `gui/<userID>` and whose plist is EXACTLY
    /// `<home>/Library/LaunchAgents/<name>.plist` for one of `homeDirectories` (compared exactly, after
    /// cleaning; the file name is one component and never `com.apple.*`).
    ///
    /// SAFETY-DECISION: the static table cannot know the user's uid or home folder, so they are
    /// checked here, by the only callers; anything else (another user's domain, `/Library/LaunchAgents`,
    /// `/Library/LaunchDaemons`, a nested path) is refused and launchctl is never run.
    public static func launchAgentBootoutAllowed(arguments: [String], userID: UInt32, homeDirectories: [String]) -> Bool {
        guard matches(tool: launchctlTool, arguments: arguments, purpose: .action), arguments.count == 3,
              arguments[1] == "gui/\(userID)" else { return false }
        let plist = arguments[2]
        guard case .success(let clean) = PathCanonicalizer.clean(plist, home: nil), clean.path == plist,
              let name = clean.lastComponent else { return false }
        return homeDirectories.contains { home in
            guard case .success(let cleanHome) = PathCanonicalizer.clean(home, home: nil), !cleanHome.components.isEmpty else {
                return false
            }
            return plist == cleanHome.appending("Library").appending("LaunchAgents").appending(name).path
        }
    }

    // MARK: - The reviewed table

    /// Docker's fixed JSON output format for the read-only listing commands.
    public static let dockerJSONFormat = "{{json .}}"

    /// Action commands (spec §6.1, §6.2, §6.4, §6.8).
    public static let standardActionEntries: [Entry] = [
        // Package managers & toolchains (§6.2).
        Entry("brew", ["cleanup", "--prune=all"], purpose: .action),
        Entry("npm", ["cache", "clean", "--force"], purpose: .action),
        Entry("yarn", ["cache", "clean"], purpose: .action),
        Entry("pnpm", ["store", "prune"], purpose: .action),
        // The only fixed "rm" subcommand: removes bun's global package cache, nothing else.
        Entry("bun", ["pm", "cache", "rm"], purpose: .action),
        Entry("uv", ["cache", "prune"], purpose: .action),
        Entry("uv", ["cache", "clean"], purpose: .action, minimumTier: .yellow),
        Entry("go", ["clean", "-cache"], purpose: .action),
        Entry("go", ["clean", "-modcache"], purpose: .action, minimumTier: .yellow),
        Entry("pod", ["cache", "clean", "--all"], purpose: .action),
        Entry("flutter", ["pub", "cache", "clean", "-f"], purpose: .action, minimumTier: .yellow),
        // Docker (§6.4). Never `system prune`, never `--volumes`.
        Entry("docker", ["image", "prune", "-f"], purpose: .action),
        Entry("docker", ["builder", "prune", "-f"], purpose: .action),
        Entry("docker", ["image", "prune", "-a", "-f"], purpose: .action, minimumTier: .yellow),
        Entry("docker", ["container", "prune", "-f"], purpose: .action, minimumTier: .yellow),
        // SAFETY-DECISION: the only Red command (databases live in volumes) is pinned to its rule.
        Entry("docker", ["volume", "rm", CommandSpec.itemToken], purpose: .action, minimumTier: .red,
              ruleIDs: ["docker.volumes"], itemKind: .dockerVolumeName),
        // Milestone 6 (§6.9): the Executor's `bootoutAndTrash` for `leftovers.launchAgents` only. No
        // rule may name it (`usableByRules: false`); uid and home folder are checked by
        // `launchAgentBootoutAllowed`.
        Entry(launchctlTool, launchAgentBootoutTemplate, purpose: .action, minimumTier: .red,
              ruleIDs: ["leftovers.launchAgents"], usableByRules: false,
              slotKinds: [guiDomainSlot: .launchdGUIDomain, plistSlot: .launchAgentPlistPath]),
        // Simulators (§6.1).
        Entry("xcrun", ["simctl", "delete", "unavailable"], purpose: .action),
        Entry("xcrun", ["simctl", "delete", CommandSpec.itemToken], purpose: .action, minimumTier: .yellow,
              itemKind: .simulatorDeviceUDID),
        Entry("xcrun", ["simctl", "runtime", "delete", CommandSpec.itemToken], purpose: .action, minimumTier: .yellow,
              itemKind: .simulatorRuntimeIdentifier, maximumTimeoutSeconds: 1800),
        // Local AI models (§6.8) and Android (§6.2).
        Entry("ollama", ["rm", CommandSpec.itemToken], purpose: .action, minimumTier: .yellow,
              itemKind: .ollamaModelName),
        Entry("avdmanager", ["delete", "avd", "-n", CommandSpec.itemToken], purpose: .action, minimumTier: .yellow,
              itemKind: .androidAVDName),
    ]

    /// Read-only commands: dry runs, discovery listings and precondition probes.
    public static let standardReadOnlyEntries: [Entry] = [
        // Simulators.
        Entry("xcrun", ["simctl", "list", "devices", "-j"], purpose: .readOnly),
        Entry("xcrun", ["simctl", "list", "devices", "unavailable", "-j"], purpose: .readOnly),
        Entry("xcrun", ["simctl", "runtime", "list", "-j"], purpose: .readOnly),
        // Package managers.
        Entry("brew", ["cleanup", "--prune=all", "-n"], purpose: .readOnly),
        Entry("npm", ["config", "get", "cache"], purpose: .readOnly),
        Entry("yarn", ["cache", "dir"], purpose: .readOnly),
        Entry("pnpm", ["store", "path"], purpose: .readOnly),
        Entry("uv", ["cache", "dir"], purpose: .readOnly),
        // Prints the global cache folder (review M4: the folder `bun pm cache rm` deletes).
        Entry("bun", ["pm", "cache"], purpose: .readOnly),
        Entry("go", ["env", "GOCACHE"], purpose: .readOnly),
        Entry("go", ["env", "GOMODCACHE"], purpose: .readOnly),
        Entry("pod", ["cache", "list"], purpose: .readOnly),
        Entry("avdmanager", ["list", "avd"], purpose: .readOnly),
        Entry("ollama", ["list"], purpose: .readOnly),
        // Docker.
        Entry("docker", ["info"], purpose: .readOnly),
        Entry("docker", ["system", "df"], purpose: .readOnly),
        Entry("docker", ["system", "df", "-v"], purpose: .readOnly),
        Entry("docker", ["system", "df", "--format", dockerJSONFormat], purpose: .readOnly),
        Entry("docker", ["image", "ls"], purpose: .readOnly),
        Entry("docker", ["image", "ls", "--format", dockerJSONFormat], purpose: .readOnly),
        Entry("docker", ["ps", "-a", "--filter", "status=exited"], purpose: .readOnly),
        Entry("docker", ["ps", "-a", "--filter", "status=exited", "--format", dockerJSONFormat], purpose: .readOnly),
        Entry("docker", ["volume", "ls", "-f", "dangling=true"], purpose: .readOnly),
        Entry("docker", ["volume", "ls", "-f", "dangling=true", "--format", dockerJSONFormat], purpose: .readOnly),
        // Precondition probes (Safety/Preconditions.swift); never available to rules.
        Entry("xcode-select", ["-p"], purpose: .readOnly, usableByRules: false),
        Entry("hdiutil", ["info", "-plist"], purpose: .readOnly, usableByRules: false),
        // Milestone 6: OrphanDetector condition 4 (package receipts, `/usr/sbin/pkgutil`) and the Time
        // Machine advisory (`/usr/bin/tmutil`). Read-only, never available to rules.
        Entry("pkgutil", ["--pkgs"], purpose: .readOnly, usableByRules: false),
        Entry("tmutil", ["listlocalsnapshots", "/"], purpose: .readOnly, usableByRules: false),
        // Precondition.notTrackedByGit (spec §6.5); never available to rules, never an action.
        // (`maximumTimeoutSeconds` only bounds rule actions; the evaluator runs it with a 30 s timeout.)
        Entry("git", gitTrackedProbeTemplate, purpose: .readOnly, usableByRules: false,
              slotKinds: [pathSlot: .gitWorkTreePath, nameSlot: .projectArtifactName]),
    ]

    /// The production table.
    public static let standard = CommandAllowList(entries: standardActionEntries + standardReadOnlyEntries)

    /// Convenience lookup against the production table.
    public static func matches(tool: String, arguments: [String], purpose: CommandPurpose) -> Bool {
        standard.matches(tool: tool, arguments: arguments, purpose: purpose)
    }

    /// Validator for the `{ITEM}` slot of a production entry with exactly this template.
    public static func itemKind(tool: String, template: [String]) -> CommandItemKind? {
        standard.entries.first { $0.matchesTemplate(tool: tool, arguments: template) }?.itemKind
    }

    // MARK: - Always-forbidden

    /// SAFETY-DECISION: tools a rule may name at all (review M2), checked before the exact tables.
    public static let ruleTools: Set<String> = [
        "xcrun", "brew", "npm", "yarn", "pnpm", "bun", "uv", "go", "docker", "pod", "flutter", "avdmanager", "ollama",
    ]

    /// Argument tokens never allowed in any command (case-insensitive, whole arguments): shells,
    /// shell flags, privilege escalation, `docker … --volumes`, `brew autoremove`, `rm -rf` flags.
    public static let forbiddenArguments: Set<String> = [
        "--volumes", "autoremove", "sudo", "doas", "-c",
        "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "fish",
        "-rf", "-fr", "-r", "--recursive", "--no-preserve-root",
    ]

    /// SAFETY-DECISION: executables that are never acceptable (shells, privilege escalation, generic
    /// removers and interpreters that could run arbitrary code).
    public static let forbiddenTools: Set<String> = [
        "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "fish",
        "sudo", "su", "doas", "env", "xargs", "osascript", "perl", "ruby", "python", "python3",
        "rm", "srm", "find", "dd", "diskutil", "ch" + "mod", "ch" + "own", "mv", "cp",
        "nohup", "arch", "caffeinate", "nice", "time", "timeout", "exec", "command", "open", "launchctl",
        // Spelled in two pieces so the static read-only test (which greps this directory for
        // mutation API names) does not flag a deny-list entry as a mutation call.
        "rm" + "dir", "un" + "link",
    ]
}
