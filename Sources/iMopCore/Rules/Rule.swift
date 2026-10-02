import Foundation

/// Safety tier (spec §3.2). Controls default selection, action type and confirmation level.
public enum Tier: String, Codable, Sendable, CaseIterable, Comparable {
    case green, yellow, red, advisory

    /// Green is preselected; Yellow and Red never are; Advisory is not actionable.
    public var selectedByDefault: Bool { self == .green }

    public var displayName: String {
        switch self {
        case .green: return "Safe"
        case .yellow: return "Review"
        case .red: return "Caution"
        case .advisory: return "Info"
        }
    }

    /// SF Symbol paired with the badge text so tier is never conveyed by colour alone.
    public var symbolName: String {
        switch self {
        case .green: return "checkmark.shield"
        case .yellow: return "exclamationmark.triangle"
        case .red: return "hand.raised"
        case .advisory: return "info.circle"
        }
    }

    private var order: Int {
        switch self {
        case .green: return 0
        case .yellow: return 1
        case .red: return 2
        case .advisory: return 3
        }
    }

    public static func < (lhs: Tier, rhs: Tier) -> Bool { lhs.order < rhs.order }
}

/// Rule category (spec §4). Advisory items are grouped by tier in the UI, not by category.
public enum RuleCategory: String, Codable, Sendable, CaseIterable, Identifiable {
    case developer, browsers, apps, system, media, ai, downloads, leftovers

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .developer: return "Developer"
        case .browsers: return "Browsers"
        case .apps: return "Apps"
        case .system: return "System & Logs"
        case .media: return "Media"
        case .ai: return "AI Models"
        case .downloads: return "Downloads"
        case .leftovers: return "Leftovers"
        }
    }

    public var symbolName: String {
        switch self {
        case .developer: return "hammer"
        case .browsers: return "globe"
        case .apps: return "square.grid.2x2"
        case .system: return "doc.plaintext"
        case .media: return "photo.on.rectangle"
        case .ai: return "cpu"
        case .downloads: return "arrow.down.circle"
        case .leftovers: return "trash.square"
        }
    }
}

/// Named inspectors that perform discovery too complex for the tiny glob grammar.
public enum InspectorID: String, Codable, Sendable, CaseIterable {
    case xcodeDerivedData
    case xcodeArchives
    case xcodeDeviceSupport
    case xcodeExtraInstalls
    case simulatorDevices
    case simulatorRuntimes
    case simulatorUnavailable
    case projectArtifacts
    case orphanedAppData
    case orphanedLaunchAgents
    case appUserCaches
    /// Folders directly in `{HOME}/Library/Caches` not resolvable to an installed app (Yellow).
    case appUserCachesUnknownOwner
    case appContainerCaches
    case electronCaches
    case chromiumCaches
    /// `<profile>/Service Worker/CacheStorage` of the Chromium browsers (Yellow).
    case chromiumServiceWorkerCaches
    case vscodeOldExtensions
    case jetbrainsCaches
    case jetbrainsConfig
    case dockerSystem
    case ollamaModels
    case lightroomPreviews
    case macOSInstallers
    case trashContents
    case packageManagerCaches
    case advisory
}

/// A vendor cleanup command (spec §5.3). Never a shell string.
public struct CommandSpec: Codable, Sendable, Hashable {
    /// Executable name resolved only from the trusted directory list (e.g. "xcrun", "brew").
    public let tool: String
    /// Argument array. The token `{ITEM}` is replaced by the per-item argument (UDID, model name, …).
    public let arguments: [String]
    /// Read-only variant used during Scan to estimate size.
    public let dryRunArguments: [String]?
    public let timeoutSeconds: Int?
    /// Required for Green rules that use a command.
    public let idempotentSafe: Bool

    public init(tool: String, arguments: [String], dryRunArguments: [String]? = nil, timeoutSeconds: Int? = nil, idempotentSafe: Bool = false) {
        self.tool = tool
        self.arguments = arguments
        self.dryRunArguments = dryRunArguments
        self.timeoutSeconds = timeoutSeconds
        self.idempotentSafe = idempotentSafe
    }

    public static let itemToken = "{ITEM}"
    public static let defaultTimeout: TimeInterval = 600

    public var timeout: TimeInterval { timeoutSeconds.map(TimeInterval.init) ?? Self.defaultTimeout }
    public var isPerItem: Bool { arguments.contains { $0.contains(Self.itemToken) } }

    public func resolvedArguments(item: String?) -> [String] {
        guard let item else { return arguments }
        return arguments.map { $0.replacingOccurrences(of: Self.itemToken, with: item) }
    }
}

/// How a rule finds candidates.
public enum Discovery: Sendable, Hashable {
    /// One or more patterns in the tiny glob grammar: `{HOME}`, literal segments, `*` within one segment.
    case glob([String])
    /// Size/presence estimated by a read-only vendor command.
    case command(CommandSpec)
    case inspector(InspectorID)
}

public enum AdvisoryKind: String, Codable, Sendable, CaseIterable {
    case revealInFinder
    case openApp
    case openStorageSettings
    case instructions
}

/// What happens to an approved item.
public enum Action: Sendable, Hashable {
    case quarantine
    case trash
    case command(CommandSpec)
    case advisory(AdvisoryKind)
    // SAFETY-DECISION: the spec requires a permanent removal for `trash.empty` (emptying the
    // Trash) and offers "Delete immediately (skip quarantine)" for AI models. Those are the only
    // rules allowed to use this action. It is never offered while Settings → "Always quarantine"
    // is ON (the default) and always requires an explicit per-run confirmation.
    case permanentDelete
    /// Milestone 6, `leftovers.launchAgents` ONLY (pinned by `RuleCatalog.bootoutAndTrashRuleIDs`):
    /// `/bin/launchctl bootout gui/<uid> <plist>` (allow-listed, validated), then the plist is moved
    /// to the Finder Trash. A bootout failure other than "not loaded" leaves the plist untouched.
    case bootoutAndTrash

    // SAFETY-DECISION (M6): `bootoutAndTrash` counts as NOT restorable. The plist can be put back
    // from the Trash, but the bootout (unloading the agent) is not undone by that; the user has to
    // acknowledge the irreversible part explicitly.
    public var isRestorable: Bool {
        switch self {
        case .quarantine, .trash: return true
        case .command, .permanentDelete, .advisory, .bootoutAndTrash: return false
        }
    }
}

/// Named, reusable predicates (spec §3.6). Any predicate that cannot be evaluated is `false`.
public enum Precondition: Sendable, Hashable {
    case appNotRunning([String])
    /// The bundle identifier of the item's owning app (resolved per item) is not running.
    case owningAppNotRunning
    case processNotRunning([String])
    case notOpenByAnyProcess
    case olderThan(days: Int)
    case manifestPresent([String])
    case notInsideCloudRoot
    case ownedByUser
    case simulatorIdle
    case dockerDaemonReachable
    case notMounted
    case appleSigned
    case notSelectedXcode
    case uploadedToCloud
    /// ProjectScanner: the project (the artifact's parent directory) was last used more than N
    /// days ago, measured as the max `lstat` mtime of every manifest file beside the artifact,
    /// `.git/index` and `.git/HEAD`. Fails closed when none of them can be read.
    case projectOlderThan(days: Int)
    /// ProjectScanner: if `<project>/.git` exists, `git ls-files --error-unmatch` must report the
    /// artifact as untracked. Any git error counts as "tracked" (fail closed).
    case notTrackedByGit
    /// OrphanDetector (spec §6.9, Milestone 6): re-evaluated at execute time for the target's
    /// `owningBundleID` — no app registered with LaunchServices or found by Spotlight (condition 2), no
    /// related running app or process (3) and no package receipt referencing it (4). Every error,
    /// timeout or unknown answer counts as "not orphaned" (fail closed).
    case stillOrphaned

    public var name: String {
        switch self {
        case .appNotRunning: return "appNotRunning"
        case .owningAppNotRunning: return "owningAppNotRunning"
        case .processNotRunning: return "processNotRunning"
        case .notOpenByAnyProcess: return "notOpenByAnyProcess"
        case .olderThan: return "olderThan"
        case .manifestPresent: return "manifestPresent"
        case .notInsideCloudRoot: return "notInsideCloudRoot"
        case .ownedByUser: return "ownedByUser"
        case .simulatorIdle: return "simulatorIdle"
        case .dockerDaemonReachable: return "dockerDaemonReachable"
        case .notMounted: return "notMounted"
        case .appleSigned: return "appleSigned"
        case .notSelectedXcode: return "notSelectedXcode"
        case .uploadedToCloud: return "uploadedToCloud"
        case .projectOlderThan: return "projectOlderThan"
        case .notTrackedByGit: return "notTrackedByGit"
        case .stillOrphaned: return "stillOrphaned"
        }
    }
}

/// How the Scanner infers the bundle identifier of the app that owns a glob-discovered target.
/// The inferred identifier feeds `Precondition.owningAppNotRunning` (which fails closed when the
/// owner is unknown).
public enum OwnerInference: String, Codable, Sendable, CaseIterable {
    /// No owner is inferred.
    case none
    /// The name of the target's parent directory (`Caches/<id>/org.sparkle-project.Sparkle`).
    case parentDirectoryName
    /// The target's name without its last extension (`<id>.savedState`).
    case nameWithoutExtension
    /// The target's name with the trailing `.ShipIt` removed (`<id>.ShipIt`).
    case nameBeforeShipIt
}

/// A data-driven cleanup rule (spec §4). Rules can only narrow what is allowed: the Swift deny-list
/// and SafetyGate always apply on top.
public struct Rule: Sendable, Identifiable, Hashable {
    public let id: String
    public let version: Int
    public let category: RuleCategory
    public let tier: Tier
    public let title: String
    public let explanation: String
    public let whatYouLose: String
    public let howItRegenerates: String
    public let discovery: Discovery
    /// Templated with `{HOME}`; must be inside the allowed root universe.
    public let allowRoots: [String]
    public let minDepthBelowRoot: Int
    public let preconditions: [Precondition]
    public let action: Action
    public let retentionHours: Int?
    public let maxExpectedBytes: Int64?
    public let maxExpectedItems: Int?
    public let allowSymlinkTarget: Bool
    /// Exact child names never matched by this rule's globs (e.g. `virtualenvs`, `iMop`).
    public let excludedNames: [String]
    /// Rule requires Full Disk Access to discover anything.
    public let requiresFullDiskAccess: Bool
    /// How the owning app of a glob-discovered target is inferred (inspectors supply owners directly).
    public let ownerInference: OwnerInference

    public init(
        id: String,
        version: Int = 1,
        category: RuleCategory,
        tier: Tier,
        title: String,
        explanation: String,
        whatYouLose: String,
        howItRegenerates: String,
        discovery: Discovery,
        allowRoots: [String],
        minDepthBelowRoot: Int = 1,
        preconditions: [Precondition] = [],
        action: Action,
        retentionHours: Int? = nil,
        maxExpectedBytes: Int64? = nil,
        maxExpectedItems: Int? = nil,
        allowSymlinkTarget: Bool = false,
        excludedNames: [String] = [],
        requiresFullDiskAccess: Bool = false,
        ownerInference: OwnerInference = .none
    ) {
        self.id = id
        self.version = version
        self.category = category
        self.tier = tier
        self.title = title
        self.explanation = explanation
        self.whatYouLose = whatYouLose
        self.howItRegenerates = howItRegenerates
        self.discovery = discovery
        self.allowRoots = allowRoots
        self.minDepthBelowRoot = minDepthBelowRoot
        self.preconditions = preconditions
        self.action = action
        self.retentionHours = retentionHours
        self.maxExpectedBytes = maxExpectedBytes
        self.maxExpectedItems = maxExpectedItems
        self.allowSymlinkTarget = allowSymlinkTarget
        self.excludedNames = excludedNames
        self.requiresFullDiskAccess = requiresFullDiskAccess
        self.ownerInference = ownerInference
    }

    public static let defaultMaxExpectedBytes: Int64 = 200 * 1_000_000_000
    public static let defaultMaxExpectedItems = 2_000_000

    public var effectiveMaxExpectedBytes: Int64 { maxExpectedBytes ?? Self.defaultMaxExpectedBytes }
    public var effectiveMaxExpectedItems: Int { maxExpectedItems ?? Self.defaultMaxExpectedItems }

    /// Quarantine retention: rule override, else 24 h for Green and 7 days for everything else.
    public var effectiveRetentionHours: Int { retentionHours ?? (tier == .green ? 24 : 24 * 7) }

    /// A copy of this rule whose quarantine retention is `hours`, or `nil` when `hours` would SHORTEN
    /// the rule's own retention (or is not positive).
    ///
    /// SAFETY-DECISION (M6): used only by the Executor to hand the CONFIRMED (hashed) retention of a
    /// plan item to the Quarantine, which checks the planned value against the rule it is given. A
    /// user override (`ScanSettings.quarantineRetentionOverrideHours`) may only lengthen retention.
    func withLengthenedRetention(hours: Int) -> Rule? {
        guard hours > 0, hours >= effectiveRetentionHours else { return nil }
        if hours == effectiveRetentionHours { return self }
        return Rule(id: id, version: version, category: category, tier: tier, title: title, explanation: explanation,
                    whatYouLose: whatYouLose, howItRegenerates: howItRegenerates, discovery: discovery,
                    allowRoots: allowRoots, minDepthBelowRoot: minDepthBelowRoot, preconditions: preconditions,
                    action: action, retentionHours: hours, maxExpectedBytes: maxExpectedBytes,
                    maxExpectedItems: maxExpectedItems, allowSymlinkTarget: allowSymlinkTarget,
                    excludedNames: excludedNames, requiresFullDiskAccess: requiresFullDiskAccess,
                    ownerInference: ownerInference)
    }

    /// Expands `{HOME}` in every allow-root. `{PROJECT_ROOTS}` is NOT expanded here (it needs the
    /// user's settings; see `resolvedAllowRoots(environment:)`) and stays an unusable relative string.
    public func resolvedAllowRoots(home: String) -> [String] {
        allowRoots.map { $0.replacingOccurrences(of: "{HOME}", with: home) }
    }

    /// Allow-root token standing for the user-selected ProjectScanner roots (spec §6.5).
    public static let projectRootsToken = "{PROJECT_ROOTS}"

    /// `true` when the rule's allow-roots are the dynamic project roots.
    public var usesProjectRoots: Bool { allowRoots.contains(Self.projectRootsToken) }

    /// Expands `{HOME}` and `{PROJECT_ROOTS}` (to the validated, canonical project roots from
    /// `environment.scanSettings`; see `ProjectRoots.resolve`).
    ///
    /// SAFETY-DECISION: `{PROJECT_ROOTS}` expands only to roots that pass every check in
    /// `ProjectRoots.resolve`; with none configured it expands to nothing (the rule has no usable
    /// allow-root, so SafetyGate check 4 rejects every target and the Scanner offers nothing).
    public func resolvedAllowRoots(environment: SafeCleanEnvironment) -> [String] {
        resolvedAllowRoots(environment: environment, waivedSystemRoots: [])
    }

    /// `waivedSystemRoots`: test-only, see `DenyList.init(homeDirectory:waivedSystemRoots:)`.
    func resolvedAllowRoots(environment: SafeCleanEnvironment, waivedSystemRoots: [String]) -> [String] {
        var resolved: [String] = []
        for raw in allowRoots {
            if raw == Self.projectRootsToken {
                for root in ProjectRoots.resolve(environment: environment, waivedSystemRoots: waivedSystemRoots)
                where !resolved.contains(root.path) {
                    resolved.append(root.path)
                }
            } else {
                resolved.append(raw.replacingOccurrences(of: "{HOME}", with: environment.homePath))
            }
        }
        return resolved
    }
}

/// The user-selected ProjectScanner roots (spec §6.5), validated.
public enum ProjectRoots {
    /// Every configured root (`environment.scanSettings.projectRoots`) that is usable, canonical and
    /// de-duplicated, in settings order.
    ///
    /// SAFETY-DECISION: a root is usable only when ALL of these hold; any other root is ignored:
    /// - it passes the §3.4 text rules (`~`/`{HOME}` expanded from the environment, no `..`);
    /// - it resolves through the file system to exactly its lexical spelling (no symlink anywhere);
    /// - it is an existing directory (lstat), not a symlink;
    /// - it is STRICTLY inside the home directory (never the home directory itself);
    /// - neither it nor anything below it is deny-listed (it is not inside, and does not contain, a
    ///   protected location such as ~/Documents, ~/Desktop, ~/Library/Mobile Documents, ~/.ssh);
    /// - it is not inside (or an ancestor of) a cloud-sync root.
    public static func resolve(environment: SafeCleanEnvironment) -> [CanonicalPath] {
        resolve(environment: environment, waivedSystemRoots: [])
    }

    /// Test-only form: fixture homes live under `/private/var/folders`, which is deny-listed.
    @_spi(FixtureTesting)
    public static func resolve(environment: SafeCleanEnvironment, waivedSystemRoots: [String]) -> [CanonicalPath] {
        let configured = environment.scanSettings.projectRoots
        guard !configured.isEmpty else { return [] }
        let canonicalizer = PathCanonicalizer(environment: environment)
        let homeForms = PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        guard !homeForms.isEmpty else { return [] }
        var homes = [environment.homePath]
        for form in homeForms where !homes.contains(form.path) { homes.append(form.path) }
        let denyLists = homes.map { home in
            waivedSystemRoots.isEmpty
                ? DenyList(homeDirectory: home)
                : DenyList(homeDirectory: home, waivedSystemRoots: waivedSystemRoots)
        }
        let evaluator = PreconditionEvaluator(environment: environment)
        let cloudRoots = evaluator.cloudRoots()
        guard !cloudRoots.isEmpty else { return [] }

        var roots: [CanonicalPath] = []
        for raw in configured {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed == raw else { continue }
            guard case .success(let lexical) = canonicalizer.lexical(raw),
                  case .success(let canonical) = canonicalizer.canonicalize(raw),
                  canonical == lexical else { continue }
            guard let info = environment.fileSystem.lstat(canonical.path), info.isDirectory, !info.isSymlink else { continue }
            guard let home = homeForms.first(where: { canonical.isStrictlyInside($0) }) else { continue }
            // SAFETY-DECISION (M5 integration): a root at or below a folder named like a project
            // artifact (`~/code/app/node_modules`) or inside a package / bundle would let nested
            // artifacts be proposed; such a root is ignored here too, so SafetyGate never accepts a
            // root the ProjectScanner would refuse to walk.
            let below = canonical.components.dropFirst(home.components.count)
            guard !below.contains(where: { ProjectArtifactsInspector.isArtifactLikeName($0) || ProjectArtifactsInspector.isPackageName($0) }),
                  SafetyGate.bundleAncestor(of: canonical, fileSystem: environment.fileSystem) == nil else { continue }
            let probe = canonical.appending("imop-project-root-probe")
            let denied = denyLists.contains { list in
                list.matchingEntry(for: canonical, ruleID: nil, purpose: .standard) != nil
                    || list.matchingEntry(for: probe, ruleID: nil, purpose: .standard) != nil
            }
            guard !denied else { continue }
            guard !cloudRoots.contains(where: { canonical.isInsideOrEqual($0) || $0.isStrictlyInside(canonical) }) else { continue }
            if !roots.contains(canonical) { roots.append(canonical) }
        }
        return roots
    }
}
