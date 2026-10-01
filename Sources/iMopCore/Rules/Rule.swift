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
    case appContainerCaches
    case electronCaches
    case chromiumCaches
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

    public var isRestorable: Bool {
        switch self {
        case .quarantine, .trash: return true
        case .command, .permanentDelete, .advisory: return false
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
        }
    }
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
        requiresFullDiskAccess: Bool = false
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
    }

    public static let defaultMaxExpectedBytes: Int64 = 200 * 1_000_000_000
    public static let defaultMaxExpectedItems = 2_000_000

    public var effectiveMaxExpectedBytes: Int64 { maxExpectedBytes ?? Self.defaultMaxExpectedBytes }
    public var effectiveMaxExpectedItems: Int { maxExpectedItems ?? Self.defaultMaxExpectedItems }

    /// Quarantine retention: rule override, else 24 h for Green and 7 days for everything else.
    public var effectiveRetentionHours: Int { retentionHours ?? (tier == .green ? 24 : 24 * 7) }

    /// Expands `{HOME}` in every allow-root.
    public func resolvedAllowRoots(home: String) -> [String] {
        allowRoots.map { $0.replacingOccurrences(of: "{HOME}", with: home) }
    }
}
