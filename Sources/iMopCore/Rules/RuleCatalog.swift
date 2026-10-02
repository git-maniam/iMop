import Foundation
import os

/// Why a rule was disabled at load time.
public struct RuleValidationIssue: Sendable, Hashable, CustomStringConvertible {
    /// The rule's id, or a placeholder (`"<catalog>"`, `"rules[3]"`) when it has none.
    public let ruleID: String
    public let message: String

    public init(ruleID: String, message: String) {
        self.ruleID = ruleID
        self.message = message
    }

    public var description: String { "\(ruleID): \(message)" }
}

/// The validated rule set (spec §4). Rules can only NARROW what is allowed; the Swift deny-list and
/// SafetyGate always apply on top. Any invalid rule is disabled and recorded; the app continues.
///
/// Read-only: loading reads the bundled Rules.json; validation is pure computation.
public struct RuleCatalog: Sendable {
    /// Valid rules, in file order.
    public let rules: [Rule]
    /// One entry per problem that disabled a rule (a rule may have several).
    public let disabled: [RuleValidationIssue]

    private static let logger = Logger(subsystem: "com.imop.cleaner", category: "RuleCatalog")

    /// Placeholder rule id for problems with the catalog file itself.
    public static let catalogIssueID = "<catalog>"
    public static let supportedFileVersion = 1
    public static let resourceBundleName = "iMop_iMopCore.bundle"

    private init(rules: [Rule], disabled: [RuleValidationIssue]) {
        self.rules = rules
        self.disabled = disabled
    }

    /// Validates in-memory rules exactly like `load(data:environment:)` (used by tests and by
    /// callers that build rules in code). Invalid rules are disabled, never trusted.
    public init(validating candidates: [Rule], environment: SafeCleanEnvironment) {
        self = Self.build(slots: candidates.enumerated().map { RuleSlot(index: $0.offset, id: $0.element.id, outcome: .success($0.element)) },
                          preIssues: [])
    }

    public func rule(id: String) -> Rule? {
        rules.first { $0.id == id }
    }

    // MARK: - Loading

    /// Loads the Rules.json shipped inside the app. Never traps: a missing or unreadable file gives an
    /// empty catalog with an issue.
    public static func loadBundled(environment: SafeCleanEnvironment) -> RuleCatalog {
        for url in bundledCandidateURLs() {
            // The rules file lives in the app's own (signed) bundle or the build directory, never in
            // user data, so it is read directly rather than through the home-guarded probe.
            guard FileManager.default.isReadableFile(atPath: url.path),
                  let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { continue }
            return load(data: data, environment: environment)
        }
        let issue = RuleValidationIssue(ruleID: catalogIssueID, message: "Rules.json was not found in the app bundle")
        logger.error("\(issue.description, privacy: .public)")
        return RuleCatalog(rules: [], disabled: [issue])
    }

    /// Candidate locations of the bundled Rules.json, most specific first.
    ///
    /// SAFETY-DECISION: the SwiftPM-generated `Bundle.module` accessor calls `fatalError` when its
    /// bundle is missing, so it is never referenced. Instead the same places it searches (next to the
    /// executable / at the main bundle's URL) are probed explicitly, after Contents/Resources.
    static func bundledCandidateURLs() -> [URL] {
        var bundleURLs: [URL] = []
        if let resources = Bundle.main.resourceURL {
            bundleURLs.append(resources.appendingPathComponent(resourceBundleName, isDirectory: true))
        }
        bundleURLs.append(Bundle.main.bundleURL.appendingPathComponent(resourceBundleName, isDirectory: true))
        if let executable = Bundle.main.executableURL {
            bundleURLs.append(executable.deletingLastPathComponent().appendingPathComponent(resourceBundleName, isDirectory: true))
        }

        var urls: [URL] = []
        if let first = bundleURLs.first {
            urls.append(contentsOf: rulesURLs(inResourceBundle: first))
        }
        if let main = Bundle.main.url(forResource: "Rules", withExtension: "json") {
            urls.append(main)
        }
        for bundleURL in bundleURLs.dropFirst() {
            urls.append(contentsOf: rulesURLs(inResourceBundle: bundleURL))
        }
        var seen = Set<String>()
        return urls.filter { seen.insert($0.standardizedFileURL.path).inserted }
    }

    private static func rulesURLs(inResourceBundle bundleURL: URL) -> [URL] {
        var urls: [URL] = []
        if let bundle = Bundle(url: bundleURL), let url = bundle.url(forResource: "Rules", withExtension: "json") {
            urls.append(url)
        }
        // Flat and Contents/Resources layouts.
        urls.append(bundleURL.appendingPathComponent("Rules.json"))
        urls.append(bundleURL.appendingPathComponent("Contents/Resources/Rules.json"))
        return urls
    }

    /// Decodes `{"version": 1, "rules": [ … ]}` one rule at a time, so a malformed rule disables
    /// only itself, then validates every rule.
    public static func load(data: Data, environment: SafeCleanEnvironment) -> RuleCatalog {
        let file: CatalogFile
        do {
            file = try JSONDecoder().decode(CatalogFile.self, from: data)
        } catch {
            let issue = RuleValidationIssue(ruleID: catalogIssueID, message: "Rules.json is malformed: \(describe(error))")
            logger.error("\(issue.description, privacy: .public)")
            return RuleCatalog(rules: [], disabled: [issue])
        }
        guard file.version == supportedFileVersion else {
            // SAFETY-DECISION: an unknown file format version is never interpreted.
            let issue = RuleValidationIssue(ruleID: catalogIssueID, message: "Unsupported Rules.json version \(file.version)")
            logger.error("\(issue.description, privacy: .public)")
            return RuleCatalog(rules: [], disabled: [issue])
        }
        return build(slots: file.slots, preIssues: [])
    }

    private static func build(slots: [RuleSlot], preIssues: [RuleValidationIssue]) -> RuleCatalog {
        var issues = preIssues

        // SAFETY-DECISION: an id used more than once (even by a rule that failed to decode) is
        // ambiguous; EVERY rule with that id is disabled.
        var counts: [String: Int] = [:]
        for slot in slots {
            if let id = slot.id { counts[id, default: 0] += 1 }
        }

        var valid: [Rule] = []
        for slot in slots {
            let label = slot.id ?? "rules[\(slot.index)]"
            switch slot.outcome {
            case .failure(let message):
                issues.append(RuleValidationIssue(ruleID: label, message: "Could not be decoded: \(message)"))
            case .success(let rule):
                var problems = validationProblems(for: rule)
                if (counts[rule.id] ?? 0) > 1 {
                    problems.insert("Duplicate rule id", at: 0)
                }
                if problems.isEmpty {
                    valid.append(rule)
                } else {
                    issues.append(contentsOf: problems.map { RuleValidationIssue(ruleID: label, message: $0) })
                }
            }
        }
        let crossRule = crossRuleProblems(valid)
        if !crossRule.isEmpty {
            valid.removeAll { crossRule[$0.id] != nil }
            for (id, messages) in crossRule.sorted(by: { $0.key < $1.key }) {
                issues.append(contentsOf: messages.map { RuleValidationIssue(ruleID: id, message: $0) })
            }
        }
        for issue in issues {
            logger.error("Rule disabled — \(issue.description, privacy: .public)")
        }
        return RuleCatalog(rules: valid, disabled: issues)
    }

    // MARK: - Swift-coded exception tables (never in Rules.json)

    /// A precondition a pinned rule must declare.
    public enum RequiredPrecondition: Sendable, Hashable {
        case appleSigned
        case notSelectedXcode
        case ownedByUser
        /// `olderThan(days)` with at least this many days.
        case olderThanAtLeast(Int)
        /// A non-empty `appNotRunning([...])` or `owningAppNotRunning`.
        case anAppNotRunningCheck
        /// `appNotRunning` listing exactly this bundle-id pattern (case-insensitive) (M6).
        case appNotRunning(String)

        func isSatisfied(by preconditions: [Precondition]) -> Bool {
            if case .appNotRunning(let pattern) = self {
                return RuleTargetMatcher.declares(preconditions, .appNotRunning([pattern]))
            }
            return preconditions.contains { precondition in
                switch (self, precondition) {
                case (.appleSigned, .appleSigned), (.notSelectedXcode, .notSelectedXcode), (.ownedByUser, .ownedByUser):
                    return true
                case (.olderThanAtLeast(let minimum), .olderThan(let days)):
                    return days >= minimum
                case (.anAppNotRunningCheck, .appNotRunning(let ids)):
                    return !ids.isEmpty
                case (.anAppNotRunningCheck, .owningAppNotRunning):
                    return true
                default:
                    return false
                }
            }
        }
    }

    /// The complete, Swift-coded shape of a rule that may declare an allow-root outside `{HOME}`.
    public struct NonHomeRuleSpec: Sendable {
        /// The rule's allow-roots must be a non-empty subset of these.
        public let allowRoots: [String]
        public let tier: Tier
        public let action: Action
        /// Must equal the rule's discovery exactly.
        public let discovery: Discovery
        public let requiredPreconditions: [RequiredPrecondition]
    }

    /// SAFETY-DECISION (review M2): rules allowed to declare an allow-root outside `{HOME}` (spec §6:
    /// `/cores/core.*`, `/Applications/…`) are pinned COMPLETELY here — allow-roots, tier, action,
    /// discovery and required preconditions. A rule with one of these ids that deviates in any field
    /// is disabled, whatever allow-root it declares (SafetyGate lets `xcode.extraInstalls` and
    /// `installers.macOS` trash a whole `.app`, so their shape must never come from Rules.json alone).
    /// Every target is still deny-list-checked and gated individually.
    ///
    /// `system.coreDumps`: spec §6.6 says quarantine is not possible (different root) → permanent
    /// delete with explicit confirmation, downgraded to Yellow. Milestone 6 reviewed both tables: it is
    /// in `permanentDeleteAllowList`, and (like every permanent deletion) it stays blocked while
    /// Settings → "Always quarantine" is ON.
    ///
    /// SAFETY-DECISION (M6): `installers.macOS` is discovered by the `macOSInstallers` inspector (it
    /// reads each bundle's Info.plist so only Apple's "Install macOS …" assistants are offered) instead
    /// of a bare glob, and must declare `appNotRunning(com.apple.InstallAssistant.*)`.
    public static let nonHomeRuleSpecs: [String: NonHomeRuleSpec] = [
        "system.coreDumps": NonHomeRuleSpec(
            allowRoots: ["/cores"], tier: .yellow, action: .permanentDelete,
            discovery: .glob(["/cores/core.*"]),
            requiredPreconditions: [.ownedByUser, .olderThanAtLeast(1)]),
        "xcode.extraInstalls": NonHomeRuleSpec(
            allowRoots: ["/Applications", "{HOME}/Applications"], tier: .red, action: .trash,
            discovery: .inspector(.xcodeExtraInstalls),
            requiredPreconditions: [.appleSigned, .notSelectedXcode, .anAppNotRunningCheck]),
        "installers.macOS": NonHomeRuleSpec(
            allowRoots: ["/Applications"], tier: .yellow, action: .trash,
            discovery: .inspector(.macOSInstallers),
            requiredPreconditions: [.appleSigned, .appNotRunning(macOSInstallerBundleIDPattern)]),
    ]

    /// Bundle-identifier pattern of Apple's "Install macOS …" assistants.
    public static let macOSInstallerBundleIDPattern = "com.apple.InstallAssistant.*"

    /// Non-home allow-roots per rule id (derived from `nonHomeRuleSpecs`).
    public static var nonHomeAllowRootExceptions: [String: [String]] {
        nonHomeRuleSpecs.mapValues { $0.allowRoots.filter { !$0.hasPrefix(GlobPattern.homeToken + "/") } }
    }

    /// An allow-root that CONTAINS deny-listed locations, with the constraints that make it safe.
    public struct ProtectedAncestorRootException: Sendable {
        public let roots: [String]
        /// The only discovery allowed for the rule; `nil` = glob discovery (SafetyGate re-checks the
        /// glob shape and `excludedNames` of every target).
        public let inspector: InspectorID?
        /// Swift-coded lower bound for the rule's `minDepthBelowRoot`.
        public let minimumDepth: Int
        /// Names the rule's `excludedNames` must contain.
        public let requiredExcludedNames: [String]
    }

    /// SAFETY-DECISION: allow-roots that CONTAIN deny-listed locations, permitted only for these rules
    /// (e.g. `~/Library/Containers` contains `com.apple.*` containers, `~/Library/Logs` contains iMop's
    /// own audit log). The root itself must not be inside a deny-listed area, the discovery and a
    /// minimum depth are pinned (review M2: 5 for containers = `<id>/Data/Library/Caches/<child>`, 2
    /// for Electron = `<App>/<cache>`, 3 for Chromium = `<browser>/<profile>/<cache>`), and SafetyGate
    /// still rejects any target that is, or contains, a deny-listed location or that does not have the
    /// rule's shape.
    public static let protectedAncestorRootExceptions: [String: ProtectedAncestorRootException] = [
        "apps.containerCaches": ProtectedAncestorRootException(
            roots: ["{HOME}/Library/Containers"], inspector: .appContainerCaches, minimumDepth: 5, requiredExcludedNames: []),
        "apps.electronCaches": ProtectedAncestorRootException(
            roots: ["{HOME}/Library/Application Support"], inspector: .electronCaches, minimumDepth: 2, requiredExcludedNames: []),
        "browser.chromium.cache": ProtectedAncestorRootException(
            roots: ["{HOME}/Library/Application Support"], inspector: .chromiumCaches, minimumDepth: 3, requiredExcludedNames: []),
        // M5: <browser…>/<profile>/Service Worker/CacheStorage (Edge has the shallowest browser folder).
        "browser.chromium.serviceWorkerCache": ProtectedAncestorRootException(
            roots: ["{HOME}/Library/Application Support"], inspector: .chromiumServiceWorkerCaches, minimumDepth: 4,
            requiredExcludedNames: []),
        "logs.user": ProtectedAncestorRootException(
            roots: ["{HOME}/Library/Logs"], inspector: nil, minimumDepth: 1, requiredExcludedNames: ["iMop"]),
        // M6 (spec §6.9): the OrphanDetector looks at `<container>/<identifier>` directly in these
        // folders; they contain `com.apple.*` / `group.com.apple.*` entries, AddressBook, MobileSync,
        // TCC and iMop's own folder, which the deny-list still refuses one by one.
        "leftovers.appData": ProtectedAncestorRootException(
            roots: orphanedAppDataRoots, inspector: .orphanedAppData, minimumDepth: 1, requiredExcludedNames: []),
        // M6: `~/Library/LaunchAgents/com.apple.*` is deny-listed; every other agent is checked one by one.
        "leftovers.launchAgents": ProtectedAncestorRootException(
            roots: ["{HOME}/Library/LaunchAgents"], inspector: .orphanedLaunchAgents, minimumDepth: 1, requiredExcludedNames: []),
    ]

    /// Spec §6.9 candidate folders of `leftovers.appData`, as allow-roots.
    ///
    /// SAFETY-DECISION (M6): `~/Library/HTTPStorages` is deny-listed as a whole (cookies / web
    /// credentials), so it is never an allow-root and never offered; `~/Library/LaunchAgents` belongs
    /// to `leftovers.launchAgents`.
    public static let orphanedAppDataRoots: [String] = [
        "{HOME}/Library/Application Support", "{HOME}/Library/Preferences", "{HOME}/Library/Containers",
        "{HOME}/Library/Group Containers", "{HOME}/Library/Caches", "{HOME}/Library/WebKit",
    ]

    /// SAFETY-DECISION: allow-roots that are themselves inside a deny-listed area, mirroring the
    /// deny-list's own narrow exception (`DenyList`: direct children of Mail Downloads for
    /// `mail.downloads` only). Accepted only if a direct child of the root is NOT deny-listed for that
    /// rule, i.e. the deny-list exception really exists.
    public static let deniedRootExceptions: [String: [String]] = [
        "mail.downloads": ["{HOME}/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"],
    ]

    /// SAFETY-DECISION (M5, spec §6.7): `lightroom.previews` finds catalogs anywhere in the home folder
    /// (via Spotlight), so it is the only rule whose allow-root may be `{HOME}` itself. Its discovery
    /// is pinned to the Lightroom inspector, whose Swift-coded shape (`RuleTargetMatcher`) only ever
    /// matches a `"<catalog> Previews.lrdata"` folder; the deny-list and every SafetyGate check still
    /// apply to each target (catalogs under ~/Pictures or ~/Documents are therefore never touched).
    public static let homeRootRuleExceptions: [String: InspectorID] = [
        "lightroom.previews": .lightroomPreviews,
    ]

    /// The complete, Swift-coded binding of a Milestone 5 inspector rule.
    public struct InspectorRuleSpec: Sendable {
        public let inspector: InspectorID
        public let tier: Tier
        /// Preconditions the rule must declare (or a stricter form; see `RuleTargetMatcher.declares`).
        public let requiredPreconditions: [Precondition]
        /// The only action the rule may use (Milestone 5 rules quarantine; Milestone 6 adds Trash flows).
        public let action: Action

        init(inspector: InspectorID, tier: Tier, requiredPreconditions: [Precondition], action: Action = .quarantine) {
            self.inspector = inspector
            self.tier = tier
            self.requiredPreconditions = requiredPreconditions
            self.action = action
        }
    }

    /// SAFETY-DECISION (M5): rule ids allowed to use each Milestone 5 inspector, with the tier and the
    /// spec §6 preconditions pinned. A Rules.json rule that binds one of these inspectors under another
    /// id, tier, or without a pinned precondition is disabled. (ProjectScanner rules are pinned in
    /// `RuleTargetMatcher.projectArtifactSpecs`.)
    public static let inspectorRuleSpecs: [String: InspectorRuleSpec] = {
        let xcode: [Precondition] = [.appNotRunning(["com.apple.dt.Xcode"])]
        let derivedData = xcode + [.processNotRunning(["xcodebuild"])]
        let jetbrains: [Precondition] = [.appNotRunning(["com.jetbrains.*"])]
        return [
            "xcode.derivedData.orphaned": InspectorRuleSpec(inspector: .xcodeDerivedData, tier: .green, requiredPreconditions: derivedData),
            "xcode.derivedData.active": InspectorRuleSpec(inspector: .xcodeDerivedData, tier: .yellow,
                                                          requiredPreconditions: derivedData + [.olderThan(days: 14)]),
            "xcode.archives.old": InspectorRuleSpec(inspector: .xcodeArchives, tier: .yellow, requiredPreconditions: xcode),
            "xcode.deviceSupport": InspectorRuleSpec(inspector: .xcodeDeviceSupport, tier: .yellow,
                                                     requiredPreconditions: xcode + [.olderThan(days: 30)]),
            "vscode.oldExtensions": InspectorRuleSpec(inspector: .vscodeOldExtensions, tier: .yellow,
                                                      requiredPreconditions: [.appNotRunning(["com.microsoft.VSCode"])]),
            "jetbrains.caches.orphanedVersion": InspectorRuleSpec(inspector: .jetbrainsCaches, tier: .green, requiredPreconditions: jetbrains),
            "jetbrains.caches.current": InspectorRuleSpec(inspector: .jetbrainsCaches, tier: .yellow, requiredPreconditions: jetbrains),
            "apps.userCaches.unknownOwner": InspectorRuleSpec(inspector: .appUserCachesUnknownOwner, tier: .yellow,
                                                              requiredPreconditions: [.notOpenByAnyProcess, .olderThan(days: 30)]),
            "browser.chromium.serviceWorkerCache": InspectorRuleSpec(inspector: .chromiumServiceWorkerCaches, tier: .yellow,
                                                                     requiredPreconditions: [.owningAppNotRunning]),
            "lightroom.previews": InspectorRuleSpec(inspector: .lightroomPreviews, tier: .yellow,
                                                    requiredPreconditions: [.appNotRunning(["com.adobe.LightroomClassicCC7"])]),
            // Milestone 6 (spec §6.3, §6.6, §6.9). SAFETY-DECISION: Red rules move to the Trash one
            // item at a time with per-item confirmation; `leftovers.appData` re-checks at execute that
            // the owner is still not installed / running / referenced by a receipt (`stillOrphaned`).
            "leftovers.appData": InspectorRuleSpec(inspector: .orphanedAppData, tier: .red,
                                                   requiredPreconditions: [.owningAppNotRunning, .olderThan(days: 30),
                                                                           .notOpenByAnyProcess, .stillOrphaned],
                                                   action: .trash),
            "leftovers.launchAgents": InspectorRuleSpec(inspector: .orphanedLaunchAgents, tier: .red,
                                                        requiredPreconditions: [.notOpenByAnyProcess], action: .bootoutAndTrash),
            "jetbrains.config.orphanedVersion": InspectorRuleSpec(inspector: .jetbrainsConfig, tier: .red,
                                                                  requiredPreconditions: jetbrains, action: .trash),
            "trash.empty": InspectorRuleSpec(inspector: .trashContents, tier: .yellow, requiredPreconditions: [],
                                             action: .permanentDelete),
        ]
    }()

    /// SAFETY-DECISION (M6): the only rule ids that may use `Action.bootoutAndTrash` (spec §6.9: an
    /// orphaned LaunchAgent is booted out with launchctl, then its plist is moved to the Trash).
    public static let bootoutAndTrashRuleIDs: Set<String> = ["leftovers.launchAgents"]

    /// SAFETY-DECISION (M6, spec §6.4, §6.7, §6.10): the Advisory rules, each pinned to its advisory
    /// action. They use the read-only `advisory` inspector, have NO allow-root at all (so even a target
    /// wrongly routed to a file action fails SafetyGate check 4), and their items are always of kind
    /// `.advisory`, which SafetyGate and the Executor never act on. The `advisory` inspector serves only
    /// these ids.
    public static let advisoryRuleSpecs: [String: AdvisoryKind] = [
        "docker.diskImage": .openApp,
        "finalcut.generated": .instructions,
        "audio.soundLibraries": .instructions,
        "advisory.timeMachineSnapshots": .instructions,
        "advisory.purgeableSpace": .instructions,
        "advisory.iosBackups": .revealInFinder,
        "advisory.systemStorage": .openStorageSettings,
        "advisory.appleIntelligenceAssets": .instructions,
        "advisory.iCloudDrive": .instructions,
        "advisory.rootOwnedLocations": .instructions,
    ]

    /// Inspectors whose rules must appear in `inspectorRuleSpecs`.
    static var pinnedM5Inspectors: Set<InspectorID> { Set(inspectorRuleSpecs.values.map(\.inspector)) }

    /// Rules allowed to use `.permanentDelete` (Yellow only). Both are blocked while Settings →
    /// "Always quarantine" is ON (PlanBuilder, ConfirmedPlan) and need the irreversible acknowledgement.
    public static let permanentDeleteAllowList: Set<String> = ["trash.empty", "system.coreDumps"]

    /// SAFETY-DECISION: Red rules may use a vendor command only when listed here (per-item
    /// confirmation is mandatory for them). `docker.volumes` (spec §6.4) is the only one.
    /// (Milestone 6: `leftovers.launchAgents` uses the pinned `bootoutAndTrash` action instead of a
    /// rule command, so it was removed from this table.)
    public static let redCommandAllowList: Set<String> = ["docker.volumes"]

    /// One reviewed vendor command (exact tool and argument array). The table itself lives in
    /// `CommandAllowList` and is shared with the live `CommandRunner`.
    public typealias AllowedCommand = CommandAllowList.Entry

    /// SAFETY-DECISION (review M2, M4): commands are not path-gated, so the validator is an
    /// ALLOW-list: only these exact (tool, arguments) pairs from spec §6 may be a rule's action.
    /// `{ITEM}` stands for the per-item argument and must be a whole argument. Anything else —
    /// wrappers (`nohup`, `arch`, `caffeinate`, `nice`, `time`), arbitrary `xcrun <tool>`, destructive
    /// vendor subcommands such as `docker volume prune` — disables the rule.
    public static var allowedActionCommands: [AllowedCommand] {
        CommandAllowList.standard.actionEntries.filter(\.usableByRules)
    }

    /// SAFETY-DECISION (review M2): the read-only commands a rule may run during Scan (its discovery
    /// command or an action's `dryRunArguments`). Exact (tool, arguments) pairs only.
    public static var allowedReadOnlyCommands: [AllowedCommand] {
        CommandAllowList.standard.readOnlyEntries.filter(\.usableByRules)
    }

    /// SAFETY-DECISION: tools a rule may name at all (review M2), checked before the exact tables.
    public static var allowedTools: Set<String> { CommandAllowList.ruleTools }

    /// Argument tokens that are never allowed in any command or dry-run argument array.
    /// (Milestone 4: the blanket "rm" token was replaced by exact allow-list entries.)
    public static var forbiddenCommandArguments: Set<String> { CommandAllowList.forbiddenArguments }

    /// SAFETY-DECISION: executables that are never acceptable as a rule's tool (shells, privilege
    /// escalation, generic removers and interpreters that could run arbitrary code).
    public static var forbiddenTools: Set<String> { CommandAllowList.forbiddenTools }

    /// Synthetic home used for validation. Validation is a property of the rule text alone and does
    /// not depend on where the current user's home directory happens to be.
    static let validationHome = "/Users/imop-rule-validation"
    private static let probeName = "imop-validation-probe"

    // MARK: - Validation

    /// Every reason `rule` is invalid (empty when valid). Spec §4 plus the SAFETY-DECISIONs above.
    public static func validationProblems(for rule: Rule) -> [String] {
        var problems: [String] = []
        let denyList = DenyList(homeDirectory: validationHome)

        // Identity and text.
        if !isValidRuleID(rule.id) {
            problems.append("Rule id must be non-empty and use only letters, digits, '.', '-' or '_'")
        }
        if rule.version < 1 { problems.append("version must be at least 1") }
        for (name, text) in [("title", rule.title), ("explanation", rule.explanation),
                             ("whatYouLose", rule.whatYouLose), ("howItRegenerates", rule.howItRegenerates)]
        where text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            problems.append("\(name) must not be empty")
        }

        // Numeric limits.
        if rule.minDepthBelowRoot < 1 { problems.append("minDepthBelowRoot must be at least 1") }
        if let bytes = rule.maxExpectedBytes, bytes <= 0 { problems.append("maxExpectedBytes must be greater than 0") }
        if let items = rule.maxExpectedItems, items <= 0 { problems.append("maxExpectedItems must be greater than 0") }
        if let hours = rule.retentionHours, hours <= 0 { problems.append("retentionHours must be greater than 0") }

        // Allow-roots.
        var roots: [(raw: String, path: CanonicalPath, isNonHome: Bool)] = []
        if advisoryRuleSpecs[rule.id] != nil, rule.tier == .advisory {
            // SAFETY-DECISION (M6): pinned advisory rules have no allow-root at all (see
            // `advisoryRuleSpecs`); anything else is a misconfiguration.
            if !rule.allowRoots.isEmpty { problems.append("advisory rules must not declare allowRoots") }
        } else if rule.allowRoots.isEmpty {
            problems.append("allowRoots must not be empty")
        }
        for raw in rule.allowRoots {
            if raw == Rule.projectRootsToken {
                problems.append(contentsOf: validateProjectRootsToken(rule))
                continue
            }
            if raw == GlobPattern.homeToken {
                problems.append(contentsOf: validateHomeRoot(rule))
                continue
            }
            switch validateAllowRoot(raw, rule: rule, denyList: denyList) {
            case .success(let entry): roots.append(entry)
            case .failure(let problem): problems.append(problem.message)
            }
        }

        // Discovery.
        switch rule.discovery {
        case .glob(let patterns):
            problems.append(contentsOf: validateGlobs(patterns, rule: rule, roots: roots, denyList: denyList))
        case .inspector:
            if rule.ownerInference != .none {
                problems.append("ownerInference applies to glob discovery only (inspectors supply owners)")
            }
        case .command(let spec):
            problems.append(contentsOf: validateCommand(spec, context: "discovery command", rule: rule, isAction: false))
            if rule.ownerInference != .none {
                problems.append("ownerInference applies to glob discovery only")
            }
        }
        if case .glob = rule.discovery {} else if !rule.excludedNames.isEmpty {
            problems.append("excludedNames applies to glob discovery only")
        }
        for name in rule.excludedNames where !isValidName(name) {
            problems.append("excludedNames entry \"\(name)\" must be a single file name")
        }

        // Tier / action matrix.
        problems.append(contentsOf: validateTierAction(rule))
        if case .command(let spec) = rule.action {
            problems.append(contentsOf: validateCommand(spec, context: "action command", rule: rule, isAction: true))
        }

        // Preconditions.
        problems.append(contentsOf: validatePreconditions(rule))

        // Swift-coded pinned shapes (review M2).
        problems.append(contentsOf: validatePinnedShapes(rule))

        return problems
    }

    private struct Problem: Error { let message: String }

    /// SAFETY-DECISION (M5, spec §6.5): `{PROJECT_ROOTS}` is accepted only as the SOLE allow-root of a
    /// Swift-pinned ProjectScanner rule. It expands at run time to the validated, canonical
    /// `scanSettings.projectRoots` (strictly inside {HOME}, not deny-listed; see `ProjectRoots`).
    private static func validateProjectRootsToken(_ rule: Rule) -> [String] {
        var problems: [String] = []
        if rule.allowRoots != [Rule.projectRootsToken] {
            problems.append("\(Rule.projectRootsToken) must be the only allowRoot")
        }
        if rule.discovery != .inspector(.projectArtifacts) || RuleTargetMatcher.projectArtifactSpecs[rule.id] == nil {
            problems.append("\(Rule.projectRootsToken) is only allowed for the reviewed ProjectScanner rules")
        }
        return problems
    }

    /// SAFETY-DECISION (M5): `{HOME}` itself is accepted only for the rules in `homeRootRuleExceptions`,
    /// as their sole allow-root, with the pinned inspector.
    private static func validateHomeRoot(_ rule: Rule) -> [String] {
        guard let inspector = homeRootRuleExceptions[rule.id] else {
            return ["allowRoot \"\(GlobPattern.homeToken)\" must be strictly inside {HOME}"]
        }
        var problems: [String] = []
        if rule.allowRoots != [GlobPattern.homeToken] { problems.append("\(GlobPattern.homeToken) must be the only allowRoot") }
        if rule.discovery != .inspector(inspector) { problems.append("discovery must be the \(inspector.rawValue) inspector for this rule") }
        if rule.allowSymlinkTarget { problems.append("allowSymlinkTarget is not allowed for this rule") }
        return problems
    }

    private static func validateAllowRoot(_ raw: String, rule: Rule, denyList: DenyList)
        -> Result<(raw: String, path: CanonicalPath, isNonHome: Bool), Problem> {
        let homePrefix = GlobPattern.homeToken + "/"
        if !raw.hasPrefix(homePrefix) {
            guard nonHomeAllowRootExceptions[rule.id]?.contains(raw) == true else {
                return .failure(Problem(message: "allowRoot \"\(raw)\" must start with {HOME}/"))
            }
            guard case .success(let path) = PathCanonicalizer.clean(raw, home: nil), !path.components.isEmpty else {
                return .failure(Problem(message: "allowRoot \"\(raw)\" is not a valid path"))
            }
            // SAFETY-DECISION: the Swift-coded non-home roots are reviewed exceptions; root-level
            // deny-list checks are not applied to them (e.g. /Applications contains
            // /Applications/Utilities), but every target below them is still deny-list-checked and
            // gated (only /cores/core.* is ever reachable under /cores).
            return .success((raw, path, true))
        }

        // Grammar: a literal {HOME}-anchored path with no wildcards.
        guard GlobPattern(raw) != nil, !raw.contains("*") else {
            return .failure(Problem(message: "allowRoot \"\(raw)\" is not a literal {HOME}/… path"))
        }
        guard case .success(let path) = PathCanonicalizer.clean(raw, home: validationHome),
              let home = PathCanonicalizer.validHome(validationHome) else {
            return .failure(Problem(message: "allowRoot \"\(raw)\" is not a valid path"))
        }
        let homePath = CanonicalPath(validatedPath: home)
        guard path.isStrictlyInside(homePath) else {
            return .failure(Problem(message: "allowRoot \"\(raw)\" must be strictly inside {HOME}"))
        }

        let probe = path.appending(probeName)
        let protectedAncestor = protectedAncestorRootExceptions[rule.id]?.roots.contains(raw) == true
        if deniedRootExceptions[rule.id]?.contains(raw) == true || protectedAncestor {
            // The root itself may be (or contain) a protected location, but its direct children must
            // be reachable for this rule — otherwise the exception is meaningless or misconfigured.
            if let entry = denyList.matchingEntry(for: probe, ruleID: rule.id, purpose: .standard) {
                return .failure(Problem(message: "allowRoot \"\(raw)\" is deny-listed (\(entry))"))
            }
            if protectedAncestor,
               let entry = denyList.matchingEntry(for: path, ruleID: rule.id, purpose: .standard),
               !entry.hasPrefix("contains ") {
                return .failure(Problem(message: "allowRoot \"\(raw)\" is deny-listed (\(entry))"))
            }
            return .success((raw, path, false))
        }

        // Neither inside nor an ancestor-or-equal of any deny-list entry (system or home-relative).
        if let entry = denyList.matchingEntry(for: path, ruleID: rule.id, purpose: .standard) {
            return .failure(Problem(message: "allowRoot \"\(raw)\" intersects the deny-list (\(entry))"))
        }
        if let entry = denyList.matchingEntry(for: probe, ruleID: rule.id, purpose: .standard) {
            return .failure(Problem(message: "allowRoot \"\(raw)\" intersects the deny-list (\(entry))"))
        }
        return .success((raw, path, false))
    }

    private static func validateGlobs(_ patterns: [String], rule: Rule,
                                      roots: [(raw: String, path: CanonicalPath, isNonHome: Bool)],
                                      denyList: DenyList) -> [String] {
        var problems: [String] = []
        if patterns.isEmpty { problems.append("glob discovery needs at least one pattern") }
        if let exception = protectedAncestorRootExceptions[rule.id], exception.inspector != nil {
            problems.append("glob discovery is not allowed for a rule whose allow-root contains protected locations")
        }
        let requiredDepth = max(1, rule.minDepthBelowRoot)
        for raw in patterns {
            guard !raw.contains("**") else {
                problems.append("glob \"\(raw)\" uses the forbidden recursive wildcard **")
                continue
            }
            guard let pattern = GlobPattern(raw) else {
                problems.append("glob \"\(raw)\" does not follow the glob grammar")
                continue
            }
            let components: [String]
            switch pattern.anchor {
            case .home:
                components = pattern.resolved(home: validationHome)
            case .absolute:
                components = pattern.segments
            }
            guard !components.isEmpty else {
                problems.append("glob \"\(raw)\" could not be resolved")
                continue
            }
            // Strictly inside one of the rule's allow-roots at depth >= minDepthBelowRoot. Root
            // components are literal; the matching pattern components must be literal and equal.
            let normalized = components.map(PathComparison.normalize)
            let inside = roots.contains { root in
                guard root.isNonHome == (pattern.anchor == .absolute) else { return false }
                let rootParts = root.path.components.map(PathComparison.normalize)
                guard normalized.count - rootParts.count >= requiredDepth else { return false }
                return Array(normalized.prefix(rootParts.count)) == rootParts
                    && !components.prefix(rootParts.count).contains { $0.contains("*") }
            }
            if !inside {
                problems.append("glob \"\(raw)\" must be inside one of the rule's allowRoots at depth >= \(requiredDepth)")
                continue
            }
            // SAFETY-DECISION: a sample match of the pattern (each "*" replaced by a probe word) must
            // not be deny-listed for this rule; a pattern that names protected data on its face is
            // invalid. Non-home exception patterns are gated per target instead.
            if pattern.anchor == .home {
                let sample = "/" + components.map { $0.replacingOccurrences(of: "*", with: "imopprobe") }.joined(separator: "/")
                if case .success(let samplePath) = PathCanonicalizer.clean(sample, home: nil),
                   let entry = denyList.matchingEntry(for: samplePath, ruleID: rule.id, purpose: .standard) {
                    problems.append("glob \"\(raw)\" matches deny-listed locations (\(entry))")
                }
            }
        }
        return problems
    }

    private static func validateTierAction(_ rule: Rule) -> [String] {
        switch (rule.tier, rule.action) {
        case (.green, .quarantine):
            return []
        case (.green, .command(let spec)):
            return spec.idempotentSafe ? [] : ["Green rules may only use commands marked idempotentSafe"]
        case (.green, _):
            return ["Green rules may only quarantine or run an idempotentSafe command"]
        case (.yellow, .quarantine), (.yellow, .trash), (.yellow, .command):
            return []
        case (.yellow, .permanentDelete):
            return permanentDeleteAllowList.contains(rule.id) ? [] : ["permanentDelete is not allowed for this rule"]
        case (.yellow, .advisory):
            return ["Yellow rules may not use an advisory action"]
        case (.red, .bootoutAndTrash):
            return bootoutAndTrashRuleIDs.contains(rule.id) ? [] : ["bootoutAndTrash is not allowed for this rule"]
        case (.red, .trash), (.red, .advisory):
            return []
        case (.red, .command):
            return redCommandAllowList.contains(rule.id) ? [] : ["Red rules may only move to Trash or be advisory"]
        case (.red, _):
            return ["Red rules may only move to Trash or be advisory"]
        case (.advisory, .advisory):
            return []
        case (.advisory, _):
            return ["Advisory rules may only use an advisory action"]
        }
    }

    /// SAFETY-DECISION (review M2): every field the Swift tables pin must match exactly.
    private static func validatePinnedShapes(_ rule: Rule) -> [String] {
        var problems: [String] = []
        problems.append(contentsOf: validateM5InspectorRule(rule))
        problems.append(contentsOf: validateProjectArtifactRule(rule))
        problems.append(contentsOf: validateM6Rule(rule))
        if let spec = nonHomeRuleSpecs[rule.id] {
            if rule.allowRoots.isEmpty || !rule.allowRoots.allSatisfy({ spec.allowRoots.contains($0) }) {
                problems.append("allowRoots must be a subset of \(spec.allowRoots) for this rule")
            }
            if rule.tier != spec.tier { problems.append("tier must be \(spec.tier.rawValue) for this rule") }
            if rule.action != spec.action { problems.append("action is not the one reviewed for this rule") }
            if rule.discovery != spec.discovery { problems.append("discovery is not the one reviewed for this rule") }
            for required in spec.requiredPreconditions where !required.isSatisfied(by: rule.preconditions) {
                problems.append("preconditions must include \(required) for this rule")
            }
            if rule.allowSymlinkTarget { problems.append("allowSymlinkTarget is not allowed for this rule") }
        }
        if let exception = protectedAncestorRootExceptions[rule.id] {
            if let inspector = exception.inspector, rule.discovery != .inspector(inspector) {
                problems.append("discovery must be the \(inspector.rawValue) inspector for this rule")
            }
            if rule.minDepthBelowRoot < exception.minimumDepth {
                problems.append("minDepthBelowRoot must be at least \(exception.minimumDepth) for this rule")
            }
            let excluded = Set(rule.excludedNames.map(PathComparison.normalize))
            for name in exception.requiredExcludedNames where !excluded.contains(PathComparison.normalize(name)) {
                problems.append("excludedNames must contain \"\(name)\" for this rule")
            }
            if rule.allowSymlinkTarget { problems.append("allowSymlinkTarget is not allowed for this rule") }
        }
        return problems
    }

    /// SAFETY-DECISION (M5): Milestone 5 inspectors only serve their pinned rules.
    private static func validateM5InspectorRule(_ rule: Rule) -> [String] {
        var problems: [String] = []
        let spec = inspectorRuleSpecs[rule.id]
        if case .inspector(let inspector) = rule.discovery, pinnedM5Inspectors.contains(inspector), spec?.inspector != inspector {
            problems.append("the \(inspector.rawValue) inspector is not reviewed for this rule")
        }
        guard let spec else { return problems }
        if rule.discovery != .inspector(spec.inspector) {
            problems.append("discovery must be the \(spec.inspector.rawValue) inspector for this rule")
        }
        if rule.tier != spec.tier { problems.append("tier must be \(spec.tier.rawValue) for this rule") }
        if rule.action != spec.action { problems.append("action is not the one reviewed for this rule") }
        for required in spec.requiredPreconditions where !RuleTargetMatcher.declares(rule.preconditions, required) {
            problems.append("must declare the reviewed \(required.name) precondition for \(rule.id)")
        }
        if rule.allowSymlinkTarget { problems.append("allowSymlinkTarget is not allowed for this rule") }
        return problems
    }

    /// SAFETY-DECISION (M6): pinned Milestone 6 shapes not covered by the tables above.
    /// - `bootoutAndTrash` only for `bootoutAndTrashRuleIDs` (any tier).
    /// - The `advisory` inspector only for `advisoryRuleSpecs`, as Advisory tier with the pinned kind;
    ///   a pinned advisory id must use exactly that shape and never needs or may name an allow-root.
    /// - `stillOrphaned` only for the OrphanDetector rule.
    /// - `leftovers.appData` / `leftovers.launchAgents` / `jetbrains.config.orphanedVersion` /
    ///   `trash.empty` allow-roots are exactly the reviewed ones.
    private static func validateM6Rule(_ rule: Rule) -> [String] {
        var problems: [String] = []
        if rule.action == .bootoutAndTrash, !bootoutAndTrashRuleIDs.contains(rule.id) {
            problems.append("bootoutAndTrash is not allowed for this rule")
        }
        let usesAdvisoryInspector = rule.discovery == .inspector(.advisory)
        if let kind = advisoryRuleSpecs[rule.id] {
            if rule.tier != .advisory { problems.append("tier must be advisory for this rule") }
            if rule.action != .advisory(kind) { problems.append("action must be advisory(\(kind.rawValue)) for this rule") }
            if !usesAdvisoryInspector { problems.append("discovery must be the advisory inspector for this rule") }
            if !rule.preconditions.isEmpty { problems.append("advisory rules declare no preconditions") }
            if rule.allowSymlinkTarget { problems.append("allowSymlinkTarget is not allowed for this rule") }
        } else if usesAdvisoryInspector {
            problems.append("the advisory inspector is not reviewed for this rule")
        }
        if rule.preconditions.contains(.stillOrphaned), rule.discovery != .inspector(.orphanedAppData) {
            problems.append("stillOrphaned is only allowed for the OrphanDetector rule")
        }
        if let expected = m6AllowRoots[rule.id], Set(rule.allowRoots) != Set(expected) || rule.allowRoots.count != expected.count {
            problems.append("allowRoots must be exactly \(expected) for this rule")
        }
        return problems
    }

    /// Exact allow-roots of the Milestone 6 home-folder rules.
    static let m6AllowRoots: [String: [String]] = [
        "leftovers.appData": orphanedAppDataRoots,
        "leftovers.launchAgents": ["{HOME}/Library/LaunchAgents"],
        "jetbrains.config.orphanedVersion": ["{HOME}/Library/Application Support/JetBrains"],
        "trash.empty": ["{HOME}/.Trash"],
    ]

    /// SAFETY-DECISION (M5, spec §6.5): ProjectScanner rules are Yellow quarantine rules over
    /// `{PROJECT_ROOTS}` that declare projectOlderThan(>= 90), notTrackedByGit, processNotRunning(⊇ the
    /// artifact's tools) and manifestPresent (a non-empty subset of the artifact's manifests).
    private static func validateProjectArtifactRule(_ rule: Rule) -> [String] {
        let usesInspector = rule.discovery == .inspector(.projectArtifacts)
        guard let spec = RuleTargetMatcher.projectArtifactSpecs[rule.id] else {
            return usesInspector ? ["the projectArtifacts inspector is not reviewed for this rule"] : []
        }
        var problems: [String] = []
        if !usesInspector { problems.append("discovery must be the projectArtifacts inspector for this rule") }
        if rule.allowRoots != [Rule.projectRootsToken] {
            problems.append("allowRoots must be [\"\(Rule.projectRootsToken)\"] for this rule")
        }
        if rule.tier != .yellow { problems.append("tier must be yellow for this rule") }
        if rule.action != .quarantine { problems.append("action must be quarantine for this rule") }
        if rule.allowSymlinkTarget { problems.append("allowSymlinkTarget is not allowed for this rule") }
        let hasAge = rule.preconditions.contains { if case .projectOlderThan(let days) = $0 { return days >= 90 } else { return false } }
        if !hasAge { problems.append("must declare projectOlderThan of at least 90 days for \(rule.id)") }
        if !rule.preconditions.contains(.notTrackedByGit) { problems.append("must declare notTrackedByGit for \(rule.id)") }
        if !RuleTargetMatcher.declares(rule.preconditions, .processNotRunning(spec.tools)) {
            problems.append("must declare processNotRunning(\(spec.tools.joined(separator: ", "))) for \(rule.id)")
        }
        var manifests: [String] = []
        for case .manifestPresent(let names) in rule.preconditions { manifests.append(contentsOf: names) }
        if manifests.isEmpty || !manifests.allSatisfy({ spec.manifestPatterns.contains($0) }) {
            problems.append("must declare manifestPresent with the reviewed manifests for \(rule.id)")
        }
        return problems
    }

    // MARK: - Cross-rule invariants

    /// SAFETY-DECISION (M5): `apps.userCaches.unknownOwner` offers folders directly in
    /// `~/Library/Caches` (Yellow). If it could offer a folder that is (or contains) another rule's
    /// allow-root or glob base, the overlap policy would let the Yellow folder swallow that rule's
    /// targets. Every other rule's root / literal glob base directly below `~/Library/Caches` must
    /// therefore be one of `RuleTargetMatcher.unknownOwnerReservedCacheNames` (or end in `.ShipIt`);
    /// wildcard bases are accepted only for the reviewed `*/org.sparkle-project.Sparkle` pattern (the
    /// unknown-owner inspector skips folders holding a Sparkle cache). Otherwise the unknown-owner rule
    /// is disabled.
    static func crossRuleProblems(_ rules: [Rule]) -> [String: [String]] {
        let unknownOwnerID = "apps.userCaches.unknownOwner"
        guard rules.contains(where: { $0.id == unknownOwnerID }) else { return [:] }
        let caches = ["library", "caches"]
        var problems: [String] = []
        for rule in rules where rule.id != unknownOwnerID {
            var bases: [[String]] = []
            for root in rule.allowRoots where root.hasPrefix(GlobPattern.homeToken + "/") {
                bases.append(root.dropFirst(GlobPattern.homeToken.count + 1).split(separator: "/").map(String.init))
            }
            if case .glob(let patterns) = rule.discovery {
                for raw in patterns {
                    guard let pattern = GlobPattern(raw), pattern.anchor == .home else { continue }
                    bases.append(pattern.segments)
                }
            }
            for base in bases {
                let n = base.map(PathComparison.normalize)
                guard n.count >= 3, Array(n.prefix(2)) == caches else { continue }
                let first = base[2]
                if first.contains("*") {
                    let sparkle = n.count == 4 && n[2] == "*" && n[3] == "org.sparkle-project.sparkle"
                    let sample = first.replacingOccurrences(of: "*", with: "imopprobe")
                    if !sparkle && !RuleTargetMatcher.isReservedUnknownOwnerCacheName(sample) {
                        problems.append("\(rule.id) has a wildcard base in ~/Library/Caches that the unknown-owner rule could overlap")
                    }
                } else if !RuleTargetMatcher.isReservedUnknownOwnerCacheName(first) {
                    problems.append("~/Library/Caches/\(first) (\(rule.id)) is not reserved from the unknown-owner rule")
                }
            }
        }
        return problems.isEmpty ? [:] : [unknownOwnerID: problems]
    }

    private static func validateCommand(_ spec: CommandSpec, context: String, rule: Rule, isAction: Bool) -> [String] {
        var problems: [String] = []
        let tool = spec.tool
        let toolChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-")
        if tool.isEmpty || tool == "." || tool == ".." || tool.hasPrefix("-") || tool.contains("/")
            || !tool.unicodeScalars.allSatisfy({ toolChars.contains($0) }) {
            problems.append("\(context): tool \"\(tool)\" must be a bare executable name")
        }
        if forbiddenTools.contains(tool.lowercased()) {
            problems.append("\(context): tool \"\(tool)\" is not allowed")
        }
        for (label, arguments) in [("arguments", spec.arguments), ("dryRunArguments", spec.dryRunArguments ?? [])] {
            let lowered = arguments.map { $0.lowercased() }
            for token in lowered where forbiddenCommandArguments.contains(token) {
                problems.append("\(context): \(label) contain the forbidden token \"\(token)\"")
            }
            // SAFETY-DECISION: no rule may run any "system prune" (Docker's `system prune` can delete
            // volumes and every unused image); the spec only needs targeted prune subcommands.
            if lowered.contains("system") && lowered.contains("prune") {
                problems.append("\(context): \(label) must not run \"system prune\"")
            }
            if arguments.contains(where: { $0.contains("\0") || $0.contains("\n") || $0.contains("\r") }) {
                problems.append("\(context): \(label) contain control characters")
            }
        }
        if let timeout = spec.timeoutSeconds, timeout <= 0 {
            problems.append("\(context): timeoutSeconds must be greater than 0")
        }

        // SAFETY-DECISION (review M2): allow-lists, not deny-lists.
        if !allowedTools.contains(tool) {
            problems.append("\(context): tool \"\(tool)\" is not one of the reviewed vendor tools")
        }
        for (label, arguments) in [("arguments", spec.arguments), ("dryRunArguments", spec.dryRunArguments ?? [])] {
            for argument in arguments where argument.contains("/") {
                problems.append("\(context): \(label) must not contain a path (\"\(argument)\")")
            }
            for argument in arguments where argument.contains(CommandSpec.itemToken) && argument != CommandSpec.itemToken {
                problems.append("\(context): \(CommandSpec.itemToken) must be a whole argument")
            }
        }
        if spec.arguments.filter({ $0 == CommandSpec.itemToken }).count > 1 {
            problems.append("\(context): at most one \(CommandSpec.itemToken) argument is allowed")
        }
        if isAction {
            let candidates = allowedActionCommands.filter { $0.matchesTemplate(tool: tool, arguments: spec.arguments) }
            let permitted = candidates.filter { $0.permits(ruleID: rule.id, tier: rule.tier) }
            if permitted.isEmpty {
                problems.append("\(context): \"\(([tool] + spec.arguments).joined(separator: " "))\" is not a reviewed command for a \(rule.tier.rawValue) rule")
            } else if !permitted.contains(where: { spec.timeout <= TimeInterval($0.maximumTimeoutSeconds) }) {
                // SAFETY-DECISION (M4): spec §5.3 hard timeouts — default 10 min, simctl runtime delete
                // 30 min. A rule may shorten a timeout, never extend it.
                problems.append("\(context): timeoutSeconds exceeds the reviewed maximum for this command")
            }
        } else {
            if !allowedReadOnlyCommands.contains(where: { $0.matchesTemplate(tool: tool, arguments: spec.arguments) }) {
                problems.append("\(context): \"\(([tool] + spec.arguments).joined(separator: " "))\" is not a reviewed read-only command")
            }
            if spec.isPerItem {
                problems.append("\(context): a discovery command cannot take \(CommandSpec.itemToken)")
            }
        }
        if let dryRun = spec.dryRunArguments,
           !allowedReadOnlyCommands.contains(where: { $0.matchesTemplate(tool: tool, arguments: dryRun) }) {
            problems.append("\(context): dryRunArguments \"\(dryRun.joined(separator: " "))\" are not a reviewed read-only command")
        }
        return problems
    }

    private static func validatePreconditions(_ rule: Rule) -> [String] {
        var problems: [String] = []
        // SAFETY-DECISION (review M4): a pinned vendor-command rule must declare the spec §6
        // preconditions pinned for it (e.g. processNotRunning(npm, node) for npm.cache).
        if let shape = RuleTargetMatcher.commandRuleShapes[rule.id] {
            for required in shape.requiredPreconditions where !RuleTargetMatcher.declares(rule.preconditions, required) {
                problems.append("must declare the reviewed \(required.name) precondition for \(rule.id)")
            }
        }
        for precondition in rule.preconditions {
            switch precondition {
            case .appNotRunning(let ids):
                if ids.isEmpty { problems.append("appNotRunning needs at least one bundle id") }
                for id in ids where BundleIDPattern(id) == nil {
                    problems.append("appNotRunning: \"\(id)\" is not a valid bundle id pattern")
                }
            case .processNotRunning(let names):
                if names.isEmpty { problems.append("processNotRunning needs at least one process name") }
                for name in names where !isValidName(name) {
                    problems.append("processNotRunning: \"\(name)\" is not a valid process name")
                }
            case .manifestPresent(let names):
                if names.isEmpty { problems.append("manifestPresent needs at least one file name") }
                for name in names where !isValidName(name) {
                    problems.append("manifestPresent: \"\(name)\" is not a single file name")
                }
            case .olderThan(let days):
                if days < 1 { problems.append("olderThan must be at least 1 day") }
            case .projectOlderThan(let days):
                if days < 1 { problems.append("projectOlderThan must be at least 1 day") }
                // SAFETY-DECISION: project predicates are meaningful only for ProjectScanner rules.
                if rule.discovery != .inspector(.projectArtifacts) {
                    problems.append("projectOlderThan is only allowed for ProjectScanner rules")
                }
            case .notTrackedByGit:
                if rule.discovery != .inspector(.projectArtifacts) {
                    problems.append("notTrackedByGit is only allowed for ProjectScanner rules")
                }
            case .owningAppNotRunning:
                // SAFETY-DECISION: a glob rule without an owner hint can never name its owner; the
                // predicate would always fail. Treat that as a misconfigured rule.
                if case .glob = rule.discovery, rule.ownerInference == .none {
                    problems.append("owningAppNotRunning needs ownerInference for glob discovery")
                }
                if case .command = rule.discovery {
                    problems.append("owningAppNotRunning cannot be used with command discovery")
                }
            case .stillOrphaned:
                // Checked in `validateM6Rule` (OrphanDetector rule only).
                break
            case .notOpenByAnyProcess, .notInsideCloudRoot, .ownedByUser, .simulatorIdle, .dockerDaemonReachable,
                 .notMounted, .appleSigned, .notSelectedXcode, .uploadedToCloud:
                break
            }
        }
        return problems
    }

    private static func isValidRuleID(_ id: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return !id.isEmpty && id.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// A single, non-empty path component.
    private static func isValidName(_ name: String) -> Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && name != "." && name != ".."
            && !name.contains("/") && !name.contains("\0")
            && !name.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    // MARK: - Decoding helpers

    fileprivate static func describe(_ error: any Error) -> String {
        guard let decodingError = error as? DecodingError else { return String(describing: error) }
        func path(_ codingPath: [any CodingKey]) -> String {
            var text = ""
            for key in codingPath {
                if let index = key.intValue {
                    text += "[\(index)]"
                } else if key.stringValue.hasPrefix("Index "), let index = Int(key.stringValue.dropFirst("Index ".count)) {
                    text += "[\(index)]"
                } else {
                    text += text.isEmpty ? key.stringValue : ".\(key.stringValue)"
                }
            }
            return text.isEmpty ? "" : " at \(text)"
        }
        switch decodingError {
        case .keyNotFound(let key, let context):
            return "missing \"\(key.stringValue)\"\(path(context.codingPath))"
        case .typeMismatch(_, let context), .valueNotFound(_, let context), .dataCorrupted(let context):
            return "\(context.debugDescription)\(path(context.codingPath))"
        @unknown default:
            return String(describing: decodingError)
        }
    }
}

// MARK: - File format

/// One element of the `rules` array: decoded independently so a bad rule fails alone.
private struct RuleSlot: Sendable {
    enum Outcome: Sendable {
        case success(Rule)
        case failure(String)
    }

    let index: Int
    let id: String?
    let outcome: Outcome
}

private struct RuleSlotDecoder: Decodable {
    let id: String?
    let outcome: RuleSlot.Outcome

    init(from decoder: any Decoder) throws {
        // Never throws: the error is captured so the enclosing array keeps decoding.
        id = (try? decoder.container(keyedBy: RuleJSONKey.self))
            .flatMap { try? $0.decode(String.self, forKey: RuleJSONKey("id")) }
        do {
            outcome = .success(try Rule(from: decoder))
        } catch {
            outcome = .failure(RuleCatalog.describe(error))
        }
    }
}

private struct CatalogFile: Decodable {
    let version: Int
    let slots: [RuleSlot]

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: RuleJSONKey.self)
        // SAFETY-DECISION: unknown top-level keys make the whole file invalid (it is bundled and
        // reviewed; an unexpected shape means it is not the file we think it is).
        try RuleCodingSupport.rejectUnknownKeys(container, allowed: ["version", "rules"], typeName: "catalog")
        version = try container.decode(Int.self, forKey: RuleJSONKey("version"))
        var array = try container.nestedUnkeyedContainer(forKey: RuleJSONKey("rules"))
        var slots: [RuleSlot] = []
        while !array.isAtEnd {
            let index = array.currentIndex
            let slot = try array.decode(RuleSlotDecoder.self)
            slots.append(RuleSlot(index: index, id: slot.id, outcome: slot.outcome))
        }
        self.slots = slots
    }
}
