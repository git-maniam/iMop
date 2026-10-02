import Foundation

// Read-only Scanner (spec §3.1, §7.2). It discovers candidates for each rule, sizes them and returns
// `ScanTarget`s. It never evaluates preconditions and never acts: PlanBuilder and SafetyGate do that.
// It only reads the file system through `SafeCleanEnvironment.fileSystem`, the GlobExpander and the
// SizeCalculator.

// MARK: - Public result types

/// Outcome of scanning one rule.
public enum RuleScanStatus: Sendable, Hashable {
    case ok
    /// The rule needs Full Disk Access, which has not been granted. Nothing was discovered.
    case lockedNeedsFullDiskAccess
    /// The rule cannot be scanned (not implemented yet, access declined, …). Nothing was discovered.
    case unavailable(String)
    /// The scan of this rule failed or was cancelled.
    case failed(String)
}

public struct RuleScanResult: Sendable, Identifiable {
    public var id: String { rule.id }
    public let rule: Rule
    public let targets: [ScanTarget]
    public let status: RuleScanStatus

    public init(rule: Rule, targets: [ScanTarget], status: RuleScanStatus) {
        self.rule = rule
        self.targets = targets
        self.status = status
    }

    /// Sum of the targets' reclaimable bytes.
    public var reclaimableBytes: Int64 { targets.reduce(0) { $0 + $1.reclaimableBytes } }
    /// Sum of the targets' allocated bytes.
    public var allocatedBytes: Int64 { targets.reduce(0) { $0 + $1.allocatedBytes } }
}

public struct ScanProgressEvent: Sendable {
    public let ruleID: String
    public let category: RuleCategory
    public let currentPath: String?
    public let targetsFound: Int
    /// Estimated reclaimable bytes found so far for this rule.
    public let bytesFound: Int64
    public let finished: Bool

    public init(ruleID: String, category: RuleCategory, currentPath: String?, targetsFound: Int, bytesFound: Int64, finished: Bool) {
        self.ruleID = ruleID
        self.category = category
        self.currentPath = currentPath
        self.targetsFound = targetsFound
        self.bytesFound = bytesFound
        self.finished = finished
    }
}

// MARK: - Inspectors

/// Discovery too complex for the glob grammar. Inspectors are read-only.
public protocol Inspector: Sendable {
    var id: InspectorID { get }
    func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput
}

public struct InspectorOutput: Sendable {
    public let candidates: [DiscoveredCandidate]
    public let status: RuleScanStatus

    public init(candidates: [DiscoveredCandidate], status: RuleScanStatus) {
        self.candidates = candidates
        self.status = status
    }
}

/// A raw candidate proposed by a glob or an inspector. The Scanner re-validates it.
///
/// - `.filesystem` candidates (globs and file inspectors) name a path the Scanner canonicalizes,
///   gates and measures itself.
/// - `.commandItem` candidates (vendor-command inspectors, Milestone 4) describe one invocation of the
///   rule's command: `argument` fills its `{ITEM}` slot (nil = the whole command). `path` is
///   informational (the cache folder, the simulator's data folder, or a plain label such as a model
///   name); the vendor command does the work.
/// - `.advisory` candidates are explanation only and are never acted on.
///
/// For command and advisory candidates the size comes from `sizePaths` (directories the Scanner
/// measures with `SizeCalculator`, each only if it is not deny-listed and lies inside the home
/// folder) or, when there are none, from `reportedBytes` (the tool's own estimate, e.g. `docker
/// system df`, `ollama list`, `brew cleanup -n`).
public struct DiscoveredCandidate: Sendable {
    public let path: String
    public let displayName: String?
    public let owningBundleID: String?
    public let notes: [String]
    public let kind: TargetKind
    public let sizePaths: [String]
    public let reportedBytes: Int64?
    public let lastUsed: Date?
    /// The command frees only an unknown part of `sizePaths` (e.g. `pnpm store prune`): the measured
    /// size is shown as allocated ("up to"), and the reclaimable estimate is 0.
    public let reclaimableUnknown: Bool

    /// A file-system candidate.
    public init(path: String, displayName: String? = nil, owningBundleID: String? = nil, notes: [String] = []) {
        self.init(kind: .filesystem, path: path, displayName: displayName, owningBundleID: owningBundleID,
                  sizePaths: [], reportedBytes: nil, lastUsed: nil, reclaimableUnknown: false, notes: notes)
    }

    /// One invocation of the rule's vendor command (`argument` = its `{ITEM}`, nil for the whole command).
    public init(commandItem argument: String?, path: String, displayName: String, sizePaths: [String] = [],
                reportedBytes: Int64? = nil, lastUsed: Date? = nil, reclaimableUnknown: Bool = false, notes: [String] = []) {
        self.init(kind: .commandItem(argument: argument), path: path, displayName: displayName, owningBundleID: nil,
                  sizePaths: sizePaths, reportedBytes: reportedBytes, lastUsed: lastUsed,
                  reclaimableUnknown: reclaimableUnknown, notes: notes)
    }

    /// An explanation-only item (never acted on).
    public init(advisoryPath path: String, displayName: String, sizePaths: [String] = [], reportedBytes: Int64? = nil,
                lastUsed: Date? = nil, notes: [String] = []) {
        self.init(kind: .advisory, path: path, displayName: displayName, owningBundleID: nil,
                  sizePaths: sizePaths, reportedBytes: reportedBytes, lastUsed: lastUsed, reclaimableUnknown: false, notes: notes)
    }

    private init(kind: TargetKind, path: String, displayName: String?, owningBundleID: String?, sizePaths: [String],
                 reportedBytes: Int64?, lastUsed: Date?, reclaimableUnknown: Bool, notes: [String]) {
        self.kind = kind
        self.path = path
        self.displayName = displayName
        self.owningBundleID = owningBundleID
        self.sizePaths = sizePaths
        self.reportedBytes = reportedBytes
        self.lastUsed = lastUsed
        self.reclaimableUnknown = reclaimableUnknown
        self.notes = notes
    }
}

// MARK: - Scanner

public struct SafeCleanScanner: Sendable {
    /// Spec §7.2: at most 4 concurrent rule scans.
    public static let maxConcurrentRuleScans = 4

    static let laterMilestoneMessage = "Available in a later milestone"
    static let noProjectRootsMessage = "Choose your project folders in Settings to look for build artifacts"
    static let cancelledMessage = "Scan cancelled"
    /// Status reason when macOS refused a listing (app-data protection / privacy). AppState treats such
    /// rules as unavailable for the rest of the session (spec §8).
    public static let accessDeclinedMessage = "Access was declined"

    private let environment: SafeCleanEnvironment
    private let catalog: RuleCatalog
    private let inspectors: [InspectorID: any Inspector]
    private let hasFullDiskAccess: Bool
    private let waivedSystemRoots: [String]
    private let cache = ScanResultCache()

    public init(environment: SafeCleanEnvironment, catalog: RuleCatalog,
                inspectors: [any Inspector] = SafeCleanScanner.defaultInspectors, hasFullDiskAccess: Bool) {
        self.init(environment: environment, catalog: catalog, inspectors: inspectors,
                  hasFullDiskAccess: hasFullDiskAccess, waivedRoots: [])
    }

    /// Test-only: see `DenyList.init(homeDirectory:waivedSystemRoots:)`. Fixture homes live under
    /// `/private/var/folders`, which is deny-listed.
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, catalog: RuleCatalog, inspectors: [any Inspector] = SafeCleanScanner.defaultInspectors,
                hasFullDiskAccess: Bool, waivedSystemRoots: [String]) {
        self.init(environment: environment, catalog: catalog, inspectors: inspectors,
                  hasFullDiskAccess: hasFullDiskAccess, waivedRoots: waivedSystemRoots)
    }

    private init(environment: SafeCleanEnvironment, catalog: RuleCatalog, inspectors: [any Inspector],
                 hasFullDiskAccess: Bool, waivedRoots: [String]) {
        self.environment = environment
        self.catalog = catalog
        var table: [InspectorID: any Inspector] = [:]
        for inspector in inspectors where table[inspector.id] == nil {
            table[inspector.id] = inspector
        }
        // SAFETY-DECISION (M5): `apps.userCaches.unknownOwner` must never offer a folder that another
        // rule of THIS scanner's catalog may target (the overlap rule would let the Yellow folder swallow
        // that rule's targets). An unknown-owner inspector without an injected catalog is therefore
        // bound to the scanner's own catalog.
        if let unknown = table[.appUserCachesUnknownOwner] as? UnknownOwnerCachesInspector, !unknown.hasInjectedCatalog {
            table[.appUserCachesUnknownOwner] = UnknownOwnerCachesInspector(catalog: catalog)
        }
        // SAFETY-DECISION (M6, spec §6.9 condition 6): likewise, the OrphanDetector excludes every
        // folder another rule of THIS scanner's catalog may target.
        if let orphans = table[.orphanedAppData] as? OrphanedAppDataInspector, !orphans.hasInjectedCatalog {
            table[.orphanedAppData] = orphans.with(catalog: catalog)
        }
        self.inspectors = table
        self.hasFullDiskAccess = hasFullDiskAccess
        self.waivedSystemRoots = waivedRoots
    }

    /// The inspectors implemented so far.
    public static var defaultInspectors: [any Inspector] {
        [AppUserCachesInspector(), AppContainerCachesInspector(), ElectronCachesInspector(), ChromiumCachesInspector(),
         SimctlUnavailableInspector(), SimctlDevicesInspector(), SimctlRuntimesInspector(), DockerSystemInspector(),
         OllamaModelsInspector(), PackageManagerCachesInspector(),
         // Milestone 5.
         XcodeDerivedDataInspector(), XcodeArchivesInspector(), XcodeDeviceSupportInspector(), VSCodeExtensionsInspector(),
         JetBrainsCachesInspector(), ProjectArtifactsInspector(), LightroomPreviewsInspector(), UnknownOwnerCachesInspector(),
         ChromiumServiceWorkerInspector(),
         // Milestone 6: OrphanDetector, LaunchAgents, Trash flows and the read-only advisory inspector.
         // (downloads.diskImages, downloads.archives and system.coreDumps are glob rules.)
         OrphanedAppDataInspector(), OrphanedLaunchAgentsInspector(), XcodeExtraInstallsInspector(),
         MacOSInstallersInspector(), JetBrainsConfigInspector(), TrashContentsInspector(), AdvisoryInspector()]
    }

    // MARK: - Volumes seen (spec §6.9 condition 8)

    /// The `ScanSettings.lastSeenVolumes` value to persist after a scan (Milestone 7 stores it).
    ///
    /// SAFETY-DECISION: see `ScanSettings.lastSeenVolumesAfterScan(mounted:)` — a drive that is not
    /// connected now stays remembered (orphan detection stays paused until it is back), and a failed
    /// listing changes nothing.
    public func updatedLastSeenVolumes() -> [String]? {
        environment.scanSettings.lastSeenVolumesAfterScan(mounted: environment.volumes.mountedVolumeIdentities())
    }

    /// A file rule and a vendor-command rule that clean the same thing: exactly one of them may offer
    /// items in a scan, decided by whether `tool` resolves to a trusted executable.
    public struct ExclusiveRulePair: Sendable, Hashable {
        /// Offered only when `tool` does NOT resolve.
        public let fileRuleID: String
        /// Offered only when `tool` resolves.
        public let commandRuleID: String
        public let tool: String
    }

    /// SAFETY-DECISION (spec §6.2 `cocoapods.cache`: "if pod found: CMD, else Q"): the quarantine rule
    /// and the command rule are never both offered in the same scan. Whether `pod` resolves is decided
    /// ONCE per scan (in the scan context), and scanning either rule always rescans the other, so the
    /// session cache can never hold items of both.
    public static let exclusiveRulePairs: [ExclusiveRulePair] = [
        ExclusiveRulePair(fileRuleID: "cocoapods.cache", commandRuleID: "cocoapods.cache.command", tool: "pod"),
    ]

    /// `ids` plus the partner of every exclusive pair member it contains.
    static func expandingExclusivePairs(_ ids: Set<String>) -> Set<String> {
        var expanded = ids
        for pair in exclusiveRulePairs where ids.contains(pair.fileRuleID) || ids.contains(pair.commandRuleID) {
            expanded.insert(pair.fileRuleID)
            expanded.insert(pair.commandRuleID)
        }
        return expanded
    }

    /// Results of the most recent completed scans in this session (memory only, never persisted),
    /// in catalog order. `nil` before the first completed scan.
    ///
    /// SAFETY-DECISION (review M2): the cache keeps each rule's latest result BEFORE overlap
    /// resolution and resolves overlaps again over the merged set on every read, so results from
    /// different (subset) scans never hold an ancestor and its descendant at the same time.
    public func cachedResults() async -> [RuleScanResult]? {
        guard let merged = await cache.results(order: catalog.rules.map(\.id)) else { return nil }
        return Self.resolveOverlaps(merged)
    }

    /// Scans the requested rules (all catalog rules when `ruleIDs` is nil). Results are in catalog order.
    ///
    /// Overlaps are resolved against every rule result cached in this session, not only the rules
    /// scanned now, so a subset scan never returns a target that contains (or is contained in) a
    /// cached target of another rule without applying the overlap policy. Overlap resolution can
    /// only see what has been scanned: a target of a rule that was never scanned is not considered.
    ///
    /// SAFETY-DECISION (review M2): a cancelled scan is incomplete for overlap purposes (a more
    /// cautious rule that never ran could own an item inside a finished rule's target). It therefore
    /// returns NO targets for any rule (status `.failed("Scan cancelled")`) and is never cached.
    public func scan(ruleIDs: Set<String>? = nil, progress: (@Sendable (ScanProgressEvent) -> Void)? = nil) async -> [RuleScanResult] {
        let requested = catalog.rules.filter { ruleIDs?.contains($0.id) ?? true }.map(\.id)
        guard !requested.isEmpty else { return [] }
        // Exclusive pairs are always scanned together (see `exclusiveRulePairs`); only the requested
        // rules are returned.
        let scanIDs = ruleIDs.map(Self.expandingExclusivePairs)
        let rules = catalog.rules.filter { scanIDs?.contains($0.id) ?? true }
        let requestedSet = Set(requested)
        let all = await scanRules(rules, progress: progress)
        return all.filter { requestedSet.contains($0.rule.id) }
    }

    private func scanRules(_ rules: [Rule], progress: (@Sendable (ScanProgressEvent) -> Void)?) async -> [RuleScanResult] {
        let context = makeContext()
        var results = [RuleScanResult?](repeating: nil, count: rules.count)

        await withTaskGroup(of: (Int, RuleScanResult).self) { group in
            var next = 0
            while next < min(Self.maxConcurrentRuleScans, rules.count) {
                let index = next
                group.addTask { (index, await self.scanRule(rules[index], context: context, progress: progress)) }
                next += 1
            }
            for await (index, result) in group {
                results[index] = result
                if next < rules.count, !Task.isCancelled {
                    let index = next
                    group.addTask { (index, await self.scanRule(rules[index], context: context, progress: progress)) }
                    next += 1
                }
            }
        }

        let cancelled = Task.isCancelled || results.contains { $0 == nil }
        if cancelled {
            return rules.map { RuleScanResult(rule: $0, targets: [], status: .failed(Self.cancelledMessage)) }
        }
        let raw = rules.enumerated().map { index, rule in
            results[index] ?? RuleScanResult(rule: rule, targets: [], status: .failed(Self.cancelledMessage))
        }
        await cache.store(raw)
        let merged = await cache.results(order: catalog.rules.map(\.id)) ?? raw
        let scanned = Set(rules.map(\.id))
        let resolved = Self.resolveOverlaps(merged).filter { scanned.contains($0.rule.id) }
        // Same order as `rules` (catalog order).
        let byID = Dictionary(resolved.map { ($0.rule.id, $0) }, uniquingKeysWith: { first, _ in first })
        return raw.map { byID[$0.rule.id] ?? $0 }
    }

    // MARK: - Context

    /// Per-scan, read-only state shared by every rule scan.
    struct Context: Sendable {
        let canonicalizer: PathCanonicalizer
        let denyLists: [DenyList]
        let sizer: SizeCalculator
        let matcher: RuleTargetMatcher
        let homeForms: [CanonicalPath]
        /// Tool of each exclusive pair → whether it resolved, decided once per scan.
        let exclusiveToolResolves: [String: Bool]
    }

    private func makeContext() -> Context {
        let canonicalizer = PathCanonicalizer(environment: environment)
        // SAFETY-DECISION: like SafetyGate, one deny-list per spelling of the home directory (as
        // configured, and resolved when different), so both spellings of every entry are protected.
        var homes = [environment.homePath]
        for form in PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        where !homes.contains(form.path) {
            homes.append(form.path)
        }
        let denyLists = homes.map { home in
            waivedSystemRoots.isEmpty
                ? DenyList(homeDirectory: home)
                : DenyList(homeDirectory: home, waivedSystemRoots: waivedSystemRoots)
        }
        let homeForms = PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        let matcher = RuleTargetMatcher(homeForms: homeForms)
        var resolves: [String: Bool] = [:]
        for pair in Self.exclusiveRulePairs where resolves[pair.tool] == nil {
            resolves[pair.tool] = environment.commands.resolveExecutable(pair.tool) != nil
        }
        return Context(canonicalizer: canonicalizer, denyLists: denyLists, sizer: SizeCalculator(environment: environment),
                       matcher: matcher, homeForms: homeForms, exclusiveToolResolves: resolves)
    }

    // MARK: - One rule

    private func scanRule(_ rule: Rule, context: Context, progress: (@Sendable (ScanProgressEvent) -> Void)?) async -> RuleScanResult {
        func report(_ path: String?, _ count: Int, _ bytes: Int64, finished: Bool) {
            progress?(ScanProgressEvent(ruleID: rule.id, category: rule.category, currentPath: path,
                                        targetsFound: count, bytesFound: bytes, finished: finished))
        }
        func finish(_ targets: [ScanTarget], _ status: RuleScanStatus) -> RuleScanResult {
            report(nil, targets.count, targets.reduce(0) { $0 + $1.reclaimableBytes }, finished: true)
            return RuleScanResult(rule: rule, targets: targets, status: status)
        }

        if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
        report(nil, 0, 0, finished: false)

        if rule.requiresFullDiskAccess && !hasFullDiskAccess {
            return finish([], .lockedNeedsFullDiskAccess)
        }
        // Milestone 6: Advisory rules yield explanation-only targets (kind .advisory) from the pinned,
        // read-only advisory inspector.
        if rule.tier == .advisory { return await scanAdvisoryRule(rule, context: context, finish: finish) }

        // Exclusive pairs (file rule vs vendor-command rule): decided once per scan.
        for pair in Self.exclusiveRulePairs {
            let resolves = context.exclusiveToolResolves[pair.tool] ?? false
            if rule.id == pair.fileRuleID, resolves {
                return finish([], .unavailable("Cleaned with \(pair.tool)'s own command instead"))
            }
            if rule.id == pair.commandRuleID, !resolves {
                return finish([], .unavailable(environment.commands.unavailableReason(for: pair.tool)
                    ?? "\(pair.tool) is not installed in a trusted location"))
            }
        }

        switch rule.action {
        case .quarantine, .trash, .permanentDelete, .bootoutAndTrash:
            break
        case .command:
            return await scanCommandRule(rule, context: context, finish: finish)
        case .advisory:
            // SAFETY-DECISION: a non-Advisory-tier rule with an advisory action is not one of the pinned
            // advisory rules; it never yields targets.
            return finish([], .unavailable(Self.laterMilestoneMessage))
        }

        let roots = allowRoots(of: rule, context: context)

        // SAFETY-DECISION (M5, spec §6.5): ProjectScanner rules scan ONLY user-selected project roots.
        // With none configured (or none usable) the rule is unavailable and its inspector never runs.
        if rule.usesProjectRoots && roots.isEmpty {
            return finish([], .unavailable(Self.noProjectRootsMessage))
        }

        // Discovery.
        var candidates: [DiscoveredCandidate] = []
        var status: RuleScanStatus = .ok
        switch rule.discovery {
        case .command:
            return finish([], .unavailable(Self.laterMilestoneMessage))
        case .inspector(let inspectorID):
            guard let inspector = inspectors[inspectorID] else {
                return finish([], .unavailable(Self.laterMilestoneMessage))
            }
            let output = await inspector.discover(rule: rule, environment: environment)
            switch output.status {
            case .ok:
                candidates = output.candidates
            case .unavailable, .failed, .lockedNeedsFullDiskAccess:
                // SAFETY-DECISION: an inspector that reports a problem contributes no targets at all,
                // even if it returned some candidates.
                return finish([], output.status)
            }
        case .glob(let patterns):
            let expander = GlobExpander(environment: environment)
            for raw in patterns {
                if Task.isCancelled { break }
                guard let pattern = GlobPattern(raw) else {
                    // SAFETY-DECISION: RuleCatalog validation already rejects such rules; a pattern that
                    // still fails to parse disables the whole rule for this scan.
                    return finish([], .failed("Invalid pattern"))
                }
                candidates += expander.expand(pattern, excludedNames: rule.excludedNames).map { DiscoveredCandidate(path: $0) }
            }
        }

        if roots.isEmpty {
            // Nothing under an existing allow-root, so nothing to offer.
            return finish([], status)
        }

        var targets: [ScanTarget] = []
        var seen = Set<CanonicalPath>()
        var bytes: Int64 = 0
        for candidate in candidates {
            if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
            report(candidate.path, targets.count, bytes, finished: false)
            guard let evaluated = evaluate(candidate, rule: rule, roots: roots, context: context) else { continue }
            if evaluated.cancelled { return finish([], .failed(Self.cancelledMessage)) }
            guard let target = evaluated.target, seen.insert(evaluated.canonical).inserted else { continue }
            targets.append(target)
            bytes += target.reclaimableBytes
            report(target.path, targets.count, bytes, finished: false)
        }
        if Task.isCancelled { status = .failed(Self.cancelledMessage); targets = [] }
        return finish(targets, status)
    }

    // MARK: - Vendor-command rules (Milestone 4)

    /// Discovers the command items of a vendor-command rule through its pinned inspector.
    ///
    /// SAFETY-DECISION: only Swift-pinned command rules (`RuleTargetMatcher.commandRuleShapes`) with
    /// inspector discovery are scanned; a rule whose discovery is a raw command is still reported
    /// unavailable (the Scanner never runs an arbitrary rule-provided command). Inspectors reach
    /// vendor tools only through `environment.commands` with purpose `.readOnly`; the Scanner itself
    /// runs no command. Every problem fails closed: an inspector status other than `.ok` yields no
    /// items at all, and a candidate that does not fit the rule's command shape is dropped.
    private func scanCommandRule(_ rule: Rule, context: Context,
                                 finish: ([ScanTarget], RuleScanStatus) -> RuleScanResult) async -> RuleScanResult {
        guard case .inspector(let inspectorID) = rule.discovery, let inspector = inspectors[inspectorID] else {
            return finish([], .unavailable(Self.laterMilestoneMessage))
        }
        if let problem = RuleTargetMatcher.commandRuleMismatch(rule) {
            return finish([], .unavailable("Rule \(problem)"))
        }
        guard case .command(let spec) = rule.action else { return finish([], .unavailable(Self.laterMilestoneMessage)) }

        let output = await inspector.discover(rule: rule, environment: environment)
        if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
        switch output.status {
        case .ok:
            break
        case .unavailable, .failed, .lockedNeedsFullDiskAccess:
            return finish([], output.status)
        }

        var targets: [ScanTarget] = []
        var seen = Set<String>()
        var withheld: String?
        for candidate in output.candidates {
            if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
            switch evaluateCommandCandidate(candidate, rule: rule, spec: spec, context: context) {
            case .target(let target):
                let key: String = {
                    switch target.kind {
                    case .commandItem(let argument): return "c|" + (argument ?? "")
                    case .advisory: return "a|" + target.path
                    case .filesystem: return "f|" + target.path
                    }
                }()
                // SAFETY-DECISION: one target per command invocation (duplicates are dropped).
                guard seen.insert(key).inserted else { continue }
                targets.append(target)
            case .skipped:
                continue
            case .withheld(let reason):
                withheld = withheld ?? reason
            }
        }
        if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
        if targets.isEmpty, let withheld {
            // Tell the user why nothing is offered instead of silently showing an empty rule.
            return finish([], .unavailable(withheld))
        }
        return finish(targets, .ok)
    }

    // MARK: - Advisory rules (Milestone 6, spec §6.4, §6.7, §6.10)

    /// Discovers the explanation-only items of a pinned Advisory rule.
    ///
    /// SAFETY-DECISION: only rules in `RuleCatalog.advisoryRuleSpecs` (Advisory tier, the pinned
    /// advisory action, the `advisory` inspector) are scanned. Only candidates of kind `.advisory` are
    /// kept — a file-system or command candidate from the advisory inspector is dropped — so nothing
    /// an advisory rule reports can ever be routed to an action (SafetyGate rejects `.advisory` kinds
    /// and the rules have no allow-root). Their paths may name protected or system locations (e.g.
    /// MobileSync, /Library) because they are only shown, never acted on; sizes are informational and
    /// never counted as reclaimable.
    private func scanAdvisoryRule(_ rule: Rule, context: Context,
                                  finish: ([ScanTarget], RuleScanStatus) -> RuleScanResult) async -> RuleScanResult {
        guard let kind = RuleCatalog.advisoryRuleSpecs[rule.id], rule.action == .advisory(kind),
              rule.discovery == .inspector(.advisory), let inspector = inspectors[.advisory] else {
            return finish([], .unavailable(Self.laterMilestoneMessage))
        }
        let output = await inspector.discover(rule: rule, environment: environment)
        if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
        switch output.status {
        case .ok:
            break
        case .unavailable, .failed, .lockedNeedsFullDiskAccess:
            return finish([], output.status)
        }
        var targets: [ScanTarget] = []
        var seen = Set<String>()
        for candidate in output.candidates {
            if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
            guard case .advisory = candidate.kind, let target = advisoryTarget(candidate, rule: rule, context: context),
                  seen.insert(target.path + "|" + target.displayName).inserted else { continue }
            targets.append(target)
        }
        if Task.isCancelled { return finish([], .failed(Self.cancelledMessage)) }
        return finish(targets, .ok)
    }

    private func advisoryTarget(_ candidate: DiscoveredCandidate, rule: Rule, context: Context) -> ScanTarget? {
        let path: String
        if SafetyGate.looksLikePath(candidate.path) {
            guard case .success(let clean) = PathCanonicalizer.clean(candidate.path, home: environment.homePath) else { return nil }
            path = clean.path
        } else {
            guard Self.isPlainLabel(candidate.path) else { return nil }
            path = candidate.path
        }
        let displayName = candidate.displayName.flatMap { Self.isPlainLabel($0) ? $0 : nil } ?? path
        var notes = candidate.notes.filter { !$0.unicodeScalars.contains { $0.properties.generalCategory == .control } }
        var allocated: Int64 = 0
        var itemCount = 0
        if candidate.sizePaths.isEmpty {
            allocated = max(0, candidate.reportedBytes ?? 0)
        } else {
            var unmeasured = false
            for raw in candidate.sizePaths {
                // Read-only measurement; never through a symlink.
                guard case .success(let clean) = PathCanonicalizer.clean(raw, home: environment.homePath),
                      let info = environment.fileSystem.lstat(clean.path), !info.isSymlink,
                      let estimate = context.sizer.measure(path: clean.path) else {
                    unmeasured = true
                    continue
                }
                allocated = Self.saturatingAdd(allocated, estimate.allocatedBytes)
                itemCount += estimate.itemCount
                if !estimate.complete { unmeasured = true }
                if Task.isCancelled { return nil }
            }
            if unmeasured { notes.append("Size may be underestimated: some items could not be read.") }
        }
        return ScanTarget(
            ruleID: rule.id,
            kind: .advisory,
            path: path,
            displayName: displayName,
            identity: nil,
            allocatedBytes: allocated,
            // SAFETY-DECISION (spec §7 honesty): iMop does not free advisory space itself.
            reclaimableBytes: 0,
            itemCount: max(itemCount, 1),
            lastUsed: candidate.lastUsed,
            owningBundleID: nil,
            notes: notes
        )
    }

    enum CommandCandidateOutcome {
        case target(ScanTarget)
        /// Not usable (malformed); dropped silently.
        case skipped
        /// Deliberately not offered for safety; the reason is shown when nothing else is offered.
        case withheld(String)
    }

    static let notRestorableNotePrefix = "This cannot be undone"

    private func evaluateCommandCandidate(_ candidate: DiscoveredCandidate, rule: Rule, spec: CommandSpec,
                                          context: Context) -> CommandCandidateOutcome {
        // Kind: only command items and advisory items; a file-system candidate under a command rule
        // could otherwise be routed to a file action.
        let argument: String?
        switch candidate.kind {
        case .filesystem:
            return .skipped
        case .advisory:
            argument = nil
        case .commandItem(let value):
            guard context.matcher.commandItemMismatch(argument: value, rule: rule) == nil else { return .skipped }
            argument = value
        }

        // Informational path: a path-like value is cleaned and deny-list checked (both spellings);
        // anything else must be a plain, printable label.
        let path: String
        if SafetyGate.looksLikePath(candidate.path) {
            guard case .success(let lexical) = context.canonicalizer.lexical(candidate.path) else { return .skipped }
            var forms = [lexical]
            if case .success(let resolved) = context.canonicalizer.canonicalize(lexical.path), resolved != lexical {
                forms.append(resolved)
            }
            // SAFETY-DECISION: a command whose own folder is protected (inside iCloud Drive, Documents,
            // a system location, or a folder that contains protected data such as the home folder
            // itself) is never offered, even though the vendor tool would do the work.
            for form in forms {
                for denyList in context.denyLists {
                    if let entry = denyList.matchingEntry(for: form, ruleID: rule.id, purpose: .standard) {
                        return .withheld("Not offered: its folder is protected (\(entry))")
                    }
                }
            }
            path = lexical.path
        } else {
            guard Self.isPlainLabel(candidate.path) else { return .skipped }
            path = candidate.path
        }
        let displayName = candidate.displayName.flatMap { Self.isPlainLabel($0) ? $0 : nil } ?? argument ?? path

        // Size.
        var notes = candidate.notes.filter { !$0.unicodeScalars.contains { $0.properties.generalCategory == .control } }
        var allocated: Int64 = 0
        var reclaimable: Int64 = 0
        var itemCount = 0
        var lastUsed = candidate.lastUsed
        if candidate.sizePaths.isEmpty {
            let bytes = max(0, candidate.reportedBytes ?? 0)
            allocated = bytes
            reclaimable = bytes
            itemCount = 1
        } else {
            var unmeasured = false
            var outsideHome = false
            var incomplete = false
            var hardLinked = false
            for raw in candidate.sizePaths {
                switch measureCommandPath(raw, rule: rule, context: context) {
                case .measured(let estimate, let canonical):
                    allocated = Self.saturatingAdd(allocated, estimate.allocatedBytes)
                    reclaimable = Self.saturatingAdd(reclaimable, estimate.reclaimableBytes)
                    itemCount += estimate.itemCount
                    if !estimate.complete { incomplete = true }
                    if estimate.hardLinkedBytesExcluded > 0 { hardLinked = true }
                    if lastUsed == nil, candidate.sizePaths.count == 1,
                       let info = environment.fileSystem.lstat(canonical.path) {
                        lastUsed = self.lastUsed(canonical, stat: info)
                    }
                case .outsideHome:
                    outsideHome = true
                case .unmeasurable:
                    unmeasured = true
                case .withheld(let reason):
                    return .withheld(reason)
                }
                if Task.isCancelled { return .skipped }
            }
            if outsideHome { notes.append("Size not measured: the folder is outside your home folder.") }
            if unmeasured { notes.append("Size could not be measured.") }
            if incomplete { notes.append("Size may be underestimated: some items could not be read.") }
            if hardLinked { notes.append("Some files are hard-linked elsewhere; their space would not be freed and is not counted.") }
            itemCount = max(itemCount, 1)
        }
        // Spec §7 honesty (review M4): a command that frees only an unknown part of its folder never
        // has the folder's size counted as reclaimable.
        if candidate.reclaimableUnknown {
            if allocated > 0 {
                notes.append("Up to \(CommandDiscovery.formatBytes(allocated)) may be freed; the amount is only known after the command runs, so it is not counted in the estimate.")
            }
            reclaimable = 0
        }

        // Spec §5.3: command actions are not restorable, and the UI must say so.
        if case .commandItem = candidate.kind,
           !notes.contains(where: { $0.hasPrefix(Self.notRestorableNotePrefix) }) {
            notes.append(argument == nil
                ? "This cannot be undone. \(spec.tool) will re-download what it needs."
                : "This cannot be undone.")
        }

        let target = ScanTarget(
            ruleID: rule.id,
            kind: candidate.kind,
            path: path,
            displayName: displayName,
            identity: nil,
            allocatedBytes: allocated,
            reclaimableBytes: reclaimable,
            itemCount: itemCount,
            lastUsed: lastUsed,
            owningBundleID: nil,
            notes: notes
        )
        return .target(target)
    }

    enum CommandPathMeasurement {
        case measured(SizeEstimate, CanonicalPath)
        case outsideHome
        case unmeasurable
        case withheld(String)
    }

    /// Measures one folder of a command item.
    ///
    /// SAFETY-DECISION: a folder that is deny-listed (on either spelling) or contains a protected item
    /// (`.git`, `.photoslibrary`, …) withholds the whole item — the vendor command would remove it. A
    /// folder outside the home folder is not measured (size 0 with a note).
    private func measureCommandPath(_ raw: String, rule: Rule, context: Context) -> CommandPathMeasurement {
        guard case .success(let lexical) = context.canonicalizer.lexical(raw) else { return .unmeasurable }
        var forms = [lexical]
        var canonical: CanonicalPath?
        if case .success(let resolved) = context.canonicalizer.canonicalize(lexical.path) {
            canonical = resolved
            if resolved != lexical { forms.append(resolved) }
        }
        for form in forms {
            for denyList in context.denyLists {
                if let entry = denyList.matchingEntry(for: form, ruleID: rule.id, purpose: .standard) {
                    return .withheld("Not offered: its folder is protected (\(entry))")
                }
            }
        }
        guard let canonical else { return .unmeasurable }
        guard context.homeForms.contains(where: { canonical.isStrictlyInside($0) }) else { return .outsideHome }
        guard let info = environment.fileSystem.lstat(canonical.path), !info.isSymlink else { return .unmeasurable }
        guard let estimate = context.sizer.measure(path: canonical.path) else { return .unmeasurable }
        if let entry = estimate.protectedDescendantEntry {
            return .withheld("Not offered: its folder contains a protected item (\(entry))")
        }
        return .measured(estimate, canonical)
    }

    /// Non-empty, at most 1024 bytes, no control characters.
    static func isPlainLabel(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 1024
            && !value.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }

    static func saturatingAdd(_ a: Int64, _ b: Int64) -> Int64 {
        let (sum, overflow) = a.addingReportingOverflow(max(0, b))
        return overflow ? Int64.max : sum
    }

    // MARK: - Allow-roots

    struct ResolvedRoot: Sendable {
        let path: CanonicalPath
        let device: Int64
    }

    /// The rule's allow-roots, canonicalized, that exist as real directories.
    private func allowRoots(of rule: Rule, context: Context) -> [ResolvedRoot] {
        var roots: [ResolvedRoot] = []
        for raw in rule.resolvedAllowRoots(environment: environment, waivedSystemRoots: waivedSystemRoots) {
            guard case .success(let lexical) = context.canonicalizer.lexical(raw),
                  case .success(let canonical) = context.canonicalizer.canonicalize(raw) else { continue }
            // SAFETY-DECISION: an allow-root reached through a symlink (its resolved form differs from
            // its lexical form) is not used: SafetyGate would reject every item below it anyway.
            guard canonical == lexical else { continue }
            guard let info = environment.fileSystem.lstat(canonical.path), info.isDirectory, !info.isSymlink else { continue }
            roots.append(ResolvedRoot(path: canonical, device: info.device))
        }
        return roots
    }

    // MARK: - One candidate

    struct Evaluated {
        let canonical: CanonicalPath
        let target: ScanTarget?
        let cancelled: Bool
    }

    /// Re-validates a raw candidate and builds its `ScanTarget`. `nil` = skipped.
    private func evaluate(_ candidate: DiscoveredCandidate, rule: Rule, roots: [ResolvedRoot], context: Context) -> Evaluated? {
        let fs = environment.fileSystem

        guard case .success(let lexical) = context.canonicalizer.lexical(candidate.path),
              let lastComponent = lexical.lastComponent, let lexicalParent = lexical.parent else { return nil }
        guard let first = fs.lstat(lexical.path) else { return nil }

        // Canonicalize.
        let canonical: CanonicalPath
        if first.isSymlink {
            // SAFETY-DECISION: symlinks are skipped unless the rule explicitly allows a symlink target;
            // even then the link itself (never its destination) is the target.
            guard rule.allowSymlinkTarget else { return nil }
            guard case .success(let parent) = context.canonicalizer.canonicalize(lexicalParent.path),
                  parent == lexicalParent else { return nil }
            canonical = parent.appending(lastComponent)
        } else {
            guard case .success(let resolved) = context.canonicalizer.canonicalize(lexical.path) else { return nil }
            // SAFETY-DECISION: a resolved path that differs from the lexical one means an intermediate
            // symlink; such items are skipped (SafetyGate check 6 would reject them).
            guard resolved == lexical else { return nil }
            canonical = resolved
        }

        // Deny-list (always wins), on both spellings.
        for denyList in context.denyLists {
            if denyList.matchingEntry(for: canonical, ruleID: rule.id, purpose: .standard) != nil { return nil }
            if canonical != lexical, denyList.matchingEntry(for: lexical, ruleID: rule.id, purpose: .standard) != nil { return nil }
        }

        // Allow-root containment and minimum depth.
        let minDepth = max(1, rule.minDepthBelowRoot)
        guard let root = roots.first(where: { root in
            canonical.isStrictlyInside(root.path) && (canonical.depth(below: root.path) ?? 0) >= minDepth
        }) else { return nil }

        // Excluded names: any component below the allow-root.
        if !rule.excludedNames.isEmpty {
            let excluded = Set(rule.excludedNames.map(PathComparison.normalize))
            let below = canonical.components.dropFirst(root.path.components.count)
            if below.contains(where: { excluded.contains(PathComparison.normalize($0)) }) { return nil }
        }

        // SAFETY-DECISION (review M2): the same shape check SafetyGate applies (check 11b): the
        // candidate must match one of the rule's patterns, or its inspector's Swift-coded shape.
        if context.matcher.mismatch(canonical, rule: rule, owningBundleID: candidate.owningBundleID) != nil { return nil }

        // Identity (required) — re-lstat the canonical spelling and make sure nothing moved.
        guard let info = fs.lstat(canonical.path), info.identity == first.identity, info.mode == first.mode else { return nil }
        // SAFETY-DECISION: never offer something on another volume than its allow-root.
        guard info.device == root.device else { return nil }

        // SAFETY-DECISION (review M2, spec §7.2 "do not descend into packages"): mirror SafetyGate
        // check 11 — nothing inside a bundle, and no bundle itself unless the rule trashes whole apps.
        if SafetyGate.bundleAncestor(of: canonical, fileSystem: fs) != nil { return nil }
        if !info.isRegularFile,
           SafetyGate.isBundle(canonical, name: lastComponent, isDirectory: info.isDirectory, fileSystem: fs) {
            let isWholeAppTrash: Bool = {
                guard case .trash = rule.action, SafetyGate.bundleTrashRuleIDs.contains(rule.id) else { return false }
                return info.isDirectory && SafetyGate.pathExtension(of: lastComponent) == "app"
            }()
            if !isWholeAppTrash { return nil }
        }

        // Size.
        var notes = candidate.notes
        let allocated: Int64
        let reclaimable: Int64
        let itemCount: Int
        if info.isSymlink {
            allocated = 0
            reclaimable = 0
            itemCount = 1
        } else {
            guard let estimate = context.sizer.measure(path: canonical.path) else { return nil }
            // SAFETY-DECISION (review M2): spec §3.5 — a `.git` directory or protected extension
            // anywhere below the candidate makes the whole candidate untouchable (moving it would move
            // the protected item). SafetyGate re-checks this before acting (check 11c).
            if estimate.containsProtectedDescendant {
                if Task.isCancelled { return Evaluated(canonical: canonical, target: nil, cancelled: true) }
                return nil
            }
            if !estimate.complete {
                if Task.isCancelled { return Evaluated(canonical: canonical, target: nil, cancelled: true) }
                notes.append("Size may be underestimated: some items could not be read.")
            }
            if estimate.hardLinkedBytesExcluded > 0 {
                notes.append("Some files are hard-linked elsewhere; their space would not be freed and is not counted.")
            }
            if estimate.crossedMountPointsSkipped > 0 {
                notes.append("Contents on other volumes were skipped.")
            }
            allocated = estimate.allocatedBytes
            reclaimable = estimate.reclaimableBytes
            itemCount = estimate.itemCount
        }

        let owner = candidate.owningBundleID ?? Self.inferOwner(canonical, inference: rule.ownerInference)
        let target = ScanTarget(
            ruleID: rule.id,
            kind: .filesystem,
            path: canonical.path,
            displayName: candidate.displayName ?? Self.modelDisplayName(canonical, rule: rule)
                ?? Self.defaultDisplayName(canonical, root: root.path),
            identity: info.identity,
            allocatedBytes: allocated,
            reclaimableBytes: reclaimable,
            itemCount: itemCount,
            lastUsed: lastUsed(canonical, stat: info),
            owningBundleID: owner,
            notes: notes
        )
        return Evaluated(canonical: canonical, target: target, cancelled: false)
    }

    /// `max(mtime(target), mtime(each immediate child))` via `lstat`; `nil` when unreadable.
    private func lastUsed(_ path: CanonicalPath, stat: FileStat) -> Date? {
        let fs = environment.fileSystem
        var latest = stat.modificationDate
        guard stat.isDirectory, !stat.isSymlink else { return latest }
        // SAFETY-DECISION: an unreadable listing or child means "last used" is unknown (nil), never
        // guessed from the folder's own mtime.
        guard let children = fs.contentsOfDirectory(path.path) else { return nil }
        for child in children {
            guard InspectorWalker.isPlainName(child), let childStat = fs.lstat(path.appending(child).path) else { return nil }
            latest = max(latest, childStat.modificationDate)
        }
        return latest
    }

    /// Owner bundle ID from the rule's owner-inference hint.
    ///
    /// SAFETY-DECISION: an inferred owner that does not look like a reverse-DNS bundle identifier is
    /// dropped (nil), so `owningAppNotRunning` fails closed for that item.
    static func inferOwner(_ path: CanonicalPath, inference: OwnerInference) -> String? {
        let name = path.lastComponent ?? ""
        let candidate: String?
        switch inference {
        case .none:
            candidate = nil
        case .parentDirectoryName:
            candidate = path.parent?.lastComponent
        case .nameWithoutExtension:
            if let dot = name.lastIndex(of: "."), dot != name.startIndex {
                candidate = String(name[..<dot])
            } else {
                candidate = nil
            }
        case .nameBeforeShipIt:
            let suffix = ".shipit"
            if PathComparison.normalize(name).hasSuffix(suffix), name.count > suffix.count {
                candidate = String(name.dropLast(suffix.count))
            } else {
                candidate = nil
            }
        }
        guard let candidate, BundleIdentifierHeuristics.looksReverseDNS(candidate) else { return nil }
        return candidate
    }

    /// Spec §6.8: Hugging Face cache folders (`models--org--name`, `datasets--org--name`) shown as the
    /// repository they hold ("org/name (model)"). `nil` for anything else.
    static func modelDisplayName(_ path: CanonicalPath, rule: Rule) -> String? {
        guard rule.category == .ai, let name = path.lastComponent else { return nil }
        for (prefix, kind) in [("models--", "model"), ("datasets--", "dataset")] where name.hasPrefix(prefix) {
            let repository = name.dropFirst(prefix.count).replacingOccurrences(of: "--", with: "/")
            guard !repository.isEmpty, isPlainLabel(repository) else { return nil }
            return "\(repository) (\(kind))"
        }
        return nil
    }

    /// The last component, prefixed by its parent when the target is more than one level below its root.
    static func defaultDisplayName(_ path: CanonicalPath, root: CanonicalPath) -> String {
        let name = path.lastComponent ?? path.path
        if let depth = path.depth(below: root), depth > 1, let parent = path.parent?.lastComponent {
            return "\(parent) — \(name)"
        }
        return name
    }

    // MARK: - Overlap resolution

    /// When two filesystem targets are equal or one contains the other, the LESS cautious one (lower
    /// tier) is dropped; on equal tiers the ancestor is dropped (equal paths: the later one).
    static func resolveOverlaps(_ results: [RuleScanResult]) -> [RuleScanResult] {
        struct Ref: Hashable { let result: Int; let target: Int }
        struct Item { let ref: Ref; let path: CanonicalPath; let tier: Tier }

        var items: [Item] = []
        var byPath: [CanonicalPath: [Item]] = [:]
        for (r, result) in results.enumerated() {
            for (t, target) in result.targets.enumerated() where target.kind == .filesystem {
                // `path` is the canonical form produced by `evaluate`.
                guard case .success(let path) = PathCanonicalizer.clean(target.path, home: nil) else { continue }
                let item = Item(ref: Ref(result: r, target: t), path: path, tier: result.rule.tier)
                items.append(item)
                byPath[path, default: []].append(item)
            }
        }

        var dropped = Set<Ref>()
        for item in items {
            // Equal paths: keep the most cautious tier; among equals keep the first.
            if let same = byPath[item.path], same.count > 1 {
                let best = same.max { a, b in a.tier < b.tier || (a.tier == b.tier && a.ref.result > b.ref.result) }!
                if best.ref != item.ref { dropped.insert(item.ref) }
            }
            // Ancestors of this item.
            var ancestor = item.path.parent
            while let current = ancestor {
                for other in byPath[current] ?? [] {
                    // `other` contains `item`.
                    if other.tier > item.tier {
                        dropped.insert(item.ref)
                    } else {
                        // Lower tier, or equal tier: drop the ancestor.
                        dropped.insert(other.ref)
                    }
                }
                ancestor = current.parent
            }
        }
        guard !dropped.isEmpty else { return results }

        return results.enumerated().map { r, result in
            let kept = result.targets.enumerated().filter { !dropped.contains(Ref(result: r, target: $0.offset)) }.map(\.element)
            return kept.count == result.targets.count ? result : RuleScanResult(rule: result.rule, targets: kept, status: result.status)
        }
    }
}

// MARK: - Session cache

/// In-memory, per-session cache of the latest result per rule. Never persisted.
actor ScanResultCache {
    private var latest: [String: RuleScanResult] = [:]
    private var hasResults = false

    func store(_ results: [RuleScanResult]) {
        for result in results { latest[result.rule.id] = result }
        hasResults = true
    }

    func results(order: [String]) -> [RuleScanResult]? {
        guard hasResults else { return nil }
        return order.compactMap { latest[$0] }
    }
}
