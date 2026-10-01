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

/// A raw candidate path proposed by a glob or an inspector. The Scanner re-validates it.
public struct DiscoveredCandidate: Sendable {
    public let path: String
    public let displayName: String?
    public let owningBundleID: String?
    public let notes: [String]

    public init(path: String, displayName: String? = nil, owningBundleID: String? = nil, notes: [String] = []) {
        self.path = path
        self.displayName = displayName
        self.owningBundleID = owningBundleID
        self.notes = notes
    }
}

// MARK: - Scanner

public struct Scanner: Sendable {
    /// Spec §7.2: at most 4 concurrent rule scans.
    public static let maxConcurrentRuleScans = 4

    static let laterMilestoneMessage = "Available in a later milestone"
    static let cancelledMessage = "Scan cancelled"

    private let environment: SafeCleanEnvironment
    private let catalog: RuleCatalog
    private let inspectors: [InspectorID: any Inspector]
    private let hasFullDiskAccess: Bool
    private let waivedSystemRoots: [String]
    private let cache = ScanResultCache()

    public init(environment: SafeCleanEnvironment, catalog: RuleCatalog,
                inspectors: [any Inspector] = Scanner.defaultInspectors, hasFullDiskAccess: Bool) {
        self.init(environment: environment, catalog: catalog, inspectors: inspectors,
                  hasFullDiskAccess: hasFullDiskAccess, waivedRoots: [])
    }

    /// Test-only: see `DenyList.init(homeDirectory:waivedSystemRoots:)`. Fixture homes live under
    /// `/private/var/folders`, which is deny-listed.
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, catalog: RuleCatalog, inspectors: [any Inspector] = Scanner.defaultInspectors,
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
        self.inspectors = table
        self.hasFullDiskAccess = hasFullDiskAccess
        self.waivedSystemRoots = waivedRoots
    }

    /// The inspectors implemented so far.
    public static var defaultInspectors: [any Inspector] {
        [AppUserCachesInspector(), AppContainerCachesInspector(), ElectronCachesInspector(), ChromiumCachesInspector()]
    }

    /// Results of the most recent completed scans in this session (memory only, never persisted),
    /// in catalog order. `nil` before the first completed scan.
    public func cachedResults() async -> [RuleScanResult]? {
        await cache.results(order: catalog.rules.map(\.id))
    }

    /// Scans the requested rules (all catalog rules when `ruleIDs` is nil). Results are in catalog order.
    public func scan(ruleIDs: Set<String>? = nil, progress: (@Sendable (ScanProgressEvent) -> Void)? = nil) async -> [RuleScanResult] {
        let rules = catalog.rules.filter { ruleIDs?.contains($0.id) ?? true }
        guard !rules.isEmpty else { return [] }

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

        var final: [RuleScanResult] = []
        for (index, rule) in rules.enumerated() {
            final.append(results[index] ?? RuleScanResult(rule: rule, targets: [], status: .failed(Self.cancelledMessage)))
        }
        final = Self.resolveOverlaps(final)

        if !Task.isCancelled {
            await cache.store(final)
        }
        return final
    }

    // MARK: - Context

    /// Per-scan, read-only state shared by every rule scan.
    struct Context: Sendable {
        let canonicalizer: PathCanonicalizer
        let denyLists: [DenyList]
        let sizer: SizeCalculator
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
        return Context(canonicalizer: canonicalizer, denyLists: denyLists, sizer: SizeCalculator(environment: environment))
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
        // Advisory targets (kind .advisory) come in a later milestone.
        if rule.tier == .advisory { return finish([], .unavailable(Self.laterMilestoneMessage)) }
        switch rule.action {
        case .quarantine, .trash, .permanentDelete:
            break
        case .command, .advisory:
            // SAFETY-DECISION: this milestone only produces `.filesystem` targets. A rule acted on by a
            // vendor command or advisory-only must never yield filesystem targets that could be routed
            // to a file action, so it is reported unavailable instead.
            return finish([], .unavailable(Self.laterMilestoneMessage))
        }

        let roots = allowRoots(of: rule, context: context)

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

    // MARK: - Allow-roots

    struct ResolvedRoot: Sendable {
        let path: CanonicalPath
        let device: Int64
    }

    /// The rule's allow-roots, canonicalized, that exist as real directories.
    private func allowRoots(of rule: Rule, context: Context) -> [ResolvedRoot] {
        var roots: [ResolvedRoot] = []
        for raw in rule.resolvedAllowRoots(home: environment.homePath) {
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

        // Identity (required) — re-lstat the canonical spelling and make sure nothing moved.
        guard let info = fs.lstat(canonical.path), info.identity == first.identity, info.mode == first.mode else { return nil }
        // SAFETY-DECISION: never offer something on another volume than its allow-root.
        guard info.device == root.device else { return nil }

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
            displayName: candidate.displayName ?? Self.defaultDisplayName(canonical, root: root.path),
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
