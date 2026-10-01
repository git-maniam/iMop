import Foundation

/// When SafetyGate is consulted. Spec §3.3: every item is validated at plan time AND again
/// immediately before acting (TOCTOU defence).
public enum ValidationPhase: Sendable {
    case plan
    case execute
}

/// Spec §3.3 hard invariants. Every item passes through `validate` twice; any failure skips the item.
///
/// SafetyGate is strictly read-only: it inspects the file system through `SafeCleanEnvironment`
/// and never modifies anything.
public struct SafetyGate: Sendable {
    private let environment: SafeCleanEnvironment
    private let canonicalizer: PathCanonicalizer
    private let evaluator: PreconditionEvaluator
    private let userExclusions: [String]
    private let waivedSystemRoots: [String]

    /// Bundle extensions for check 11.
    static let bundleExtensions: Set<String> = ["app", "framework", "bundle", "plugin", "kext", "systemextension", "appex"]

    /// Rules whose `.trash` action removes an entire `.app` bundle (spec §6.1, §6.6). Only for these
    /// may the target itself be a bundle root.
    static let bundleTrashRuleIDs: Set<String> = ["xcode.extraInstalls", "installers.macOS"]

    public init(environment: SafeCleanEnvironment, userExclusions: [String] = [], ageThresholdOverrides: [String: Int] = [:]) {
        self.init(environment: environment, userExclusions: userExclusions,
                  ageThresholdOverrides: ageThresholdOverrides, waivedSystemRoots: [])
    }

    /// Test-only: see `DenyList.init(homeDirectory:waivedSystemRoots:)`.
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, userExclusions: [String], ageThresholdOverrides: [String: Int], waivedSystemRoots: [String]) {
        self.environment = environment
        self.canonicalizer = PathCanonicalizer(environment: environment)
        self.evaluator = PreconditionEvaluator(environment: environment, ageThresholdOverrides: ageThresholdOverrides)
        self.userExclusions = userExclusions
        self.waivedSystemRoots = waivedSystemRoots
    }

    // MARK: - Public API

    /// Runs spec §3.3 checks 1…14 in order and returns the first failure.
    public func validate(target: ScanTarget, rule: Rule, phase: ValidationPhase) async -> SafetyVerdict {
        await validate(target: target, rule: rule, phase: phase, purpose: .standard)
    }

    /// Like `validate`, also returning every precondition result (empty when an earlier check
    /// rejected the item before preconditions were evaluated).
    public func validateWithDetails(target: ScanTarget, rule: Rule, phase: ValidationPhase) async -> (verdict: SafetyVerdict, preconditions: [PreconditionResult]) {
        await run(target: target, rule: rule, phase: phase, purpose: .standard)
    }

    /// `purpose: .quarantine` is reserved for the Quarantine module.
    internal func validate(target: ScanTarget, rule: Rule, phase: ValidationPhase, purpose: DenyListPurpose) async -> SafetyVerdict {
        await run(target: target, rule: rule, phase: phase, purpose: purpose).verdict
    }

    // MARK: - Pipeline

    private func run(target: ScanTarget, rule: Rule, phase: ValidationPhase, purpose: DenyListPurpose) async -> (verdict: SafetyVerdict, preconditions: [PreconditionResult]) {
        // SAFETY-DECISION: both phases run exactly the same checks; nothing is skipped at execute
        // time because it passed at plan time.
        _ = phase

        // Check 1 — process identity.
        if let rejection = check1ProcessIdentity() { return (.rejected(rejection), []) }

        // Pre-check — the (target, rule) pair must be coherent before any rule-specific exception
        // (deny-list exceptions, bundle exception) can be keyed off `rule.id`.
        if let rejection = checkTargetMatchesRule(target: target, rule: rule) { return (.rejected(rejection), []) }

        switch target.kind {
        case .advisory:
            // Never actionable (unreachable: rejected by the pre-check; kept for exhaustiveness).
            return (.rejected(Self.advisoryRejection), [])
        case .commandItem:
            return await runCommandItem(target: target, rule: rule)
        case .filesystem:
            return await runFilesystem(target: target, rule: rule, purpose: purpose)
        }
    }

    /// Command items: only checks 1 (done by the caller), 12 and 14 (when the item has a path).
    /// Their paths are informational; the vendor command does the work.
    private func runCommandItem(target: ScanTarget, rule: Rule) async -> (verdict: SafetyVerdict, preconditions: [PreconditionResult]) {
        // Check 12 — preconditions.
        let (preconditionRejection, results) = await check12Preconditions(target: target, rule: rule)
        if let preconditionRejection { return (.rejected(preconditionRejection), results) }

        // Check 14 — user exclusions (only when the informational path looks like a path).
        if Self.looksLikePath(target.path) {
            switch canonicalizer.lexical(target.path) {
            case .failure(let rejection):
                // SAFETY-DECISION: a path-like value that fails the text rules is suspicious → reject.
                return (.rejected(rejection), results)
            case .success(let lexical):
                if let rejection = check14UserExclusions(candidates: [lexical]) { return (.rejected(rejection), results) }
            }
        }
        return (.allowed, results)
    }

    private func runFilesystem(target: ScanTarget, rule: Rule, purpose: DenyListPurpose) async -> (verdict: SafetyVerdict, preconditions: [PreconditionResult]) {
        // Check 2 — canonicalize (and detect symlink traversal by comparing with the lexical path).
        let resolved: ResolvedTarget
        switch check2Canonicalize(target: target, rule: rule, purpose: purpose) {
        case .failure(let rejection): return (.rejected(rejection), [])
        case .success(let value): resolved = value
        }

        // Check 3 — absolute deny-list (always wins).
        if let rejection = check3DenyList(resolved, rule: rule, purpose: purpose) { return (.rejected(rejection), []) }

        // Check 4 — strictly inside an allow-root.
        let roots: AllowRootMatch
        switch check4AllowRootContainment(resolved.canonical, rule: rule) {
        case .failure(let rejection): return (.rejected(rejection), [])
        case .success(let value): roots = value
        }

        // Check 5 — minimum depth below the allow-root.
        if let rejection = check5MinimumDepth(resolved.canonical, root: roots.innermost, rule: rule) {
            return (.rejected(rejection), [])
        }

        // Check 6 — no symlink at any level from the allow-root down to the target.
        let chain: [ChainEntry]
        switch check6NoSymlinks(resolved.canonical, from: roots.outermost, rule: rule) {
        case .failure(let rejection): return (.rejected(rejection), [])
        case .success(let value): chain = value
        }
        guard let targetStat = chain.last?.stat else { return (.rejected(.itemMissing), []) }

        // Check 7 — same volume as the allow-root.
        if let rejection = check7SameVolume(resolved, chain: chain, root: roots.outermost) { return (.rejected(rejection), []) }

        // Check 8 — owned by the current user.
        if let rejection = check8Ownership(targetStat) { return (.rejected(rejection), []) }

        // Check 9 — identity pinned at scan time.
        if let rejection = check9IdentityPinning(target: target, current: targetStat) { return (.rejected(rejection), []) }

        // Check 10 — cloud-sync guard.
        if let rejection = check10CloudGuard(resolved, chain: chain) { return (.rejected(rejection), []) }

        // Check 11 — bundle guard.
        if let rejection = check11BundleGuard(resolved.canonical, targetStat: targetStat, rule: rule) {
            return (.rejected(rejection), [])
        }

        // Check 12 — preconditions.
        let (preconditionRejection, results) = await check12Preconditions(target: target, rule: rule)
        if let preconditionRejection { return (.rejected(preconditionRejection), results) }

        // Check 13 — sanity limits (downgrade to Red, never act).
        let sanity = check13SanityLimits(target: target, rule: rule)

        // Check 14 — user exclusions.
        // SAFETY-DECISION: check 14 is still evaluated when check 13 tripped: an item the user
        // excluded must be rejected outright, never offered as a Red item for manual review.
        if let rejection = check14UserExclusions(candidates: [resolved.canonical, resolved.lexical]) {
            return (.rejected(rejection), results)
        }
        if let sanity { return (.downgradedToRed(sanity), results) }

        return (.allowed, results)
    }

    // MARK: - Check 1

    private func check1ProcessIdentity() -> SafetyRejection? {
        // SAFETY-DECISION: a real uid of 0 is refused as well as an effective uid of 0; otherwise the
        // ownership check (8) would accept root-owned files.
        if environment.effectiveUserID == 0 || environment.userID == 0 { return .runningAsRoot }
        return nil
    }

    // MARK: - Pre-check (target/rule coherence)

    static let advisoryRejection = SafetyRejection.preconditionFailed(
        name: "advisoryOnly", detail: "Information only — iMop never acts on this item")

    private func checkTargetMatchesRule(target: ScanTarget, rule: Rule) -> SafetyRejection? {
        // SAFETY-DECISION: rule-specific exceptions (deny-list, bundle guard) are keyed by `rule.id`, so a
        // target must only ever be validated against the rule that discovered it.
        guard target.ruleID == rule.id else {
            return .preconditionFailed(name: "ruleMismatch", detail: "Item does not belong to this rule")
        }
        if case .advisory = target.kind { return Self.advisoryRejection }
        // SAFETY-DECISION: an Advisory rule or action is never actionable, whatever the target kind.
        if rule.tier == .advisory { return Self.advisoryRejection }
        if case .advisory = rule.action { return Self.advisoryRejection }
        // SAFETY-DECISION: command items get only checks 1, 12 and 14, so they are valid only for
        // command actions; a file-system action on a command item would bypass the path checks.
        if case .commandItem = target.kind {
            guard case .command = rule.action else {
                return .preconditionFailed(name: "actionMismatch", detail: "Item kind does not match the rule's action")
            }
        }
        return nil
    }

    // MARK: - Check 2

    private struct ResolvedTarget {
        /// Text rules only (what the path claims to be).
        let lexical: CanonicalPath
        /// Resolved through the file system. Equal to `lexical` (normalized) when accepted.
        let canonical: CanonicalPath
        /// The target itself is a symlink and the rule allows removing the link.
        let isSymlinkTarget: Bool
        /// Where an accepted symlink target points, when resolvable.
        let symlinkDestination: CanonicalPath?
    }

    private func check2Canonicalize(target: ScanTarget, rule: Rule, purpose: DenyListPurpose) -> Result<ResolvedTarget, SafetyRejection> {
        let lexical: CanonicalPath
        switch canonicalizer.lexical(target.path) {
        case .failure(let rejection): return .failure(rejection)
        case .success(let value): lexical = value
        }
        // SAFETY-DECISION: `ScanTarget.path` is documented as already canonical, and the Executor can
        // only act on that exact string. The text rules silently drop a trailing "/", "." and empty
        // components and expand "~"/{HOME}; acting on the raw string could then mean something else
        // than what was validated ("lnk/" or "lnk/." names the symlink's DESTINATION in POSIX, and
        // "~/x" is a relative path). Any filesystem target whose raw path is not already in its clean
        // lexical form is therefore rejected outright.
        guard target.path == lexical.path else {
            // Reporting only: a protected location keeps its specific deny-list reason.
            for denyList in denyLists() {
                if let entry = denyList.matchingEntry(for: lexical, ruleID: rule.id, purpose: purpose) {
                    return .failure(.denyListed(entry: entry))
                }
            }
            return .failure(.canonicalizationFailed("path is not in canonical form"))
        }
        // SAFETY-DECISION: "/" can never be a target.
        guard let name = lexical.lastComponent, let lexicalParent = lexical.parent else {
            return .failure(.canonicalizationFailed("root directory"))
        }
        guard let stat = environment.fileSystem.lstat(lexical.path) else { return .failure(.itemMissing) }

        if stat.isSymlink && !rule.allowSymlinkTarget {
            // SAFETY-DECISION: a target that is itself a symlink is refused right here, with a specific
            // reason, for every rule that does not opt in. Resolving it would otherwise produce a
            // generic canonicalization failure (canonicalPathKey does not follow the final link but
            // realpath does), and nothing about a link to /System, ~/Documents etc. should depend on
            // how the destination happens to resolve.
            return .failure(.symlinkInPath(component: lexical.path))
        }

        if stat.isSymlink && rule.allowSymlinkTarget {
            // The link itself is the item: resolve its parent, never the link.
            let parent: CanonicalPath
            switch canonicalizer.canonicalize(lexicalParent.path) {
            case .failure(let rejection): return .failure(rejection)
            case .success(let value): parent = value
            }
            guard parent == lexicalParent else {
                return .failure(.symlinkInPath(component: symlinkComponent(lexical: lexicalParent, resolved: parent)))
            }
            // SAFETY-DECISION: a link whose destination is protected is refused even though only the
            // link would be removed. The destination is resolved with realpath(3) (canonicalize()
            // cannot be used: canonicalPathKey does not follow the final link, so it never agrees with
            // realpath for a link). A destination that cannot be resolved (dangling link, permission
            // error) cannot be proven unprotected, so the link is refused too (fail closed).
            guard let resolvedDestination = environment.fileSystem.realpath(lexical.path) else {
                return .failure(.canonicalizationFailed("symlink destination could not be resolved"))
            }
            RealHomeGuard.check(resolvedDestination)
            let destination: CanonicalPath
            switch PathCanonicalizer.clean(resolvedDestination, home: nil) {
            case .success(let value): destination = value
            case .failure(.denyListed(let entry)): return .failure(.denyListed(entry: entry))
            case .failure: return .failure(.canonicalizationFailed("symlink destination is malformed"))
            }
            // SAFETY-DECISION: the link's own name is never resolved by realpath, so its spelling is
            // taken from the parent's directory listing instead of the caller. APFS matches names with
            // full Unicode case folding ("ſ" U+017F finds "s"), which `PathComparison.normalize` does
            // not reproduce; a spelling that only the file system considers equal (e.g. "Addreſſbook"
            // for "AddressBook") would otherwise slip past the deny-list. The lexical name must match
            // exactly one listed entry under `normalize` that is this very link (same identity);
            // otherwise — including an unreadable listing — the item is refused.
            guard let onDiskName = onDiskSpelling(of: name, in: parent, identity: stat.identity) else {
                return .failure(.canonicalizationFailed("symlink name does not match its directory entry"))
            }
            return .success(ResolvedTarget(lexical: lexical, canonical: parent.appending(onDiskName),
                                           isSymlinkTarget: true, symlinkDestination: destination))
        }

        let canonical: CanonicalPath
        switch canonicalizer.canonicalize(target.path) {
        case .failure(let rejection): return .failure(rejection)
        case .success(let value): canonical = value
        }
        // Resolution changed the path → a symlink was traversed somewhere (target or ancestor).
        guard canonical == lexical else {
            return .failure(.symlinkInPath(component: symlinkComponent(lexical: lexical, resolved: canonical)))
        }
        return .success(ResolvedTarget(lexical: lexical, canonical: canonical, isSymlinkTarget: false, symlinkDestination: nil))
    }

    /// The directory entry of `parent` that spells `name` (normalized compare) and is the item with
    /// `identity`; `nil` when there is no such entry, more than one, or the listing is unreadable.
    private func onDiskSpelling(of name: String, in parent: CanonicalPath, identity: FileIdentity) -> String? {
        guard let entries = environment.fileSystem.contentsOfDirectory(parent.path) else { return nil }
        let wanted = PathComparison.normalize(name)
        let candidates = entries.filter { PathComparison.normalize($0) == wanted }
        guard candidates.count == 1, let entry = candidates.first,
              !entry.isEmpty, entry != ".", entry != "..", !entry.contains("/"), !entry.contains("\0"),
              environment.fileSystem.lstat(parent.appending(entry).path)?.identity == identity else {
            return nil
        }
        return entry
    }

    /// The first lexical prefix that is a symlink (`lstat`), for the rejection reason; falls back to
    /// `firstDifference` when no prefix is (or can be shown to be) a symlink. Reporting only — the
    /// rejection itself does not depend on this.
    private func symlinkComponent(lexical: CanonicalPath, resolved: CanonicalPath) -> String {
        var current = CanonicalPath(components: [])
        for component in lexical.components {
            current = current.appending(component)
            if let stat = environment.fileSystem.lstat(current.path), stat.isSymlink { return current.path }
        }
        return Self.firstDifference(lexical: lexical, resolved: resolved)
    }

    /// The lexical prefix up to and including the first component that resolution changed.
    static func firstDifference(lexical: CanonicalPath, resolved: CanonicalPath) -> String {
        let l = lexical.components, r = resolved.components
        for index in l.indices {
            if index >= r.count || PathComparison.normalize(l[index]) != PathComparison.normalize(r[index]) {
                return "/" + l[...index].joined(separator: "/")
            }
        }
        return lexical.path
    }

    // MARK: - Check 3

    private func check3DenyList(_ resolved: ResolvedTarget, rule: Rule, purpose: DenyListPurpose) -> SafetyRejection? {
        var candidates = [resolved.canonical, resolved.lexical]
        if let destination = resolved.symlinkDestination { candidates.append(destination) }
        for denyList in denyLists() {
            for candidate in candidates {
                if let entry = denyList.matchingEntry(for: candidate, ruleID: rule.id, purpose: purpose) {
                    return .denyListed(entry: entry)
                }
            }
        }
        return nil
    }

    /// One deny-list per form of the home directory (as configured, and resolved when different).
    private func denyLists() -> [DenyList] {
        // SAFETY-DECISION: the configured home string is always used (an unusable one makes that
        // deny-list deny everything); the resolved home is added when it differs, so both spellings
        // of every home-relative entry are protected.
        var homes = [environment.homePath]
        for form in PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        where !homes.contains(form.path) {
            homes.append(form.path)
        }
        return homes.map { home in
            let base = waivedSystemRoots.isEmpty
                ? DenyList(homeDirectory: home)
                : DenyList(homeDirectory: home, waivedSystemRoots: waivedSystemRoots)
            guard case .success(let homePath) = canonicalizer.lexical(home), !homePath.components.isEmpty else {
                return base // an unusable home already makes this deny-list deny everything
            }
            return base.adding(aliases: resolvedHomeEntryAliases(home: homePath))
        }
    }

    /// Where home-relative deny entries really live when they are (or are reached through) symlinks.
    ///
    /// SAFETY-DECISION (§3.5: a symlink to a protected folder must not be a bypass): every existing
    /// home-relative entry is resolved with realpath(3); when the destination differs from the
    /// entry's own location it is protected under the same label (with the same "contains" rule).
    /// For wildcard entries the directory holding the children is resolved, and every matching child
    /// that is itself a symlink is resolved too. If an existing entry cannot be resolved, its
    /// directory cannot be listed, or a destination is malformed, the protected data could be
    /// anywhere, so EVERY target under the home directory is denied (fail closed).
    private func resolvedHomeEntryAliases(home: CanonicalPath) -> [DenyList.Alias] {
        let fs = environment.fileSystem
        var aliases: [DenyList.Alias] = []
        var failClosed: String?

        /// Resolves `path` (which exists per lstat); returns the cleaned realpath or nil on failure.
        /// `.success(nil)` means the destination is already deny-listed (/System).
        func resolve(_ path: CanonicalPath) -> Result<CanonicalPath?, SafetyRejection> {
            guard let real = fs.realpath(path.path) else { return .failure(.canonicalizationFailed("unresolvable")) }
            RealHomeGuard.check(real)
            switch PathCanonicalizer.clean(real, home: nil) {
            case .success(let p): return .success(p)
            case .failure(.denyListed): return .success(nil)
            case .failure(let rejection): return .failure(rejection)
            }
        }

        for spec in DenyList.homeEntrySpecs {
            var location = home
            for component in spec.fixedComponents { location = location.appending(component) }
            guard fs.lstat(location.path) != nil else { continue } // nothing protected there
            let resolvedLocation: CanonicalPath
            switch resolve(location) {
            case .failure:
                failClosed = spec.label
                continue
            case .success(nil):
                continue
            case .success(let p?):
                resolvedLocation = p
                if p != location {
                    aliases.append(DenyList.Alias(label: spec.label, path: p, wildcard: spec.wildcard))
                }
            }

            guard let wildcard = spec.wildcard else { continue }
            guard let children = fs.contentsOfDirectory(resolvedLocation.path) else {
                // The location exists but its children cannot be enumerated (or it is not a directory).
                if let st = fs.lstat(resolvedLocation.path), !st.isDirectory { continue }
                failClosed = spec.label
                continue
            }
            for child in children where wildcard.matches(PathComparison.normalize(child)) {
                guard !child.isEmpty, child != ".", child != "..", !child.contains("/"), !child.contains("\0") else {
                    failClosed = spec.label
                    continue
                }
                let childPath = resolvedLocation.appending(child)
                guard let st = fs.lstat(childPath.path), st.isSymlink else { continue }
                switch resolve(childPath) {
                case .failure:
                    failClosed = spec.label
                case .success(nil):
                    continue
                case .success(let p?):
                    aliases.append(DenyList.Alias(label: spec.label, path: p, wildcard: nil))
                }
            }
        }
        if let failClosed {
            aliases.append(DenyList.Alias(label: "\(failClosed) (link could not be resolved)", path: home, wildcard: nil))
        }
        return aliases
    }

    // MARK: - Check 4

    private struct AllowRootMatch {
        /// Deepest declared root containing the target (used for the depth check).
        let innermost: CanonicalPath
        /// Shallowest declared root containing the target (symlink/volume/cloud walks start here).
        let outermost: CanonicalPath
    }

    private func check4AllowRootContainment(_ canonical: CanonicalPath, rule: Rule) -> Result<AllowRootMatch, SafetyRejection> {
        var usable: [CanonicalPath] = []
        var equalsARoot = false
        for raw in rule.resolvedAllowRoots(home: environment.homePath) {
            guard case .success(let lexicalRoot) = canonicalizer.lexical(raw) else { continue }
            if canonical == lexicalRoot { equalsARoot = true }
            guard case .success(let resolvedRoot) = canonicalizer.canonicalize(raw) else { continue }
            if canonical == resolvedRoot { equalsARoot = true }
            // SAFETY-DECISION: an allow-root that resolves through a symlink, or is "/", is unusable.
            guard resolvedRoot == lexicalRoot, !resolvedRoot.components.isEmpty else { continue }
            usable.append(resolvedRoot)
        }
        // SAFETY-DECISION: equality with ANY declared root rejects, even if the path is strictly
        // inside another declared root.
        if equalsARoot { return .failure(.equalsAllowRoot) }
        let containing = usable.filter { canonical.isStrictlyInside($0) }
        guard let innermost = containing.max(by: { $0.components.count < $1.components.count }),
              let outermost = containing.min(by: { $0.components.count < $1.components.count }) else {
            return .failure(.notInsideAllowRoot)
        }
        return .success(AllowRootMatch(innermost: innermost, outermost: outermost))
    }

    // MARK: - Check 5

    private func check5MinimumDepth(_ canonical: CanonicalPath, root: CanonicalPath, rule: Rule) -> SafetyRejection? {
        let required = max(1, rule.minDepthBelowRoot)
        guard let depth = canonical.depth(below: root) else { return .notInsideAllowRoot }
        if depth < required { return .insufficientDepth(required: required, actual: depth) }
        return nil
    }

    // MARK: - Check 6

    private struct ChainEntry {
        let path: CanonicalPath
        /// `lstat` result.
        let stat: FileStat
    }

    /// `lstat`s every component from `root` (inclusive) down to the target (inclusive).
    private func check6NoSymlinks(_ canonical: CanonicalPath, from root: CanonicalPath, rule: Rule) -> Result<[ChainEntry], SafetyRejection> {
        var paths = [root]
        var current = root
        for component in canonical.components.dropFirst(root.components.count) {
            current = current.appending(component)
            paths.append(current)
        }
        var chain: [ChainEntry] = []
        for (index, path) in paths.enumerated() {
            let isTarget = index == paths.count - 1
            guard let stat = environment.fileSystem.lstat(path.path) else {
                return .failure(isTarget ? .itemMissing : .canonicalizationFailed("could not inspect \(path.path)"))
            }
            if stat.isSymlink && !(isTarget && rule.allowSymlinkTarget) {
                return .failure(.symlinkInPath(component: path.path))
            }
            chain.append(ChainEntry(path: path, stat: stat))
        }
        return .success(chain)
    }

    // MARK: - Check 7

    private func check7SameVolume(_ resolved: ResolvedTarget, chain: [ChainEntry], root: CanonicalPath) -> SafetyRejection? {
        guard let rootStat = environment.fileSystem.stat(root.path) else {
            return .canonicalizationFailed("could not inspect allow-root")
        }
        // SAFETY-DECISION: every component between the allow-root and the target must be on the
        // allow-root's device, not just the target (rejects any mount point on the way).
        for entry in chain where entry.stat.device != rootStat.device { return .crossVolume }
        if !resolved.isSymlinkTarget {
            guard let targetStat = environment.fileSystem.stat(resolved.canonical.path) else {
                return .canonicalizationFailed("could not inspect item")
            }
            if targetStat.device != rootStat.device { return .crossVolume }
        }
        return nil
    }

    // MARK: - Check 8

    private func check8Ownership(_ stat: FileStat) -> SafetyRejection? {
        stat.uid == environment.userID ? nil : .notOwnedByUser(uid: stat.uid)
    }

    // MARK: - Check 9

    private func check9IdentityPinning(target: ScanTarget, current: FileStat) -> SafetyRejection? {
        guard let pinned = target.identity else { return .missingIdentity }
        return pinned == current.identity ? nil : .changedSinceScan
    }

    // MARK: - Check 10

    private func check10CloudGuard(_ resolved: ResolvedTarget, chain: [ChainEntry]) -> SafetyRejection? {
        let roots = evaluator.cloudRoots()
        // SAFETY-DECISION: if the cloud roots cannot be computed, nothing can be proven outside them.
        guard !roots.isEmpty else { return .insideCloudRoot }
        for candidate in [resolved.canonical, resolved.lexical] {
            for root in roots where candidate.isInsideOrEqual(root) || root.isStrictlyInside(candidate) {
                return .insideCloudRoot
            }
        }
        // Target and every ancestor up to (and including) the allow-root.
        for entry in chain.reversed() {
            switch PreconditionEvaluator.cloudAttributesVerdict(fileSystem: environment.fileSystem, path: entry.path.path) {
            case .clean:
                continue
            case .ubiquitous:
                return .ubiquitousItem
            case .unknownUbiquity:
                // SAFETY-DECISION: "could not determine" is treated as ubiquitous.
                return .ubiquitousItem
            case .unreadableAttributes:
                // SAFETY-DECISION: unreadable extended attributes are treated as File Provider managed.
                return .fileProviderItem(attribute: "unreadable extended attributes")
            case .fileProvider(let attribute):
                return .fileProviderItem(attribute: attribute)
            }
        }
        return nil
    }

    // MARK: - Check 11

    private func check11BundleGuard(_ canonical: CanonicalPath, targetStat: FileStat, rule: Rule) -> SafetyRejection? {
        let components = canonical.components
        var ancestor = CanonicalPath(components: [])
        for component in components.dropLast() {
            ancestor = ancestor.appending(component)
            if isBundle(ancestor, name: component, isDirectory: true) {
                return .insideBundle(component: component)
            }
        }
        guard let name = components.last else { return nil }
        // SAFETY-DECISION: anything that is not a regular file (directory, symlink, other) carrying a
        // bundle extension is treated as a bundle.
        if !targetStat.isRegularFile && isBundle(canonical, name: name, isDirectory: targetStat.isDirectory) {
            let isWholeAppTrash: Bool = {
                guard case .trash = rule.action, Self.bundleTrashRuleIDs.contains(rule.id) else { return false }
                return targetStat.isDirectory && Self.pathExtension(of: name) == "app"
            }()
            if !isWholeAppTrash { return .insideBundle(component: name) }
        }
        return nil
    }

    /// Whether the directory-like item `path` (last component `name`) must be treated as a bundle.
    ///
    /// SAFETY-DECISION: the spec's bundle guard is name based ("ends with .app, .framework, …"), and a
    /// name-only match is kept for every ordinary name ("Foo.app", "X.framework"). Reverse-DNS
    /// directory names are the one exception: `~/Library/Caches/com.example.app` is a per-app cache
    /// folder named after a bundle identifier whose last label happens to be "app", not an app bundle.
    /// Such a name (3+ dot-separated identifier labels, first label alphabetic) is treated as a bundle
    /// only if it has bundle structure — a `Contents`, `Info.plist`, `_CodeSignature`, `Versions` or
    /// `Resources` child — OR if it is not a directory, OR if its listing cannot be read (fail closed).
    private func isBundle(_ path: CanonicalPath, name: String, isDirectory: Bool) -> Bool {
        guard Self.isBundleComponent(name) else { return false }
        guard Self.isReverseDNSName(name), isDirectory else { return true }
        guard let children = environment.fileSystem.contentsOfDirectory(path.path) else { return true }
        return children.contains { Self.bundleStructureMarkers.contains(PathComparison.normalize($0)) }
    }

    /// Child names (normalized) that identify a directory as a real bundle (macOS, iOS-style shallow
    /// bundles and versioned frameworks).
    static let bundleStructureMarkers: Set<String> = ["contents", "info.plist", "_codesignature", "versions", "resources"]

    /// "com.example.app": at least three non-empty labels of ASCII letters, digits, "-" or "_", the
    /// first one letters only.
    static func isReverseDNSName(_ name: String) -> Bool {
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 3 else { return false }
        for (index, label) in labels.enumerated() {
            guard !label.isEmpty else { return false }
            for scalar in label.unicodeScalars {
                let v = scalar.value
                let isLetter = (v >= 65 && v <= 90) || (v >= 97 && v <= 122)
                let isDigit = v >= 48 && v <= 57
                if index == 0 { guard isLetter else { return false } }
                else { guard isLetter || isDigit || v == 45 || v == 95 else { return false } }
            }
        }
        return true
    }

    static func isBundleComponent(_ component: String) -> Bool {
        guard let ext = pathExtension(of: component) else { return false }
        return bundleExtensions.contains(ext)
    }

    /// Normalized text after the last ".", or nil. (".app" alone counts: extension "app".)
    static func pathExtension(of component: String) -> String? {
        guard let dot = component.lastIndex(of: ".") else { return nil }
        let ext = component[component.index(after: dot)...]
        return ext.isEmpty ? nil : PathComparison.normalize(String(ext))
    }

    // MARK: - Check 12

    private func check12Preconditions(target: ScanTarget, rule: Rule) async -> (SafetyRejection?, [PreconditionResult]) {
        let results = await evaluator.evaluateAll(rule: rule, target: target)
        if let failed = results.first(where: { !$0.passed }) {
            return (.preconditionFailed(name: failed.name, detail: failed.detail), results)
        }
        return (nil, results)
    }

    // MARK: - Check 13

    private func check13SanityLimits(target: ScanTarget, rule: Rule) -> SafetyRejection? {
        // SAFETY-DECISION: negative sizes/counts mean sizing went wrong → treated like exceeding the limit.
        let bytes = target.allocatedBytes, items = target.itemCount
        if bytes > rule.effectiveMaxExpectedBytes || items > rule.effectiveMaxExpectedItems || bytes < 0 || items < 0 {
            return .sanityLimitExceeded(bytes: bytes, items: items)
        }
        return nil
    }

    // MARK: - Check 14

    private func check14UserExclusions(candidates: [CanonicalPath]) -> SafetyRejection? {
        for exclusion in userExclusions {
            var forms: [CanonicalPath] = []
            switch canonicalizer.lexical(exclusion) {
            case .success(let lexical):
                forms.append(lexical)
            case .failure(.denyListed):
                // Already protected by the deny-list (check 3); nothing to add.
                continue
            case .failure:
                // SAFETY-DECISION: an exclusion that cannot be interpreted might cover this item → reject.
                return .userExcluded(path: exclusion)
            }
            if case .success(let resolved) = canonicalizer.canonicalize(exclusion), !forms.contains(resolved) {
                forms.append(resolved)
            }
            // SAFETY-DECISION: `canonicalize` fails for an exclusion that is itself a symlink
            // (canonicalPathKey does not follow the final link, realpath does), so the location the
            // user actually excluded is added from realpath(3), which follows every link. If the
            // exclusion exists as a symlink but its destination cannot be resolved, the exclusion
            // cannot be interpreted and the item is refused (fail closed).
            if let lexical = forms.first {
                let fs = environment.fileSystem
                if let real = fs.realpath(lexical.path) {
                    RealHomeGuard.check(real)
                    switch PathCanonicalizer.clean(real, home: nil) {
                    case .success(let followed):
                        if !forms.contains(followed) { forms.append(followed) }
                    case .failure(.denyListed):
                        break // destination is protected by the deny-list (check 3) anyway
                    case .failure:
                        return .userExcluded(path: exclusion)
                    }
                } else if let st = fs.lstat(lexical.path), st.isSymlink {
                    return .userExcluded(path: exclusion)
                }
            }
            // SAFETY-DECISION: also rejects a target that CONTAINS an excluded path — acting on it
            // would act on the excluded content.
            for form in forms {
                for candidate in candidates where candidate.isInsideOrEqual(form) || form.isStrictlyInside(candidate) {
                    return .userExcluded(path: exclusion)
                }
            }
        }
        return nil
    }

    // MARK: - Helpers

    static func looksLikePath(_ value: String) -> Bool {
        value.hasPrefix("/") || value.hasPrefix("~") || value.hasPrefix("{HOME}")
    }
}
