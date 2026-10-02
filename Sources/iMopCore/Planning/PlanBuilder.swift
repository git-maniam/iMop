import Foundation

/// User settings that shape a plan (spec §9.9).
public struct PlanSettings: Sendable {
    /// "Always quarantine (never permanently delete in one step)" — default ON.
    public var alwaysQuarantine: Bool = true
    /// User-configured exclusions (paths; `~` / `{HOME}` allowed).
    public var userExclusions: [String]
    /// Per-rule age thresholds in days (may only raise a rule's threshold; see PreconditionEvaluator).
    public var ageThresholdOverrides: [String: Int]

    public init(alwaysQuarantine: Bool = true, userExclusions: [String] = [], ageThresholdOverrides: [String: Int] = [:]) {
        self.alwaysQuarantine = alwaysQuarantine
        self.userExclusions = userExclusions
        self.ageThresholdOverrides = ageThresholdOverrides
    }
}

/// Builds an immutable `CleanupPlan` from scan results (spec §3.1).
///
/// Strictly read-only: every item is validated by `SafetyGate` (plan phase), which only inspects
/// the file system through the injected environment.
public struct PlanBuilder: Sendable {
    private let environment: SafeCleanEnvironment
    private let gate: SafetyGate
    private let settings: PlanSettings

    /// - Parameter gate: should be constructed with the same `userExclusions` and
    ///   `ageThresholdOverrides` as `settings`. The builder additionally applies
    ///   `settings.userExclusions` itself (defence in depth).
    public init(environment: SafeCleanEnvironment, gate: SafetyGate, settings: PlanSettings) {
        self.environment = environment
        self.gate = gate
        self.settings = settings
    }

    public func build(from results: [RuleScanResult]) async -> CleanupPlan {
        // SAFETY-DECISION: a target ID that occurs more than once makes selection ambiguous, so every
        // item carrying a duplicated ID is blocked.
        var idCounts: [UUID: Int] = [:]
        for result in results {
            for target in result.targets { idCounts[target.id, default: 0] += 1 }
        }

        var items: [PlanItem] = []
        for result in results {
            let rule = result.rule
            for target in result.targets {
                let (gateVerdict, preconditions) = await gate.validateWithDetails(target: target, rule: rule, phase: .plan)
                let action = plannedAction(for: target, rule: rule)

                var verdict = gateVerdict
                if !Self.isRejected(gateVerdict),
                   let rejection = planLevelRejection(target: target, rule: rule, action: action,
                                                      duplicated: (idCounts[target.id] ?? 0) > 1) {
                    // Also replaces a Red downgrade: a hard rejection is the more conservative verdict.
                    verdict = .rejected(rejection)
                }

                let effectiveTier: Tier
                if case .downgradedToRed = verdict {
                    effectiveTier = .red
                } else {
                    effectiveTier = rule.tier
                }

                items.append(PlanItem(target: target, rule: rule, effectiveTier: effectiveTier, action: action,
                                      preconditions: preconditions, planVerdict: verdict))
            }
        }
        return CleanupPlan(createdAt: environment.clock.now, items: items, alwaysQuarantine: settings.alwaysQuarantine)
    }

    /// Skip reason of a permanent deletion while "Always quarantine" is on.
    public static let alwaysQuarantineRejection = SafetyRejection.preconditionFailed(
        name: "alwaysQuarantine",
        detail: "“Always quarantine” is on in Settings, so items are never permanently deleted in one step")

    private static func isRejected(_ verdict: SafetyVerdict) -> Bool {
        if case .rejected = verdict { return true }
        return false
    }

    // MARK: - Action mapping

    private func plannedAction(for target: ScanTarget, rule: Rule) -> PlannedAction {
        // SAFETY-DECISION: an Advisory rule or target is always advisory, whatever action the rule
        // declares (SafetyGate rejects such pairs too).
        if rule.tier == .advisory || target.kind == .advisory {
            if case .advisory(let kind) = rule.action { return .advisory(kind) }
            return .advisory(.instructions)
        }
        switch rule.action {
        case .quarantine:
            // M6: Settings → retention override. SAFETY-DECISION: it may only LENGTHEN the rule's own
            // retention (`ScanSettings.effectiveRetentionHours(for:)` ignores shorter or non-positive
            // values). The planned value is hashed into the ConfirmedPlan; the Executor accepts it only
            // when it is at least the rule's retention and hands exactly it to the Quarantine.
            return .quarantine(retentionHours: environment.scanSettings.effectiveRetentionHours(for: rule))
        case .trash:
            return .trash
        case .bootoutAndTrash:
            return .bootoutAndTrash
        case .permanentDelete:
            return .permanentDelete
        case .advisory(let kind):
            return .advisory(kind)
        case .command(let spec):
            if case .commandItem(let argument) = target.kind { return .command(spec, argument: argument) }
            return .command(spec, argument: nil)
        }
    }

    // MARK: - Plan-level checks (on top of SafetyGate)

    private func planLevelRejection(target: ScanTarget, rule: Rule, action: PlannedAction, duplicated: Bool) -> SafetyRejection? {
        if duplicated {
            return .doesNotMatchRule(detail: "duplicate plan item")
        }

        switch action {
        case .advisory:
            return nil // never actionable anyway
        case .quarantine(let hours):
            // SAFETY-DECISION: a non-positive retention would make a quarantined item purgeable at
            // once, i.e. an unconfirmed permanent deletion → refuse.
            if hours <= 0 { return .doesNotMatchRule(detail: "invalid quarantine retention") }
            if target.kind != .filesystem { return .doesNotMatchRule(detail: "item kind does not match the action") }
        case .trash, .permanentDelete:
            // SAFETY-DECISION: file-system actions only ever apply to file-system targets.
            if target.kind != .filesystem { return .doesNotMatchRule(detail: "item kind does not match the action") }
            // SAFETY-DECISION: RuleCatalog loads `.permanentDelete` only for its allow-listed rules; a
            // rule that reached the builder without the catalog is refused too (defence in depth).
            if action == .permanentDelete, !RuleCatalog.permanentDeleteAllowList.contains(rule.id) {
                return .doesNotMatchRule(detail: "permanent delete is not allowed for this rule")
            }
            // SAFETY-DECISION: spec §9.9 "Always quarantine (never permanently delete in one step)",
            // default ON. With it on, a one-step permanent deletion is not offered at all (shown as
            // blocked with this reason) rather than silently re-routed through a different action.
            if action == .permanentDelete, settings.alwaysQuarantine {
                return Self.alwaysQuarantineRejection
            }
        case .bootoutAndTrash:
            // SAFETY-DECISION (M6): only the Swift-pinned LaunchAgent rule, only file-system targets.
            if target.kind != .filesystem { return .doesNotMatchRule(detail: "item kind does not match the action") }
            if !RuleCatalog.bootoutAndTrashRuleIDs.contains(rule.id) {
                return .doesNotMatchRule(detail: "bootout is not allowed for this rule")
            }
        case .command(let spec, let argument):
            if let rejection = commandRejection(spec: spec, argument: argument) { return rejection }
        }

        return userExclusionRejection(target: target)
    }

    private func commandRejection(spec: CommandSpec, argument: String?) -> SafetyRejection? {
        if spec.isPerItem {
            // SAFETY-DECISION: a per-item command without its item would run with the literal
            // `{ITEM}` token (or act on everything) → refuse.
            guard let argument else { return .doesNotMatchRule(detail: "command item has no argument") }
            // SAFETY-DECISION: an argument that is empty, looks like an option, contains control
            // characters, or contains the token itself could change what the vendor command does.
            if argument.isEmpty || argument.hasPrefix("-") || argument.contains(CommandSpec.itemToken)
                || argument.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
                return .doesNotMatchRule(detail: "command item argument is not acceptable")
            }
        } else if argument != nil {
            // SAFETY-DECISION: an argument the command never consumes means target and rule disagree.
            return .doesNotMatchRule(detail: "command does not take an item argument")
        }
        return nil
    }

    /// Lexical check of `settings.userExclusions` (SafetyGate check 14 performs the full check,
    /// including symlink-resolved forms, when constructed with the same exclusions).
    private func userExclusionRejection(target: ScanTarget) -> SafetyRejection? {
        guard !settings.userExclusions.isEmpty, SafetyGate.looksLikePath(target.path) else { return nil }
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let targetPath) = canonicalizer.lexical(target.path) else {
            // SAFETY-DECISION: a target path that cannot be interpreted cannot be shown to be outside
            // every exclusion.
            return .userExcluded(path: target.path)
        }
        for exclusion in settings.userExclusions {
            switch canonicalizer.lexical(exclusion) {
            case .success(let excluded):
                if targetPath.isInsideOrEqual(excluded) || excluded.isStrictlyInside(targetPath) {
                    return .userExcluded(path: exclusion)
                }
            case .failure(.denyListed):
                continue // protected by the deny-list anyway
            case .failure:
                // SAFETY-DECISION: an exclusion that cannot be interpreted might cover this item.
                return .userExcluded(path: exclusion)
            }
        }
        return nil
    }
}
