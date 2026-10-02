import Foundation

/// User-configurable scan settings (spec §6.5, §6.1 `xcode.archives.old`, §3.3 #14, §5.1).
///
/// Carried by `SafeCleanEnvironment.scanSettings` so inspectors, the precondition evaluator and
/// the SafetyGate all read one source of truth.
public struct ScanSettings: Sendable, Codable, Hashable {
    /// User-selected ProjectScanner roots (`~`-prefixed or absolute). Empty by default.
    /// SAFETY-DECISION: nothing is scanned for project artifacts until the user picks roots;
    /// `suggestedProjectRoots` are only OFFERED in the UI, never enabled automatically.
    public var projectRoots: [String] = []

    /// Newest Xcode archives kept per bundle identifier (clamped to `archivesToKeepRange`).
    public var archivesToKeep: Int = ScanSettings.defaultArchivesToKeep {
        didSet { archivesToKeep = Self.clampArchivesToKeep(archivesToKeep) }
    }

    /// Rule ID → days. SAFETY-DECISION: an override may only RAISE a rule's `olderThan` /
    /// `projectOlderThan` threshold, never lower it (enforced by `PreconditionEvaluator`).
    public var ageThresholdOverrides: [String: Int] = [:]

    /// Paths the user never wants touched (SafetyGate check 14).
    public var userExclusions: [String] = []

    /// Settings → "Always quarantine" (ON by default).
    public var alwaysQuarantine: Bool = true

    /// Rule ID → hours. SAFETY-DECISION: may only LENGTHEN a rule's quarantine retention; see
    /// `effectiveRetentionHours(for:)`.
    public var quarantineRetentionOverrideHours: [String: Int] = [:]

    /// Mount points under `/Volumes` seen by the previous scan (spec §6.9 condition 8). Persisted by
    /// the UI (Milestone 7); updated after every scan with `lastSeenVolumesAfterScan(mounted:)`.
    ///
    /// SAFETY-DECISION: when a volume listed here is not mounted now (or the mounted volumes cannot be
    /// listed), the OrphanDetector offers NOTHING — apps on a disconnected drive are invisible to
    /// LaunchServices and Spotlight, so their data would look orphaned.
    public var lastSeenVolumes: [String] = []

    public static let defaultArchivesToKeep = 3
    public static let archivesToKeepRange: ClosedRange<Int> = 1...50

    /// Project roots offered (not pre-enabled) in Settings.
    public static let suggestedProjectRoots = ["~/Developer", "~/Projects", "~/code", "~/src", "~/dev"]

    public static let `default` = ScanSettings()

    public init(
        projectRoots: [String] = [],
        archivesToKeep: Int = ScanSettings.defaultArchivesToKeep,
        ageThresholdOverrides: [String: Int] = [:],
        userExclusions: [String] = [],
        alwaysQuarantine: Bool = true,
        quarantineRetentionOverrideHours: [String: Int] = [:],
        lastSeenVolumes: [String] = []
    ) {
        self.projectRoots = projectRoots
        self.archivesToKeep = Self.clampArchivesToKeep(archivesToKeep)
        self.ageThresholdOverrides = ageThresholdOverrides
        self.userExclusions = userExclusions
        self.alwaysQuarantine = alwaysQuarantine
        self.quarantineRetentionOverrideHours = quarantineRetentionOverrideHours
        self.lastSeenVolumes = lastSeenVolumes
    }

    /// The archives-to-keep value actually used (always inside `archivesToKeepRange`).
    public var effectiveArchivesToKeep: Int { Self.clampArchivesToKeep(archivesToKeep) }

    public static func clampArchivesToKeep(_ value: Int) -> Int {
        min(max(value, archivesToKeepRange.lowerBound), archivesToKeepRange.upperBound)
    }

    /// Age threshold for `rule` after applying a user override (which may only raise it).
    public func effectiveAgeThreshold(ruleID: String, declared: Int) -> Int {
        guard let override = ageThresholdOverrides[ruleID], override > declared else { return declared }
        return override
    }

    /// Quarantine retention for `rule`. SAFETY-DECISION: an override shorter than the rule's own
    /// retention (or non-positive) is ignored.
    public func effectiveRetentionHours(for rule: Rule) -> Int {
        let base = rule.effectiveRetentionHours
        guard let override = quarantineRetentionOverrideHours[rule.id], override > base else { return base }
        return override
    }

    // MARK: - Volumes (spec §6.9 condition 8)

    /// The value to store in `lastSeenVolumes` after a scan that saw `mounted`.
    ///
    /// SAFETY-DECISION: a volume that was seen before but is not connected now is REMEMBERED (it may
    /// hold apps), so orphan detection stays paused until it is reconnected; a listing that failed
    /// (`nil`) changes nothing. Newly connected volumes are added.
    public func lastSeenVolumesAfterScan(mounted: [String]?) -> [String] {
        let previous = Self.normalizedVolumes(lastSeenVolumes)
        guard let mounted else { return previous }
        return Self.normalizedVolumes(previous + mounted)
    }

    /// Non-empty, de-duplicated, sorted.
    static func normalizedVolumes(_ volumes: [String]) -> [String] {
        Array(Set(volumes.filter { !$0.isEmpty })).sorted()
    }

    // MARK: - Codable (tolerant of missing keys; clamps archivesToKeep)

    private enum CodingKeys: String, CodingKey {
        case projectRoots, archivesToKeep, ageThresholdOverrides, userExclusions, alwaysQuarantine
        case quarantineRetentionOverrideHours, lastSeenVolumes
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            projectRoots: try c.decodeIfPresent([String].self, forKey: .projectRoots) ?? [],
            archivesToKeep: try c.decodeIfPresent(Int.self, forKey: .archivesToKeep) ?? Self.defaultArchivesToKeep,
            ageThresholdOverrides: try c.decodeIfPresent([String: Int].self, forKey: .ageThresholdOverrides) ?? [:],
            userExclusions: try c.decodeIfPresent([String].self, forKey: .userExclusions) ?? [],
            // SAFETY-DECISION: a missing value decodes to the safe default (ON).
            alwaysQuarantine: try c.decodeIfPresent(Bool.self, forKey: .alwaysQuarantine) ?? true,
            quarantineRetentionOverrideHours: try c.decodeIfPresent([String: Int].self, forKey: .quarantineRetentionOverrideHours) ?? [:],
            lastSeenVolumes: try c.decodeIfPresent([String].self, forKey: .lastSeenVolumes) ?? []
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(projectRoots, forKey: .projectRoots)
        try c.encode(effectiveArchivesToKeep, forKey: .archivesToKeep)
        try c.encode(ageThresholdOverrides, forKey: .ageThresholdOverrides)
        try c.encode(userExclusions, forKey: .userExclusions)
        try c.encode(alwaysQuarantine, forKey: .alwaysQuarantine)
        try c.encode(quarantineRetentionOverrideHours, forKey: .quarantineRetentionOverrideHours)
        try c.encode(lastSeenVolumes, forKey: .lastSeenVolumes)
    }
}
