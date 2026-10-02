import AppKit
import Foundation
import Observation

// Milestone 7: the single source of truth the SwiftUI app (Sources/iMop) reads and drives.
//
// AppState never acts on a file itself. It runs the read-only pipeline (scan → plan) off the main
// thread, keeps the user's selection, and hands a `ConfirmedPlan` — built only from an explicit
// review + confirmation — to the `Executor`, the only component that acts (spec §3.1). Quarantine
// browsing / restore / purge go through `Quarantine`, which gates every move with SafetyGate and
// `MutationPolicy.compiledIn` itself. There is no background auto-clean (spec §10): nothing is ever
// cleaned without `confirmAndClean(acknowledgedIrreversible:)`.
//
// Threading (spec M8): every file-system operation (permission probe, catalog load, scan, plan,
// sizing, disk usage, quarantine) runs in a detached task or on an actor; only state assignment
// happens on the main actor.

// MARK: - Public value types

public enum AppPhase: Sendable, Hashable {
    case idle, scanning, scanned, executing, finished
}

public enum SidebarDestination: Hashable, Sendable {
    case scan
    case category(RuleCategory)
    case advisory
    case quarantine
    case permissions
    case results
}

/// Live per-category scan progress (spec §9.1).
public struct CategoryProgress: Sendable, Hashable {
    public var targetsFound: Int
    public var bytesFound: Int64
    public var finished: Bool

    public init(targetsFound: Int = 0, bytesFound: Int64 = 0, finished: Bool = false) {
        self.targetsFound = targetsFound
        self.bytesFound = bytesFound
        self.finished = finished
    }
}

/// Permission states shown in the sidebar and the Permissions screen (spec §8).
public struct PermissionsSnapshot: Sendable, Hashable {
    public var fullDiskAccess: PermissionState
    /// Always `.unknown`: there is no read-only probe (see `AppManagementProbe`).
    public var appManagement: PermissionState

    public init(fullDiskAccess: PermissionState = .unknown, appManagement: PermissionState = .unknown) {
        self.fullDiskAccess = fullDiskAccess
        self.appManagement = appManagement
    }
}

/// What the review sheet shows (spec §9.4): the selected items grouped by action type.
public struct ReviewSummary: Sendable {
    public var quarantineItems: [PlanItem]
    public var commandItems: [PlanItem]
    /// Finder Trash moves (including the LaunchAgent bootout + Trash flow).
    public var trashItems: [PlanItem]
    public var permanentItems: [PlanItem]
    /// Selected items that cannot be undone (commands, permanent removal, bootout).
    public var irreversibleItems: [PlanItem]
    public var totalReclaimable: Int64
    public var totalAllocated: Int64
    /// Selected Red items (each confirmed one by one).
    public var redItems: [PlanItem]
    /// Selected Yellow items (spec §3.2: "what you lose" shown + one checkbox per category).
    public var yellowItems: [PlanItem]

    public init(quarantineItems: [PlanItem] = [], commandItems: [PlanItem] = [], trashItems: [PlanItem] = [],
                permanentItems: [PlanItem] = [], irreversibleItems: [PlanItem] = [], totalReclaimable: Int64 = 0,
                totalAllocated: Int64 = 0, redItems: [PlanItem] = [], yellowItems: [PlanItem] = []) {
        self.quarantineItems = quarantineItems
        self.commandItems = commandItems
        self.trashItems = trashItems
        self.permanentItems = permanentItems
        self.irreversibleItems = irreversibleItems
        self.totalReclaimable = totalReclaimable
        self.totalAllocated = totalAllocated
        self.redItems = redItems
        self.yellowItems = yellowItems
    }

    /// `true` when the acknowledgement checkbox is required.
    public var requiresIrreversibleAcknowledgement: Bool { !irreversibleItems.isEmpty }

    /// Categories with selected Yellow items, in sidebar order; each needs its own acknowledgement
    /// ("I understand what I lose in <Category>") before Clean.
    public var yellowCategories: [RuleCategory] {
        let present = Set(yellowItems.map(\.rule.category))
        return AppState.categoryOrder.filter { present.contains($0) }
    }

    /// Selected Yellow items of `category`.
    public func yellowItems(in category: RuleCategory) -> [PlanItem] {
        yellowItems.filter { $0.rule.category == category }
    }

    public var isEmpty: Bool {
        quarantineItems.isEmpty && commandItems.isEmpty && trashItems.isEmpty && permanentItems.isEmpty
    }
}

/// The grouped "Empty Trash" choice (spec §6.6 `trash.empty`): every item in the Trash is selected
/// or deselected together, and only through its own confirmation dialog.
public struct EmptyTrashRequest: Sendable, Hashable, Identifiable {
    public let id: UUID
    public let itemIDs: [UUID]
    public let reclaimableBytes: Int64
    public let allocatedBytes: Int64

    public var count: Int { itemIDs.count }

    public init(id: UUID = UUID(), itemIDs: [UUID], reclaimableBytes: Int64, allocatedBytes: Int64) {
        self.id = id
        self.itemIDs = itemIDs
        self.reclaimableBytes = reclaimableBytes
        self.allocatedBytes = allocatedBytes
    }
}

/// A rule the last scan could not offer anything for, with the reason (spec §8 / §11: never fail
/// silently).
public struct UnavailableRule: Sendable, Hashable, Identifiable {
    public var id: String { rule.id }
    public let rule: Rule
    public let reason: String

    public init(rule: Rule, reason: String) {
        self.rule = rule
        self.reason = reason
    }
}

/// Errors `AppState` itself raises (confirmation errors from the core are rethrown unchanged).
public enum AppStateError: Error, Sendable, Equatable, LocalizedError {
    /// No scanned plan, or the app is not in the scanned state.
    case nothingToClean
    /// `confirmAndClean` without a review sheet presented for the current selection.
    case reviewNotPresented
    /// The plan was built under different settings; the user must scan again.
    case planOutdated
    /// A cleanup is already running.
    case executionInProgress
    /// Selected Yellow items of this category whose "what you lose" was not acknowledged (spec §3.2).
    case categoryNotAcknowledged(RuleCategory)
    /// Items in the Trash are selected without the "Empty Trash" confirmation (spec §6.6).
    case emptyTrashNotConfirmed
    /// Stored settings could not be read completely; the user must check Settings first.
    case settingsNeedReview

    public var errorDescription: String? {
        switch self {
        case .nothingToClean: return "There is nothing to clean. Scan first and select items."
        case .reviewNotPresented: return "Review the selected items before cleaning."
        case .planOutdated: return AppState.planOutdatedMessage
        case .executionInProgress: return "A cleanup is already running."
        case .categoryNotAcknowledged(let category):
            return "Confirm that you understand what you lose in \(category.displayName)."
        case .emptyTrashNotConfirmed:
            return "Emptying the Trash needs its own confirmation. Deselect the Trash items and select them again."
        case .settingsNeedReview: return AppState.settingsReviewBlockedMessage
        }
    }
}

// MARK: - System actions (open URLs, Finder, apps)

/// Side effects that leave iMop (System Settings deep links, Finder, launching an app). None of them
/// changes a file. Injectable so tests never open anything.
@_spi(FixtureTesting)
public protocol AppStateSystemActions: Sendable {
    @MainActor func open(url: URL)
    @MainActor func revealInFinder(path: String)
    @MainActor func openApp(bundleID: String) -> Bool
}

struct LiveSystemActions: AppStateSystemActions {
    @MainActor func open(url: URL) {
        NSWorkspace.shared.open(url)
    }

    @MainActor func revealInFinder(path: String) {
        // Read-only: selects the item in a Finder window.
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    @MainActor func openApp(bundleID: String) -> Bool {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return false }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
        return true
    }
}

// MARK: - Fixture configuration (tests only)

/// Test-only knobs: the fixture deny-list waiver, an injected catalog / inspectors / permission
/// probes, and recorded system actions.
///
/// SAFETY-DECISION: there is deliberately NO mutation-policy knob. AppState always uses
/// `MutationPolicy.compiledIn` (dry-run in every build without IMOP_ALLOW_MUTATION, and refused while
/// the test-suite guard is installed), so even a test can never make AppState mutate.
@_spi(FixtureTesting)
public struct AppStateFixtureOptions: Sendable {
    public var waivedSystemRoots: [String]
    public var catalog: RuleCatalog?
    public var inspectors: [any Inspector]?
    public var permissionProbes: PermissionProbes?
    public var systemActions: (any AppStateSystemActions)?
    public var runsLaunchMaintenance: Bool
    public var startsDailyPurgeTimer: Bool

    public init(waivedSystemRoots: [String] = [], catalog: RuleCatalog? = nil, inspectors: [any Inspector]? = nil,
                permissionProbes: PermissionProbes? = nil, systemActions: (any AppStateSystemActions)? = nil,
                runsLaunchMaintenance: Bool = true, startsDailyPurgeTimer: Bool = false) {
        self.waivedSystemRoots = waivedSystemRoots
        self.catalog = catalog
        self.inspectors = inspectors
        self.permissionProbes = permissionProbes
        self.systemActions = systemActions
        self.runsLaunchMaintenance = runsLaunchMaintenance
        self.startsDailyPurgeTimer = startsDailyPurgeTimer
    }
}

// MARK: - AppState

@MainActor
@Observable
public final class AppState {
    // MARK: Messages

    public nonisolated static let planOutdatedMessage = "Settings changed since this scan. Scan again before cleaning."
    public nonisolated static let dryRunBannerText = "Dry-run build — cleaning disabled"
    /// Spec §9.1.
    public nonisolated static let scanReadOnlyNotice = "Scanning is read-only — nothing is changed until you review and confirm."
    public nonisolated static let storageSettingsDeepLink = "x-apple.systempreferences:com.apple.settings.Storage"
    /// Spec §9.4: the review sheet's Clean button stays disabled this long after the sheet appears
    /// (the same interval `ConfirmedPlan.confirm` enforces).
    public nonisolated static let minimumReviewInterval: TimeInterval = ConfirmedPlan.minimumReviewInterval
    /// Spec §5.1: quarantine retention expiry is re-checked daily while the app runs.
    public nonisolated static let purgeInterval: TimeInterval = 24 * 60 * 60
    /// Spec §9.2 grouping order (sidebar, review sheet).
    public nonisolated static let categoryOrder: [RuleCategory] = [
        .developer, .browsers, .apps, .system, .media, .ai, .downloads, .leftovers
    ]
    /// Rule of the grouped "Empty Trash" choice (spec §6.6).
    public nonisolated static let emptyTrashRuleID = TrashContentsInspector.ruleID
    /// Spec §8: a rule whose access was declined is not scanned again in this session.
    public nonisolated static let declinedThisSessionMessage =
        "Unavailable this session (access was declined). Quit and reopen iMop to try again."
    public nonisolated static let settingsReviewBlockedMessage =
        "Some of your settings could not be read. Cleaning is paused until you check Settings and confirm them."
    /// Shown while a cleanup runs and the user adds an exclusion.
    public nonisolated static let exclusionDuringRunNotice =
        "New exclusions also apply to the cleanup in progress: items at or inside them that have not been processed yet are skipped."

    /// `true` only in builds compiled with IMOP_ALLOW_MUTATION. The UI shows `dryRunBannerText` otherwise.
    public nonisolated static var isMutationEnabledInBuild: Bool { MutationPolicy.compiledIn.isEnabled }

    // MARK: Navigation

    public private(set) var phase: AppPhase = .idle
    public var destination: SidebarDestination = .scan
    public var selectedItemID: UUID?

    // MARK: Scan

    public private(set) var categoryProgress: [RuleCategory: CategoryProgress] = [:]
    public private(set) var currentScanPath: String?
    public private(set) var plan: CleanupPlan?
    public private(set) var ruleStatuses: [String: RuleScanStatus] = [:]
    /// Rules of the most recently loaded catalog (for the locked-rules list).
    public private(set) var catalogRules: [Rule] = []

    // MARK: Selection

    public private(set) var selection: Set<UUID> = []
    public private(set) var redConfirmed: Set<UUID> = []
    /// Set by `requestToggle` on an unselected Red item; the UI shows the per-item dialog.
    public var pendingRedConfirmation: PlanItem?
    /// Set by `requestToggle` on an unselected item in the Trash; the UI shows the "Empty Trash" dialog.
    public var pendingEmptyTrashConfirmation: EmptyTrashRequest?
    /// The Trash items selected through the "Empty Trash" confirmation.
    public private(set) var emptyTrashConfirmed: Set<UUID> = []

    // MARK: Disk / permissions

    public private(set) var diskUsage = DiskUsage()
    public private(set) var permissions = PermissionsSnapshot()

    // MARK: Review / execution

    public var showReview: Bool = false
    public private(set) var reviewPresentedAt: Date?
    public private(set) var executionOutcomes: [ItemOutcome] = []
    public private(set) var executionTotal: Int = 0
    /// The item the Executor is working on (for the progress screen).
    public private(set) var executingItemID: UUID?
    /// IDs of the confirmed items of the current / last run, in the order the Executor works.
    /// (The progress screen lists from this, never from `selection`.)
    public private(set) var confirmedItemIDs: [UUID] = []
    /// Exclusions added while the current run was in progress (they apply to it; see
    /// `exclusionDuringRunNotice`).
    public private(set) var exclusionsAddedDuringExecution: [String] = []
    public private(set) var lastReport: ExecutionReport?

    // MARK: Quarantine

    public private(set) var quarantineSessions: [QuarantineSessionInfo] = []
    public var quarantineNotice: String { Quarantine.spaceNotice }

    // MARK: Errors

    public private(set) var lastError: String?
    /// Non-nil when the stored settings could not be read completely (which parts, in plain words).
    /// SAFETY-DECISION (review M7): cleaning is refused until the user has checked Settings and called
    /// `acknowledgeSettingsReview()`, because a lost exclusion would silently widen what iMop may touch.
    public private(set) var settingsReviewNotice: String?

    // MARK: Settings

    private var storedSettings: ScanSettings

    /// Persisted on every set. Takes effect for the NEXT scan / plan; a plan built under different
    /// (safety-relevant) settings is refused by `confirmAndClean` until the user scans again.
    public var settings: ScanSettings {
        get { storedSettings }
        set {
            storedSettings = newValue
            settingsStore.save(newValue)
            // SAFETY-DECISION (review M7): an exclusion added while a cleanup runs applies to that run
            // too (the Executor's SafetyGate reads `runExclusions` live at every item).
            if let runExclusions {
                let before = Set(runExclusions.current)
                for exclusion in newValue.userExclusions where !before.contains(exclusion) {
                    runExclusions.add(exclusion)
                    if !exclusionsAddedDuringExecution.contains(exclusion) { exclusionsAddedDuringExecution.append(exclusion) }
                }
            }
        }
    }

    // MARK: Dependencies (not observed)

    @ObservationIgnored private let baseEnvironment: SafeCleanEnvironment
    @ObservationIgnored private let settingsStore: SettingsStore
    @ObservationIgnored private let options: AppStateFixtureOptions
    @ObservationIgnored private let probes: PermissionProbes
    @ObservationIgnored private let actions: any AppStateSystemActions
    @ObservationIgnored private let quarantine: Quarantine
    @ObservationIgnored private let auditLog: AuditLog

    @ObservationIgnored private var scanTask: Task<Void, Never>?
    @ObservationIgnored private var scanToken: UUID?
    @ObservationIgnored private var executionTask: Task<Void, Never>?
    @ObservationIgnored private var executor: Executor?
    @ObservationIgnored private var pendingTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var ruleProgress: [String: ScanProgressEvent] = [:]
    /// Settings (minus bookkeeping) the current plan was built with.
    @ObservationIgnored private var planSettings: ScanSettings?
    /// The selection the review sheet was presented for.
    @ObservationIgnored private var reviewedSelection: Set<UUID>?
    @ObservationIgnored private var itemIndex: [UUID: PlanItem] = [:]
    /// Exclusions read live by the running Executor's SafetyGate.
    @ObservationIgnored private var runExclusions: LiveExclusions?
    /// Rules whose discovery was refused by macOS ("Access was declined") in this session.
    @ObservationIgnored private var sessionDeclinedRuleIDs: Set<String> = []
    @ObservationIgnored private var itemsByCategory: [RuleCategory: [PlanItem]] = [:]
    @ObservationIgnored private var advisoryCache: [PlanItem] = []

    // MARK: Init

    /// - Parameters:
    ///   - environment: `nil` → `LiveEnvironment.make()` with the persisted settings. A given
    ///     environment's own `scanSettings` are replaced by the persisted ones.
    ///   - settingsStore: where settings are loaded from and saved to.
    public convenience init(environment: SafeCleanEnvironment? = nil, settingsStore: SettingsStore = .standard) {
        self.init(environment: environment, settingsStore: settingsStore, options: nil)
    }

    /// Test-only: see `AppStateFixtureOptions`.
    @_spi(FixtureTesting)
    public convenience init(environment: SafeCleanEnvironment, settingsStore: SettingsStore, fixture: AppStateFixtureOptions) {
        self.init(environment: environment, settingsStore: settingsStore, options: fixture)
    }

    private init(environment: SafeCleanEnvironment?, settingsStore: SettingsStore, options: AppStateFixtureOptions?) {
        let loaded = settingsStore.load()
        let base = environment ?? LiveEnvironment.make(scanSettings: loaded)
        let resolvedOptions = options ?? AppStateFixtureOptions(runsLaunchMaintenance: true, startsDailyPurgeTimer: true)
        self.storedSettings = loaded
        self.settingsStore = settingsStore
        self.baseEnvironment = base
        self.options = resolvedOptions
        self.probes = resolvedOptions.permissionProbes ?? PermissionProbes.live(environment: base)
        self.actions = resolvedOptions.systemActions ?? LiveSystemActions()
        let configured = base.with(scanSettings: loaded)
        let quarantineGate = SafetyGate(environment: configured, userExclusions: [], ageThresholdOverrides: [:],
                                        waivedSystemRoots: resolvedOptions.waivedSystemRoots)
        // SAFETY-DECISION: always the compile-time policy (see AppStateFixtureOptions).
        self.quarantine = Quarantine(environment: configured, gate: quarantineGate, mutationPolicy: .compiledIn)
        self.auditLog = AuditLog(environment: configured, exportWaivedSystemRoots: resolvedOptions.waivedSystemRoots)
        if settingsStore.lastLoadFellBackToDefaults {
            let parts = settingsStore.lastLoadUnreadableFields
            let what = parts.isEmpty ? "your settings" : parts.joined(separator: ", ")
            settingsReviewNotice = "Some of your settings could not be read (\(what)). Exclusions, project folders or "
                + "other choices you made may be missing. Check Settings, then confirm them to allow cleaning again. "
                + "The unreadable data was kept as a backup."
        }

        if resolvedOptions.runsLaunchMaintenance {
            track { [weak self] in await self?.launchMaintenance() }
        } else {
            refreshPermissions()
            refreshDiskUsage()
        }
        if resolvedOptions.startsDailyPurgeTimer {
            startDailyPurgeTimer()
        }
    }

    /// The environment the next scan / plan / execution uses (current settings).
    private var currentEnvironment: SafeCleanEnvironment { baseEnvironment.with(scanSettings: storedSettings) }

    // MARK: - Scanning

    public func startScan() {
        guard phase != .scanning, phase != .executing else { return }
        scanTask?.cancel()
        let token = UUID()
        scanToken = token
        phase = .scanning
        resetPlanState()
        lastReport = nil
        executionOutcomes = []
        executionTotal = 0
        ruleProgress = [:]
        categoryProgress = Dictionary(uniqueKeysWithValues: RuleCategory.allCases.map { ($0, CategoryProgress()) })
        currentScanPath = nil
        lastError = nil

        let environment = currentEnvironment
        let snapshot = storedSettings
        let options = self.options
        let probes = self.probes
        let declined = sessionDeclinedRuleIDs
        let coalescer = ProgressCoalescer { [weak self] events, path in
            self?.applyProgress(events, path: path, token: token)
        }

        scanTask = Task { [weak self] in
            let outcome = await Self.offMain {
                await Self.performScan(environment: environment, settings: snapshot, options: options,
                                       probes: probes, declinedRuleIDs: declined, progress: coalescer)
            }
            guard let self else { return }
            self.finishScan(outcome, settings: snapshot, token: token)
        }
    }

    public func cancelScan() {
        guard phase == .scanning else { return }
        scanTask?.cancel()
        scanTask = nil
        scanToken = nil
        resetPlanState()
        ruleProgress = [:]
        categoryProgress = [:]
        currentScanPath = nil
        phase = .idle
    }

    private struct ScanOutcome: Sendable {
        let fullDiskAccess: PermissionState
        let rules: [Rule]
        let results: [RuleScanResult]
        let plan: CleanupPlan?
        let lastSeenVolumes: [String]?
        let cancelled: Bool
    }

    /// The read-only pipeline: probe → catalog → scan → plan. Runs off the main thread.
    private nonisolated static func performScan(environment: SafeCleanEnvironment, settings: ScanSettings,
                                                options: AppStateFixtureOptions, probes: PermissionProbes,
                                                declinedRuleIDs: Set<String>,
                                                progress: ProgressCoalescer) async -> ScanOutcome {
        let fda = probes.fullDiskAccess.fullDiskAccessState()
        let catalog = options.catalog ?? RuleCatalog.loadBundled(environment: environment)
        // SAFETY-DECISION (spec §8, review M7): rules whose access macOS refused earlier in this
        // session are not scanned again (no repeated prompting); they are reported as unavailable.
        let skipped = catalog.rules.filter { declinedRuleIDs.contains($0.id) }
        let ruleIDs: Set<String>? = skipped.isEmpty
            ? nil : Set(catalog.rules.map(\.id)).subtracting(skipped.map(\.id))
        let scanner = SafeCleanScanner(environment: environment, catalog: catalog,
                                       inspectors: options.inspectors ?? SafeCleanScanner.defaultInspectors,
                                       // SAFETY-DECISION: only a positively confirmed grant unlocks the
                                       // rules that need Full Disk Access (`.unknown` keeps them locked).
                                       hasFullDiskAccess: fda == .granted,
                                       waivedSystemRoots: options.waivedSystemRoots)
        var results = ruleIDs?.isEmpty == true
            ? [] : await scanner.scan(ruleIDs: ruleIDs, progress: { event in progress.report(event) })
        let cancelledByScanner = !results.isEmpty && results.allSatisfy {
            if case .failed(let message) = $0.status { return message == SafeCleanScanner.cancelledMessage }
            return false
        }
        if Task.isCancelled || cancelledByScanner {
            return ScanOutcome(fullDiskAccess: fda, rules: catalog.rules, results: [], plan: nil,
                               lastSeenVolumes: nil, cancelled: true)
        }
        for rule in skipped {
            results.append(RuleScanResult(rule: rule, targets: [], status: .unavailable(Self.declinedThisSessionMessage)))
        }
        let gate = SafetyGate(environment: environment, userExclusions: settings.userExclusions,
                              ageThresholdOverrides: settings.ageThresholdOverrides,
                              waivedSystemRoots: options.waivedSystemRoots)
        let planSettings = PlanSettings(alwaysQuarantine: settings.alwaysQuarantine, userExclusions: settings.userExclusions,
                                        ageThresholdOverrides: settings.ageThresholdOverrides)
        let plan = await PlanBuilder(environment: environment, gate: gate, settings: planSettings).build(from: results)
        let lastSeen = scanner.updatedLastSeenVolumes()
        return ScanOutcome(fullDiskAccess: fda, rules: catalog.rules, results: results, plan: plan,
                           lastSeenVolumes: lastSeen, cancelled: Task.isCancelled)
    }

    private func applyProgress(_ events: [ScanProgressEvent], path: String?, token: UUID) {
        guard scanToken == token, phase == .scanning else { return }
        for event in events {
            if let existing = ruleProgress[event.ruleID], existing.finished, !event.finished { continue }
            ruleProgress[event.ruleID] = event
        }
        var totals = Dictionary(uniqueKeysWithValues: RuleCategory.allCases.map { ($0, CategoryProgress()) })
        var categoryHasUnfinished = Set<RuleCategory>()
        var categorySeen = Set<RuleCategory>()
        for event in ruleProgress.values {
            totals[event.category, default: CategoryProgress()].targetsFound += event.targetsFound
            totals[event.category, default: CategoryProgress()].bytesFound += event.bytesFound
            categorySeen.insert(event.category)
            if !event.finished { categoryHasUnfinished.insert(event.category) }
        }
        for category in categorySeen where !categoryHasUnfinished.contains(category) {
            totals[category]?.finished = true
        }
        categoryProgress = totals
        if let path { currentScanPath = path }
    }

    private func finishScan(_ outcome: ScanOutcome, settings snapshot: ScanSettings, token: UUID) {
        guard scanToken == token else { return }
        scanTask = nil
        scanToken = nil
        currentScanPath = nil
        permissions.fullDiskAccess = outcome.fullDiskAccess
        catalogRules = outcome.rules
        guard !outcome.cancelled, let plan = outcome.plan else {
            resetPlanState()
            categoryProgress = [:]
            phase = .idle
            return
        }
        ruleStatuses = Dictionary(outcome.results.map { ($0.rule.id, $0.status) }, uniquingKeysWith: { first, _ in first })
        for (id, status) in ruleStatuses where status == .unavailable(SafeCleanScanner.accessDeclinedMessage) {
            sessionDeclinedRuleIDs.insert(id)
        }
        var finalProgress = Dictionary(uniqueKeysWithValues: RuleCategory.allCases.map { ($0, CategoryProgress(finished: true)) })
        for result in outcome.results {
            finalProgress[result.rule.category, default: CategoryProgress(finished: true)].targetsFound += result.targets.count
            finalProgress[result.rule.category, default: CategoryProgress(finished: true)].bytesFound += result.reclaimableBytes
        }
        categoryProgress = finalProgress
        setPlan(plan)
        planSettings = Self.planRelevant(snapshot)

        // Spec §6.9 condition 8: remember the drives seen by this scan (persisted). A failed listing
        // (`nil`) changes nothing (see `ScanSettings.lastSeenVolumesAfterScan`).
        if let lastSeen = outcome.lastSeenVolumes, lastSeen != storedSettings.lastSeenVolumes {
            var updated = storedSettings
            updated.lastSeenVolumes = lastSeen
            settings = updated
        }
        phase = .scanned
        refreshDiskUsage()
    }

    private func setPlan(_ plan: CleanupPlan) {
        self.plan = plan
        itemIndex = Dictionary(plan.items.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var grouped: [RuleCategory: [PlanItem]] = [:]
        var advisory: [PlanItem] = []
        for item in plan.items {
            if Self.isAdvisory(item) {
                advisory.append(item)
            } else {
                grouped[item.rule.category, default: []].append(item)
            }
        }
        itemsByCategory = grouped.mapValues { $0.sorted(by: Self.listOrder) }
        advisoryCache = advisory.sorted(by: Self.listOrder)
        // Spec §3.2: only Green actionable items are preselected (never Yellow, Red or permanent deletes).
        selection = plan.defaultSelection
        redConfirmed = []
        pendingRedConfirmation = nil
        emptyTrashConfirmed = []
        pendingEmptyTrashConfirmation = nil
        invalidateReview()
        updateRecoverableBytes()
    }

    private func resetPlanState() {
        plan = nil
        planSettings = nil
        ruleStatuses = [:]
        itemIndex = [:]
        itemsByCategory = [:]
        advisoryCache = []
        selection = []
        redConfirmed = []
        pendingRedConfirmation = nil
        emptyTrashConfirmed = []
        pendingEmptyTrashConfirmation = nil
        selectedItemID = nil
        invalidateReview()
        updateRecoverableBytes()
    }

    private nonisolated static func isAdvisory(_ item: PlanItem) -> Bool {
        item.action.isAdvisory || item.effectiveTier == .advisory || item.rule.tier == .advisory
    }

    /// Actionable first, then by estimated reclaimable size (largest first), then by path.
    private nonisolated static func listOrder(_ lhs: PlanItem, _ rhs: PlanItem) -> Bool {
        if lhs.isActionable != rhs.isActionable { return lhs.isActionable }
        if lhs.target.reclaimableBytes != rhs.target.reclaimableBytes {
            return lhs.target.reclaimableBytes > rhs.target.reclaimableBytes
        }
        return lhs.target.path < rhs.target.path
    }

    /// Settings minus pure bookkeeping (`lastSeenVolumes` is updated after every scan and only ever
    /// makes the OrphanDetector more cautious).
    private nonisolated static func planRelevant(_ settings: ScanSettings) -> ScanSettings {
        var copy = settings
        copy.lastSeenVolumes = nil
        return copy
    }

    /// `true` when the current plan was built under different safety-relevant settings.
    public var planIsOutdated: Bool {
        guard plan != nil, let planSettings else { return false }
        return planSettings != Self.planRelevant(storedSettings)
    }

    // MARK: - Items

    /// Non-advisory items of `category`: actionable first, then by reclaimable size (largest first).
    public func items(in category: RuleCategory) -> [PlanItem] {
        _ = plan // observation dependency
        return itemsByCategory[category] ?? []
    }

    /// Advisory items (explain only, never cleaned).
    public var advisoryItems: [PlanItem] {
        _ = plan
        return advisoryCache
    }

    public func item(id: UUID) -> PlanItem? {
        _ = plan
        return itemIndex[id]
    }

    /// The item shown in the detail pane.
    public var selectedItem: PlanItem? {
        guard let selectedItemID else { return nil }
        return item(id: selectedItemID)
    }

    /// Rules that are locked because Full Disk Access is missing ("Locked — needs Full Disk Access").
    /// Before the first scan: every rule that needs Full Disk Access while access is not confirmed.
    public func ruleStatusesLocked() -> [Rule] {
        if !ruleStatuses.isEmpty {
            return catalogRules.filter { ruleStatuses[$0.id] == .lockedNeedsFullDiskAccess }
        }
        guard permissions.fullDiskAccess != .granted else { return [] }
        return catalogRules.filter(\.requiresFullDiskAccess)
    }

    /// Rules the last scan could not offer anything for, with the reason verbatim (excluding locked
    /// rules, which `ruleStatusesLocked()` lists, and a cancelled scan). Sorted by category, then title.
    public func unavailableRules() -> [UnavailableRule] {
        var list: [UnavailableRule] = []
        for rule in catalogRules {
            switch ruleStatuses[rule.id] {
            case .unavailable(let reason)?:
                list.append(UnavailableRule(rule: rule, reason: reason))
            case .failed(let reason)? where reason != SafeCleanScanner.cancelledMessage:
                list.append(UnavailableRule(rule: rule, reason: reason))
            default:
                continue
            }
        }
        let order = Dictionary(uniqueKeysWithValues: Self.categoryOrder.enumerated().map { ($1, $0) })
        return list.sorted {
            let l = order[$0.rule.category] ?? Int.max, r = order[$1.rule.category] ?? Int.max
            return l != r ? l < r : $0.rule.title < $1.rule.title
        }
    }

    /// Number of locked rules in `category`.
    public func lockedRuleCount(in category: RuleCategory) -> Int {
        ruleStatusesLocked().filter { $0.category == category }.count
    }

    /// `count`: every non-advisory item (blocked ones included, so skip reasons are visible);
    /// `reclaimable` / `allocated`: actionable items only (blocked items are never cleaned).
    public func totals(for category: RuleCategory) -> (count: Int, reclaimable: Int64, allocated: Int64,
                                                       selectedCount: Int, selectedReclaimable: Int64) {
        let list = items(in: category)
        var reclaimable: Int64 = 0, allocated: Int64 = 0, selectedCount = 0, selectedReclaimable: Int64 = 0
        for item in list where item.isActionable {
            reclaimable += item.target.reclaimableBytes
            allocated += item.target.allocatedBytes
            if selection.contains(item.id) {
                selectedCount += 1
                selectedReclaimable += item.target.reclaimableBytes
            }
        }
        return (list.count, reclaimable, allocated, selectedCount, selectedReclaimable)
    }

    public var selectedItems: [PlanItem] {
        guard let plan else { return [] }
        return plan.items.filter { selection.contains($0.id) }
    }

    public var selectedReclaimableBytes: Int64 {
        selectedItems.reduce(0) { $0 + $1.target.reclaimableBytes }
    }

    public func isSelected(_ id: UUID) -> Bool { selection.contains(id) }

    // MARK: - Selection

    /// Green / Yellow: toggles. Red: deselects directly; selecting needs `confirmRed` (the UI shows a
    /// per-item dialog for `pendingRedConfirmation`). Non-actionable items: no-op.
    public func requestToggle(_ id: UUID) {
        guard phase == .scanned, let item = itemIndex[id], item.isActionable else { return }
        if Self.isEmptyTrashItem(item) {
            toggleEmptyTrash(selecting: !selection.contains(id))
            return
        }
        if selection.contains(id) {
            selection.remove(id)
            redConfirmed.remove(id)
            selectionChanged()
            return
        }
        if item.requiresPerItemConfirmation {
            pendingRedConfirmation = item
            return
        }
        selection.insert(id)
        selectionChanged()
    }

    /// Confirms the Red item the per-item dialog presented and selects it.
    // SAFETY-DECISION: only the item currently presented in the dialog (`pendingRedConfirmation`) can
    // be confirmed, so no code path selects a Red item without its dialog having been shown.
    public func confirmRed(_ id: UUID) {
        guard let pending = pendingRedConfirmation, pending.id == id else { return }
        pendingRedConfirmation = nil
        guard phase == .scanned, let item = itemIndex[id], item.isActionable, item.requiresPerItemConfirmation else { return }
        redConfirmed.insert(id)
        selection.insert(id)
        selectionChanged()
    }

    public func cancelRedConfirmation() {
        pendingRedConfirmation = nil
    }

    // MARK: Empty Trash (spec §6.6)

    nonisolated static func isPermanentDelete(_ item: PlanItem) -> Bool {
        if case .permanentDelete = item.action { return true }
        return false
    }

    nonisolated static func isEmptyTrashItem(_ item: PlanItem) -> Bool {
        item.rule.id == emptyTrashRuleID
    }

    /// Actionable items of the grouped "Empty Trash" choice.
    public var emptyTrashItems: [PlanItem] {
        guard let plan else { return [] }
        return plan.items.filter { Self.isEmptyTrashItem($0) && $0.isActionable }
    }

    /// SAFETY-DECISION (spec §6.6, review M7): the items in the Trash form ONE "Empty Trash" choice.
    /// Deselecting any of them deselects all; selecting needs the dedicated confirmation dialog
    /// (`pendingEmptyTrashConfirmation` → `confirmEmptyTrash()`), which names the count and size.
    private func toggleEmptyTrash(selecting: Bool) {
        let items = emptyTrashItems
        guard !items.isEmpty else { return }
        if !selecting {
            for item in items {
                selection.remove(item.id)
            }
            emptyTrashConfirmed = []
            selectionChanged()
            return
        }
        pendingEmptyTrashConfirmation = EmptyTrashRequest(
            itemIDs: items.map(\.id),
            reclaimableBytes: items.reduce(0) { $0 + $1.target.reclaimableBytes },
            allocatedBytes: items.reduce(0) { $0 + $1.target.allocatedBytes })
    }

    /// Confirms the presented "Empty Trash" dialog and selects every item in the Trash.
    // SAFETY-DECISION: only the request currently presented can be confirmed.
    public func confirmEmptyTrash(_ requestID: UUID) {
        guard let pending = pendingEmptyTrashConfirmation, pending.id == requestID else { return }
        pendingEmptyTrashConfirmation = nil
        guard phase == .scanned else { return }
        let current = Set(emptyTrashItems.map(\.id))
        // The Trash items must be exactly the ones the dialog named.
        guard current == Set(pending.itemIDs) else { return }
        selection.formUnion(current)
        emptyTrashConfirmed = current
        selectionChanged()
    }

    public func cancelEmptyTrashConfirmation() {
        pendingEmptyTrashConfirmation = nil
    }

    /// Bulk select / deselect for a category.
    // SAFETY-DECISION: bulk selection never selects a Red item (each needs its own dialog), never a
    // non-actionable one and never a one-step permanent deletion (e.g. the items of "Empty Trash",
    // which need their own confirmation); bulk deselection removes everything in the category.
    public func setSelection(category: RuleCategory, selected: Bool) {
        guard phase == .scanned else { return }
        let list = items(in: category)
        if selected {
            for item in list where item.isActionable && !item.requiresPerItemConfirmation
                && !Self.isEmptyTrashItem(item) && !Self.isPermanentDelete(item) {
                selection.insert(item.id)
            }
        } else {
            for item in list {
                selection.remove(item.id)
                redConfirmed.remove(item.id)
                emptyTrashConfirmed.remove(item.id)
            }
        }
        selectionChanged()
    }

    private func selectionChanged() {
        // SAFETY-DECISION: a review is valid only for the exact selection it showed. Any change
        // invalidates it, so the user always reviews (and waits 2 s on) what will actually be cleaned.
        invalidateReview()
        updateRecoverableBytes()
    }

    private func updateRecoverableBytes() {
        diskUsage.recoverableBytes = selectedReclaimableBytes
    }

    // MARK: - Review & clean

    public var reviewSummary: ReviewSummary {
        var summary = ReviewSummary()
        for item in selectedItems {
            switch item.action {
            case .quarantine: summary.quarantineItems.append(item)
            case .command: summary.commandItems.append(item)
            case .trash, .bootoutAndTrash: summary.trashItems.append(item)
            case .permanentDelete: summary.permanentItems.append(item)
            case .advisory: continue // never selectable
            }
            if !item.isRestorable { summary.irreversibleItems.append(item) }
            if item.requiresPerItemConfirmation { summary.redItems.append(item) }
            if item.effectiveTier == .yellow { summary.yellowItems.append(item) }
            summary.totalReclaimable += item.target.reclaimableBytes
            summary.totalAllocated += item.target.allocatedBytes
        }
        return summary
    }

    /// Records `reviewPresentedAt = clock.now` and shows the review sheet.
    public func beginReview() {
        guard phase == .scanned, plan != nil, !selection.isEmpty else { return }
        if settingsReviewNotice != nil {
            lastError = Self.settingsReviewBlockedMessage
            return
        }
        if planIsOutdated {
            lastError = Self.planOutdatedMessage
            return
        }
        reviewPresentedAt = baseEnvironment.clock.now
        reviewedSelection = selection
        showReview = true
    }

    /// Closes the review sheet without cleaning.
    public func cancelReview() {
        invalidateReview()
    }

    private func invalidateReview() {
        showReview = false
        reviewPresentedAt = nil
        reviewedSelection = nil
    }

    /// Confirms the reviewed selection and starts the Executor.
    ///
    /// Throws `AppStateError` or the core's `ConfirmationError` (e.g. `.confirmedTooQuickly` within 2 s
    /// of `beginReview()`, `.irreversibleNotAcknowledged`, `.missingPerItemConfirmation`).
    ///
    /// - Parameter acknowledgedCategories: categories whose "I understand what I lose" checkbox the
    ///   user ticked. Every category with a selected Yellow item must be listed (spec §3.2).
    public func confirmAndClean(acknowledgedIrreversible: Bool, acknowledgedCategories: Set<RuleCategory> = []) throws {
        guard executionTask == nil, phase != .executing else { throw AppStateError.executionInProgress }
        guard settingsReviewNotice == nil else {
            lastError = Self.settingsReviewBlockedMessage
            throw AppStateError.settingsNeedReview
        }
        guard phase == .scanned, let plan, !selection.isEmpty else { throw AppStateError.nothingToClean }
        guard let presentedAt = reviewPresentedAt, reviewedSelection == selection else {
            throw AppStateError.reviewNotPresented
        }
        let summary = reviewSummary
        // SAFETY-DECISION (spec §3.2, review M7): Yellow items need the per-category acknowledgement of
        // their "what you lose" text, enforced here and not only in the review sheet.
        for category in summary.yellowCategories where !acknowledgedCategories.contains(category) {
            let error = AppStateError.categoryNotAcknowledged(category)
            lastError = error.errorDescription
            throw error
        }
        // SAFETY-DECISION (spec §6.6, review M7): Trash items are cleaned only as the whole, separately
        // confirmed "Empty Trash" choice.
        let selectedTrash = Set(plan.items.filter { Self.isEmptyTrashItem($0) && selection.contains($0.id) }.map(\.id))
        if !selectedTrash.isEmpty {
            let allTrash = Set(emptyTrashItems.map(\.id))
            guard selectedTrash == emptyTrashConfirmed, selectedTrash == allTrash else {
                lastError = AppStateError.emptyTrashNotConfirmed.errorDescription
                throw AppStateError.emptyTrashNotConfirmed
            }
        }
        // SAFETY-DECISION: settings that affect safety (exclusions, project roots, overrides, "Always
        // quarantine") apply to the NEXT scan; a plan built under different settings is refused here
        // and the user is asked to scan again (never silently re-planned at confirm time).
        guard !planIsOutdated else {
            lastError = Self.planOutdatedMessage
            throw AppStateError.planOutdated
        }

        let environment = currentEnvironment
        let confirmation = UserConfirmation(reviewPresentedAt: presentedAt, confirmedAt: environment.clock.now,
                                            perItemConfirmed: redConfirmed.intersection(selection),
                                            acknowledgedIrreversible: acknowledgedIrreversible)
        let confirmed: ConfirmedPlan
        do {
            confirmed = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: selection, confirmation: confirmation,
                                                  alwaysQuarantine: storedSettings.alwaysQuarantine)
        } catch {
            lastError = Self.message(for: error)
            throw error
        }

        // One confirmation, one run.
        invalidateReview()
        phase = .executing
        executionOutcomes = []
        executionTotal = confirmed.items.count
        confirmedItemIDs = confirmed.items.map(\.id)
        exclusionsAddedDuringExecution = []
        executingItemID = nil
        lastReport = nil
        lastError = nil

        // SAFETY-DECISION (review M7): the execute-time gate also reads exclusions added during the run.
        let live = LiveExclusions(storedSettings.userExclusions)
        runExclusions = live
        let gate = SafetyGate(environment: environment, userExclusions: storedSettings.userExclusions,
                              ageThresholdOverrides: storedSettings.ageThresholdOverrides,
                              waivedSystemRoots: options.waivedSystemRoots, liveExclusions: live)
        // Public initializer: FinderTrash / RemovefileRemover with MutationPolicy.compiledIn.
        let executor = Executor(environment: environment, gate: gate, quarantine: quarantine, auditLog: auditLog)
        self.executor = executor

        executionTask = Task { [weak self] in
            let stream = await executor.execute(confirmed)
            for await event in stream {
                guard let self else { continue }
                self.apply(event)
            }
            self?.executionEnded()
        }
    }

    /// Requests cancellation; honoured between items.
    public func cancelExecution() {
        guard phase == .executing, let executor else { return }
        track { await executor.cancel() }
    }

    private func apply(_ event: ExecutionEvent) {
        switch event {
        case .started(_, let total):
            executionTotal = total
        case .itemStarted(let id):
            executingItemID = id
        case .itemFinished(let outcome):
            executionOutcomes.append(outcome)
        case .finished(let report):
            lastReport = report
            executionOutcomes = report.outcomes
            executingItemID = nil
        }
    }

    private func executionEnded() {
        executionTask = nil
        executor = nil
        executingItemID = nil
        runExclusions = nil
        if lastReport == nil {
            lastError = "The cleanup ended without a report. Check the audit log."
        }
        // The plan describes the pre-clean state; it is kept for reference but can no longer be
        // reviewed or confirmed (phase is `.finished` until the next scan).
        selection = []
        redConfirmed = []
        pendingRedConfirmation = nil
        emptyTrashConfirmed = []
        pendingEmptyTrashConfirmation = nil
        invalidateReview()
        updateRecoverableBytes()
        phase = .finished
        destination = .results
        refreshQuarantine()
        refreshDiskUsage()
    }

    // MARK: - Quarantine

    public func refreshQuarantine() {
        let quarantine = self.quarantine
        track { [weak self] in
            let sessions = (try? await quarantine.sessions()) ?? []
            self?.quarantineSessions = sessions
        }
    }

    public func restore(entryID: UUID) {
        guard phase != .executing else { lastError = "Wait for the cleanup to finish."; return }
        let quarantine = self.quarantine, audit = self.auditLog, clock = baseEnvironment.clock
        track { [weak self] in
            do {
                let entry = try await quarantine.restore(entryID: entryID)
                await audit.record(AuditEvent(timestamp: clock.now, sessionID: entry.sessionID, ruleID: entry.ruleID,
                                              path: entry.restoredPath ?? entry.originalPath, action: "quarantine.restore",
                                              bytes: entry.allocatedBytes, verdict: "succeeded"))
            } catch {
                let message = Self.message(for: error)
                await audit.record(AuditEvent(timestamp: clock.now, action: "quarantine.restore", verdict: "failed",
                                              rejectionReason: message, detail: "entry \(entryID.uuidString)"))
                self?.lastError = "Could not restore the item: \(message)"
            }
            self?.refreshQuarantine()
            self?.refreshDiskUsage()
        }
    }

    public func restoreSession(_ id: UUID) {
        guard phase != .executing else { lastError = "Wait for the cleanup to finish."; return }
        let quarantine = self.quarantine, audit = self.auditLog, clock = baseEnvironment.clock
        track { [weak self] in
            let results = await quarantine.restoreSession(id)
            var failures: [String] = []
            for result in results {
                switch result {
                case .success(let entry):
                    await audit.record(AuditEvent(timestamp: clock.now, sessionID: id, ruleID: entry.ruleID,
                                                  path: entry.restoredPath ?? entry.originalPath, action: "quarantine.restore",
                                                  bytes: entry.allocatedBytes, verdict: "succeeded"))
                case .failure(let error):
                    failures.append(error.message)
                    await audit.record(AuditEvent(timestamp: clock.now, sessionID: id, action: "quarantine.restore",
                                                  verdict: "failed", rejectionReason: error.message))
                }
            }
            if !failures.isEmpty {
                let unique = Array(Set(failures)).sorted()
                self?.lastError = "\(failures.count) item(s) could not be restored: " + unique.joined(separator: "; ")
            }
            self?.refreshQuarantine()
            self?.refreshDiskUsage()
        }
    }

    /// "Empty Quarantine Now" (the UI asks for confirmation first). Permanently removes every
    /// quarantined item through `Quarantine.purgeAll()` (SafetyGate-checked, never follows symlinks).
    public func emptyQuarantineNow() {
        guard phase != .executing else { lastError = "Wait for the cleanup to finish."; return }
        let quarantine = self.quarantine, audit = self.auditLog, clock = baseEnvironment.clock
        track { [weak self] in
            let outcomes = await quarantine.purgeAll()
            await Self.audit(outcomes, action: "quarantine.purgeAll", log: audit, clock: clock)
            let problems = outcomes.filter { if case .purged = $0.status { return false } else { return true } }
            if !problems.isEmpty {
                self?.lastError = "\(problems.count) quarantined item(s) could not be removed: "
                    + Array(Set(problems.map { Self.describe($0.status) })).sorted().joined(separator: "; ")
            }
            self?.refreshQuarantine()
            self?.refreshDiskUsage()
        }
    }

    private nonisolated static func audit(_ outcomes: [QuarantinePurgeOutcome], action: String, log: AuditLog,
                                          clock: any Clock) async {
        for outcome in outcomes {
            let (verdict, reason): (String, String?) = {
                switch outcome.status {
                case .purged: return ("succeeded", nil)
                case .rejected(let rejection): return ("rejected", rejection.reason)
                case .failed(let error): return ("failed", error.message)
                case .incomplete(let error): return ("incomplete", error.message)
                }
            }()
            await log.record(AuditEvent(timestamp: clock.now, sessionID: outcome.entry.sessionID, ruleID: outcome.entry.ruleID,
                                        path: outcome.entry.originalPath, action: action, bytes: outcome.entry.reclaimableBytes,
                                        verdict: verdict, rejectionReason: reason))
        }
    }

    private nonisolated static func describe(_ status: QuarantinePurgeOutcome.Status) -> String {
        switch status {
        case .purged: return "removed"
        case .rejected(let rejection): return rejection.reason
        case .failed(let error), .incomplete(let error): return error.message
        }
    }

    /// Launch: reconcile interrupted operations, purge expired items, refresh everything.
    private func launchMaintenance() async {
        refreshPermissions()
        refreshDiskUsage()
        let quarantine = self.quarantine, audit = self.auditLog, clock = baseEnvironment.clock
        let environment = currentEnvironment, options = self.options
        do {
            let events = try await quarantine.reconcile()
            for event in events {
                await audit.record(AuditEvent(timestamp: clock.now, sessionID: event.sessionID, ruleID: event.entry?.ruleID,
                                              path: event.entry?.originalPath, action: "quarantine.reconcile",
                                              verdict: "\(event.kind)"))
            }
        } catch {
            await audit.record(AuditEvent(timestamp: clock.now, action: "quarantine.reconcile", verdict: "failed",
                                          rejectionReason: Self.message(for: error)))
        }
        await purgeExpiredNow()
        refreshQuarantine()
        // Catalog for the locked-rules list before the first scan (read off the main thread).
        let rules = await Self.offMain { (options.catalog ?? RuleCatalog.loadBundled(environment: environment)).rules }
        if catalogRules.isEmpty { catalogRules = rules }
    }

    private func purgeExpiredNow() async {
        // SAFETY-DECISION: no purge while a cleanup is running (the Executor owns the open session).
        guard phase != .executing else { return }
        let outcomes = await quarantine.purgeExpired()
        await Self.audit(outcomes, action: "quarantine.purgeExpired", log: auditLog, clock: baseEnvironment.clock)
    }

    private func startDailyPurgeTimer() {
        // Weakly held: the loop ends when the AppState goes away. Purging expired quarantine items is
        // retention housekeeping of items the user already confirmed — never a new cleanup (spec §10).
        Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(Self.purgeInterval * 1_000_000_000))
                guard let self else { return }
                await self.purgeExpiredNow()
                self.refreshQuarantine()
                self.refreshDiskUsage()
            }
        }
    }

    // MARK: - Audit log

    /// Exports the audit log to a NEW file at `url` (chosen with NSSavePanel). The core refuses
    /// deny-listed destinations (e.g. ~/Desktop, ~/Documents), iMop's own folders and existing files;
    /// the error is rethrown and its message stored in `lastError`.
    public func exportAuditLog(to url: URL) async throws {
        do {
            try await auditLog.export(to: url)
        } catch {
            lastError = "Could not export the log: " + Self.message(for: error)
            throw error
        }
    }

    // MARK: - Settings helpers

    public func addExclusion(path: String) {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var updated = storedSettings
        if !updated.userExclusions.contains(trimmed) { updated.userExclusions.append(trimmed) }
        settings = updated
        // SAFETY-DECISION (review M7): during a cleanup the selection is the confirmed run and is left
        // alone; the new exclusion reaches the running Executor through `runExclusions` (see the
        // `settings` setter), so matching items not processed yet are skipped with the exclusion reason.
        guard phase != .executing else { return }
        // SAFETY-DECISION: deselect anything inside (or containing) the new exclusion right away; the
        // plan itself is outdated now and must be rebuilt by a new scan before cleaning.
        let excluded = Self.normalizedPath(trimmed, home: baseEnvironment.homePath)
        var changed = false
        for id in selection {
            guard let item = itemIndex[id] else { continue }
            let path = Self.normalizedPath(item.target.path, home: baseEnvironment.homePath)
            if Self.isInsideOrEqual(path, excluded) || Self.isInsideOrEqual(excluded, path) {
                selection.remove(id)
                redConfirmed.remove(id)
                changed = true
            }
        }
        // The Empty Trash choice is all-or-nothing: if one Trash item is excluded, deselect all of them.
        if changed, !emptyTrashConfirmed.isSubset(of: selection) {
            for id in emptyTrashConfirmed { selection.remove(id) }
            emptyTrashConfirmed = []
        }
        if changed { selectionChanged() }
    }

    public func dropExclusion(_ path: String) {
        var updated = storedSettings
        updated.userExclusions.removeAll { $0 == path }
        settings = updated
    }

    public func addProjectRoot(path: String) {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var updated = storedSettings
        if !updated.projectRoots.contains(trimmed) { updated.projectRoots.append(trimmed) }
        settings = updated
    }

    public func dropProjectRoot(_ path: String) {
        var updated = storedSettings
        updated.projectRoots.removeAll { $0 == path }
        settings = updated
    }

    /// Settings → "Forget remembered drives".
    // SAFETY-DECISION: `nil` means "never recorded", which pauses the OrphanDetector until the next scan
    // records the connected drives again (see `ScanSettings.lastSeenVolumes`).
    public func forgetRememberedDrives() {
        var updated = storedSettings
        updated.lastSeenVolumes = nil
        settings = updated
    }

    private nonisolated static func normalizedPath(_ path: String, home: String) -> String {
        var expanded = path
        if expanded == "~" || expanded.hasPrefix("~/") {
            expanded = home + expanded.dropFirst()
        } else if expanded.hasPrefix("{HOME}") {
            expanded = home + expanded.dropFirst("{HOME}".count)
        }
        expanded = (expanded as NSString).standardizingPath
        while expanded.count > 1 && expanded.hasSuffix("/") { expanded.removeLast() }
        return expanded.precomposedStringWithCanonicalMapping.lowercased()
    }

    private nonisolated static func isInsideOrEqual(_ candidate: String, _ root: String) -> Bool {
        candidate == root || candidate.hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }

    // MARK: - Permissions & system

    public func refreshPermissions() {
        let probes = self.probes
        track { [weak self] in
            let snapshot = await Self.offMain {
                PermissionsSnapshot(fullDiskAccess: probes.fullDiskAccess.fullDiskAccessState(),
                                    appManagement: probes.appManagement.appManagementState())
            }
            self?.permissions = snapshot
        }
    }

    public func openFullDiskAccessSettings() { openDeepLink(FullDiskAccessProbe.settingsDeepLink) }
    public func openAppManagementSettings() { openDeepLink(AppManagementProbe.settingsDeepLink) }
    public func openStorageSettings() { openDeepLink(Self.storageSettingsDeepLink) }

    private func openDeepLink(_ link: String) {
        guard let url = URL(string: link) else { return }
        actions.open(url: url)
    }

    /// Selects the item in Finder (read-only).
    public func revealInFinder(path: String) {
        guard path.hasPrefix("/") else { return }
        actions.revealInFinder(path: path)
    }

    /// Advisory "Open App".
    public func openApp(bundleID: String) {
        if !actions.openApp(bundleID: bundleID) {
            lastError = "The app \(bundleID) could not be found."
        }
    }

    public func clearError() {
        lastError = nil
    }

    /// The user has checked Settings after `settingsReviewNotice` appeared; cleaning is allowed again.
    /// The current settings are saved (the unreadable original stays in the store's backup).
    public func acknowledgeSettingsReview() {
        guard settingsReviewNotice != nil else { return }
        settingsReviewNotice = nil
        settingsStore.save(storedSettings)
        if lastError == Self.settingsReviewBlockedMessage { lastError = nil }
    }

    /// Volume capacity of the home volume (read off the main thread).
    public func refreshDiskUsage() {
        let environment = baseEnvironment
        track { [weak self] in
            let usage = await Self.offMain { Self.measureDiskUsage(environment: environment) }
            guard let self else { return }
            var updated = usage
            updated.recoverableBytes = self.selectedReclaimableBytes
            self.diskUsage = updated
        }
    }

    private nonisolated static func measureDiskUsage(environment: SafeCleanEnvironment) -> DiskUsage {
        let home = environment.homePath
        let free = environment.volumes.availableCapacityForImportantUsage(at: home)
            ?? environment.volumes.availableCapacity(at: home) ?? 0
        let values = try? URL(fileURLWithPath: home, isDirectory: true).resourceValues(forKeys: [.volumeTotalCapacityKey])
        let total = Int64(values?.volumeTotalCapacity ?? 0)
        guard total > 0 else { return DiskUsage() }
        let clampedFree = min(max(0, free), total)
        return DiskUsage(totalBytes: total, freeBytes: clampedFree, usedBytes: total - clampedFree)
    }

    // MARK: - Error text

    /// A user-facing message for any error AppState or the core raises.
    public nonisolated static func message(for error: any Error) -> String {
        switch error {
        case let error as AppStateError:
            return error.errorDescription ?? "\(error)"
        case let error as ConfirmationError:
            switch error {
            case .emptySelection: return "Nothing is selected."
            case .unknownItem, .notActionable: return "An item changed since the scan. Scan again before cleaning."
            case .missingPerItemConfirmation: return "Each Caution item must be confirmed on its own."
            case .irreversibleNotAcknowledged: return "Confirm that you understand some actions cannot be undone."
            case .permanentDeleteBlockedByAlwaysQuarantine:
                return "“Always quarantine” is on, so items are never permanently deleted in one step."
            case .confirmedTooQuickly: return "Take a moment to review the list before cleaning."
            }
        case let error as AuditLogError:
            switch error {
            case .invalidDestination(let detail): return "That location cannot be used (\(detail)). Choose another location, such as Downloads."
            case .destinationRefused(let detail): return "iMop does not write to that location (\(detail)). Choose another location, such as Downloads."
            case .destinationExists: return "A file with that name already exists. Choose a new name."
            case .logDirectoryUnavailable: return "The audit log folder is unavailable."
            case .io(let detail): return detail
            }
        case let error as QuarantineError:
            return error.message
        default:
            return error.localizedDescription
        }
    }

    // MARK: - Task plumbing

    /// Runs `work` in a detached task (never on the main thread) and forwards cancellation.
    private nonisolated static func offMain<T: Sendable>(_ work: @escaping @Sendable () async -> T) async -> T {
        let task = Task.detached(priority: .userInitiated) { await work() }
        return await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
    }

    /// Starts a main-actor task whose heavy work hops off the main thread itself; tracked so tests can
    /// wait for it.
    private func track(_ work: @escaping @MainActor () async -> Void) {
        let id = UUID()
        let task = Task { @MainActor [weak self] in
            await work()
            self?.pendingTasks[id] = nil
        }
        pendingTasks[id] = task
    }

    /// Test-only: waits until the scan, the cleanup and every background refresh have finished.
    @_spi(FixtureTesting)
    public func waitUntilIdle() async {
        while true {
            if let scanTask {
                await scanTask.value
                continue
            }
            if let executionTask {
                await executionTask.value
                continue
            }
            if let (_, task) = pendingTasks.first {
                await task.value
                continue
            }
            return
        }
    }
}

// MARK: - Progress coalescing

/// Collects scanner progress events (reported from any thread) and delivers them to the main actor
/// in batches, so a large scan does not flood the main thread with one hop per event.
final class ProgressCoalescer: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: [String: ScanProgressEvent] = [:]
    private var latestPath: String?
    private var scheduled = false
    private let deliver: @MainActor ([ScanProgressEvent], String?) -> Void

    init(deliver: @escaping @MainActor ([ScanProgressEvent], String?) -> Void) {
        self.deliver = deliver
    }

    func report(_ event: ScanProgressEvent) {
        lock.lock()
        if let existing = pending[event.ruleID], existing.finished, !event.finished {
            // Keep the finished event.
        } else {
            pending[event.ruleID] = event
        }
        if let path = event.currentPath { latestPath = path }
        let needsSchedule = !scheduled
        scheduled = true
        lock.unlock()
        guard needsSchedule else { return }
        Task { @MainActor in
            // Small delay so several events are delivered together.
            try? await Task.sleep(nanoseconds: 50_000_000)
            let (events, path) = self.drain()
            self.deliver(events, path)
        }
    }

    private func drain() -> ([ScanProgressEvent], String?) {
        lock.lock(); defer { lock.unlock() }
        let events = Array(pending.values)
        let path = latestPath
        pending = [:]
        latestPath = nil
        scheduled = false
        return (events, path)
    }
}
