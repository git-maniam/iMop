import AppKit
import iMopCore
import SwiftUI

// Spec §9.4: the review sheet. Summary grouped by action type (Quarantine / Vendor command / Trash /
// Permanent delete), totals, an explicit warning-styled list of every non-undoable action, and a
// "Clean" button that stays disabled for 2 seconds after the sheet appears. The core enforces the
// same rules again in `ConfirmedPlan.confirm` (2-second interval, per-item Red confirmation,
// irreversible acknowledgement, Always-quarantine); this view only makes them visible.

struct ReviewSheet: View {
    @Environment(AppState.self) private var appState

    @LocalState private var cleanUnlocked = false
    @LocalState private var acknowledgedIrreversible = false
    /// Spec §3.2: one "I understand what I lose" checkbox per category with selected Yellow items.
    @LocalState private var acknowledgedCategories: Set<RuleCategory> = []
    @LocalState private var isSubmitting = false
    @LocalState private var errorMessage: String?

    init() {}

    private var summary: ReviewSummary { appState.reviewSummary }

    private var selectedCount: Int {
        summary.quarantineItems.count + summary.commandItems.count + summary.trashItems.count + summary.permanentItems.count
    }

    private var needsAcknowledgement: Bool { !summary.irreversibleItems.isEmpty }

    private var unacknowledgedYellowCategories: [RuleCategory] {
        summary.yellowCategories.filter { !acknowledgedCategories.contains($0) }
    }

    /// Red items that are selected but were not confirmed one by one (should never happen; the
    /// selection API only selects Red items through `confirmRed`).
    private var unconfirmedRedItems: [PlanItem] {
        summary.redItems.filter { !appState.redConfirmed.contains($0.id) }
    }

    // SAFETY-DECISION: a selected permanent deletion while Settings › "Always quarantine" is ON would
    // be refused by `ConfirmedPlan.confirm`; the Clean button is disabled up front and the reason is
    // shown, instead of letting the user press Clean and fail.
    private var permanentBlockedByAlwaysQuarantine: Bool {
        appState.settings.alwaysQuarantine && !summary.permanentItems.isEmpty
    }

    private var cleanDisabledReason: String? {
        if selectedCount == 0 { return "Nothing is selected." }
        if appState.planIsOutdated { return AppState.planOutdatedMessage }
        if !cleanUnlocked { return "Clean becomes available 2 seconds after this summary appears — please read it first." }
        if permanentBlockedByAlwaysQuarantine {
            return "Settings › Always quarantine is on, so permanent deletions are not allowed. Deselect them first."
        }
        if !unconfirmedRedItems.isEmpty { return "Every Caution item must be confirmed individually." }
        if let category = unacknowledgedYellowCategories.first {
            return "Tick “I understand what I lose in \(category.displayName)” to continue."
        }
        if needsAcknowledgement && !acknowledgedIrreversible {
            return "Tick the box to confirm you understand that some actions cannot be undone."
        }
        if isSubmitting { return "Starting…" }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            header
                .padding(20)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if !AppState.isMutationEnabledInBuild {
                        ActNoticeBanner(
                            symbol: "eye",
                            title: "Dry-run build — cleaning disabled",
                            message: "This build of iMop cannot change files. Clean will only record what would have happened.",
                            style: .info
                        )
                    }

                    // SAFETY-DECISION: settings changed after this scan (e.g. in the Settings window while
                    // the sheet is open) — the plan must be rebuilt by a new scan; Clean stays disabled.
                    if appState.planIsOutdated {
                        ActNoticeBanner(symbol: "arrow.clockwise.circle", title: "Scan again before cleaning",
                                        message: AppState.planOutdatedMessage, style: .warning)
                    }

                    if needsAcknowledgement {
                        irreversibleSection
                    }

                    if !summary.yellowCategories.isEmpty {
                        yellowSection
                    }

                    if permanentBlockedByAlwaysQuarantine {
                        ActNoticeBanner(
                            symbol: "lock.shield",
                            title: "Permanent deletion is turned off",
                            message: "Settings › “Always quarantine (never permanently delete in one step)” is on. Deselect the items under Permanent delete, or turn the setting off and scan again.",
                            style: .warning
                        )
                    }

                    if !unconfirmedRedItems.isEmpty {
                        ActNoticeBanner(
                            symbol: "hand.raised",
                            title: "Confirmation missing",
                            message: "These Caution items were not confirmed one by one: "
                                + unconfirmedRedItems.map(\.target.displayName).joined(separator: ", ")
                                + ". Deselect them and select them again to confirm each one.",
                            style: .warning
                        )
                    }

                    ReviewGroupSection(
                        title: "Quarantine",
                        symbol: "archivebox",
                        items: summary.quarantineItems,
                        footnote: "Restorable from Quarantine until its retention period ends. " + Quarantine.spaceNotice,
                        redConfirmed: appState.redConfirmed
                    )
                    ReviewGroupSection(
                        title: "Vendor command",
                        symbol: "terminal",
                        items: summary.commandItems,
                        footnote: "Runs the owning tool's own cleanup command (no shell). Not undoable.",
                        redConfirmed: appState.redConfirmed
                    )
                    ReviewGroupSection(
                        title: "Trash",
                        symbol: "trash",
                        items: summary.trashItems,
                        footnote: "Moved to the Finder Trash one item at a time. iMop empties the Trash only when you choose Empty Trash.",
                        redConfirmed: appState.redConfirmed
                    )
                    ReviewGroupSection(
                        title: "Permanent delete",
                        symbol: "xmark.bin",
                        items: summary.permanentItems,
                        footnote: "Removed in one step, without Quarantine. Not undoable.",
                        redConfirmed: appState.redConfirmed
                    )

                    if let errorMessage {
                        ActNoticeBanner(symbol: "exclamationmark.octagon", title: "Cleaning did not start",
                                        message: errorMessage, style: .error)
                    }
                }
                .padding(20)
            }

            Divider()

            footer
                .padding(20)
        }
        .frame(minWidth: 560, idealWidth: 640, minHeight: 460, idealHeight: 620)
        .onAppear {
            cleanUnlocked = false
            acknowledgedIrreversible = false
            acknowledgedCategories = []
            isSubmitting = false
            errorMessage = nil
            // SAFETY-DECISION: the 2-second window needs a recorded presentation time; if the sheet
            // was shown without `beginReview()`, record it now (the core measures from it).
            if appState.reviewPresentedAt == nil { appState.beginReview() }
        }
        .task {
            // Spec §9.4: Clean stays disabled for 2 seconds after the sheet appears.
            do {
                try await Task.sleep(for: .seconds(ConfirmedPlan.minimumReviewInterval))
            } catch {
                return
            }
            cleanUnlocked = true
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "checklist")
                .font(.largeTitle)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text("Review & Clean")
                    .font(.title2.weight(.bold))
                Text("\(selectedCount) item\(selectedCount == 1 ? "" : "s") selected · Estimated reclaimable: \(ByteFormatter.format(summary.totalReclaimable)) (\(ByteFormatter.format(summary.totalAllocated)) on disk)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Nothing has been changed yet. Every item is checked for safety again just before it is acted on.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: Irreversible list

    private var irreversibleSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label {
                Text("These actions cannot be undone (\(summary.irreversibleItems.count))")
                    .font(.headline)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.red)

            ForEach(summary.irreversibleItems) { item in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(item.target.displayName)
                            .font(.body.weight(.semibold))
                        Spacer(minLength: 8)
                        Text(ByteFormatter.format(item.target.reclaimableBytes))
                            .font(.body.monospacedDigit())
                    }
                    Text(ActCopy.irreversibleWarning(for: item.action))
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Cannot be undone: \(item.target.displayName), \(ByteFormatter.format(item.target.reclaimableBytes)). \(ActCopy.irreversibleWarning(for: item.action))")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.red.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.red.opacity(0.45), lineWidth: 1)
        )
    }

    // MARK: Yellow: what you lose (spec §3.2)

    private var yellowSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label {
                Text("What you lose")
                    .font(.headline)
            } icon: {
                Image(systemName: "exclamationmark.circle")
            }
            .foregroundStyle(.orange)

            Text("These items come back only at a cost — time, downloads or convenience. Read what you lose and confirm each category.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(summary.yellowCategories, id: \.self) { category in
                VStack(alignment: .leading, spacing: 8) {
                    Text(category.displayName)
                        .font(.subheadline.weight(.semibold))
                        .accessibilityAddTraits(.isHeader)
                    ForEach(summary.yellowItems(in: category)) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                ActTierTag(tier: item.effectiveTier)
                                Text(item.target.displayName)
                                    .font(.body.weight(.medium))
                                Spacer(minLength: 8)
                                Text(ByteFormatter.format(item.target.reclaimableBytes))
                                    .font(.callout.monospacedDigit())
                            }
                            Text("What you lose: \(item.rule.whatYouLose)")
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("\(item.effectiveTier.displayName) tier. \(item.target.displayName), \(ByteFormatter.format(item.target.reclaimableBytes)). What you lose: \(item.rule.whatYouLose)")
                    }
                    Toggle(isOn: Binding(
                        get: { acknowledgedCategories.contains(category) },
                        set: { isOn in
                            if isOn { acknowledgedCategories.insert(category) } else { acknowledgedCategories.remove(category) }
                        }
                    )) {
                        Text("I understand what I lose in \(category.displayName)")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .toggleStyle(.checkbox)
                    .accessibilityLabel("I understand what I lose in \(category.displayName)")
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.background.opacity(0.6)))
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.orange.opacity(0.07))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.orange.opacity(0.4), lineWidth: 1)
        )
    }

    // MARK: Footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: 12) {
            if needsAcknowledgement {
                Toggle(isOn: Binding(get: { acknowledgedIrreversible }, set: { acknowledgedIrreversible = $0 })) {
                    Text("I understand that \(summary.irreversibleItems.count) of these action\(summary.irreversibleItems.count == 1 ? "" : "s") cannot be undone.")
                        .fixedSize(horizontal: false, vertical: true)
                }
                .toggleStyle(.checkbox)
                .accessibilityLabel("I understand that some of these actions cannot be undone")
            }

            HStack(alignment: .center, spacing: 12) {
                if let reason = cleanDisabledReason {
                    Text(reason)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)

                Button("Cancel", role: .cancel) {
                    appState.cancelReview()
                }
                .keyboardShortcut(.cancelAction)

                // SAFETY-DECISION: Clean is NOT bound to Return (no `.defaultAction`), so a stray key
                // press can never confirm; it must be clicked (or focused and activated) deliberately.
                Button {
                    clean()
                } label: {
                    Text("Clean")
                        .frame(minWidth: 70)
                }
                .buttonStyle(.borderedProminent)
                .disabled(cleanDisabledReason != nil)
                .accessibilityLabel("Clean \(selectedCount) items")
                .accessibilityHint(cleanDisabledReason ?? "Starts cleaning the items listed above.")
            }
        }
    }

    // MARK: Actions

    private func clean() {
        guard cleanDisabledReason == nil else { return }
        isSubmitting = true
        errorMessage = nil
        do {
            // On success AppState closes the sheet itself (one confirmation, one run).
            try appState.confirmAndClean(acknowledgedIrreversible: needsAcknowledgement && acknowledgedIrreversible,
                                         acknowledgedCategories: acknowledgedCategories.intersection(summary.yellowCategories))
        } catch let error as ConfirmationError {
            errorMessage = ActCopy.confirmationMessage(error, plan: appState.plan)
        } catch {
            errorMessage = ActCopy.genericErrorMessage(error)
        }
        isSubmitting = false
    }
}

// MARK: - Group section

private struct ReviewGroupSection: View {
    let title: String
    let symbol: String
    let items: [PlanItem]
    let footnote: String
    let redConfirmed: Set<UUID>

    private var reclaimable: Int64 { items.reduce(0) { $0 + $1.target.reclaimableBytes } }
    private var allocated: Int64 { items.reduce(0) { $0 + $1.target.allocatedBytes } }

    var body: some View {
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    Label(title, systemImage: symbol)
                        .font(.headline)
                    Spacer(minLength: 8)
                    Text("\(items.count) · \(ByteFormatter.format(reclaimable)) (\(ByteFormatter.format(allocated)) on disk)")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(title): \(items.count) items, \(ByteFormatter.format(reclaimable)) reclaimable, \(ByteFormatter.format(allocated)) on disk")

                Text(footnote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(spacing: 0) {
                    ForEach(items) { item in
                        ReviewItemRow(item: item, isRedConfirmed: redConfirmed.contains(item.id))
                        if item.id != items.last?.id { Divider() }
                    }
                }
                .padding(.horizontal, 10)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(.background.opacity(0.6))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                )
            }
        }
    }
}

private struct ReviewItemRow: View {
    let item: PlanItem
    let isRedConfirmed: Bool

    /// Spec §3.2: shown for every Yellow and Red item.
    private var whatYouLose: String? {
        guard item.effectiveTier == .yellow || item.effectiveTier == .red, !item.rule.whatYouLose.isEmpty else { return nil }
        return item.rule.whatYouLose
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            ActTierTag(tier: item.effectiveTier)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.target.displayName)
                    .font(.body)
                Text(item.rule.title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(ActCopy.displayPath(item.target.path))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                Text(ActCopy.actionDescription(item.action))
                    .font(.caption)
                    .foregroundStyle(item.isRestorable ? Color.secondary : Color.red)
                    .fixedSize(horizontal: false, vertical: true)
                if let lose = whatYouLose {
                    Text("What you lose: \(lose)")
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if item.requiresPerItemConfirmation {
                    Label(isRedConfirmed ? "Confirmed individually" : "Not confirmed individually",
                          systemImage: isRedConfirmed ? "checkmark.seal" : "exclamationmark.octagon")
                        .font(.caption)
                        .foregroundStyle(isRedConfirmed ? Color.secondary : Color.red)
                }
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                Text(ByteFormatter.format(item.target.reclaimableBytes))
                    .font(.body.monospacedDigit())
                Text("\(ByteFormatter.format(item.target.allocatedBytes)) on disk")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(item.effectiveTier.displayName) tier. \(item.target.displayName), \(item.rule.title). "
                + "Estimated reclaimable \(ByteFormatter.format(item.target.reclaimableBytes)), "
                + "\(ByteFormatter.format(item.target.allocatedBytes)) on disk. \(ActCopy.actionDescription(item.action))"
                + (whatYouLose.map { " What you lose: \($0)" } ?? "")
        )
    }
}

// MARK: - Shared helpers (used by the review, progress, results, quarantine and advisory screens)

/// Tier badge: text + SF Symbol, never colour alone (spec §9.10).
struct ActTierTag: View {
    let tier: Tier

    private var tint: Color {
        switch tier {
        case .green: return .green
        case .yellow: return .orange
        case .red: return .red
        case .advisory: return .blue
        }
    }

    var body: some View {
        Label(tier.displayName, systemImage: tier.symbolName)
            .font(.caption.weight(.semibold))
            .labelStyle(.titleAndIcon)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundStyle(tint)
            .background(Capsule().fill(tint.opacity(0.14)))
            .overlay(Capsule().stroke(tint.opacity(0.4), lineWidth: 0.5))
            .fixedSize()
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Tier: \(tier.displayName)")
    }
}

/// A banner with an icon, a title and a message. The style changes the icon tint and border only;
/// the meaning is always carried by the text.
struct ActNoticeBanner: View {
    enum Style { case info, warning, error, success }

    let symbol: String
    let title: String
    let message: String
    let style: Style

    private var tint: Color {
        switch style {
        case .info: return .blue
        case .warning: return .orange
        case .error: return .red
        case .success: return .green
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.headline)
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(tint.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(tint.opacity(0.35), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
    }
}

/// Plain-language text shared by the action screens.
enum ActCopy {
    /// `~`-abbreviated path for display (non-paths, e.g. advisory labels, are returned unchanged).
    static func displayPath(_ path: String) -> String {
        guard path.hasPrefix("/") else { return path }
        return (path as NSString).abbreviatingWithTildeInPath
    }

    static func lastComponent(_ path: String) -> String {
        let name = (path as NSString).lastPathComponent
        return name.isEmpty ? path : name
    }

    /// Human name of a vendor tool, used in "This cannot be undone. <tool> will re-download what it needs."
    static func toolName(_ spec: CommandSpec) -> String {
        let tool = (spec.tool as NSString).lastPathComponent
        switch tool {
        case "xcrun": return "Xcode"
        case "brew": return "Homebrew"
        case "docker": return "Docker"
        case "ollama": return "Ollama"
        case "pod": return "CocoaPods"
        case "flutter": return "Flutter"
        case "avdmanager": return "Android SDK"
        case "go": return "Go"
        default: return tool
        }
    }

    static func retentionText(hours: Int) -> String {
        if hours % 24 == 0 {
            let days = hours / 24
            return days == 1 ? "24 hours" : "\(days) days"
        }
        return hours == 1 ? "1 hour" : "\(hours) hours"
    }

    static func actionDescription(_ action: PlannedAction) -> String {
        switch action {
        case .quarantine(let hours):
            return "Moved to Quarantine — restorable for \(retentionText(hours: hours))."
        case .trash:
            return "Moved to the Finder Trash — restorable from the Trash."
        case .command(let spec, _):
            return "Runs \(toolName(spec))'s own cleanup command — cannot be undone."
        case .permanentDelete:
            return "Deleted permanently in one step — cannot be undone."
        case .bootoutAndTrash:
            return "Launch agent is unloaded, then its file is moved to the Trash — the unload cannot be undone."
        case .advisory:
            return "Information only — iMop never acts on this."
        }
    }

    static func irreversibleWarning(for action: PlannedAction) -> String {
        switch action {
        case .command(let spec, _):
            return "This cannot be undone. \(toolName(spec)) will re-download what it needs."
        case .permanentDelete:
            return "This cannot be undone. The item is deleted immediately, without Quarantine."
        case .bootoutAndTrash:
            return "This cannot be undone. The launch agent is unloaded now; putting its file back from the Trash does not load it again."
        case .quarantine, .trash, .advisory:
            return "This cannot be undone."
        }
    }

    static func itemName(_ id: UUID, plan: CleanupPlan?) -> String {
        if let item = plan?.items.first(where: { $0.id == id }) { return "“\(item.target.displayName)”" }
        return "An item"
    }

    /// `ConfirmationError` in plain language.
    static func confirmationMessage(_ error: ConfirmationError, plan: CleanupPlan?) -> String {
        switch error {
        case .emptySelection:
            return "Nothing is selected. Select at least one item, then review again."
        case .unknownItem:
            return "An item you selected is no longer part of the current scan results. Scan again, then review."
        case .notActionable(let id):
            return "\(itemName(id, plan: plan)) can't be cleaned — it was blocked for safety or is information only. Deselect it and review again."
        case .missingPerItemConfirmation(let id):
            return "\(itemName(id, plan: plan)) is a Caution item and must be confirmed on its own. Deselect it, then select it again and confirm it."
        case .irreversibleNotAcknowledged:
            return "Some selected actions cannot be undone. Tick the acknowledgement box to continue."
        case .permanentDeleteBlockedByAlwaysQuarantine(let id):
            return "\(itemName(id, plan: plan)) would be deleted permanently, but Settings › Always quarantine is on. Deselect it, or turn the setting off and scan again."
        case .confirmedTooQuickly:
            return "Clean was pressed too soon after the summary appeared. Take a moment to read it, then click Clean again."
        }
    }

    static func genericErrorMessage(_ error: any Error) -> String {
        AppState.message(for: error)
    }

    static func errorCategoryText(_ category: ErrorCategory) -> String {
        switch category {
        case .permissionDenied: return "Permission denied"
        case .inUse: return "In use by another app"
        case .changedSinceScan: return "Changed since the scan"
        case .preconditionFailed(let name): return "Requirement not met (\(name))"
        case .safetyRejected(let reason): return "Skipped for safety: \(reason)"
        case .commandFailed(let code): return "Command failed (exit code \(code))"
        case .timeout: return "Timed out"
        case .crossVolume: return "On a different volume"
        case .mutationDisabled: return "Cleaning is disabled in this build"
        }
    }

    /// Short status text for one finished item.
    static func statusText(_ status: ItemStatus) -> String {
        switch status {
        case .quarantined: return "Moved to Quarantine"
        case .trashed: return "Moved to the Trash"
        case .commandSucceeded: return "Cleanup command finished"
        case .permanentlyRemoved: return "Deleted permanently"
        case .skipped: return "Skipped"
        case .failed(let category, _): return "Not cleaned — \(errorCategoryText(category))"
        }
    }

    /// The reason a skipped or failed item was not acted on (`nil` for successes).
    static func reasonText(_ status: ItemStatus) -> String? {
        switch status {
        case .skipped(let rejection): return "Skipped for safety: \(rejection.reason)"
        case .failed(let category, let message):
            let categoryText = errorCategoryText(category)
            return message.isEmpty || message == categoryText ? categoryText : "\(categoryText) — \(message)"
        case .quarantined, .trashed, .commandSucceeded, .permanentlyRemoved: return nil
        }
    }

    static func statusSymbol(_ status: ItemStatus) -> String {
        switch status {
        case .quarantined: return "archivebox"
        case .trashed: return "trash"
        case .commandSucceeded: return "terminal"
        case .permanentlyRemoved: return "xmark.bin"
        case .skipped: return "shield.lefthalf.filled"
        case .failed: return "exclamationmark.circle"
        }
    }
}
