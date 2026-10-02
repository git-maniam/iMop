import iMopCore
import SwiftUI

// Spec §9.6: per-item status while the Executor runs; skipped items show their reason. Cancel is
// honoured between items only (spec §5.4). Named ExecutionProgressView to avoid SwiftUI.ProgressView.

struct ExecutionProgressView: View {
    @Environment(AppState.self) private var appState
    @LocalState private var cancelRequested = false

    init() {}

    private var isRunning: Bool { appState.phase == .executing }

    private var finishedIDs: Set<UUID> { Set(appState.executionOutcomes.map(\.id)) }

    /// The confirmed items not finished yet, in the order the Executor works in.
    /// Review M7: listed from the confirmed run (`confirmedItemIDs`), never from the live selection.
    private var pendingItems: [PlanItem] {
        let done = finishedIDs
        let byID = planItemsByID
        return appState.confirmedItemIDs.filter { !done.contains($0) }.compactMap { byID[$0] }
    }

    private var planItemsByID: [UUID: PlanItem] {
        var map: [UUID: PlanItem] = [:]
        for item in appState.plan?.items ?? [] where map[item.id] == nil { map[item.id] = item }
        return map
    }

    /// The Executor reports the item it is working on; before the first report, nothing is marked.
    private func isCurrent(_ item: PlanItem) -> Bool {
        appState.executingItemID == item.id
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header

            if !AppState.isMutationEnabledInBuild {
                ActNoticeBanner(symbol: "eye", title: "Dry-run build — cleaning disabled",
                                message: "Nothing is being changed; each item is reported as it would have been handled.",
                                style: .info)
            }

            if !appState.exclusionsAddedDuringExecution.isEmpty {
                ActNoticeBanner(symbol: "nosign", title: "Exclusion added during the cleanup",
                                message: AppState.exclusionDuringRunNotice + " "
                                    + appState.exclusionsAddedDuringExecution.map(ActCopy.displayPath).joined(separator: ", "),
                                style: .info)
            }

            List {
                Section("Done (\(appState.executionOutcomes.count))") {
                    if appState.executionOutcomes.isEmpty {
                        Text("No items finished yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(appState.executionOutcomes) { outcome in
                        OutcomeRow(outcome: outcome, item: planItemsByID[outcome.id])
                    }
                }
                if isRunning && !pendingItems.isEmpty {
                    Section("Up next (\(pendingItems.count))") {
                        ForEach(pendingItems) { item in
                            PendingRow(item: item, isCurrent: isCurrent(item))
                        }
                    }
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: true))
            .frame(minHeight: 200)

            footer
        }
        .padding(24)
        .onChange(of: appState.phase) { _, phase in
            if phase != .executing { cancelRequested = false }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(isRunning ? (cancelRequested ? "Stopping after the current item…" : "Cleaning…") : "Cleanup finished")
                .font(.title2.weight(.bold))
            let done = appState.executionOutcomes.count
            let total = max(appState.executionTotal, done)
            ProgressView(value: Double(done), total: Double(max(total, 1)))
                .accessibilityLabel("Cleaning progress")
                .accessibilityValue("\(done) of \(total) items finished")
            Text("\(done) of \(total) item\(total == 1 ? "" : "s") finished")
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        HStack(alignment: .center, spacing: 12) {
            Text("Cancel stops after the current item — an item is never interrupted halfway.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button(cancelRequested ? "Stopping…" : "Cancel") {
                cancelRequested = true
                appState.cancelExecution()
            }
            .keyboardShortcut(.cancelAction)
            .disabled(!isRunning || cancelRequested)
            .accessibilityHint("Stops cleaning after the item in progress finishes.")
        }
    }
}

// MARK: - Rows

private struct OutcomeRow: View {
    let outcome: ItemOutcome
    let item: PlanItem?

    private var title: String { item?.target.displayName ?? ActCopy.lastComponent(outcome.path) }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: outcome.status.succeeded ? "checkmark.circle" : ActCopy.statusSymbol(outcome.status))
                .foregroundStyle(outcome.status.succeeded ? Color.green : Color.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(title).font(.body)
                    if let tier = item?.effectiveTier { ActTierTag(tier: tier) }
                }
                Text(ActCopy.statusText(outcome.status))
                    .font(.callout)
                if let reason = ActCopy.reasonText(outcome.status) {
                    Text(reason)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 8)
            Text(ByteFormatter.format(outcome.estimatedBytes))
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(title)\(item.map { ", \($0.effectiveTier.displayName) tier" } ?? ""). \(ActCopy.statusText(outcome.status)). "
                + (ActCopy.reasonText(outcome.status) ?? "") + " Estimated \(ByteFormatter.format(outcome.estimatedBytes))."
        )
    }
}

private struct PendingRow: View {
    let item: PlanItem
    let isCurrent: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            if isCurrent {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityHidden(true)
            } else {
                Image(systemName: "clock")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(item.target.displayName)
                    ActTierTag(tier: item.effectiveTier)
                }
                Text(isCurrent ? "In progress" : "Waiting")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Text(ByteFormatter.format(item.target.reclaimableBytes))
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(item.target.displayName), \(item.effectiveTier.displayName) tier. \(isCurrent ? "In progress" : "Waiting").")
    }
}
