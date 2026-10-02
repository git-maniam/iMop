import iMopCore
import SwiftUI

/// Item detail (spec §9.3): full path (selectable), Reveal in Finder, on-disk + reclaimable sizes,
/// last used, owning app, What it is / What you lose / How it comes back (the rule texts verbatim),
/// precondition status, skip reason and notes. Pure presentation of the scan-time `PlanItem`.
public struct ItemDetailView: View {
    public let item: PlanItem

    @Environment(AppState.self) private var appState

    public init(item: PlanItem) {
        self.item = item
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                titleBlock
                selectionBlock
                pathBlock
                factsBlock
                actionBlock
                explanationBlock
                preconditionsBlock
                notesBlock
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Blocks

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                TierBadge(tier: item.effectiveTier)
                if item.effectiveTier != item.rule.tier {
                    Text("Raised from \(item.rule.tier.displayName) for manual review")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text(item.target.displayName)
                .font(.title3.weight(.bold))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text(item.rule.title)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var selectionBlock: some View {
        if let reason = item.skipReason, !item.action.isAdvisory {
            callout(symbol: "nosign", title: "Skipped for safety", text: reason, tint: .orange)
        } else if item.action.isAdvisory {
            callout(symbol: "info.circle", title: "Advisory only",
                    text: "iMop explains this item but never cleans it.", tint: .blue)
        } else {
            let isSelected = appState.selection.contains(item.id)
            let canToggle = appState.phase == .scanned
            Toggle(isOn: Binding(get: { isSelected }, set: { _ in appState.requestToggle(item.id) })) {
                Text(BrowseItemText.isEmptyTrash(item)
                     ? "Include in cleanup (part of Empty Trash — asks you to confirm emptying the whole Trash)"
                     : item.requiresPerItemConfirmation
                     ? "Include in cleanup (asks you to confirm this item)"
                     : "Include in cleanup")
                    .fixedSize(horizontal: false, vertical: true)
            }
            .toggleStyle(.checkbox)
            // Review M7: only while the scan results are current (not after a cleanup).
            .disabled(!canToggle)
            .accessibilityLabel(BrowseItemText.checkboxLabel(item: item, isSelected: isSelected))
            .accessibilityHint(canToggle ? BrowseItemText.checkboxHint(item: item) : BrowseItemText.staleHint)
            if !canToggle && appState.phase == .finished {
                Text(BrowseItemText.staleHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var pathBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            sectionTitle("Location")
            Text(item.target.path.isEmpty ? "—" : item.target.path)
                .font(.callout.monospaced())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Full path: \(item.target.path)")
            if item.target.path.hasPrefix("/") {
                Button {
                    appState.revealInFinder(path: item.target.path)
                } label: {
                    Label("Reveal in Finder", systemImage: "folder")
                }
                .controlSize(.small)
                .accessibilityHint("Shows this item in Finder without changing it")
            }
        }
    }

    private var factsBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            sectionTitle("Size")
            fact("Estimated reclaimable", ByteFormatter.format(item.target.reclaimableBytes))
            fact("On disk", ByteFormatter.format(item.target.allocatedBytes))
            fact("Contents", BrowseItemText.itemCount(item.target.itemCount))
            fact("Last used", item.target.lastUsed.map { Self.dateFormatter.string(from: $0) } ?? "Unknown")
            if let owner = item.target.owningBundleID, !owner.isEmpty {
                fact("Owning app", owner)
            }
            if item.target.allocatedBytes > item.target.reclaimableBytes {
                Text("Reclaimable is lower than on-disk size when files are APFS clones or hard links shared with other places.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var actionBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            sectionTitle("What iMop will do")
            Label {
                Text(BrowseItemText.actionShortName(item.action))
                    .font(.callout.weight(.semibold))
            } icon: {
                Image(systemName: item.isRestorable ? "arrow.uturn.backward.circle" : "exclamationmark.triangle")
            }
            Text(BrowseItemText.actionDescription(item))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if case .permanentDelete = item.action, appState.settings.alwaysQuarantine {
                Text("“Always quarantine” is on in Settings, so this item cannot be cleaned in this run.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var explanationBlock: some View {
        VStack(alignment: .leading, spacing: 12) {
            textSection("What it is", item.rule.explanation, symbol: "questionmark.circle")
            textSection("What you lose", item.rule.whatYouLose, symbol: "minus.circle")
            textSection("How it comes back", item.rule.howItRegenerates, symbol: "arrow.clockwise.circle")
        }
    }

    @ViewBuilder
    private var preconditionsBlock: some View {
        if !item.preconditions.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                sectionTitle("Checks")
                ForEach(Array(item.preconditions.enumerated()), id: \.offset) { _, result in
                    Label {
                        Text(result.detail.isEmpty ? result.name : result.detail)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: result.passed ? "checkmark.circle" : "xmark.octagon")
                            .foregroundStyle(result.passed ? Color.green : Color.orange)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("\(result.passed ? "Passed" : "Not met"): \(result.detail.isEmpty ? result.name : result.detail)")
                }
                Text("Checks are evaluated again right before cleaning; an item that fails any check is skipped.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private var notesBlock: some View {
        if !item.target.notes.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                sectionTitle("Notes")
                ForEach(Array(item.target.notes.enumerated()), id: \.offset) { _, note in
                    Text("• \(note)")
                        .font(.callout)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: - Helpers

    private func sectionTitle(_ title: String) -> some View {
        Text(title)
            .font(.headline)
            .accessibilityAddTraits(.isHeader)
    }

    private func fact(_ label: String, _ value: String) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .firstTextBaseline) {
                Text(label).foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Text(value).monospacedDigit().textSelection(.enabled)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(label).foregroundStyle(.secondary)
                Text(value).monospacedDigit().textSelection(.enabled)
            }
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }

    private func textSection(_ title: String, _ text: String, symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: symbol)
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            // Rule texts are shown verbatim.
            Text(verbatim: text)
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func callout(symbol: String, title: String, text: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: symbol)
                .font(.callout.weight(.semibold))
                .foregroundStyle(tint)
            Text(verbatim: text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(tint.opacity(0.08)))
        .accessibilityElement(children: .combine)
    }
}
