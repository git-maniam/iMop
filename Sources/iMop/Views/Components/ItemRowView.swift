import iMopCore
import SwiftUI

/// One row of the category list (spec §9.2): tier badge (text + symbol), title, path / owner,
/// "Estimated reclaimable X (Y on disk)", item count, checkbox defaulting per tier, and the skip
/// reason for blocked items. Pure presentation: no file-system access (spec M8 — the v1.0 row read
/// file icons from disk on the main thread; this one uses SF Symbols only).
public struct ItemRowView: View {
    public let item: PlanItem
    public let isSelected: Bool
    /// `false` outside the scanned phase (e.g. after a cleanup, when the list shows the pre-clean
    /// plan): the checkbox and the VoiceOver action are disabled instead of silently doing nothing.
    public let canToggle: Bool
    public let onToggle: () -> Void

    public init(item: PlanItem, isSelected: Bool, canToggle: Bool = true, onToggle: @escaping () -> Void) {
        self.item = item
        self.isSelected = isSelected
        self.canToggle = canToggle
        self.onToggle = onToggle
    }

    private var toggleEnabled: Bool { canToggle && item.isActionable }

    public var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Toggle(isOn: Binding(get: { isSelected }, set: { _ in onToggle() })) {
                EmptyView()
            }
            .toggleStyle(.checkbox)
            .labelsHidden()
            .disabled(!toggleEnabled)
            .accessibilityLabel(BrowseItemText.checkboxLabel(item: item, isSelected: isSelected))
            .accessibilityHint(canToggle ? BrowseItemText.checkboxHint(item: item) : BrowseItemText.staleHint)
            .help(canToggle ? BrowseItemText.checkboxHint(item: item) : BrowseItemText.staleHint)

            Image(systemName: BrowseItemText.symbol(for: item))
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(minWidth: 22)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    TierBadge(tier: item.effectiveTier, compact: true)
                    Text(item.target.displayName)
                        .font(.body.weight(.medium))
                        .foregroundStyle(item.isActionable ? .primary : .secondary)
                        .lineLimit(2)
                }

                Text(BrowseItemText.subtitle(for: item))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                if let reason = item.skipReason, !item.action.isAdvisory {
                    Label {
                        Text("Skipped for safety: \(reason)")
                    } icon: {
                        Image(systemName: "nosign")
                    }
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                } else if item.isActionable, BrowseItemText.isEmptyTrash(item) {
                    Label("Part of Empty Trash — all items in the Trash are selected together after a confirmation",
                          systemImage: "trash")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if item.isActionable, item.requiresPerItemConfirmation {
                    Label("Asks for confirmation of this item before it is selected", systemImage: "hand.raised")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if item.isActionable, !item.isRestorable {
                    Label("Cannot be undone", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 3) {
                Text(ByteFormatter.format(item.target.reclaimableBytes))
                    .font(.body.weight(.semibold).monospacedDigit())
                    .foregroundStyle(.primary)
                Text("(\(ByteFormatter.format(item.target.allocatedBytes)) on disk)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                Text(BrowseItemText.itemCount(item.target.itemCount))
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .multilineTextAlignment(.trailing)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel(BrowseItemText.rowAccessibilityLabel(item: item, isSelected: isSelected))
        .accessibilityAddTraits(isSelected ? [.isSelected] : [])
        .accessibilityActions {
            if toggleEnabled {
                Button(isSelected ? "Deselect" : "Select") { onToggle() }
            }
        }
    }
}

// MARK: - Shared item texts (browse screens)

/// User-facing texts derived from a `PlanItem`, shared by the row and the detail view.
enum BrowseItemText {
    static let staleHint = "These results are from before the cleanup. Scan again to select items."

    static func isEmptyTrash(_ item: PlanItem) -> Bool {
        item.rule.id == AppState.emptyTrashRuleID
    }

    static func symbol(for item: PlanItem) -> String {
        switch item.target.kind {
        case .filesystem: return "folder"
        case .commandItem: return "terminal"
        case .advisory: return "info.circle"
        }
    }

    static func subtitle(for item: PlanItem) -> String {
        var parts: [String] = []
        if !item.target.path.isEmpty { parts.append(abbreviated(item.target.path)) }
        if let owner = item.target.owningBundleID, !owner.isEmpty { parts.append(owner) }
        if parts.isEmpty { parts.append(item.rule.title) }
        return parts.joined(separator: " · ")
    }

    /// `~`-abbreviated path for compact display (the detail view always shows the full path).
    static func abbreviated(_ path: String) -> String {
        (path as NSString).abbreviatingWithTildeInPath
    }

    static func itemCount(_ count: Int) -> String {
        count == 1 ? "1 item" : "\(count.formatted()) items"
    }

    /// Spec §7.1: "Estimated reclaimable: X (Y on disk)".
    static func sizeSummary(_ item: PlanItem) -> String {
        "\(ByteFormatter.format(item.target.reclaimableBytes)) (\(ByteFormatter.format(item.target.allocatedBytes)) on disk)"
    }

    static func toolName(_ spec: CommandSpec) -> String {
        let name = (spec.tool as NSString).lastPathComponent
        return name.isEmpty ? spec.tool : name
    }

    static func retentionText(hours: Int) -> String {
        if hours >= 48, hours % 24 == 0 { return "\(hours / 24) days" }
        return hours == 1 ? "1 hour" : "\(hours) hours"
    }

    /// What iMop will do with the item, in plain words.
    static func actionDescription(_ item: PlanItem) -> String {
        switch item.action {
        case .quarantine(let hours):
            return "Moved to iMop's Quarantine and kept for \(retentionText(hours: hours)) — you can restore it until then."
        case .trash:
            return "Moved to the Finder Trash (one item at a time). You can put it back from the Trash; iMop never empties the Trash on its own."
        case .command(let spec, let argument):
            let args = spec.resolvedArguments(item: argument).joined(separator: " ")
            return "Runs “\(toolName(spec)) \(args)”. This cannot be undone. \(toolName(spec)) will re-download what it needs."
        case .permanentDelete:
            return "Permanently deleted in one step — this cannot be undone. Not available while “Always quarantine” is on."
        case .advisory:
            return "Explanation only — iMop never cleans this item."
        case .bootoutAndTrash:
            return "Unloads the background agent, then moves its file to the Finder Trash. Unloading cannot be undone."
        }
    }

    static func actionShortName(_ action: PlannedAction) -> String {
        switch action {
        case .quarantine: return "Quarantine"
        case .trash: return "Move to Trash"
        case .command: return "Vendor command"
        case .permanentDelete: return "Permanent delete"
        case .advisory: return "Advisory"
        case .bootoutAndTrash: return "Unload & move to Trash"
        }
    }

    static func checkboxLabel(item: PlanItem, isSelected: Bool) -> String {
        "\(isSelected ? "Selected" : "Not selected"): \(item.target.displayName), \(item.effectiveTier.displayName) tier"
    }

    static func checkboxHint(item: PlanItem) -> String {
        if !item.isActionable {
            return item.skipReason.map { "Cannot be selected: \($0)" } ?? "Cannot be selected"
        }
        if isEmptyTrash(item) {
            return "Part of Empty Trash: selecting it asks you to confirm emptying the whole Trash (permanent)."
        }
        if item.requiresPerItemConfirmation {
            return "Caution item: selecting it asks you to confirm this item by name and size."
        }
        return "Include this item in the cleanup plan."
    }

    static func rowAccessibilityLabel(item: PlanItem, isSelected: Bool) -> String {
        var parts = [
            item.target.displayName,
            TierBadge.accessibilityText(for: item.effectiveTier),
            "Estimated reclaimable \(sizeSummary(item))",
            itemCount(item.target.itemCount)
        ]
        if !item.target.path.isEmpty { parts.append(abbreviated(item.target.path)) }
        if let reason = item.skipReason, !item.action.isAdvisory {
            parts.append("Skipped for safety: \(reason)")
        } else if item.isActionable {
            parts.append(isSelected ? "selected" : "not selected")
        }
        return parts.joined(separator: ", ")
    }
}
