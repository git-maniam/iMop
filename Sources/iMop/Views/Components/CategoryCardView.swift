import iMopCore
import SwiftUI

/// Category summary card shown on the Scan screen (v1.0 card language): live progress while
/// scanning, then reclaimable size, item count and selection after the scan. Navigation only — it
/// never changes the selection.
public struct CategoryCardView: View {
    public let category: RuleCategory
    public let itemsCount: Int
    public let reclaimableBytes: Int64
    public let allocatedBytes: Int64
    public let selectedCount: Int
    public let selectedBytes: Int64
    public let progress: CategoryProgress?
    public let isScanning: Bool
    public let lockedRuleCount: Int
    /// `true` after a cleanup: the figures describe the plan from before it (review M7).
    public let isPreClean: Bool
    public let onSelectCategory: () -> Void

    @State private var isHovered = false

    public init(
        category: RuleCategory,
        itemsCount: Int,
        reclaimableBytes: Int64,
        allocatedBytes: Int64,
        selectedCount: Int,
        selectedBytes: Int64,
        progress: CategoryProgress?,
        isScanning: Bool,
        lockedRuleCount: Int,
        isPreClean: Bool = false,
        onSelectCategory: @escaping () -> Void
    ) {
        self.category = category
        self.itemsCount = itemsCount
        self.reclaimableBytes = reclaimableBytes
        self.allocatedBytes = allocatedBytes
        self.selectedCount = selectedCount
        self.selectedBytes = selectedBytes
        self.progress = progress
        self.isScanning = isScanning
        self.lockedRuleCount = lockedRuleCount
        self.isPreClean = isPreClean
        self.onSelectCategory = onSelectCategory
    }

    public static func accentColor(for category: RuleCategory) -> Color {
        switch category {
        case .developer: return .cyan
        case .browsers: return .blue
        case .apps: return .indigo
        case .system: return .purple
        case .media: return .pink
        case .ai: return .teal
        case .downloads: return .mint
        case .leftovers: return .orange
        }
    }

    private var accent: Color { Self.accentColor(for: category) }

    public var body: some View {
        Button(action: onSelectCategory) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(accent.opacity(0.18))
                            .frame(width: 40, height: 40)
                        Image(systemName: category.symbolName)
                            .font(.title3.weight(.semibold))
                            .foregroundStyle(accent)
                    }
                    .accessibilityHidden(true)

                    Spacer()

                    statusIndicator
                }

                Text(category.displayName)
                    .font(.headline)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 0)

                footer
            }
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: 130, alignment: .topLeading)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .stroke(isHovered ? accent.opacity(0.4) : Color.primary.opacity(0.08), lineWidth: 1)
                    )
                    .shadow(color: isHovered ? accent.opacity(0.12) : Color.black.opacity(0.03), radius: 8, x: 0, y: 4)
            )
            .contentShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.18)) { isHovered = hovering }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilitySummary)
        .accessibilityHint("Shows the items found in \(category.displayName)")
        .accessibilityAddTraits(.isButton)
    }

    @ViewBuilder
    private var statusIndicator: some View {
        if isScanning {
            if progress?.finished == true {
                Image(systemName: "checkmark.circle")
                    .foregroundStyle(.secondary)
                    .help("Finished")
            } else {
                ProgressView()
                    .controlSize(.small)
                    .help("Scanning…")
            }
        } else if lockedRuleCount > 0 {
            Image(systemName: "lock")
                .foregroundStyle(.secondary)
                .help("\(lockedRuleCount) rule(s) locked — needs Full Disk Access")
        }
    }

    @ViewBuilder
    private var footer: some View {
        if isScanning {
            let found = progress?.targetsFound ?? 0
            let bytes = progress?.bytesFound ?? 0
            VStack(alignment: .leading, spacing: 2) {
                Text(ByteFormatter.format(bytes))
                    .font(.title3.weight(.bold).monospacedDigit())
                Text(progress?.finished == true ? "\(found) found" : "\(found) found so far…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } else if itemsCount > 0 {
            HStack(alignment: .bottom) {
                VStack(alignment: .leading, spacing: 2) {
                    if isPreClean {
                        Text("Before the cleanup")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                    }
                    Text(ByteFormatter.format(reclaimableBytes))
                        .font(.title3.weight(.bold).monospacedDigit())
                    Text("\(ByteFormatter.format(allocatedBytes)) on disk · \(itemsCount) items")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if selectedCount > 0 {
                        Text("\(selectedCount) selected (\(ByteFormatter.format(selectedBytes)))")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
        } else {
            Label(lockedRuleCount > 0 ? "Nothing found (some rules locked)" : "Nothing found",
                  systemImage: "checkmark")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
        }
    }

    private var accessibilitySummary: String {
        var parts = [category.displayName]
        if isScanning {
            let found = progress?.targetsFound ?? 0
            parts.append(progress?.finished == true ? "scan finished" : "scanning")
            parts.append("\(found) found, \(ByteFormatter.format(progress?.bytesFound ?? 0))")
        } else if itemsCount > 0 {
            if isPreClean { parts.append("before the cleanup") }
            parts.append("\(itemsCount) items")
            parts.append("estimated reclaimable \(ByteFormatter.format(reclaimableBytes)), \(ByteFormatter.format(allocatedBytes)) on disk")
            if selectedCount > 0 { parts.append("\(selectedCount) selected") }
        } else {
            parts.append("nothing found")
        }
        if lockedRuleCount > 0 { parts.append("\(lockedRuleCount) rules locked, needs Full Disk Access") }
        return parts.joined(separator: ", ")
    }
}
