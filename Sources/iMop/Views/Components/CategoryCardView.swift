import iMopCore
import SwiftUI

public struct CategoryCardView: View {
    public let category: JunkCategoryType
    public let itemsCount: Int
    public let totalBytes: Int64
    public let selectedBytes: Int64
    public let isSelected: Bool
    public let onSelectCategory: () -> Void
    public let onToggleAll: () -> Void

    @LocalState private var isHovered: Bool = false

    public init(
        category: JunkCategoryType,
        itemsCount: Int,
        totalBytes: Int64,
        selectedBytes: Int64,
        isSelected: Bool,
        onSelectCategory: @escaping () -> Void,
        onToggleAll: @escaping () -> Void
    ) {
        self.category = category
        self.itemsCount = itemsCount
        self.totalBytes = totalBytes
        self.selectedBytes = selectedBytes
        self.isSelected = isSelected
        self.onSelectCategory = onSelectCategory
        self.onToggleAll = onToggleAll
    }

    private var accentColor: Color {
        switch category {
        case .appRemnants: return .orange
        case .userCaches: return .blue
        case .systemLogs: return .indigo
        case .developer: return .cyan
        case .trashAndTemp: return .pink
        }
    }

    public var body: some View {
        Button(action: onSelectCategory) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top) {
                    // Category Icon with subtle gradient glow
                    ZStack {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(accentColor.opacity(0.18))
                            .frame(width: 40, height: 40)

                        Image(systemName: category.iconName)
                            .font(.system(size: 19, weight: .semibold))
                            .foregroundStyle(accentColor)
                    }

                    Spacer()

                    // Selection Checkbox Button
                    if itemsCount > 0 {
                        Button(action: onToggleAll) {
                            Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                                .font(.system(size: 18))
                                .foregroundStyle(isSelected ? accentColor : Color.secondary.opacity(0.4))
                        }
                        .buttonStyle(.plain)
                        .help(isSelected ? "Deselect category" : "Select category")
                    }
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(category.rawValue)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(.primary)

                    Text(category.subtitle)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 4)

                // Stats footer
                HStack {
                    if itemsCount > 0 {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ByteFormatter.format(totalBytes))
                                .font(.system(size: 15, weight: .bold, design: .rounded))
                                .foregroundStyle(.primary)

                            Text("\(itemsCount) items")
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Image(systemName: "chevron.right")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(.tertiary)
                    } else {
                        HStack(spacing: 5) {
                            Image(systemName: "checkmark")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundStyle(.green)
                            Text("Clean")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding(16)
            .frame(minHeight: 140)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .stroke(isHovered ? accentColor.opacity(0.4) : Color.primary.opacity(0.08), lineWidth: 1)
                    )
                    .shadow(color: isHovered ? accentColor.opacity(0.12) : Color.black.opacity(0.03), radius: 8, x: 0, y: 4)
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.18)) {
                isHovered = hovering
            }
        }
    }
}
