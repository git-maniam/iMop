import iMopCore
import SwiftUI

/// Tier badge (spec §9.2 / §9.10): always TEXT + SF Symbol, colour is only a secondary cue, so the
/// tier is never conveyed by colour alone.
public struct TierBadge: View {
    public let tier: Tier
    public var compact: Bool

    public init(tier: Tier, compact: Bool = false) {
        self.tier = tier
        self.compact = compact
    }

    public var body: some View {
        HStack(spacing: 4) {
            Image(systemName: tier.symbolName)
                .imageScale(.small)
            Text(tier.displayName)
                .lineLimit(1)
        }
        .font(compact ? .caption2.weight(.semibold) : .caption.weight(.semibold))
        .padding(.horizontal, compact ? 5 : 7)
        .padding(.vertical, compact ? 1.5 : 2.5)
        .foregroundStyle(TierBadge.color(for: tier))
        .background(
            Capsule(style: .continuous)
                .fill(TierBadge.color(for: tier).opacity(0.14))
        )
        .overlay(
            Capsule(style: .continuous)
                .stroke(TierBadge.color(for: tier).opacity(0.35), lineWidth: 0.5)
        )
        .fixedSize()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(TierBadge.accessibilityText(for: tier))
    }

    /// Secondary colour cue only; the text and symbol carry the meaning.
    public nonisolated static func color(for tier: Tier) -> Color {
        switch tier {
        case .green: return .green
        case .yellow: return .orange
        case .red: return .red
        case .advisory: return .blue
        }
    }

    /// Spoken tier text, e.g. "Safe tier (Green)".
    public nonisolated static func accessibilityText(for tier: Tier) -> String {
        let colourName: String
        switch tier {
        case .green: colourName = "Green"
        case .yellow: colourName = "Yellow"
        case .red: colourName = "Red"
        case .advisory: colourName = "Advisory"
        }
        return "\(tier.displayName) tier (\(colourName))"
    }
}
