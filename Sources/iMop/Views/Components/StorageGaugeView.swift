import iMopCore
import SwiftUI

/// Sidebar disk gauge (v1.0 visual language). Pure presentation: the `DiskUsage` value is measured
/// off the main thread by `AppState`; this view never touches the file system.
public struct StorageGaugeView: View {
    public let usage: DiskUsage

    public init(usage: DiskUsage) {
        self.usage = usage
    }

    private var hasData: Bool { usage.totalBytes > 0 }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Label("Startup Disk", systemImage: "internaldrive")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)

                Spacer(minLength: 4)

                Text(hasData ? ByteFormatter.format(usage.totalBytes) : "—")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
            }

            // Segmented bar (graphic only — the numbers below carry the information).
            GeometryReader { geometry in
                let totalWidth = geometry.size.width
                let usedFraction = max(0, min(1, usage.usedPercentage))
                let recoverableFraction = max(0, min(usedFraction, usage.recoverablePercentage))
                let usedWidth = totalWidth * usedFraction
                let recoverableWidth = totalWidth * recoverableFraction

                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.primary.opacity(0.08))

                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [Color.blue.opacity(0.85), Color.purple.opacity(0.85)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .frame(width: max(0, usedWidth - recoverableWidth))

                    if recoverableWidth > 0 {
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [Color.teal, Color.green],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(width: recoverableWidth)
                            .offset(x: max(0, usedWidth - recoverableWidth))
                    }
                }
            }
            .frame(height: 10)
            .accessibilityHidden(true)

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) { legendItems }
                VStack(alignment: .leading, spacing: 4) { legendItems }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                )
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilitySummary)
    }

    @ViewBuilder
    private var legendItems: some View {
        legend(color: .blue, text: "Used: \(hasData ? ByteFormatter.format(max(0, usage.usedBytes - usage.recoverableBytes)) : "—")")

        if usage.recoverableBytes > 0 {
            legend(color: .green, text: "Est. reclaimable: \(ByteFormatter.format(usage.recoverableBytes))", emphasised: true)
        }

        legend(color: Color.secondary.opacity(0.4), text: "Free: \(hasData ? ByteFormatter.format(usage.freeBytes) : "—")")
    }

    private func legend(color: Color, text: String, emphasised: Bool = false) -> some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
                .accessibilityHidden(true)
            Text(text)
                .font(emphasised ? .caption.weight(.medium) : .caption)
                .foregroundStyle(emphasised ? AnyShapeStyle(Color.green) : AnyShapeStyle(.secondary))
                .lineLimit(1)
        }
    }

    private var accessibilitySummary: String {
        guard hasData else { return "Startup disk usage not measured yet" }
        var parts = [
            "Startup disk, \(ByteFormatter.format(usage.totalBytes)) total",
            "\(ByteFormatter.format(usage.usedBytes)) used",
            "\(ByteFormatter.format(usage.freeBytes)) free"
        ]
        if usage.recoverableBytes > 0 {
            parts.append("\(ByteFormatter.format(usage.recoverableBytes)) estimated reclaimable")
        }
        return parts.joined(separator: ", ")
    }
}
