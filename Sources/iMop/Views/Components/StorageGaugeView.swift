import iMopCore
import SwiftUI

public struct StorageGaugeView: View {
    public let usage: DiskUsage

    public init(usage: DiskUsage) {
        self.usage = usage
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Macintosh HD")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)

                Spacer()

                Text(ByteFormatter.format(usage.totalBytes))
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
            }

            // Segmented Progress Bar
            GeometryReader { geometry in
                let totalWidth = geometry.size.width
                let usedWidth = totalWidth * max(0, min(1, usage.usedPercentage))
                let recoverableWidth = totalWidth * max(0, min(1, usage.recoverablePercentage))

                ZStack(alignment: .leading) {
                    // Total Background Bar
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.primary.opacity(0.08))

                    // Used Disk Space
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [Color.blue.opacity(0.85), Color.purple.opacity(0.85)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .frame(width: max(0, usedWidth - recoverableWidth))

                    // Recoverable Disk Space (Glowing Green / Emerald)
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

            // Legend / Metrics
            HStack(spacing: 12) {
                HStack(spacing: 4) {
                    Circle()
                        .fill(Color.blue)
                        .frame(width: 7, height: 7)
                    Text("Used: \(ByteFormatter.format(max(0, usage.usedBytes - usage.recoverableBytes)))")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }

                if usage.recoverableBytes > 0 {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 7, height: 7)
                        Text("Cleanable: \(ByteFormatter.format(usage.recoverableBytes))")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(.green)
                    }
                }

                Spacer()

                HStack(spacing: 4) {
                    Circle()
                        .fill(Color.secondary.opacity(0.4))
                        .frame(width: 7, height: 7)
                    Text("Free: \(ByteFormatter.format(usage.freeBytes))")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
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
    }
}
