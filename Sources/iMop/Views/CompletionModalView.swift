import iMopCore
import SwiftUI

public struct CompletionModalView: View {
    @Environment(AppState.self) private var appState

    public init() {}

    public var body: some View {
        let result = appState.lastDeletionResult ?? DeletionResult(itemsDeleted: 0, bytesReclaimed: 0)

        VStack(spacing: 20) {
            // Animated Checkmark / Ring
            ZStack {
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [Color.green.opacity(0.2), Color.teal.opacity(0.1)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 76, height: 76)

                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(Color.green)
            }

            // Title & Reclaimed stats
            VStack(spacing: 6) {
                Text(result.isDryRun ? "Simulation Finished!" : "Cleaning Complete!")
                    .font(.system(size: 20, weight: .bold))

                let split = ByteFormatter.splitFormat(result.bytesReclaimed)
                HStack(alignment: .firstTextBaseline, spacing: 3) {
                    Text(split.value)
                        .font(.system(size: 34, weight: .heavy, design: .rounded))
                        .foregroundStyle(.primary)

                    Text(split.unit)
                        .font(.system(size: 18, weight: .bold, design: .rounded))
                        .foregroundStyle(.secondary)

                    Text(result.isDryRun ? "simulated" : "reclaimed")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 4)
                }

                Text("Safely processed \(result.itemsDeleted) items from your Mac.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }

            if !result.errors.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Skipped / Warnings (\(result.errors.count)):")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.orange)

                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(result.errors.prefix(5), id: \.self) { error in
                                Text(error)
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                    .frame(maxHeight: 60)
                }
                .padding(10)
                .background(Color.orange.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            Button {
                appState.dismissCompletionModal()
            } label: {
                Text("Done")
                    .fontWeight(.semibold)
                    .frame(minWidth: 100)
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .controlSize(.regular)
        }
        .padding(24)
        .frame(width: 380)
    }
}
