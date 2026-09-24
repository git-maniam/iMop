import iMopCore
import SwiftUI

public struct ConfirmationModalView: View {
    @Environment(AppState.self) private var appState

    public init() {}

    public var body: some View {
        VStack(spacing: 20) {
            // Icon
            ZStack {
                Circle()
                    .fill(appState.isPermanentDeleteEnabled ? Color.red.opacity(0.12) : Color.blue.opacity(0.12))
                    .frame(width: 56, height: 56)

                Image(systemName: appState.isPermanentDeleteEnabled ? "exclamationmark.triangle.fill" : "trash.circle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(appState.isPermanentDeleteEnabled ? .red : .blue)
            }

            // Title & Subtitle
            VStack(spacing: 6) {
                Text(appState.isDryRunEnabled ? "Confirm Cleaning Simulation" : (appState.isPermanentDeleteEnabled ? "Confirm Permanent Deletion" : "Confirm Clean with iMop"))
                    .font(.system(size: 18, weight: .bold))

                Text(appState.isDryRunEnabled ? "This simulation will not delete or alter any files." : (appState.isPermanentDeleteEnabled ? "These files will be permanently erased and cannot be restored." : "Selected items will be moved to the macOS Trash, allowing you to restore them anytime if needed."))
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 340)
            }

            // Selected summary badge
            VStack(spacing: 8) {
                HStack {
                    Text("Selected to Clean:")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.secondary)

                    Spacer()

                    Text(ByteFormatter.format(appState.totalSelectedBytes))
                        .font(.system(size: 16, weight: .bold, design: .rounded))
                        .foregroundStyle(.primary)
                }

                HStack {
                    Text("Total Items:")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.secondary)

                    Spacer()

                    Text("\(appState.totalSelectedCount) files")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.primary.opacity(0.04))
            )

            // Category breakdown list
            VStack(alignment: .leading, spacing: 6) {
                ForEach(JunkCategoryType.allCases) { category in
                    let count = appState.selectedCount(for: category)
                    let size = appState.selectedBytes(for: category)
                    if count > 0 {
                        HStack(spacing: 8) {
                            Image(systemName: category.iconName)
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                            Text(category.rawValue)
                                .font(.system(size: 12))
                            Spacer()
                            Text(ByteFormatter.format(size))
                                .font(.system(size: 12, weight: .medium, design: .rounded))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding(.horizontal, 4)

            // Action Buttons
            HStack(spacing: 12) {
                Button("Cancel") {
                    appState.showConfirmationModal = false
                }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.bordered)
                .controlSize(.regular)

                Button {
                    appState.confirmAndExecuteCleaning()
                } label: {
                    Text(appState.isDryRunEnabled ? "Run Simulation" : "Start Cleaning")
                        .fontWeight(.semibold)
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(appState.isPermanentDeleteEnabled ? .red : .blue)
                .controlSize(.regular)
            }
        }
        .padding(24)
        .frame(width: 420)
    }
}
