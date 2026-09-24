import SwiftUI

public struct MainView: View {
    @Environment(AppState.self) private var appState

    public init() {}

    public var body: some View {
        @Bindable var state = appState

        ZStack(alignment: .bottom) {
            NavigationSplitView {
                SidebarView()
            } detail: {
                Group {
                    if let category = appState.selectedCategory {
                        CategoryDetailView(category: category)
                    } else {
                        DashboardView()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .navigationSplitViewStyle(.balanced)

            // Floating Clean Action Bar (when items are selected and not in scanning/cleaning state)
            if appState.totalSelectedCount > 0 && appState.scanStatus == .scanned {
                floatingBottomBar
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .frame(minWidth: 980, minHeight: 640)
        .sheet(isPresented: $state.showConfirmationModal) {
            ConfirmationModalView()
        }
        .sheet(isPresented: $state.showCompletionModal) {
            CompletionModalView()
        }
    }

    // MARK: - Floating Bottom Clean Bar
    private var floatingBottomBar: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.system(size: 13))

                    Text("\(appState.totalSelectedCount) items selected")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)
                }

                Text(ByteFormatter.format(appState.totalSelectedBytes) + " ready to be reclaimed")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button("Clear Selection") {
                appState.deselectAllGlobal()
            }
            .buttonStyle(.borderless)
            .font(.system(size: 12))
            .foregroundStyle(.secondary)

            Button {
                appState.requestCleaning()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "sparkles")
                        .font(.system(size: 13, weight: .bold))
                    Text(appState.isDryRunEnabled ? "Simulate Clean" : "Clean with iMop")
                        .font(.system(size: 13, weight: .bold))
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .tint(appState.isDryRunEnabled ? .purple : .blue)
            .controlSize(.regular)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .background(
            Capsule()
                .fill(.regularMaterial)
                .shadow(color: Color.black.opacity(0.18), radius: 14, x: 0, y: 6)
                .overlay(
                    Capsule()
                        .stroke(Color.primary.opacity(0.1), lineWidth: 1)
                )
        )
        .padding(.horizontal, 28)
        .padding(.bottom, 20)
    }
}
