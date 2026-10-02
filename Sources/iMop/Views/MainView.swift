import iMopCore
import SwiftUI

/// Main window: NavigationSplitView (sidebar + detail by destination), the floating bottom bar
/// "X items selected (Y reclaimable)" + "Review & Clean…", the dry-run banner, the review sheet and
/// the Red per-item confirmation dialog.
public struct MainView: View {
    @Environment(AppState.self) private var appState

    public init() {}

    public var body: some View {
        @Bindable var state = appState

        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 240, ideal: 260, max: 320)
        } detail: {
            VStack(spacing: 0) {
                banners
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            // Review M7: a safe-area inset (not an overlay), so every screen — lists, scroll views and
            // the item inspector — can scroll its last rows out from under the floating bar.
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if showsBottomBar {
                    floatingBottomBar
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.2), value: showsBottomBar)
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 980, minHeight: 640)
        // SAFETY-DECISION: however the sheet goes away (Cancel, Esc, programmatic dismissal), the
        // recorded review is discarded, so showing it again always restarts the 2-second wait.
        .sheet(isPresented: $state.showReview, onDismiss: { appState.cancelReview() }) {
            ReviewSheet()
                .environment(appState)
        }
        .redItemConfirmation(appState: appState)
        .emptyTrashConfirmation(appState: appState)
    }

    // MARK: - Detail routing

    @ViewBuilder
    private var detail: some View {
        if appState.phase == .executing {
            // While the Executor runs, its per-item progress replaces the detail column; Cancel is
            // honoured between items.
            ExecutionProgressView()
        } else {
            switch appState.destination {
            case .scan:
                ScanView()
            case .category(let category):
                CategoryListView(category: category)
                    .id(category)
            case .advisory:
                AdvisoryView()
            case .quarantine:
                QuarantineView()
            case .permissions:
                PermissionsView()
            case .results:
                ResultsView()
            }
        }
    }

    // MARK: - Banners

    @ViewBuilder
    private var banners: some View {
        if !AppState.isMutationEnabledInBuild {
            banner(symbol: "eye.slash",
                   text: "\(AppState.dryRunBannerText). iMop can scan and review, but nothing will be changed.",
                   tint: .purple)
        }
        if let notice = appState.settingsReviewNotice {
            // SAFETY-DECISION (review M7): stored settings could not be read completely; cleaning is
            // paused until the user has checked them in Settings and confirmed.
            banner(symbol: "exclamationmark.shield", text: notice, tint: .red) {
                SettingsLink {
                    Text("Open Settings…")
                }
                .controlSize(.small)
                .accessibilityHint("Opens iMop Settings, where you can check and confirm your settings")
            }
        }
        if appState.planIsOutdated {
            // SAFETY-DECISION: a plan built under different safety settings is never cleaned; the
            // Review button is disabled and the user is asked to scan again.
            banner(symbol: "arrow.clockwise", text: AppState.planOutdatedMessage, tint: .orange) {
                Button("Scan Again") { appState.startScan() }
                    .controlSize(.small)
                    .disabled(appState.phase == .scanning || appState.phase == .executing)
            }
        }
        if let error = appState.lastError, !error.isEmpty, error != AppState.planOutdatedMessage || !appState.planIsOutdated {
            banner(symbol: "exclamationmark.triangle", text: error, tint: .orange) {
                Button("Dismiss") { appState.clearError() }
                    .controlSize(.small)
                    .accessibilityLabel("Dismiss error")
            }
        }
    }

    private func banner(symbol: String, text: String, tint: Color) -> some View {
        banner(symbol: symbol, text: text, tint: tint) { EmptyView() }
    }

    private func banner<Accessory: View>(symbol: String, text: String, tint: Color,
                                         @ViewBuilder accessory: () -> Accessory) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(verbatim: text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            accessory()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.10))
        .overlay(alignment: .bottom) { Divider() }
        .accessibilityElement(children: .contain)
    }

    // MARK: - Floating bottom bar

    private var showsBottomBar: Bool {
        appState.phase == .scanned && !appState.selection.isEmpty
    }

    private var floatingBottomBar: some View {
        let count = appState.selectedItems.count
        let bytes = appState.selectedReclaimableBytes
        let summary = "\(count) \(count == 1 ? "item" : "items") selected (\(ByteFormatter.format(bytes)) reclaimable)"

        return HStack(spacing: 16) {
            Label {
                Text(verbatim: summary)
                    .font(.callout.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "checkmark.circle")
                    .foregroundStyle(.blue)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(summary)

            Spacer(minLength: 8)

            Button {
                appState.beginReview()
            } label: {
                Label("Review & Clean…", systemImage: "list.bullet.clipboard")
                    .font(.callout.weight(.bold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
            }
            .buttonStyle(.borderedProminent)
            .disabled(appState.planIsOutdated || appState.settingsReviewNotice != nil)
            .accessibilityHint(appState.planIsOutdated
                               ? AppState.planOutdatedMessage
                               : "Shows everything that will happen before anything is changed")
            .help("Review the plan before anything is changed")
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .background(
            Capsule()
                .fill(.regularMaterial)
                .shadow(color: Color.black.opacity(0.18), radius: 14, x: 0, y: 6)
                .overlay(Capsule().stroke(Color.primary.opacity(0.1), lineWidth: 1))
        )
        .padding(.horizontal, 28)
        .padding(.bottom, 20)
    }
}
