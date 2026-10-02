import iMopCore
import SwiftUI

/// Scan screen (spec §9.1): big pulsing Scan button, Cancel, live per-category progress, the path
/// being inspected, and the explicit read-only promise. Replaces v1.0's dashboard screen.
public struct ScanView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isPulsing = false

    public init() {}

    /// Exact wording of the read-only promise (spec §9.1).
    static let readOnlyNotice = AppState.scanReadOnlyNotice

    private let columns = [GridItem(.adaptive(minimum: 220, maximum: 320), spacing: 16)]

    public var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                hero

                if appState.phase != .idle {
                    categoryGrid
                } else {
                    introCards
                }
            }
            .padding(24)
        }
        .navigationTitle("Scan")
    }

    // MARK: - Hero

    private var hero: some View {
        VStack(spacing: 18) {
            switch appState.phase {
            case .idle:
                scanButton(title: "Scan", subtitle: "Find caches, build artifacts and leftovers you can safely reclaim.")
            case .scanning:
                scanningStatus
            case .scanned, .finished:
                scannedSummary
            case .executing:
                Label("Cleaning in progress…", systemImage: "hourglass")
                    .font(.title3.weight(.semibold))
            }

            readOnlyBadge
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .padding(.horizontal, 20)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                )
        )
    }

    private var readOnlyBadge: some View {
        Label(Self.readOnlyNotice, systemImage: "eye")
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func scanButton(title: String, subtitle: String) -> some View {
        VStack(spacing: 16) {
            Button {
                appState.startScan()
            } label: {
                ZStack {
                    Circle()
                        .fill(
                            RadialGradient(
                                colors: [Color.blue.opacity(0.35), Color.blue.opacity(0.0)],
                                center: .center,
                                startRadius: 40,
                                endRadius: 80
                            )
                        )
                        .frame(width: 140, height: 140)
                        .scaleEffect(isPulsing && !reduceMotion ? 1.15 : 0.95)
                        .opacity(isPulsing && !reduceMotion ? 0.8 : 0.4)
                        .animation(
                            reduceMotion ? nil : .easeInOut(duration: 1.8).repeatForever(autoreverses: true),
                            value: isPulsing
                        )

                    Circle()
                        .fill(
                            LinearGradient(colors: [Color.blue, Color.cyan], startPoint: .topLeading, endPoint: .bottomTrailing)
                        )
                        .frame(width: 96, height: 96)
                        .shadow(color: Color.blue.opacity(0.4), radius: 10, x: 0, y: 5)

                    Image(systemName: "sparkle.magnifyingglass")
                        .font(.system(size: 30, weight: .bold))
                        .foregroundStyle(.white)
                }
                .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .keyboardShortcut(.defaultAction)
            .disabled(appState.phase == .scanning || appState.phase == .executing)
            .accessibilityLabel(title)
            .accessibilityHint("Starts a read-only scan. Nothing is changed until you review and confirm.")
            .help("\(title) (⌘R)")
            .onAppear { isPulsing = true }

            VStack(spacing: 4) {
                Text(title)
                    .font(.title2.weight(.bold))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityHidden(true)
        }
    }

    private var scanningStatus: some View {
        VStack(spacing: 14) {
            ProgressView()
                .controlSize(.large)
                .accessibilityLabel("Scanning")

            Text("Scanning your Mac…")
                .font(.title3.weight(.bold))

            let finished = finishedCategoryCount
            Text("\(finished) of \(SidebarView.categoryOrder.count) categories finished · \(foundCount) found")
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)

            Group {
                if let path = appState.currentScanPath, !path.isEmpty {
                    Text(path)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .accessibilityLabel("Currently inspecting \(path)")
                } else {
                    Text("Preparing…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: 520)

            Button("Cancel Scan", role: .cancel) {
                appState.cancelScan()
            }
            .buttonStyle(.bordered)
            .keyboardShortcut(.cancelAction)
            .accessibilityHint("Stops the scan. Nothing has been changed.")
        }
    }

    private var scannedSummary: some View {
        let totals = SidebarView.categoryOrder.map { appState.totals(for: $0) }
        let count = totals.reduce(0) { $0 + $1.count }
        let reclaimable = totals.reduce(Int64(0)) { $0 + $1.reclaimable }
        let allocated = totals.reduce(Int64(0)) { $0 + $1.allocated }

        return VStack(spacing: 18) {
            HStack(alignment: .top, spacing: 28) {
                VStack(alignment: .leading, spacing: 6) {
                    Label(appState.phase == .finished ? "Cleanup finished" : "Scan complete",
                          systemImage: "checkmark.circle")
                        .font(.title3.weight(.bold))

                    Text(appState.phase == .finished
                         ? "Before the cleanup: estimated reclaimable \(ByteFormatter.format(reclaimable)) (\(ByteFormatter.format(allocated)) on disk)"
                         : "Estimated reclaimable: \(ByteFormatter.format(reclaimable)) (\(ByteFormatter.format(allocated)) on disk)")
                        .font(.title3.weight(.semibold).monospacedDigit())
                        .fixedSize(horizontal: false, vertical: true)

                    Text("\(count) items found · \(appState.selectedItems.count) selected (\(ByteFormatter.format(appState.selectedReclaimableBytes)))")
                        .font(.callout)
                        .foregroundStyle(.secondary)

                    Text(appState.phase == .finished
                         ? "These figures describe the scan before the cleanup. Scan again to see what is left."
                         : "Only Safe items are preselected. Review each category before cleaning.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(spacing: 8) {
                    Button {
                        appState.startScan()
                    } label: {
                        Label("Scan Again", systemImage: "arrow.clockwise")
                    }
                    .controlSize(.large)
                    .accessibilityHint("Runs a new read-only scan and replaces the current results.")

                    if appState.phase == .finished {
                        Button {
                            appState.destination = .results
                        } label: {
                            Label("View Results", systemImage: "checkmark.seal")
                        }
                    }
                }
            }
        }
    }

    // MARK: - Categories

    private var categoryGrid: some View {
        let locked = appState.ruleStatusesLocked()
        let isScanning = appState.phase == .scanning

        return VStack(alignment: .leading, spacing: 12) {
            Text(isScanning ? "Progress by category" : "Categories")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)

            LazyVGrid(columns: columns, spacing: 16) {
                ForEach(SidebarView.categoryOrder, id: \.self) { category in
                    let totals = appState.totals(for: category)
                    CategoryCardView(
                        category: category,
                        itemsCount: totals.count,
                        reclaimableBytes: totals.reclaimable,
                        allocatedBytes: totals.allocated,
                        selectedCount: totals.selectedCount,
                        selectedBytes: totals.selectedReclaimable,
                        progress: appState.categoryProgress[category],
                        isScanning: isScanning,
                        lockedRuleCount: locked.filter { $0.category == category }.count,
                        isPreClean: appState.phase == .finished
                    ) {
                        appState.destination = .category(category)
                    }
                }
            }

            if !locked.isEmpty && !isScanning {
                Button {
                    appState.destination = .permissions
                } label: {
                    Label("\(locked.count) rule(s) locked — needs Full Disk Access", systemImage: "lock")
                }
                .buttonStyle(.link)
                .accessibilityHint("Opens the Permissions screen")
            }
        }
    }

    private var introCards: some View {
        LazyVGrid(columns: columns, spacing: 16) {
            introCard(symbol: "eye", title: "Read-only scan",
                      text: "iMop looks for caches, build artifacts and leftovers. It does not change anything while scanning.")
            introCard(symbol: "list.bullet.rectangle", title: "You review everything",
                      text: "Each item shows where it is, how big it is, what you lose and how it comes back.")
            introCard(symbol: "arrow.uturn.backward.circle", title: "Recoverable by default",
                      text: "Most items are moved to iMop's Quarantine first, so you can restore them during the retention period.")
        }
    }

    private func introCard(symbol: String, title: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(.blue)
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                )
        )
        .accessibilityElement(children: .combine)
    }

    // MARK: - Progress helpers

    private var finishedCategoryCount: Int {
        SidebarView.categoryOrder.filter { appState.categoryProgress[$0]?.finished == true }.count
    }

    private var foundCount: Int {
        appState.categoryProgress.values.reduce(0) { $0 + $1.targetsFound }
    }
}
