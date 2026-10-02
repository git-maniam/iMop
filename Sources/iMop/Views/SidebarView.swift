import iMopCore
import SwiftUI

/// Sidebar (v1.0 visual language): branding with app icon + "iMop" + v1.1 badge, disk gauge,
/// Full Disk Access card when not granted, and the destinations of spec §9.
public struct SidebarView: View {
    @Environment(AppState.self) private var appState

    public init() {}

    /// Spec §9.2 grouping order.
    static let categoryOrder: [RuleCategory] = AppState.categoryOrder

    public var body: some View {
        VStack(spacing: 0) {
            branding
                .padding(.horizontal, 16)
                .padding(.top, 16)
                .padding(.bottom, 12)

            StorageGaugeView(usage: appState.diskUsage)
                .padding(.horizontal, 12)
                .padding(.bottom, 12)

            if appState.permissions.fullDiskAccess != .granted {
                fullDiskAccessCard
                    .padding(.horizontal, 12)
                    .padding(.bottom, 10)
            }

            Divider()
                .padding(.horizontal, 12)

            destinationList
        }
        .frame(minWidth: 240, idealWidth: 260, maxWidth: 320)
        .background(.ultraThinMaterial)
    }

    // MARK: - Branding

    private var branding: some View {
        HStack(spacing: 10) {
            AppIconImage(size: 34)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(verbatim: "iMop")
                        .font(.title3.weight(.bold))
                        .foregroundStyle(.primary)

                    Text(verbatim: "v1.1")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background(Color.blue.opacity(0.12))
                        .clipShape(Capsule())
                        .foregroundStyle(.blue)
                        .accessibilityLabel("version 1.1")
                }

                Text("Smart macOS Storage Cleaner")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: - Full Disk Access card (spec §8)

    private var fullDiskAccessCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label {
                Text("Full Disk Access")
                    .font(.callout.weight(.semibold))
            } icon: {
                Image(systemName: "lock.shield")
                    .foregroundStyle(.orange)
            }

            Text("Some rules (for example Safari and Mail caches, app containers) are locked until iMop has Full Disk Access. iMop only reads to check — it never writes to probe.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                Button {
                    appState.openFullDiskAccessSettings()
                } label: {
                    Label("Open Settings", systemImage: "arrow.up.right")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .accessibilityHint("Opens System Settings, Privacy & Security, Full Disk Access")

                Button("Check Again") {
                    appState.refreshPermissions()
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .accessibilityHint("Checks the Full Disk Access permission again")
            }
            .padding(.top, 2)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.orange.opacity(0.08))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(Color.orange.opacity(0.2), lineWidth: 1)
                )
        )
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Full Disk Access not granted")
    }

    // MARK: - Destinations

    private var selectionBinding: Binding<SidebarDestination?> {
        Binding(
            get: { appState.destination },
            set: { newValue in
                if let newValue { appState.destination = newValue }
            }
        )
    }

    private var destinationList: some View {
        let lockedRules = appState.ruleStatusesLocked()
        let unavailableRules = appState.unavailableRules()
        // Review M7: after a cleanup the totals describe the pre-clean plan, so they are not shown.
        let isPreClean = appState.phase == .finished

        return List(selection: selectionBinding) {
            Section {
                row(title: "Scan", symbol: "sparkle.magnifyingglass", detail: scanRowDetail, count: nil, locked: 0)
                    .tag(SidebarDestination.scan)
            }

            Section("Categories") {
                ForEach(Self.categoryOrder, id: \.self) { category in
                    let totals = appState.totals(for: category)
                    let locked = lockedRules.filter { $0.category == category }.count
                    let unavailable = unavailableRules.filter { $0.rule.category == category }.count
                    row(
                        title: category.displayName,
                        symbol: category.symbolName,
                        detail: isPreClean ? nil : (totals.count > 0 ? ByteFormatter.format(totals.reclaimable) : nil),
                        count: isPreClean ? nil : (totals.count > 0 ? totals.count : nil),
                        locked: locked,
                        unavailable: unavailable,
                        selectedCount: totals.selectedCount
                    )
                    .tag(SidebarDestination.category(category))
                }
            }

            Section("Review & Recover") {
                let advisoryCount = appState.advisoryItems.count
                row(title: "Advisory", symbol: "info.circle",
                    detail: nil, count: advisoryCount > 0 ? advisoryCount : nil, locked: 0)
                    .tag(SidebarDestination.advisory)

                let quarantineCount = appState.quarantineSessions.count
                row(title: "Quarantine", symbol: "archivebox",
                    detail: nil, count: quarantineCount > 0 ? quarantineCount : nil, locked: 0,
                    countNoun: "sessions")
                    .tag(SidebarDestination.quarantine)

                row(title: "Permissions", symbol: "lock.shield",
                    detail: appState.permissions.fullDiskAccess == .granted ? nil : "Action needed",
                    count: nil, locked: lockedRules.count, unavailable: unavailableRules.count)
                    .tag(SidebarDestination.permissions)

                row(title: "Results", symbol: "checkmark.seal",
                    detail: nil, count: nil, locked: 0)
                    .tag(SidebarDestination.results)
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .accessibilityLabel("Destinations")
    }

    private var scanRowDetail: String? {
        switch appState.phase {
        case .scanning: return "Scanning…"
        case .executing: return "Cleaning…"
        default: return nil
        }
    }

    private func row(
        title: String,
        symbol: String,
        detail: String?,
        count: Int?,
        locked: Int,
        unavailable: Int = 0,
        selectedCount: Int = 0,
        countNoun: String = "items"
    ) -> some View {
        HStack(spacing: 8) {
            Label(title, systemImage: symbol)
                .lineLimit(1)

            Spacer(minLength: 4)

            if locked > 0 {
                Image(systemName: "lock")
                    .imageScale(.small)
                    .foregroundStyle(.secondary)
                    .help("\(locked) rule(s) locked — needs Full Disk Access")
                    .accessibilityHidden(true)
            }

            if unavailable > 0 {
                Image(systemName: "slash.circle")
                    .imageScale(.small)
                    .foregroundStyle(.secondary)
                    .help("\(unavailable) rule(s) not offered in this scan — see the reasons in the list")
                    .accessibilityHidden(true)
            }

            if let detail {
                Text(detail)
                    .font(.caption.weight(.medium).monospacedDigit())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            if let count {
                Text("\(count)")
                    .font(.caption2.weight(.semibold).monospacedDigit())
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Color.primary.opacity(0.08))
                    .clipShape(Capsule())
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(rowAccessibilityLabel(title: title, detail: detail, count: count, locked: locked,
                                                  unavailable: unavailable, selectedCount: selectedCount, countNoun: countNoun))
    }

    private func rowAccessibilityLabel(title: String, detail: String?, count: Int?, locked: Int,
                                       unavailable: Int, selectedCount: Int, countNoun: String) -> String {
        var parts = [title]
        if let count { parts.append("\(count) \(countNoun)") }
        if let detail { parts.append(count != nil ? "\(detail) estimated reclaimable" : detail) }
        if selectedCount > 0 { parts.append("\(selectedCount) selected") }
        if locked > 0 { parts.append("\(locked) rules locked, needs Full Disk Access") }
        if unavailable > 0 { parts.append("\(unavailable) rules not offered in this scan") }
        return parts.joined(separator: ", ")
    }
}
