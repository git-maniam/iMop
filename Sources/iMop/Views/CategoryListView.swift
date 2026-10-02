import iMopCore
import SwiftUI

/// Category list (spec §9.2): one row per candidate with tier badge, title, path / owner,
/// "Estimated reclaimable X (Y on disk)", item count, checkbox defaulting per tier and skip reasons;
/// search + sort; context menu Reveal in Finder / Exclude from future scans; item detail in the
/// inspector. Replaces v1.0's category detail screen.
public struct CategoryListView: View {
    public let category: RuleCategory

    @Environment(AppState.self) private var appState
    @State private var searchText = ""
    @State private var sortOrder: SortOrder = .recommended
    @State private var showInspector = true

    public init(category: RuleCategory) {
        self.category = category
    }

    enum SortOrder: String, CaseIterable, Identifiable {
        case recommended = "Recommended"
        case reclaimable = "Reclaimable (largest)"
        case name = "Name (A–Z)"
        case tier = "Tier"
        case lastUsed = "Last used (oldest)"

        var id: String { rawValue }
    }

    public var body: some View {
        @Bindable var state = appState
        let allItems = appState.items(in: category)
        let visible = sorted(filtered(allItems))
        let locked = appState.ruleStatusesLocked().filter { $0.category == category }
        let unavailable = appState.unavailableRules().filter { $0.rule.category == category }
        let canToggle = appState.phase == .scanned

        VStack(spacing: 0) {
            header(allItems: allItems)

            Divider()

            if appState.phase == .finished && !allItems.isEmpty {
                // Review M7: after a cleanup the list still shows the plan it was built from.
                staleResultsBanner
                Divider()
            }

            controlBar(allItems: allItems)

            Divider()

            if allItems.isEmpty {
                emptyState(locked: locked, unavailable: unavailable)
            } else {
                List(selection: $state.selectedItemID) {
                    if !locked.isEmpty {
                        lockedSection(locked)
                    }
                    if !unavailable.isEmpty {
                        unavailableSection(unavailable)
                    }

                    Section {
                        if visible.isEmpty {
                            Text("No items match “\(searchText)”.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(visible) { item in
                            ItemRowView(item: item, isSelected: appState.selection.contains(item.id), canToggle: canToggle) {
                                appState.requestToggle(item.id)
                            }
                            .tag(item.id)
                            .contextMenu { contextMenu(for: item) }
                        }
                    } header: {
                        Text("\(visible.count) of \(allItems.count) items")
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
                // Keyboard: Space toggles the focused row's checkbox (same rules as clicking it).
                .onKeyPress(.space) {
                    guard let id = appState.selectedItemID,
                          allItems.contains(where: { $0.id == id }) else { return .ignored }
                    appState.requestToggle(id)
                    return .handled
                }
                .accessibilityLabel("\(category.displayName) items")
            }
        }
        .navigationTitle(category.displayName)
        .inspector(isPresented: $showInspector) {
            Group {
                if let id = appState.selectedItemID, let item = allItems.first(where: { $0.id == id }) {
                    ItemDetailView(item: item)
                } else {
                    ContentUnavailableView("No Item Selected",
                                           systemImage: "sidebar.right",
                                           description: Text("Select an item to see what it is, what you lose and how it comes back."))
                }
            }
            .inspectorColumnWidth(min: 280, ideal: 340, max: 520)
        }
        .toolbar {
            ToolbarItem {
                Button {
                    showInspector.toggle()
                } label: {
                    Label(showInspector ? "Hide Details" : "Show Details", systemImage: "sidebar.right")
                }
                .help(showInspector ? "Hide item details" : "Show item details")
            }
        }
    }

    // MARK: - Header

    private func header(allItems: [PlanItem]) -> some View {
        let totals = appState.totals(for: category)
        let accent = CategoryCardView.accentColor(for: category)

        return HStack(alignment: .top, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(accent.opacity(0.18))
                    .frame(width: 48, height: 48)
                Image(systemName: category.symbolName)
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(accent)
            }
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(category.displayName)
                    .font(.title2.weight(.bold))
                    .accessibilityAddTraits(.isHeader)
                Text("Estimated reclaimable: \(ByteFormatter.format(totals.reclaimable)) (\(ByteFormatter.format(totals.allocated)) on disk)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 4) {
                Text(ByteFormatter.format(totals.selectedReclaimable))
                    .font(.title2.weight(.bold).monospacedDigit())
                Text("\(totals.selectedCount) of \(totals.count) selected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("\(totals.selectedCount) of \(totals.count) items selected, \(ByteFormatter.format(totals.selectedReclaimable)) estimated reclaimable")
        }
        .padding(20)
        .background(.ultraThinMaterial)
    }

    // MARK: - Search / sort / bulk selection

    private func controlBar(allItems: [PlanItem]) -> some View {
        let hasRed = allItems.contains { $0.isActionable && $0.requiresPerItemConfirmation }
        let hasPermanent = allItems.contains {
            guard $0.isActionable else { return false }
            if case .permanentDelete = $0.action { return true }
            return false
        }
        let hasYellow = allItems.contains { $0.isActionable && $0.effectiveTier == .yellow }

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    TextField("Search items or paths", text: $searchText)
                        .textFieldStyle(.plain)
                        .accessibilityLabel("Search items or paths")
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Clear search")
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(Color.primary.opacity(0.05))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                .frame(maxWidth: 280)

                Spacer(minLength: 8)

                Picker("Sort", selection: $sortOrder) {
                    ForEach(SortOrder.allCases) { order in
                        Text(order.rawValue).tag(order)
                    }
                }
                .pickerStyle(.menu)
                .fixedSize()
                .accessibilityLabel("Sort items")

                Button("Select All") {
                    appState.setSelection(category: category, selected: true)
                }
                .disabled(allItems.isEmpty || appState.phase != .scanned)
                .help(hasRed ? "Selects every selectable item except Caution items, which you confirm one by one, and permanent deletions such as Empty Trash."
                             : "Selects every selectable item in this category except permanent deletions such as Empty Trash.")
                .accessibilityHint("Selects every selectable item in \(category.displayName). Caution items and permanent deletions are never selected in bulk.")

                Button("Deselect All") {
                    appState.setSelection(category: category, selected: false)
                }
                .disabled(allItems.isEmpty || appState.phase != .scanned)
                .accessibilityHint("Deselects every item in \(category.displayName)")
            }

            if hasRed {
                // SAFETY-DECISION: bulk selection never selects Red items (enforced in AppState);
                // say so here so the user is not surprised that they stay unchecked.
                Label("Caution items are never selected in bulk — select each one to confirm it by name and size.",
                      systemImage: "hand.raised")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if hasPermanent {
                Label("Permanent deletions (such as Empty Trash) are never selected in bulk — select them on their own.",
                      systemImage: "xmark.bin")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if hasYellow {
                // Spec §3.2: Yellow items show what you lose; the review asks you to confirm it per category.
                Label("Selected Yellow items cost time or downloads to get back — the review lists what you lose for each and asks you to confirm it.",
                      systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    // MARK: - Context menu

    @ViewBuilder
    private func contextMenu(for item: PlanItem) -> some View {
        let path = item.target.path
        let isRealPath = path.hasPrefix("/")
        Button {
            appState.revealInFinder(path: path)
        } label: {
            Label("Reveal in Finder", systemImage: "folder")
        }
        .disabled(!isRealPath)

        Divider()

        // Excluding only ever narrows what iMop may touch; it takes effect for the next scan.
        Button {
            appState.addExclusion(path: path)
        } label: {
            Label("Exclude from Future Scans", systemImage: "nosign")
        }
        .disabled(!isRealPath)
    }

    // MARK: - Locked rules / empty states

    private func lockedSection(_ locked: [Rule]) -> some View {
        Section {
            ForEach(locked, id: \.id) { rule in
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(rule.title)
                        Text("Locked — needs Full Disk Access")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "lock")
                }
                .accessibilityElement(children: .combine)
                .selectionDisabled()
            }
            Button("Full Disk Access Settings…") {
                appState.openFullDiskAccessSettings()
            }
            .buttonStyle(.link)
            .selectionDisabled()
        } header: {
            Text("Locked rules")
        }
    }

    private var staleResultsBanner: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "clock.arrow.circlepath")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("Results from before the cleanup — sizes may no longer be on disk. Scan again to see what is left.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button("Scan Again") { appState.startScan() }
                .controlSize(.small)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
        .accessibilityElement(children: .contain)
    }

    private func unavailableSection(_ unavailable: [UnavailableRule]) -> some View {
        Section {
            ForEach(unavailable) { entry in
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.rule.title)
                        Text("Unavailable this session — \(entry.reason)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } icon: {
                    Image(systemName: "slash.circle")
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(entry.rule.title). Unavailable this session: \(entry.reason)")
                .selectionDisabled()
            }
        } header: {
            Text("Not offered in this scan")
        }
    }

    @ViewBuilder
    private func emptyState(locked: [Rule], unavailable: [UnavailableRule]) -> some View {
        VStack(spacing: 16) {
            switch appState.phase {
            case .idle:
                ContentUnavailableView {
                    Label("Not Scanned Yet", systemImage: "sparkle.magnifyingglass")
                } description: {
                    Text("Run a read-only scan to see what can be reclaimed in \(category.displayName).")
                } actions: {
                    Button("Scan") { appState.startScan() }
                        .keyboardShortcut(.defaultAction)
                }
            case .scanning:
                ContentUnavailableView {
                    Label("Scanning…", systemImage: "hourglass")
                } description: {
                    let progress = appState.categoryProgress[category]
                    Text("\(progress?.targetsFound ?? 0) found so far (\(ByteFormatter.format(progress?.bytesFound ?? 0))).")
                }
            default:
                ContentUnavailableView("Nothing Found", systemImage: "checkmark.circle",
                                       description: Text("iMop found nothing to reclaim in \(category.displayName)."))
            }

            if !locked.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Label("\(locked.count) rule(s) locked — needs Full Disk Access", systemImage: "lock")
                        .font(.callout.weight(.semibold))
                    ForEach(locked, id: \.id) { rule in
                        Text("• \(rule.title)")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    Button("Full Disk Access Settings…") {
                        appState.openFullDiskAccessSettings()
                    }
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.ultraThinMaterial))
            }

            if !unavailable.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Label("\(unavailable.count) rule(s) not offered in this scan", systemImage: "slash.circle")
                        .font(.callout.weight(.semibold))
                    ForEach(unavailable) { entry in
                        Text("• \(entry.rule.title) — \(entry.reason)")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(14)
                .frame(maxWidth: 560, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.ultraThinMaterial))
                .accessibilityElement(children: .combine)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(24)
    }

    // MARK: - Filtering & sorting

    private func filtered(_ items: [PlanItem]) -> [PlanItem] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return items }
        return items.filter { item in
            item.target.displayName.localizedCaseInsensitiveContains(query)
                || item.target.path.localizedCaseInsensitiveContains(query)
                || item.rule.title.localizedCaseInsensitiveContains(query)
                || (item.target.owningBundleID?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    private func sorted(_ items: [PlanItem]) -> [PlanItem] {
        switch sortOrder {
        case .recommended:
            // AppState already orders items: actionable first, then by reclaimable size.
            return items
        case .reclaimable:
            return items.sorted { $0.target.reclaimableBytes > $1.target.reclaimableBytes }
        case .name:
            return items.sorted {
                $0.target.displayName.localizedStandardCompare($1.target.displayName) == .orderedAscending
            }
        case .tier:
            return items.sorted {
                $0.effectiveTier == $1.effectiveTier
                    ? $0.target.reclaimableBytes > $1.target.reclaimableBytes
                    : $0.effectiveTier < $1.effectiveTier
            }
        case .lastUsed:
            return items.sorted {
                ($0.target.lastUsed ?? .distantFuture) < ($1.target.lastUsed ?? .distantFuture)
            }
        }
    }
}
