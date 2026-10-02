import iMopCore
import SwiftUI

// Spec §5.1 / §9.8: Quarantine browser — sessions, items, retention countdown, restore per item and
// per session, "Empty Quarantine Now" (with confirmation) and the space notice.

struct QuarantineView: View {
    @Environment(AppState.self) private var appState
    @LocalState private var confirmEmpty = false
    @LocalState private var showHistory = false

    init() {}

    private static let activeStatuses: Set<QuarantineStatus> = [.pending, .moved, .restoring, .purging, .needsReview]

    private var sessions: [QuarantineSessionInfo] {
        appState.quarantineSessions.sorted { $0.createdAt > $1.createdAt }
    }

    private var activeEntries: [QuarantineEntry] {
        appState.quarantineSessions.flatMap(\.entries).filter { Self.activeStatuses.contains($0.status) }
    }

    /// Entries that "Empty Quarantine Now" may remove (needs-review entries are never purged).
    private var purgeableEntries: [QuarantineEntry] {
        appState.quarantineSessions.flatMap(\.entries).filter { $0.status == .moved || $0.status == .purging }
    }

    private var heldBytes: Int64 { activeEntries.reduce(0) { $0 + $1.reclaimableBytes } }
    private var purgeableBytes: Int64 { purgeableEntries.reduce(0) { $0 + $1.reclaimableBytes } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(24)

            Divider()

            if visibleSessions.isEmpty {
                emptyState
            } else {
                TimelineView(.periodic(from: .now, by: 60)) { context in
                    List {
                        ForEach(visibleSessions) { session in
                            QuarantineSessionSection(
                                session: session,
                                entries: visibleEntries(of: session),
                                now: context.date,
                                mutationEnabled: AppState.isMutationEnabledInBuild,
                                restoreEntry: { appState.restore(entryID: $0) },
                                restoreSession: { appState.restoreSession($0) }
                            )
                        }
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                }
            }
        }
        .task { appState.refreshQuarantine() }
        .confirmationDialog(
            "Empty the Quarantine now?",
            isPresented: Binding(get: { confirmEmpty }, set: { confirmEmpty = $0 }),
            titleVisibility: .visible
        ) {
            Button("Empty Quarantine (\(purgeableEntries.count) items, \(ByteFormatter.format(purgeableBytes)))", role: .destructive) {
                appState.emptyQuarantineNow()
            }
            // SAFETY-DECISION: Cancel is the default (Return) action of this destructive confirmation.
            Button("Cancel", role: .cancel) {}
                .keyboardShortcut(.defaultAction)
        } message: {
            Text("\(purgeableEntries.count) item\(purgeableEntries.count == 1 ? "" : "s") (\(ByteFormatter.format(purgeableBytes))) will be deleted permanently and can no longer be restored. Items marked “Needs review” are kept.")
        }
    }

    private var visibleSessions: [QuarantineSessionInfo] {
        sessions.filter { !visibleEntries(of: $0).isEmpty }
    }

    private func visibleEntries(of session: QuarantineSessionInfo) -> [QuarantineEntry] {
        let entries = showHistory ? session.entries : session.entries.filter { Self.activeStatuses.contains($0.status) }
        return entries.sorted { $0.quarantinedAt > $1.quarantinedAt }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Quarantine")
                        .font(.largeTitle.weight(.bold))
                    Text("\(activeEntries.count) item\(activeEntries.count == 1 ? "" : "s") held · \(ByteFormatter.format(heldBytes))")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 12)
                Button {
                    appState.refreshQuarantine()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                Button(role: .destructive) {
                    confirmEmpty = true
                } label: {
                    Label("Empty Quarantine Now", systemImage: "xmark.bin")
                }
                .disabled(purgeableEntries.isEmpty || !AppState.isMutationEnabledInBuild)
                .accessibilityHint("Asks for confirmation, then permanently deletes the quarantined items.")
            }

            ActNoticeBanner(symbol: "info.circle", title: "Space is freed when the Quarantine is emptied",
                            message: Quarantine.spaceNotice + " Items are also removed automatically when their retention period ends (checked at launch and daily while iMop runs).",
                            style: .info)

            if !AppState.isMutationEnabledInBuild {
                ActNoticeBanner(symbol: "eye", title: "Dry-run build — cleaning disabled",
                                message: "Restore and Empty Quarantine are not available in this build.",
                                style: .info)
            }

            if let error = appState.lastError {
                HStack(alignment: .top) {
                    ActNoticeBanner(symbol: "exclamationmark.octagon", title: "Something went wrong",
                                    message: error, style: .error)
                    Button("Dismiss") { appState.clearError() }
                }
            }

            Toggle("Show restored and removed items", isOn: Binding(get: { showHistory }, set: { showHistory = $0 }))
                .toggleStyle(.checkbox)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "archivebox")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("The Quarantine is empty")
                .font(.title3.weight(.semibold))
            Text("Cleaned Safe and Review items are moved here first, so you can restore them until their retention period ends.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 460)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Session

private struct QuarantineSessionSection: View {
    let session: QuarantineSessionInfo
    let entries: [QuarantineEntry]
    let now: Date
    let mutationEnabled: Bool
    let restoreEntry: (UUID) -> Void
    let restoreSession: (UUID) -> Void

    private var restorableCount: Int { entries.filter { QuarantineEntryRow.isRestorable($0) }.count }

    var body: some View {
        Section {
            ForEach(entries) { entry in
                QuarantineEntryRow(entry: entry, now: now, mutationEnabled: mutationEnabled, restore: { restoreEntry(entry.id) })
            }
        } header: {
            HStack(alignment: .firstTextBaseline) {
                Text("Cleaned \(session.createdAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.headline)
                Text("· \(entries.count) item\(entries.count == 1 ? "" : "s") · \(ByteFormatter.format(entries.reduce(0) { $0 + $1.reclaimableBytes }))")
                    .foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Button {
                    restoreSession(session.id)
                } label: {
                    Label("Restore Session", systemImage: "arrow.uturn.backward")
                }
                .disabled(restorableCount == 0 || !mutationEnabled)
                .accessibilityLabel("Restore all \(restorableCount) items from the session cleaned \(session.createdAt.formatted(date: .abbreviated, time: .shortened))")
            }
        }
    }
}

// MARK: - Entry

private struct QuarantineEntryRow: View {
    let entry: QuarantineEntry
    let now: Date
    let mutationEnabled: Bool
    let restore: () -> Void

    /// Restore never overwrites (a clash restores beside the original as "<name> (restored <date>)"),
    /// so it is offered for every entry whose item is in the Quarantine, including needs-review ones.
    static func isRestorable(_ entry: QuarantineEntry) -> Bool {
        entry.status == .moved || entry.status == .needsReview
    }

    private var statusText: String {
        switch entry.status {
        case .pending: return "Being moved to the Quarantine"
        case .moved: return "In Quarantine"
        case .restoring: return "Being restored"
        case .restored:
            if let path = entry.restoredPath { return "Restored to \(ActCopy.displayPath(path))" }
            return "Restored"
        case .purging: return "Being removed — can no longer be restored"
        case .purged: return "Removed permanently"
        case .needsReview: return "Needs review — iMop could not verify this item, so it is never removed automatically"
        }
    }

    private var countdownText: String? {
        guard entry.status == .moved else { return nil }
        if entry.expiresAt <= now {
            return "Retention ended — removed at the next check"
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        let relative = formatter.localizedString(for: entry.expiresAt, relativeTo: now)
        return "Removed permanently \(relative) (\(entry.expiresAt.formatted(date: .abbreviated, time: .shortened)))"
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            ActTierTag(tier: entry.tier)
            VStack(alignment: .leading, spacing: 2) {
                Text(ActCopy.lastComponent(entry.originalPath))
                    .font(.body)
                Text(ActCopy.displayPath(entry.originalPath))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Text(statusText)
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
                if let countdownText {
                    Label(countdownText, systemImage: "timer")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            Text(ByteFormatter.format(entry.reclaimableBytes))
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
            if Self.isRestorable(entry) {
                Button("Restore") { restore() }
                    .disabled(!mutationEnabled)
                    .accessibilityLabel("Restore \(ActCopy.lastComponent(entry.originalPath)) to its original location")
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(
            "\(entry.tier.displayName) tier. \(ActCopy.lastComponent(entry.originalPath)), \(ByteFormatter.format(entry.reclaimableBytes)). \(statusText). \(countdownText ?? "")"
        )
    }
}
