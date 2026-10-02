import AppKit
import iMopCore
import SwiftUI

// Spec §9.7 / §7.3: estimated vs measured reclaim, the honest explanations from the report, the
// skipped list with reasons, "Open Quarantine" and "Export Log…".

struct ResultsView: View {
    @Environment(AppState.self) private var appState
    @LocalState private var exportMessage: ExportMessage?

    init() {}

    var body: some View {
        Group {
            if appState.phase == .executing {
                ExecutionProgressView()
            } else if let report = appState.lastReport {
                ScrollView {
                    ReportContent(report: report, plan: appState.plan, exportMessage: exportMessage,
                                  openQuarantine: openQuarantine, exportLog: exportLog)
                        .padding(24)
                        .frame(maxWidth: 900, alignment: .leading)
                        .frame(maxWidth: .infinity)
                }
            } else {
                emptyState
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("No cleanup has run yet")
                .font(.title3.weight(.semibold))
            Text("Scan, select items, then choose Review & Clean. The results appear here.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Go to Scan") { appState.destination = .scan }
                Button("Export Log…") { exportLog() }
            }
            if let exportMessage {
                ActNoticeBanner(symbol: exportMessage.isError ? "exclamationmark.octagon" : "checkmark.circle",
                                title: exportMessage.isError ? "Export failed" : "Log exported",
                                message: exportMessage.text, style: exportMessage.isError ? .error : .success)
                    .frame(maxWidth: 520)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func openQuarantine() {
        appState.refreshQuarantine()
        appState.destination = .quarantine
    }

    private func exportLog() {
        Task { @MainActor in
            if let message = await AuditLogExporter.run(appState: appState) { exportMessage = message }
        }
    }
}

// MARK: - Report

private struct ReportContent: View {
    let report: ExecutionReport
    let plan: CleanupPlan?
    let exportMessage: ExportMessage?
    let openQuarantine: () -> Void
    let exportLog: () -> Void

    private var succeeded: [ItemOutcome] { report.outcomes.filter(\.status.succeeded) }
    private var notCleaned: [ItemOutcome] { report.outcomes.filter { !$0.status.succeeded } }

    private func count(_ match: (ItemStatus) -> Bool) -> Int { succeeded.filter { match($0.status) }.count }

    private var titleText: String {
        if report.mutationDisabled { return "Dry run finished — nothing was changed" }
        if report.cancelled { return "Cleanup stopped" }
        return "Cleanup finished"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(titleText)
                    .font(.largeTitle.weight(.bold))
                Text("\(succeeded.count) of \(report.outcomes.count) item\(report.outcomes.count == 1 ? "" : "s") cleaned"
                     + (notCleaned.isEmpty ? "." : " · \(notCleaned.count) not cleaned (reasons below)."))
                    .foregroundStyle(.secondary)
            }

            if report.mutationDisabled {
                ActNoticeBanner(symbol: "eye", title: "Dry-run build — cleaning disabled",
                                message: "This build of iMop cannot change files, so nothing was moved or deleted.",
                                style: .info)
            }
            if report.cancelled {
                ActNoticeBanner(symbol: "stop.circle", title: "Cancelled",
                                message: "Cleaning stopped between items. Items after the cancellation were not touched.",
                                style: .info)
            }

            statCards

            if !report.explanations.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Why the measured number can differ")
                        .font(.headline)
                    ForEach(Array(report.explanations.enumerated()), id: \.offset) { _, explanation in
                        Label {
                            Text(explanation).fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: "info.circle")
                        }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.ultraThinMaterial))
            }

            if !succeeded.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Done").font(.headline)
                    summaryLine("archivebox", "Moved to Quarantine", count { if case .quarantined = $0 { return true }; return false })
                    summaryLine("trash", "Moved to the Trash", count { if case .trashed = $0 { return true }; return false })
                    summaryLine("terminal", "Cleanup commands run", count { if case .commandSucceeded = $0 { return true }; return false })
                    summaryLine("xmark.bin", "Deleted permanently", count { if case .permanentlyRemoved = $0 { return true }; return false })
                }
            }

            if !notCleaned.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Skipped or not cleaned (\(notCleaned.count))")
                        .font(.headline)
                    VStack(spacing: 0) {
                        ForEach(notCleaned) { outcome in
                            SkippedRow(outcome: outcome, item: plan?.items.first { $0.id == outcome.id })
                            if outcome.id != notCleaned.last?.id { Divider() }
                        }
                    }
                    .padding(.horizontal, 12)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.ultraThinMaterial))
                }
            }

            HStack(spacing: 12) {
                Button {
                    openQuarantine()
                } label: {
                    Label("Open Quarantine", systemImage: "archivebox")
                }
                Button {
                    exportLog()
                } label: {
                    Label("Export Log…", systemImage: "square.and.arrow.up")
                }
            }
            .controlSize(.large)

            if let exportMessage {
                ActNoticeBanner(symbol: exportMessage.isError ? "exclamationmark.octagon" : "checkmark.circle",
                                title: exportMessage.isError ? "Export failed" : "Log exported",
                                message: exportMessage.text, style: exportMessage.isError ? .error : .success)
            }
        }
    }

    @ViewBuilder
    private func summaryLine(_ symbol: String, _ text: String, _ count: Int) -> some View {
        if count > 0 {
            Label("\(text): \(count)", systemImage: symbol)
        }
    }

    private var measuredText: String {
        guard let delta = report.measuredDelta else { return "Not measured" }
        if delta < 0 { return "−\(ByteFormatter.format(-delta))" }
        return ByteFormatter.format(delta)
    }

    private var measuredCaption: String {
        guard let delta = report.measuredDelta else { return "Free space could not be read before and after." }
        if delta < 0 { return "Free space went down — other apps wrote data while iMop was cleaning." }
        return "Change in free space, measured before and after."
    }

    private var statCards: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 12) { cards }
            VStack(alignment: .leading, spacing: 12) { cards }
        }
    }

    @ViewBuilder
    private var cards: some View {
        ResultStatCard(title: "Estimated reclaim", value: ByteFormatter.format(report.estimatedReclaimBytes),
                       caption: "What iMop calculated for the items it cleaned.", symbol: "chart.bar")
        ResultStatCard(title: "Measured free space", value: measuredText, caption: measuredCaption,
                       symbol: "internaldrive")
        ResultStatCard(title: "Still in Quarantine", value: ByteFormatter.format(report.quarantinedBytes),
                       caption: Quarantine.spaceNotice, symbol: "archivebox")
    }
}

private struct ResultStatCard: View {
    let title: String
    let value: String
    let caption: String
    let symbol: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: symbol)
                .font(.callout.weight(.medium))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.title.weight(.bold).monospacedDigit())
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(minWidth: 180, maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.ultraThinMaterial))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Color.primary.opacity(0.06), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

private struct SkippedRow: View {
    let outcome: ItemOutcome
    let item: PlanItem?

    private var title: String { item?.target.displayName ?? ActCopy.lastComponent(outcome.path) }
    private var reason: String { ActCopy.reasonText(outcome.status) ?? ActCopy.statusText(outcome.status) }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: ActCopy.statusSymbol(outcome.status))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(title)
                    if let tier = item?.effectiveTier { ActTierTag(tier: tier) }
                }
                Text(ActCopy.displayPath(outcome.path))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Text(reason)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Text(ByteFormatter.format(outcome.estimatedBytes))
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title)\(item.map { ", \($0.effectiveTier.displayName) tier" } ?? ""). Not cleaned: \(reason)")
    }
}

// MARK: - Audit log export

struct ExportMessage: Equatable {
    let text: String
    let isError: Bool
}

/// "Export Log…": an NSSavePanel defaulting to ~/Downloads, then `AppState.exportAuditLog(to:)`.
/// The core refuses deny-listed destinations (e.g. ~/Desktop, ~/Documents), iMop's own folders and
/// existing files; the refusal is shown in plain language.
@MainActor
enum AuditLogExporter {
    /// Returns `nil` when the user cancelled the panel.
    static func run(appState: AppState) async -> ExportMessage? {
        let panel = NSSavePanel()
        panel.title = "Export Audit Log"
        panel.message = "iMop writes a new file and never overwrites an existing one."
        panel.prompt = "Export"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        panel.nameFieldStringValue = defaultFileName()
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        do {
            try await appState.exportAuditLog(to: url)
            return ExportMessage(text: "Saved to \(ActCopy.displayPath(url.path)).", isError: false)
        } catch let error as AuditLogError {
            return ExportMessage(text: message(for: error), isError: true)
        } catch {
            return ExportMessage(text: ActCopy.genericErrorMessage(error), isError: true)
        }
    }

    static func defaultFileName() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        return "iMop-audit-\(formatter.string(from: Date())).jsonl"
    }

    static func message(for error: AuditLogError) -> String {
        switch error {
        case .invalidDestination(let detail):
            return "That location can't be used (\(detail)). Choose a folder such as Downloads."
        case .destinationRefused(let detail):
            return "iMop does not write there (\(detail)) — it is a protected location or one of iMop's own folders. Choose another folder, such as Downloads."
        case .destinationExists:
            return "A file with that name already exists. iMop never overwrites files — choose a new name."
        case .logDirectoryUnavailable:
            return "The audit log folder (~/Library/Logs/iMop) is missing or could not be read safely."
        case .io(let detail):
            return "The file could not be written: \(detail)"
        }
    }
}
