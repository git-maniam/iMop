import iMopCore
import SwiftUI

// Spec §6.10 / §3.2 Advisory tier: iMop explains and guides but never acts. Each item shows its
// explanation (rule texts verbatim) and offers only Reveal in Finder / Open App / Open Storage
// Settings. There is no selection and no clean action on this screen.

struct AdvisoryView: View {
    @Environment(AppState.self) private var appState

    init() {}

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Advisory")
                        .font(.largeTitle.weight(.bold))
                    Label("iMop explains these but never cleans them. Use the app or setting named in each item to manage the space yourself.",
                          systemImage: Tier.advisory.symbolName)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if appState.advisoryItems.isEmpty {
                    emptyState
                } else {
                    ForEach(appState.advisoryItems) { item in
                        AdvisoryCard(
                            item: item,
                            reveal: { appState.revealInFinder(path: $0) },
                            openApp: { appState.openApp(bundleID: $0) },
                            openStorage: { appState.openStorageSettings() }
                        )
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "info.circle")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(appState.phase == .idle ? "Scan to see advisory items" : "No advisory items found")
                .font(.title3.weight(.semibold))
            Text("Advisory items are large things iMop will not touch — Time Machine snapshots, device backups, Docker's disk and more — with guidance on managing them.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 480)
            if appState.phase == .idle {
                Button("Go to Scan") { appState.destination = .scan }
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity)
    }
}

private struct AdvisoryCard: View {
    let item: PlanItem
    let reveal: (String) -> Void
    let openApp: (String) -> Void
    let openStorage: () -> Void

    private var kind: AdvisoryKind? {
        if case .advisory(let kind) = item.action { return kind }
        if case .advisory(let kind) = item.rule.action { return kind }
        return nil
    }

    /// Advisory items may carry a descriptive label instead of a path (e.g. "Purgeable space").
    private var revealablePath: String? { item.target.path.hasPrefix("/") ? item.target.path : nil }

    /// Bundle identifier for "Open App": the target's owner when known. The Docker disk image rule
    /// does not record one, so the well-known IDs of the apps that own those files are used.
    private var appBundleID: String? {
        if let owner = item.target.owningBundleID, !owner.isEmpty { return owner }
        guard item.rule.id == "docker.diskImage" else { return nil }
        let path = item.target.path.lowercased()
        if path.contains("orbstack") { return "dev.kdrag0n.MacVirt" }
        if path.contains("com.docker.docker") || path.contains("/docker") { return "com.docker.docker" }
        return nil
    }

    private var sizeText: String? {
        let bytes = max(item.target.allocatedBytes, item.target.reclaimableBytes)
        return bytes > 0 ? ByteFormatter.format(bytes) : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                ActTierTag(tier: .advisory)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.target.displayName)
                        .font(.headline)
                    Text("\(item.rule.title) · \(item.rule.category.displayName)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                if let sizeText {
                    Text("About \(sizeText)")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }

            if let revealablePath {
                Text(revealablePath)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            AdvisoryText(heading: "What it is", text: item.rule.explanation)
            AdvisoryText(heading: "What you lose", text: item.rule.whatYouLose)
            AdvisoryText(heading: "How it comes back", text: item.rule.howItRegenerates)

            if !item.target.notes.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(item.target.notes.enumerated()), id: \.offset) { _, note in
                        Label(note, systemImage: "info.circle")
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            HStack(spacing: 10) {
                if let revealablePath {
                    Button {
                        reveal(revealablePath)
                    } label: {
                        Label("Reveal in Finder", systemImage: "folder")
                    }
                    .accessibilityLabel("Reveal \(item.target.displayName) in Finder")
                }
                if kind == .openApp, let appBundleID {
                    Button {
                        openApp(appBundleID)
                    } label: {
                        Label("Open App", systemImage: "arrow.up.forward.app")
                    }
                    .accessibilityLabel("Open the app that manages \(item.target.displayName)")
                }
                if kind == .openStorageSettings {
                    Button {
                        openStorage()
                    } label: {
                        Label("Open Storage Settings", systemImage: "internaldrive")
                    }
                    .accessibilityHint("Opens System Settings, General, Storage.")
                }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(.ultraThinMaterial))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.primary.opacity(0.06), lineWidth: 1))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Info tier. \(item.target.displayName)\(sizeText.map { ", about \($0)" } ?? "")")
    }
}

private struct AdvisoryText: View {
    let heading: String
    let text: String

    var body: some View {
        if !text.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text(heading)
                    .font(.subheadline.weight(.semibold))
                Text(text)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
        }
    }
}
