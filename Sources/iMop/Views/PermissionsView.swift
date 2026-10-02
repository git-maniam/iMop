import AppKit
import iMopCore
import SwiftUI

// Spec §8: Full Disk Access status, why it is needed and a deep link; App Management explanation and
// deep link; rules that need Full Disk Access are listed as "Locked — needs Full Disk Access", never
// silently skipped.

struct PermissionsView: View {
    @Environment(AppState.self) private var appState

    init() {}

    private var lockedRules: [Rule] {
        appState.ruleStatusesLocked().sorted {
            ($0.category.displayName, $0.title) < ($1.category.displayName, $1.title)
        }
    }

    private var fdaGranted: Bool { appState.permissions.fullDiskAccess == .granted }
    private var fdaDenied: Bool { appState.permissions.fullDiskAccess == .denied }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Permissions")
                    .font(.largeTitle.weight(.bold))
                Text("iMop checks permissions by trying to read, never by writing. It never asks for administrator rights.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                fullDiskAccessCard
                appManagementCard
                lockedRulesCard
                unavailableRulesCard
            }
            .padding(24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .task { appState.refreshPermissions() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            // Picks up a permission granted or revoked in System Settings while iMop was in the background.
            appState.refreshPermissions()
        }
    }

    // MARK: Full Disk Access

    private var fdaStatusText: String {
        if fdaGranted { return "Granted" }
        if fdaDenied { return "Not granted" }
        return "Unknown"
    }

    private var fdaStatusSymbol: String {
        if fdaGranted { return "checkmark.seal.fill" }
        if fdaDenied { return "xmark.octagon.fill" }
        return "questionmark.circle.fill"
    }

    private var fdaStatusTint: Color {
        if fdaGranted { return .green }
        if fdaDenied { return .red }
        return .orange
    }

    private var lockedCategories: [String] {
        var seen = Set<RuleCategory>()
        return lockedRules.compactMap { seen.insert($0.category).inserted ? $0.category.displayName : nil }
    }

    private var fullDiskAccessCard: some View {
        PermissionCard(
            title: "Full Disk Access",
            symbol: "lock.shield",
            statusText: fdaStatusText,
            statusSymbol: fdaStatusSymbol,
            statusTint: fdaStatusTint
        ) {
            Text("macOS protects some app data — for example Safari and Mail data and other apps' sandbox containers. Without Full Disk Access, iMop cannot even look there, so the rules for those locations are shown as locked instead of being skipped silently.")
                .fixedSize(horizontal: false, vertical: true)
            if !lockedCategories.isEmpty {
                Text("Locked in the last scan: \(lockedCategories.joined(separator: ", ")).")
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !fdaGranted {
                Text("To grant it: open System Settings › Privacy & Security › Full Disk Access, turn on iMop, then come back and choose Check Again. macOS may ask you to quit and reopen iMop.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 10) {
                Button("Open Full Disk Access Settings…") { appState.openFullDiskAccessSettings() }
                    .accessibilityHint("Opens System Settings at Privacy & Security, Full Disk Access.")
                Button("Check Again") { appState.refreshPermissions() }
            }
        }
    }

    // MARK: App Management

    private var appManagementCard: some View {
        PermissionCard(
            title: "App Management",
            symbol: "app.badge.checkmark",
            statusText: appState.permissions.appManagement == .granted ? "Granted" : "Asked only when needed",
            statusSymbol: appState.permissions.appManagement == .granted ? "checkmark.seal.fill" : "info.circle.fill",
            statusTint: appState.permissions.appManagement == .granted ? .green : .blue
        ) {
            Text("Needed only if you choose to move a whole app to the Trash — for example an extra copy of Xcode or an old macOS installer. macOS asks the first time; if you decline, those items are not cleaned and the results say that the permission is needed.")
                .fixedSize(horizontal: false, vertical: true)
            Text("iMop cannot check this permission without changing an app, so it never tries to.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Open App Management Settings…") { appState.openAppManagementSettings() }
                .accessibilityHint("Opens System Settings at Privacy & Security, App Management.")
        }
    }

    // MARK: Locked rules

    private var lockedRulesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Locked rules")
                .font(.headline)
            if lockedRules.isEmpty {
                Text(fdaGranted
                     ? "No rules are locked."
                     : "No rules were locked in the last scan. Scan to see which rules need Full Disk Access.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(spacing: 0) {
                    ForEach(lockedRules) { rule in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Image(systemName: "lock.fill")
                                .foregroundStyle(.secondary)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(rule.title)
                                Text("\(rule.category.displayName) · Locked — needs Full Disk Access")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 8)
                            ActTierTag(tier: rule.tier)
                        }
                        .padding(.vertical, 8)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("\(rule.title), \(rule.category.displayName), \(rule.tier.displayName) tier. Locked — needs Full Disk Access.")
                        if rule.id != lockedRules.last?.id { Divider() }
                    }
                }
                .padding(.horizontal, 12)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.background.opacity(0.6)))
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(.ultraThinMaterial))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.primary.opacity(0.06), lineWidth: 1))
    }
}

// MARK: - Unavailable rules

extension PermissionsView {
    /// Review M7 (spec §8 / §11): every rule the last scan could not offer anything for, with the reason
    /// verbatim — e.g. access declined, a tool not installed in a trusted location, Docker not running.
    var unavailableRulesCard: some View {
        let unavailable = appState.unavailableRules()
        return VStack(alignment: .leading, spacing: 10) {
            Text("Unavailable this session")
                .font(.headline)
            Text("Rules the last scan could not offer anything for, and why. Access that macOS declined is not asked for again until you reopen iMop.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if unavailable.isEmpty {
                Text(appState.phase == .idle ? "Scan to see which rules are unavailable." : "Every rule could be checked in the last scan.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(spacing: 0) {
                    ForEach(unavailable) { entry in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Image(systemName: "slash.circle")
                                .foregroundStyle(.secondary)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.rule.title)
                                Text("\(entry.rule.category.displayName) · \(entry.reason)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .textSelection(.enabled)
                            }
                            Spacer(minLength: 8)
                            ActTierTag(tier: entry.rule.tier)
                        }
                        .padding(.vertical, 8)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("\(entry.rule.title), \(entry.rule.category.displayName), \(entry.rule.tier.displayName) tier. Unavailable: \(entry.reason)")
                        if entry.id != unavailable.last?.id { Divider() }
                    }
                }
                .padding(.horizontal, 12)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.background.opacity(0.6)))
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(.ultraThinMaterial))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.primary.opacity(0.06), lineWidth: 1))
    }
}

// MARK: - Card

private struct PermissionCard<Content: View>: View {
    let title: String
    let symbol: String
    let statusText: String
    let statusSymbol: String
    let statusTint: Color
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Label(title, systemImage: symbol)
                    .font(.title3.weight(.semibold))
                Spacer(minLength: 8)
                Label(statusText, systemImage: statusSymbol)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(statusTint)
                    .accessibilityLabel("\(title): \(statusText)")
            }
            content()
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(.ultraThinMaterial))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.primary.opacity(0.06), lineWidth: 1))
    }
}
