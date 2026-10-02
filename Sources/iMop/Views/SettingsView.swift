import AppKit
import iMopCore
import SwiftUI

// Spec §9.9: Settings — project roots, exclusions (folder picker), retention overrides (may only
// lengthen), age-threshold overrides (may only raise), archives to keep, "Always quarantine" (ON by
// default), "Trust Homebrew tools" (OFF by default; turning it on shows who else could change those
// tools and asks first) and "Forget remembered drives". Every change is persisted by `AppState.settings` and
// takes effect for the NEXT scan.

struct SettingsView: View {
    @Environment(AppState.self) private var appState

    @LocalState private var confirmDisableAlwaysQuarantine = false
    @LocalState private var confirmForgetDrives = false
    @LocalState private var confirmTrustHomebrew = false
    /// What the "Trust Homebrew tools" confirmation shows: the other admin accounts (`nil` = unknown).
    @LocalState private var homebrewDisclosure: [String]? = nil

    init() {}

    var body: some View {
        Form {
            if let notice = appState.settingsReviewNotice {
                // SAFETY-DECISION (review M7): cleaning stays paused until the user confirms here.
                Section {
                    Label {
                        Text(notice)
                            .fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: "exclamationmark.shield")
                            .foregroundStyle(.red)
                    }
                    Button("I Have Checked My Settings") {
                        appState.acknowledgeSettingsReview()
                    }
                    .accessibilityHint("Confirms the settings shown below and allows cleaning again")
                } header: {
                    Text("Check your settings")
                }
            }
            Section {
                Text("Changes apply to the next scan. Results already on screen keep the settings they were scanned with — scan again before cleaning.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            alwaysQuarantineSection
            homebrewTrustSection
            projectRootsSection
            exclusionsSection
            retentionSection
            ageThresholdSection
            archivesSection
            drivesSection
        }
        .formStyle(.grouped)
        .frame(minWidth: 560, idealWidth: 620, minHeight: 480, idealHeight: 640)
        .confirmationDialog(
            "Turn off “Always quarantine”?",
            isPresented: Binding(get: { confirmDisableAlwaysQuarantine }, set: { confirmDisableAlwaysQuarantine = $0 }),
            titleVisibility: .visible
        ) {
            Button("Turn Off", role: .destructive) {
                update { $0.alwaysQuarantine = false }
            }
            // SAFETY-DECISION: keeping the safer setting is the default (Return) action.
            Button("Keep On", role: .cancel) {}
                .keyboardShortcut(.defaultAction)
        } message: {
            Text("Items that can only be deleted permanently (emptying the Trash and crash core dumps in /cores) become available and are then deleted in one step, without Quarantine. Each one is still listed as not undoable and needs your acknowledgement in the review; Empty Trash also asks for its own confirmation.")
        }
        .confirmationDialog(
            "Trust Homebrew tools?",
            isPresented: Binding(get: { confirmTrustHomebrew }, set: { confirmTrustHomebrew = $0 }),
            titleVisibility: .visible
        ) {
            Button("Trust Homebrew Tools") {
                appState.setTrustHomebrewTools(true, disclosedAccounts: homebrewDisclosure)
            }
            // SAFETY-DECISION: keeping the setting OFF is the default (Return) action.
            Button("Cancel", role: .cancel) {}
                .keyboardShortcut(.defaultAction)
        } message: {
            Text(homebrewTrustMessage)
        }
        .confirmationDialog(
            "Forget remembered drives?",
            isPresented: Binding(get: { confirmForgetDrives }, set: { confirmForgetDrives = $0 }),
            titleVisibility: .visible
        ) {
            Button("Forget Drives", role: .destructive) {
                appState.forgetRememberedDrives()
            }
            Button("Cancel", role: .cancel) {}
                .keyboardShortcut(.defaultAction)
        } message: {
            Text("Connect every drive that holds apps before your next scan. Until a scan records the connected drives again, iMop offers no leftovers from deleted apps.")
        }
    }

    // MARK: Helpers

    private func update(_ change: (inout ScanSettings) -> Void) {
        var settings = appState.settings
        change(&settings)
        appState.settings = settings
    }

    /// Rule titles and declared values for the override pickers (the catalog AppState loaded).
    private var rules: [Rule] { appState.catalogRules }

    private func rule(_ id: String) -> Rule? { rules.first { $0.id == id } }

    private func ruleTitle(_ id: String) -> String { rule(id)?.title ?? id }

    private static func expanded(_ path: String) -> String {
        ((path as NSString).expandingTildeInPath as NSString).standardizingPath
    }

    private static func chooseFolders(message: String, allowFiles: Bool) -> [URL] {
        let panel = NSOpenPanel()
        panel.message = message
        panel.prompt = "Add"
        panel.canChooseDirectories = true
        panel.canChooseFiles = allowFiles
        panel.allowsMultipleSelection = true
        panel.canCreateDirectories = false
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
        guard panel.runModal() == .OK else { return [] }
        return panel.urls
    }

    // MARK: Always quarantine

    private var alwaysQuarantineSection: some View {
        Section("Safety") {
            Toggle(isOn: Binding(
                get: { appState.settings.alwaysQuarantine },
                set: { newValue in
                    // SAFETY-DECISION: turning the protection ON is immediate; turning it OFF asks first.
                    if newValue {
                        update { $0.alwaysQuarantine = true }
                    } else {
                        confirmDisableAlwaysQuarantine = true
                    }
                }
            )) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Always quarantine (never permanently delete in one step)")
                    Text("When on, iMop never deletes anything in one step: files go to the Quarantine (or the Trash) first, so you can restore them. Vendor cleanup commands are separate — they are always shown as not undoable in the review.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityLabel("Always quarantine, never permanently delete in one step")
        }
    }

    // MARK: Homebrew tools

    private var homebrewTrustSection: some View {
        Section {
            Toggle(isOn: Binding(
                get: { appState.settings.trustHomebrewAdminWritableDirectories },
                set: { newValue in
                    // SAFETY-DECISION: turning the relaxation ON asks first (showing who else could
                    // change the tools); turning it OFF is immediate.
                    if newValue {
                        homebrewDisclosure = appState.homebrewTrustDisclosure()
                        confirmTrustHomebrew = true
                    } else {
                        appState.setTrustHomebrewTools(false, disclosedAccounts: appState.homebrewTrustDisclosure())
                    }
                }
            )) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Trust Homebrew tools in \(appState.homebrewLocation)")
                    Text("Off by default. Homebrew's folders can be changed by every account in the admin group, so iMop does not run brew, npm, yarn, pnpm, go and other Homebrew tools unless you turn this on. Their cleanup rules show as unavailable until then.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityLabel("Trust Homebrew tools in \(appState.homebrewLocation)")
        } header: {
            Text("Command-line tools")
        }
    }

    private var homebrewTrustMessage: String {
        let what = "iMop will also run Homebrew tools whose folders in \(appState.homebrewLocation) the admin group can change — "
            + "only folders you own, in Homebrew's own locations, that are not writable by everyone. "
            + "The tools themselves and every other check stay the same. This setting is off by default; "
            + "it applies from the next scan and you can turn it off at any time."
        guard let accounts = homebrewDisclosure else {
            return "iMop could not determine which accounts are in the admin group. Any of them could replace these tools "
                + "with other programs that iMop would then run as you. Only continue if you know who can sign in to this Mac as an administrator.\n\n"
                + what
        }
        if accounts.isEmpty {
            return "No other account (besides you and root) is in the admin group, so no one else can change these tools today. "
                + "An administrator added later could.\n\n" + what
        }
        return "These accounts can change Homebrew tools, and iMop would then run what they put there as you: "
            + accounts.joined(separator: ", ") + ".\n\n" + what
    }

    // MARK: Project roots

    private var projectRootsSection: some View {
        Section {
            if appState.settings.projectRoots.isEmpty {
                Text("No project folders. Build folders inside projects (node_modules, DerivedData, target, …) are not scanned until you add one.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(appState.settings.projectRoots, id: \.self) { root in
                PathRow(path: root) {
                    appState.dropProjectRoot(root)
                }
            }
            Button {
                for url in Self.chooseFolders(message: "Choose folders that contain your code projects.", allowFiles: false) {
                    appState.addProjectRoot(path: url.path)
                }
            } label: {
                Label("Add Folder…", systemImage: "plus")
            }

            let current = Set(appState.settings.projectRoots.map(Self.expanded))
            let suggestions = ScanSettings.suggestedProjectRoots.filter { !current.contains(Self.expanded($0)) }
            if !suggestions.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Suggested (not enabled until you add them):")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(suggestions, id: \.self) { suggestion in
                        HStack {
                            Text(suggestion).font(.callout.monospaced())
                            Spacer()
                            Button("Add") { appState.addProjectRoot(path: suggestion) }
                                .accessibilityLabel("Add suggested project folder \(suggestion)")
                        }
                    }
                }
            }
        } header: {
            Text("Project folders")
        } footer: {
            Text("Only projects inside these folders are checked for rebuildable build artifacts.")
        }
    }

    // MARK: Exclusions

    private var exclusionsSection: some View {
        Section {
            if appState.settings.userExclusions.isEmpty {
                Text("No exclusions.")
                    .foregroundStyle(.secondary)
            }
            ForEach(appState.settings.userExclusions, id: \.self) { path in
                PathRow(path: path) {
                    appState.dropExclusion(path)
                }
            }
            Button {
                // SAFETY-DECISION: files may be excluded as well as folders (excluding more is safer).
                for url in Self.chooseFolders(message: "Choose folders (or files) iMop must never touch.", allowFiles: true) {
                    appState.addExclusion(path: url.path)
                }
            } label: {
                Label("Add…", systemImage: "plus")
            }
        } header: {
            Text("Exclusions")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("iMop never cleans anything at or inside these locations.")
                if appState.phase == .executing {
                    Text(AppState.exclusionDuringRunNotice)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: Retention overrides

    /// Rules whose items go to the Quarantine (the only ones retention applies to).
    private var quarantineRules: [Rule] {
        rules.filter { if case .quarantine = $0.action { return true }; return false }
    }

    /// Smallest override (in whole days) that is longer than the rule's own retention.
    private static func minimumRetentionDays(for rule: Rule?) -> Int {
        let base = rule?.effectiveRetentionHours ?? 24 * 7
        return base / 24 + 1
    }

    private static let maximumRetentionDays = 30

    private var retentionSection: some View {
        Section {
            let overrides = appState.settings.quarantineRetentionOverrideHours.sorted { $0.key < $1.key }
            if overrides.isEmpty {
                Text("All rules use their default retention (Safe items 24 hours, Review items 7 days).")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(overrides, id: \.key) { ruleID, hours in
                let minDays = Self.minimumRetentionDays(for: rule(ruleID))
                let maxDays = max(minDays, Self.maximumRetentionDays)
                OverrideRow(
                    title: ruleTitle(ruleID),
                    defaultText: "Default: \(ActCopy.retentionText(hours: rule(ruleID)?.effectiveRetentionHours ?? 0))",
                    valueText: { "Keep \($0) days" },
                    value: Binding(
                        get: { min(max(minDays, (hours + 23) / 24), maxDays) },
                        set: { days in
                            // SAFETY-DECISION: never write an override that is not longer than the default.
                            update { $0.quarantineRetentionOverrideHours[ruleID] = min(max(days, minDays), maxDays) * 24 }
                        }
                    ),
                    range: minDays...maxDays,
                    remove: { update { $0.quarantineRetentionOverrideHours.removeValue(forKey: ruleID) } }
                )
            }
            RulePickerMenu(
                title: "Add Retention Override",
                rules: quarantineRules.filter { appState.settings.quarantineRetentionOverrideHours[$0.id] == nil }
            ) { picked in
                update { $0.quarantineRetentionOverrideHours[picked.id] = Self.minimumRetentionDays(for: picked) * 24 }
            }
            .disabled(quarantineRules.isEmpty)
        } header: {
            Text("Quarantine retention")
        } footer: {
            Text("You can keep items in the Quarantine longer than the default, never shorter.")
        }
    }

    // MARK: Age thresholds

    /// The age threshold (days) a rule declares, if any.
    private static func declaredAge(_ rule: Rule) -> Int? {
        let values: [Int] = rule.preconditions.compactMap {
            switch $0 {
            case .olderThan(let days), .projectOlderThan(let days): return days
            default: return nil
            }
        }
        return values.max()
    }

    private static let maximumAgeDays = 3650

    private var ageRules: [Rule] { rules.filter { Self.declaredAge($0) != nil } }

    private var ageThresholdSection: some View {
        Section {
            let overrides = appState.settings.ageThresholdOverrides.sorted { $0.key < $1.key }
            if overrides.isEmpty {
                Text("All rules use their default age thresholds.")
                    .foregroundStyle(.secondary)
            }
            ForEach(overrides, id: \.key) { ruleID, days in
                let declared = rule(ruleID).flatMap(Self.declaredAge)
                let minDays = (declared ?? 0) + 1
                let maxDays = max(minDays, Self.maximumAgeDays)
                OverrideRow(
                    title: ruleTitle(ruleID),
                    defaultText: declared.map { "Default: older than \($0) days" } ?? "Default: unknown",
                    valueText: { "Older than \($0) days" },
                    value: Binding(
                        get: { min(max(minDays, days), maxDays) },
                        set: { newDays in
                            // SAFETY-DECISION: an override may only RAISE the threshold.
                            update { $0.ageThresholdOverrides[ruleID] = min(max(newDays, minDays), maxDays) }
                        }
                    ),
                    range: minDays...maxDays,
                    remove: { update { $0.ageThresholdOverrides.removeValue(forKey: ruleID) } }
                )
            }
            RulePickerMenu(
                title: "Add Age Override",
                rules: ageRules.filter { appState.settings.ageThresholdOverrides[$0.id] == nil }
            ) { picked in
                let declared = Self.declaredAge(picked) ?? 0
                update { $0.ageThresholdOverrides[picked.id] = declared + 1 }
            }
            .disabled(ageRules.isEmpty)
        } header: {
            Text("Age thresholds")
        } footer: {
            Text("Rules that only offer items unused for a while can wait longer than the default, never less.")
        }
    }

    // MARK: Archives

    private var archivesSection: some View {
        Section {
            Stepper(
                value: Binding(
                    get: { appState.settings.effectiveArchivesToKeep },
                    set: { value in update { $0.archivesToKeep = ScanSettings.clampArchivesToKeep(value) } }
                ),
                in: ScanSettings.archivesToKeepRange
            ) {
                Text("Keep the newest \(appState.settings.effectiveArchivesToKeep) archive\(appState.settings.effectiveArchivesToKeep == 1 ? "" : "s") of each app")
            }
            .accessibilityValue("\(appState.settings.effectiveArchivesToKeep)")
        } header: {
            Text("Xcode archives")
        } footer: {
            Text("Older archives are offered for review; the newest ones are never offered.")
        }
    }

    // MARK: Drives

    private var drivesSection: some View {
        Section {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(rememberedDrivesText)
                    Text("iMop remembers which external drives it has seen, so apps on a disconnected drive are never mistaken for deleted apps.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button("Forget Remembered Drives…") { confirmForgetDrives = true }
                    .disabled(appState.settings.lastSeenVolumes == nil)
            }
        } header: {
            Text("External drives")
        }
    }

    private var rememberedDrivesText: String {
        guard let volumes = appState.settings.lastSeenVolumes else { return "No drives recorded yet (recorded at the next scan)." }
        return volumes.isEmpty ? "No external drives remembered." : "\(volumes.count) external drive\(volumes.count == 1 ? "" : "s") remembered."
    }
}

// MARK: - Rows

private struct PathRow: View {
    let path: String
    let remove: () -> Void

    var body: some View {
        HStack {
            Image(systemName: "folder")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(ActCopy.displayPath(path))
                .font(.callout.monospaced())
                .lineLimit(2)
                .truncationMode(.middle)
                .textSelection(.enabled)
            Spacer(minLength: 8)
            Button {
                remove()
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help("Remove")
            .accessibilityLabel("Remove \(ActCopy.displayPath(path))")
        }
    }
}

private struct OverrideRow: View {
    let title: String
    let defaultText: String
    let valueText: (Int) -> String
    let value: Binding<Int>
    let range: ClosedRange<Int>
    let remove: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(defaultText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Stepper(value: value, in: range) {
                Text(valueText(value.wrappedValue))
                    .monospacedDigit()
            }
            .accessibilityLabel("\(title): \(valueText(value.wrappedValue))")
            Button {
                remove()
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help("Use the default")
            .accessibilityLabel("Remove override for \(title)")
        }
    }
}

private struct RulePickerMenu: View {
    let title: String
    let rules: [Rule]
    let pick: (Rule) -> Void

    var body: some View {
        Menu {
            ForEach(RuleCategory.allCases) { category in
                let inCategory = rules.filter { $0.category == category }.sorted { $0.title < $1.title }
                if !inCategory.isEmpty {
                    Menu(category.displayName) {
                        ForEach(inCategory) { rule in
                            Button("\(rule.title) (\(rule.tier.displayName))") { pick(rule) }
                        }
                    }
                }
            }
        } label: {
            Label(title, systemImage: "plus")
        }
        .fixedSize()
    }
}
