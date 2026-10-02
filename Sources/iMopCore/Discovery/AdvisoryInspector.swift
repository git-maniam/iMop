import Foundation

// Read-only inspector for the explain-only rules (spec §6.4 `docker.diskImage`, §6.7
// `finalcut.generated` / `audio.soundLibraries`, §6.10 advisory items).
//
// Every candidate it returns is `.advisory`: explanation and facts only, never actionable
// (SafetyGate rejects the advisory kind). It may READ locations that are deny-listed for actions
// (`/Library`, `MobileSync`, `/System/Library/AssetsV2`, `.fcpbundle` libraries) because it only
// looks: `lstat`, directory listings and bounded plist reads through `environment.fileSystem`,
// `SizeCalculator` for sizes, and allow-listed read-only commands (`tmutil listlocalsnapshots /`)
// through `environment.commands`. It never modifies anything.
//
// Sizes are measured here (SizeCalculator, allocated bytes) and returned as `reportedBytes`, so the
// Scanner never has to measure a deny-listed location itself. They describe what the item occupies;
// iMop cannot free any of it.

public struct AdvisoryInspector: Inspector {
    public static let dockerDiskImageRuleID = "docker.diskImage"
    public static let finalCutGeneratedRuleID = "finalcut.generated"
    public static let soundLibrariesRuleID = "audio.soundLibraries"
    public static let timeMachineSnapshotsRuleID = "advisory.timeMachineSnapshots"
    public static let purgeableSpaceRuleID = "advisory.purgeableSpace"
    public static let iosBackupsRuleID = "advisory.iosBackups"
    public static let systemStorageRuleID = "advisory.systemStorage"
    public static let appleIntelligenceAssetsRuleID = "advisory.appleIntelligenceAssets"
    public static let iCloudDriveRuleID = "advisory.iCloudDrive"
    public static let rootOwnedLocationsRuleID = "advisory.rootOwnedLocations"

    /// Every rule id this inspector answers.
    public static let ruleIDs: [String] = [
        dockerDiskImageRuleID, finalCutGeneratedRuleID, soundLibrariesRuleID, timeMachineSnapshotsRuleID,
        purgeableSpaceRuleID, iosBackupsRuleID, systemStorageRuleID, appleIntelligenceAssetsRuleID,
        iCloudDriveRuleID, rootOwnedLocationsRuleID,
    ]

    /// System Settings › General › Storage.
    public static let storageSettingsDeepLink = "x-apple.systempreferences:com.apple.settings.Storage"

    static let tmutilTimeout: TimeInterval = 30
    static let snapshotPrefix = "com.apple.TimeMachine."
    /// SAFETY-DECISION: bounded work for explain-only items.
    static let maxLibraries = 50
    static let maxBackups = 50

    static let dockerImageComponents = ["Library", "Containers", "com.docker.docker", "Data", "vms", "0", "data", "Docker.raw"]
    static let backupComponents = ["Library", "Application Support", "MobileSync", "Backup"]
    static let soundLibraryPaths = ["/Library/Application Support/GarageBand", "/Library/Application Support/Logic",
                                    "/Library/Audio/Apple Loops"]
    static let rootOwnedPaths = ["/Library/Caches", "/Library/Logs", "/Library/Developer/CoreSimulator"]
    static let assetsPath = "/System/Library/AssetsV2"

    /// Prefix applied to system (non-home) paths; empty in production.
    private let systemRoot: String

    public init() {
        self.systemRoot = ""
    }

    /// Test-only: system paths (`/Library/…`, `/System/Library/AssetsV2`) are looked up below
    /// `systemRoot` (a fixture folder) instead of `/`.
    @_spi(FixtureTesting)
    public init(systemRoot: String) {
        var root = systemRoot
        while root.hasSuffix("/") { root.removeLast() }
        self.systemRoot = root
    }

    public var id: InspectorID { .advisory }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        // SAFETY-DECISION: only advisory rules (advisory tier AND advisory action) are answered, so
        // these explain-only candidates can never be attached to an actionable rule.
        guard rule.tier == .advisory, case .advisory = rule.action else {
            return InspectorOutput(candidates: [], status: .unavailable("Not an advisory rule"))
        }
        switch rule.id {
        case Self.dockerDiskImageRuleID: return dockerDiskImage(environment)
        case Self.finalCutGeneratedRuleID: return finalCutLibraries(environment)
        case Self.soundLibrariesRuleID: return soundLibraries(environment)
        case Self.timeMachineSnapshotsRuleID: return await timeMachineSnapshots(environment)
        case Self.purgeableSpaceRuleID: return purgeableSpace(environment)
        case Self.iosBackupsRuleID: return iosBackups(environment)
        case Self.systemStorageRuleID: return systemStorage()
        case Self.appleIntelligenceAssetsRuleID: return appleIntelligenceAssets(environment)
        case Self.iCloudDriveRuleID: return iCloudDrive(environment)
        case Self.rootOwnedLocationsRuleID: return rootOwnedLocations(environment)
        // SAFETY-DECISION: an unknown rule id bound to this inspector gets nothing.
        default: return InspectorOutput(candidates: [], status: .unavailable("Unknown advisory item"))
        }
    }

    // MARK: - Shared

    private static let nothing = InspectorOutput(candidates: [], status: .ok)

    private func systemPath(_ path: String) -> String { systemRoot + path }

    /// `lstat` of `path` when it is a real directory (not a symlink).
    private static func realDirectory(_ path: String, _ environment: SafeCleanEnvironment) -> FileStat? {
        guard let info = environment.fileSystem.lstat(path), info.isDirectory, !info.isSymlink else { return nil }
        return info
    }

    /// Size facts of `path` measured with SizeCalculator: `(allocated bytes, notes)`; `nil` bytes when
    /// it cannot be measured.
    private static func measure(_ path: String, _ environment: SafeCleanEnvironment) -> (Int64?, [String]) {
        guard let estimate = SizeCalculator(environment: environment).measure(path: path) else {
            return (nil, ["Size could not be measured."])
        }
        var notes = ["Uses \(CommandDiscovery.formatBytes(estimate.allocatedBytes)) on disk."]
        if !estimate.complete { notes.append("Size may be underestimated: some items could not be read.") }
        return (estimate.allocatedBytes, notes)
    }

    private static let neverActs = "iMop only explains this item; it never changes or removes it."

    // MARK: - docker.diskImage

    private func dockerDiskImage(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        let home = environment.homePath
        var candidates: [DiscoveredCandidate] = []

        let image = home + "/" + Self.dockerImageComponents.joined(separator: "/")
        // SAFETY-DECISION: the disk image is only looked at (lstat + SizeCalculator); a symlink is ignored.
        if let info = environment.fileSystem.lstat(image), info.isRegularFile, !info.isSymlink {
            let (bytes, sizeNotes) = Self.measure(image, environment)
            var notes = sizeNotes
            notes.append("Maximum size of the disk image: \(CommandDiscovery.formatBytes(max(0, info.logicalSize))).")
            notes += [
                "Docker Desktop keeps all images, containers and volumes inside this single disk image. It does not shrink automatically when you delete them.",
                // SAFETY-DECISION (review M6): the non-destructive route comes first; the two Docker
                // Desktop options that recreate the disk image are named only together with the
                // plain statement that they delete every image, container and volume.
                "To reclaim space without losing data, remove what you no longer need from inside Docker: the Docker cleanup items in iMop, or unused images and stopped containers in Docker Desktop. The command docker system df shows what uses the space. Docker Desktop then returns the freed space to macOS, which can take a few minutes.",
                "Warning: lowering the disk size limit (Settings › Resources › Advanced) and Troubleshoot › Clean / Purge data both delete and recreate this disk image — ALL images, containers and volumes, including any databases in them, are lost.",
                "Never delete or move Docker.raw yourself — all your images, containers and volumes would be lost.",
                Self.neverActs,
            ]
            candidates.append(DiscoveredCandidate(advisoryPath: image, displayName: "Docker Desktop disk image",
                                                  reportedBytes: bytes, lastUsed: info.modificationDate, notes: notes))
        }

        let orbstack = home + "/.orbstack"
        if let info = Self.realDirectory(orbstack, environment) {
            candidates.append(DiscoveredCandidate(
                advisoryPath: orbstack, displayName: "OrbStack data", lastUsed: info.modificationDate,
                notes: [
                    "OrbStack stores its containers, images and Linux machines in its own disk image and returns freed space to macOS automatically.",
                    "To reclaim space, remove unused images, containers and machines in OrbStack (or with docker / orb commands).",
                    "Size not measured: OrbStack's data lives in its own managed disk image.",
                    Self.neverActs,
                ]))
        }

        let colima = home + "/.colima"
        if let info = Self.realDirectory(colima, environment) {
            let (bytes, sizeNotes) = Self.measure(colima, environment)
            candidates.append(DiscoveredCandidate(
                advisoryPath: colima, displayName: "Colima virtual machines", reportedBytes: bytes, lastUsed: info.modificationDate,
                notes: sizeNotes + [
                    "Colima keeps containers, images and volumes inside each virtual machine's disk.",
                    "To reclaim space, remove unused images and containers with docker while Colima is running. Deleting a Colima profile (colima delete) also deletes every container and volume in it.",
                    Self.neverActs,
                ]))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    // MARK: - finalcut.generated

    private func finalCutLibraries(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        guard let reported = environment.spotlight.paths(withExtension: "fcpbundle", under: nil) else {
            return InspectorOutput(candidates: [], status: .unavailable("Spotlight could not search for Final Cut Pro libraries"))
        }
        var seen = Set<String>()
        var candidates: [DiscoveredCandidate] = []
        for raw in reported.sorted() {
            if candidates.count >= Self.maxLibraries || Task.isCancelled { break }
            var path = raw
            while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
            // Spotlight results are hints: re-validate each (absolute, no traversal, real directory).
            guard path.hasPrefix("/"), !path.contains("\0"),
                  !path.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }),
                  path.lowercased().hasSuffix(".fcpbundle"),
                  seen.insert(PathComparison.normalize(path)).inserted,
                  let info = Self.realDirectory(path, environment) else { continue }
            let name = String((path as NSString).lastPathComponent.dropLast(".fcpbundle".count))
            // SAFETY-DECISION: never descend into the library (not even to measure it).
            candidates.append(DiscoveredCandidate(
                advisoryPath: path, displayName: name.isEmpty ? "Final Cut Pro library" : name, lastUsed: info.modificationDate,
                notes: [
                    "Final Cut Pro keeps render files, optimized and proxy media inside the library. They can be recreated.",
                    "To reclaim space: open the library in Final Cut Pro, select it in the sidebar, then choose File › Delete Generated Library Files…",
                    "iMop never looks inside or changes Final Cut Pro libraries.",
                ]))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    // MARK: - audio.soundLibraries

    private func soundLibraries(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        var candidates: [DiscoveredCandidate] = []
        for logical in Self.soundLibraryPaths {
            if Task.isCancelled { break }
            let path = systemPath(logical)
            guard let info = Self.realDirectory(path, environment) else { continue }
            let (bytes, sizeNotes) = Self.measure(path, environment)
            let label = (logical as NSString).lastPathComponent
            candidates.append(DiscoveredCandidate(
                advisoryPath: path, displayName: "\(label) sound library", reportedBytes: bytes, lastUsed: info.modificationDate,
                notes: sizeNotes + [
                    "Instruments, loops and sounds downloaded by GarageBand or Logic Pro. These files belong to the system (root-owned).",
                    "To remove sound packs, use the app's Sound Library manager (in Logic Pro: Logic Pro › Sound Library › Open Sound Library Manager).",
                    Self.neverActs,
                ]))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    // MARK: - advisory.timeMachineSnapshots

    private func timeMachineSnapshots(_ environment: SafeCleanEnvironment) async -> InspectorOutput {
        let unavailable = InspectorOutput(candidates: [], status: .unavailable("Could not list Time Machine local snapshots"))
        guard let tool = environment.commands.resolveExecutable("tmutil") else { return unavailable }
        let result = await environment.commands.run(executable: tool, arguments: ["listlocalsnapshots", "/"],
                                                    timeout: Self.tmutilTimeout, purpose: .readOnly)
        guard result.succeeded, let dates = Self.snapshotDates(fromListing: result.stdout) else { return unavailable }
        guard dates.count > 0 else { return Self.nothing }
        var notes = ["\(dates.count) local snapshot\(dates.count == 1 ? "" : "s") on the startup disk."]
        let known = dates.compactMap { $0 }.sorted()
        if let oldest = known.first, let newest = known.last {
            notes.append(oldest == newest
                ? "Taken \(DevToolsFileReader.formatDate(oldest))."
                : "Oldest \(DevToolsFileReader.formatDate(oldest)), newest \(DevToolsFileReader.formatDate(newest)).")
        }
        notes += [
            "Time Machine keeps local snapshots of your disk. Their space counts as purgeable: macOS removes them automatically when space is needed, and they expire on their own (usually within 24 hours).",
            "Space from files you delete may not come back until the snapshots that still contain them expire.",
            Self.neverActs,
        ]
        return InspectorOutput(candidates: [DiscoveredCandidate(
            advisoryPath: "Time Machine local snapshots", displayName: "Time Machine local snapshots",
            lastUsed: known.last, notes: notes)], status: .ok)
    }

    /// One entry per snapshot line of `tmutil listlocalsnapshots /` (its date when parsable). `nil`
    /// when the output does not look like a snapshot listing.
    static func snapshotDates(fromListing text: String) -> [Date?]? {
        var dates: [Date?] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("Snapshots for") { continue }
            guard trimmed.hasPrefix(snapshotPrefix) else {
                // SAFETY-DECISION: unexpected output (an error message on stdout) is "unknown", not 0.
                return nil
            }
            dates.append(snapshotDate(trimmed))
        }
        return dates
    }

    /// `com.apple.TimeMachine.2024-05-01-101010.local` → that date (UTC-agnostic, local time).
    static func snapshotDate(_ name: String) -> Date? {
        var stamp = name.dropFirst(snapshotPrefix.count)
        if stamp.hasSuffix(".local") { stamp = stamp.dropLast(".local".count) }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        return formatter.date(from: String(stamp))
    }

    // MARK: - advisory.purgeableSpace

    private func purgeableSpace(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        let home = environment.homePath
        let important = environment.volumes.availableCapacityForImportantUsage(at: home)
        let plain = environment.volumes.availableCapacity(at: home)
        guard important != nil || plain != nil else {
            return InspectorOutput(candidates: [], status: .unavailable("Could not read the free space of the startup disk"))
        }
        var notes: [String] = []
        if let plain { notes.append("Free right now: \(CommandDiscovery.formatBytes(max(0, plain))).") }
        if let important { notes.append("Available including purgeable space: \(CommandDiscovery.formatBytes(max(0, important))).") }
        var purgeable: Int64?
        if let plain, let important, important > plain {
            purgeable = important - plain
            notes.append("About \(CommandDiscovery.formatBytes(important - plain)) is purgeable.")
        }
        notes += [
            "Purgeable space is held by things macOS can remove on its own when space is needed: local Time Machine snapshots, iCloud files that are also stored in the cloud, and system caches.",
            "macOS frees it automatically and gradually, so Finder and System Settings may show different numbers. iMop cannot free purgeable space directly.",
        ]
        return InspectorOutput(candidates: [DiscoveredCandidate(
            advisoryPath: "Purgeable space", displayName: "Purgeable space", reportedBytes: purgeable, notes: notes)], status: .ok)
    }

    // MARK: - advisory.iosBackups

    private func iosBackups(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let backups = walker.descend(from: home, through: Self.backupComponents, device: homeStat.device) else {
            return Self.nothing
        }
        let entries: [InspectorWalker.Entry]
        switch walker.list(backups, device: homeStat.device) {
        case .absent: return Self.nothing
        // MobileSync is protected by Full Disk Access.
        case .declined: return InspectorOutput(candidates: [], status: .lockedNeedsFullDiskAccess)
        case .entries(let list): entries = list
        }
        var candidates: [DiscoveredCandidate] = []
        for entry in entries {
            if candidates.count >= Self.maxBackups || Task.isCancelled { break }
            guard InspectorWalker.isDescendable(entry, device: homeStat.device) else { continue }
            let plist = DevToolsFileReader.readPlistDictionary(entry.path + "/Info.plist", fileSystem: environment.fileSystem)
            let device = AppBundleReader.displayValue(plist?["Device Name"]) ?? AppBundleReader.displayValue(plist?["Display Name"])
            let date = plist?["Last Backup Date"] as? Date
            var notes: [String] = []
            notes.append(device.map { "Device: \($0)." } ?? "Device name unavailable.")
            if let version = AppBundleReader.displayValue(plist?["Product Version"]) {
                let product = AppBundleReader.displayValue(plist?["Product Type"]).map { "\($0), " } ?? ""
                notes.append("\(product)iOS \(version).")
            }
            if let date { notes.append("Last backed up \(DevToolsFileReader.formatDate(date)).") }
            let (bytes, sizeNotes) = Self.measure(entry.path, environment)
            notes += sizeNotes
            notes += [
                "Manage backups in Finder: connect the device, select it in the Finder sidebar, then click Manage Backups…",
                "A deleted backup cannot be recovered. iMop never changes or removes backups.",
            ]
            candidates.append(DiscoveredCandidate(
                advisoryPath: entry.path, displayName: device.map { "Backup of \($0)" } ?? "Device backup",
                reportedBytes: bytes, lastUsed: date ?? entry.stat.modificationDate, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    // MARK: - advisory.systemStorage

    private func systemStorage() -> InspectorOutput {
        InspectorOutput(candidates: [DiscoveredCandidate(
            advisoryPath: "Messages, Photos, Music, Podcasts and TV", displayName: "Messages, Photos, Music, Podcasts and TV",
            notes: [
                "Messages attachments, the Photos library and downloaded music, podcasts and TV shows are managed by their apps.",
                "Review them in System Settings › General › Storage, where each app offers its own safe way to free space (for example, Optimize Storage for Photos or removing downloaded episodes).",
                Self.neverActs,
            ])], status: .ok)
    }

    // MARK: - advisory.appleIntelligenceAssets

    private func appleIntelligenceAssets(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        let path = systemPath(Self.assetsPath)
        guard Self.realDirectory(path, environment) != nil else { return Self.nothing }
        return InspectorOutput(candidates: [DiscoveredCandidate(
            advisoryPath: path, displayName: "Apple Intelligence, Siri and dictation assets",
            notes: [
                "Models and language assets for Apple Intelligence, Siri, dictation and other system features. macOS downloads and removes them itself.",
                "To reduce them, turn off features you do not use in System Settings (for example Apple Intelligence & Siri).",
                "Size not measured: this folder is managed by macOS.",
                Self.neverActs,
            ])], status: .ok)
    }

    // MARK: - advisory.iCloudDrive

    private func iCloudDrive(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        let mobileDocuments = environment.homePath + "/Library/Mobile Documents"
        guard Self.realDirectory(mobileDocuments, environment) != nil else { return Self.nothing }
        return InspectorOutput(candidates: [DiscoveredCandidate(
            advisoryPath: "iCloud Drive", displayName: "iCloud Drive local copies",
            notes: [
                "Files in iCloud Drive may also be stored on this Mac.",
                "Turn on Optimize Mac Storage (System Settings › Apple Account › iCloud › Drive) to let macOS keep only recent files locally, or right-click a file in iCloud Drive and choose Remove Download.",
                "Deleting files from iCloud Drive deletes them from iCloud and all your devices. iMop never removes or evicts iCloud files.",
            ])], status: .ok)
    }

    // MARK: - advisory.rootOwnedLocations

    private func rootOwnedLocations(_ environment: SafeCleanEnvironment) -> InspectorOutput {
        var candidates: [DiscoveredCandidate] = []
        for logical in Self.rootOwnedPaths {
            if Task.isCancelled { break }
            let path = systemPath(logical)
            guard let info = Self.realDirectory(path, environment) else { continue }
            let (bytes, sizeNotes) = Self.measure(path, environment)
            let guidance: String
            if logical.hasSuffix("/CoreSimulator") {
                guidance = "Simulator runtimes live here. Remove runtimes you no longer need with the Simulator runtimes item, or in Xcode › Settings › Components."
            } else {
                guidance = "Caches and logs of macOS and of apps installed for all users. macOS and those apps manage them."
            }
            candidates.append(DiscoveredCandidate(
                advisoryPath: path, displayName: logical, reportedBytes: bytes, lastUsed: info.modificationDate,
                notes: sizeNotes + [
                    guidance,
                    "This folder belongs to the system (root-owned). iMop has no privileged helper and never changes system folders.",
                ]))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}
