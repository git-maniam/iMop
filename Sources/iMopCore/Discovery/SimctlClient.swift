import Foundation

// Read-only discovery for the Xcode simulator command rules (spec §6.1):
// `simulator.unavailable`, `simulator.devices.stale` and `simulator.runtimes`.
//
// Everything here only READS: vendor tools are reached exclusively through
// `SafeCleanEnvironment.commands` with purpose `.readOnly` (the live runner refuses any invocation
// that is not on the read-only allow-list), and the file system only through
// `SafeCleanEnvironment.fileSystem`. Inspectors propose `.commandItem` candidates; the Scanner
// re-validates them (rule shape, item argument, deny-list) and measures their folders. Nothing here
// acts on anything: the vendor cleanup command runs only in the Executor, after SafetyGate.
//
// This file also holds the helpers shared by every command-item inspector (Docker, Ollama).

// MARK: - Shared command-discovery helpers

/// Helpers shared by the command-item inspectors.
enum CommandDiscovery {
    /// SAFETY-DECISION: the runner keeps at most 64 KB of stdout. An output this close to that limit
    /// may have been cut, and a cut line-based listing could end in a TRUNCATED item name that names
    /// a different item (`pgdata_backup` → `pgdata`). Such output is never parsed.
    static let maxTrustedOutputBytes = 60 * 1024

    enum Failure: Error, Sendable, Equatable {
        case toolMissing(String)
        case failed(String)
    }

    /// Resolves `tool` and runs it read-only. `.success(stdout)` only for exit 0, no timeout and an
    /// output well below the runner's truncation limit.
    static func readOnly(_ tool: String, _ arguments: [String], timeout: TimeInterval,
                         environment: SafeCleanEnvironment) async -> Result<String, Failure> {
        guard let executable = environment.commands.resolveExecutable(tool) else {
            return .failure(.toolMissing(environment.commands.unavailableReason(for: tool)
                ?? "\(tool) was not found in a trusted location"))
        }
        let result = await environment.commands.run(executable: executable, arguments: arguments,
                                                    timeout: timeout, purpose: .readOnly)
        if result.timedOut { return .failure(.failed("\(tool) did not answer in time")) }
        guard result.exitCode == 0 else {
            return .failure(.failed("\(tool) \(arguments.first ?? "") failed (exit code \(result.exitCode))"))
        }
        guard result.stdout.utf8.count < maxTrustedOutputBytes else {
            return .failure(.failed("\(tool) output was too large to read safely"))
        }
        return .success(result.stdout)
    }

    /// `true` when `rule` is acted on by exactly `tool arguments` and declares every precondition in
    /// `required` (by name).
    ///
    /// SAFETY-DECISION: an inspector only emits items for the exact command it was written for. A
    /// rule whose command (or required precondition) differs from what the inspector expects gets
    /// no targets at all, so a rule edit can never pair this discovery with another command.
    static func ruleMatches(_ rule: Rule, tool: String, arguments: [String], required: [String]) -> Bool {
        guard case .command(let spec) = rule.action, spec.tool == tool, spec.arguments == arguments else { return false }
        let declared = Set(rule.preconditions.map(\.name))
        return required.allSatisfy { declared.contains($0) }
    }

    /// A non-path, informational `DiscoveredCandidate.path` for command items that have no folder
    /// of their own (Docker objects, Ollama models, simulator runtimes). It never starts with `/`,
    /// `~` or `{HOME}`, so nothing treats it as a file-system path.
    static func informationalPath(_ tool: String, _ item: String) -> String {
        "\(tool): \(item)"
    }

    /// Adds two byte counts without overflowing.
    static func add(_ a: Int64, _ b: Int64) -> Int64 {
        let (sum, overflow) = a.addingReportingOverflow(b)
        return overflow ? Int64.max : sum
    }

    /// Decimal (`kB`, `MB`, `GB`, Docker / Ollama style) and binary (`KiB`, …) human sizes:
    /// `"16.43GB"`, `"115.2kB"`, `"0B"`, `"4.7 GB"`. `nil` for anything else.
    static func parseHumanSize(_ text: String) -> Int64? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        var numberPart = ""
        var unitPart = ""
        var sawSpace = false
        for character in trimmed {
            if unitPart.isEmpty, !sawSpace, character.isASCII, character.isNumber || character == "." {
                numberPart.append(character)
            } else if character == " " && unitPart.isEmpty && !sawSpace {
                sawSpace = true
            } else {
                unitPart.append(character)
            }
        }
        guard !numberPart.isEmpty, numberPart.filter({ $0 == "." }).count <= 1,
              let value = Double(numberPart), value.isFinite, value >= 0 else { return nil }
        let multipliers: [String: Double] = [
            "b": 1,
            "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "pb": 1e15,
            "kib": 1024, "mib": 1_048_576, "gib": 1_073_741_824, "tib": 1_099_511_627_776,
        ]
        guard let multiplier = multipliers[unitPart.lowercased()] else { return nil }
        let bytes = value * multiplier
        guard bytes.isFinite, bytes < 9.0e18 else { return nil }
        return Int64(bytes.rounded())
    }

    /// One JSON object per non-empty line (`--format '{{json .}}'`). `nil` if any line is not an object.
    static func jsonLines(_ text: String) -> [[String: Any]]? {
        var objects: [[String: Any]] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            guard let data = trimmed.data(using: .utf8),
                  let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
            objects.append(object)
        }
        return objects
    }

    static func formatBytes(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}

// MARK: - simctl client

/// Read-only `xcrun simctl` queries and their defensive parsers.
public struct SimctlClient: Sendable {
    public static let tool = "xcrun"
    public static let listDevicesArguments = ["simctl", "list", "devices", "-j"]
    public static let listUnavailableDevicesArguments = ["simctl", "list", "devices", "unavailable", "-j"]
    public static let listRuntimesArguments = ["simctl", "runtime", "list", "-j"]
    /// Read-only listing timeout.
    static let timeout: TimeInterval = 60

    public struct Device: Sendable, Hashable {
        public let udid: String
        public let name: String
        public let state: String
        /// `nil` when simctl did not say.
        public let isAvailable: Bool?
        /// Runtime key the device was listed under (`com.apple.CoreSimulator.SimRuntime.iOS-27-0`).
        public let runtimeKey: String
        public let dataPath: String?
    }

    public struct Runtime: Sendable, Hashable {
        /// Disk-image identifier (UUID) — what `simctl runtime delete` is given.
        public let identifier: String
        public let runtimeIdentifier: String?
        public let platformIdentifier: String?
        public let version: String?
        public let build: String?
        public let state: String?
        public let deletable: Bool
        public let sizeBytes: Int64?
    }

    let environment: SafeCleanEnvironment

    public init(environment: SafeCleanEnvironment) {
        self.environment = environment
    }

    func devices(unavailableOnly: Bool) async -> Result<[Device], CommandDiscovery.Failure> {
        let arguments = unavailableOnly ? Self.listUnavailableDevicesArguments : Self.listDevicesArguments
        switch await CommandDiscovery.readOnly(Self.tool, arguments, timeout: Self.timeout, environment: environment) {
        case .failure(let failure): return .failure(failure)
        case .success(let json):
            guard let devices = Self.parseDevices(json: json) else {
                return .failure(.failed("Could not read the simulator list"))
            }
            return .success(devices)
        }
    }

    func runtimes() async -> Result<[Runtime], CommandDiscovery.Failure> {
        switch await CommandDiscovery.readOnly(Self.tool, Self.listRuntimesArguments, timeout: Self.timeout, environment: environment) {
        case .failure(let failure): return .failure(failure)
        case .success(let json):
            guard let runtimes = Self.parseRuntimes(json: json) else {
                return .failure(.failed("Could not read the simulator runtime list"))
            }
            return .success(runtimes)
        }
    }

    /// Parses `simctl list devices [-j]` output: `{"devices": {runtimeKey: [{udid, name, state, …}]}}`.
    ///
    /// SAFETY-DECISION: all or nothing — `nil` when the shape is unexpected, any device lacks a
    /// readable UDID / state / name, or any UDID is not a canonical upper-case UUID.
    @_spi(FixtureTesting)
    public static func parseDevices(json: String) -> [Device]? {
        guard let data = json.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let byRuntime = root["devices"] as? [String: Any] else { return nil }
        var devices: [Device] = []
        var seen = Set<String>()
        for runtimeKey in byRuntime.keys.sorted() {
            guard let list = byRuntime[runtimeKey] as? [Any] else { return nil }
            for entry in list {
                guard let object = entry as? [String: Any],
                      let udid = object["udid"] as? String, CommandItemKind.simulatorDeviceUDID.accepts(udid),
                      let state = object["state"] as? String,
                      let name = object["name"] as? String else { return nil }
                // SAFETY-DECISION: a UDID listed twice means the output cannot be trusted.
                guard seen.insert(udid).inserted else { return nil }
                let available: Bool?
                if let value = object["isAvailable"] {
                    guard let flag = value as? Bool else { return nil }
                    available = flag
                } else {
                    available = nil
                }
                let dataPath: String?
                if let value = object["dataPath"] {
                    guard let path = value as? String else { return nil }
                    dataPath = path
                } else {
                    dataPath = nil
                }
                devices.append(Device(udid: udid, name: name, state: state, isAvailable: available,
                                      runtimeKey: runtimeKey, dataPath: dataPath))
            }
        }
        return devices
    }

    /// Parses `simctl runtime list -j` output: `{uuid: {identifier, runtimeIdentifier, version, …}}`.
    ///
    /// SAFETY-DECISION: all or nothing — `nil` when the shape is unexpected, an entry's identifier is
    /// missing, malformed, or differs from its key.
    @_spi(FixtureTesting)
    public static func parseRuntimes(json: String) -> [Runtime]? {
        guard let data = json.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        var runtimes: [Runtime] = []
        for key in root.keys.sorted() {
            guard let object = root[key] as? [String: Any],
                  let identifier = object["identifier"] as? String,
                  identifier == key, CommandItemKind.simulatorDeviceUDID.accepts(identifier) else { return nil }
            let size: Int64?
            if let number = object["sizeBytes"] as? NSNumber, number.int64Value >= 0 {
                size = number.int64Value
            } else {
                size = nil
            }
            runtimes.append(Runtime(
                identifier: identifier,
                runtimeIdentifier: object["runtimeIdentifier"] as? String,
                platformIdentifier: object["platformIdentifier"] as? String,
                version: object["version"] as? String,
                build: object["build"] as? String,
                state: object["state"] as? String,
                // SAFETY-DECISION: only an explicit `"deletable": true` counts.
                deletable: (object["deletable"] as? Bool) == true,
                sizeBytes: size
            ))
        }
        return runtimes
    }

    /// `com.apple.CoreSimulator.SimRuntime.iOS-27-0` → `iOS 27.0`; anything else is returned as is.
    static func runtimeDisplayName(_ key: String) -> String {
        let prefix = "com.apple.CoreSimulator.SimRuntime."
        guard key.hasPrefix(prefix) else { return key }
        let rest = key.dropFirst(prefix.count)
        let parts = rest.split(separator: "-")
        guard let platform = parts.first, parts.count >= 2 else { return String(rest) }
        return "\(platform) " + parts.dropFirst().joined(separator: ".")
    }

    /// `com.apple.platform.iphonesimulator` → `iOS`, etc.
    static func platformDisplayName(_ identifier: String?) -> String? {
        guard let identifier else { return nil }
        let table = [
            "com.apple.platform.iphonesimulator": "iOS",
            "com.apple.platform.watchsimulator": "watchOS",
            "com.apple.platform.appletvsimulator": "tvOS",
            "com.apple.platform.xrsimulator": "visionOS",
        ]
        return table[identifier.lowercased()] ?? identifier
    }
}

// MARK: - Simulator device folders (read-only)

/// Read-only access to `{HOME}/Library/Developer/CoreSimulator/Devices/<UDID>`.
struct SimulatorDeviceFolders: Sendable {
    let environment: SafeCleanEnvironment
    let walker: InspectorWalker
    /// `{HOME}/Library/Developer/CoreSimulator/Devices` when it is reachable without symlinks.
    let devicesDirectory: String?
    let device: Int64?

    static let components = ["Library", "Developer", "CoreSimulator", "Devices"]

    init(environment: SafeCleanEnvironment) {
        self.environment = environment
        let walker = InspectorWalker(environment: environment)
        self.walker = walker
        let home = environment.homePath
        // SAFETY-DECISION: the folders are always derived from the home directory plus fixed
        // components plus a validated UDID — never from a path printed by simctl — and every step
        // must be a real directory (no symlink) on the home volume.
        if let homeStat = walker.realDirectory(home),
           let devices = walker.descend(from: home, through: Self.components, device: homeStat.device) {
            devicesDirectory = devices
            device = homeStat.device
        } else {
            devicesDirectory = nil
            device = nil
        }
    }

    /// The device folder when it exists as a real directory on the home volume.
    func folder(udid: String) -> String? {
        guard CommandItemKind.simulatorDeviceUDID.accepts(udid), let devicesDirectory, let device else { return nil }
        return walker.descend(from: devicesDirectory, through: [udid], device: device)
    }

    /// `true` when simctl's `dataPath` (if it printed one) is exactly `<folder>/data`.
    ///
    /// SAFETY-DECISION: a device whose data lives elsewhere (custom device set) is not offered.
    func dataPathAgrees(_ dataPath: String?, udid: String) -> Bool {
        guard let dataPath else { return true }
        let canonicalizer = PathCanonicalizer(environment: environment)
        guard case .success(let reported) = canonicalizer.lexical(dataPath) else { return false }
        let homes = PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        return homes.contains { home in
            let expected = home.components + Self.components + [udid, "data"]
            return PathComparison.equal(reported.components, expected)
        }
    }

    /// `max(mtime(folder), mtime(each immediate child))` via `lstat`; `nil` when anything is unreadable.
    func lastUsed(_ folder: String) -> Date? {
        let fs = environment.fileSystem
        guard let info = fs.lstat(folder), info.isDirectory, !info.isSymlink else { return nil }
        var latest = info.modificationDate
        guard let children = fs.contentsOfDirectory(folder) else { return nil }
        for child in children {
            guard InspectorWalker.isPlainName(child), let childStat = fs.lstat(folder + "/" + child) else { return nil }
            latest = max(latest, childStat.modificationDate)
        }
        return latest
    }
}

/// Expected command per simulator rule.
enum SimulatorRules {
    static let unavailableID = "simulator.unavailable"
    static let unavailableArguments = ["simctl", "delete", "unavailable"]
    static let staleDevicesID = "simulator.devices.stale"
    static let staleDevicesArguments = ["simctl", "delete", CommandSpec.itemToken]
    static let runtimesID = "simulator.runtimes"
    static let runtimesArguments = ["simctl", "runtime", "delete", CommandSpec.itemToken]
    static let requiredPreconditions = ["simulatorIdle"]
    /// Spec §6.1: stale = device folder not used in over 90 days.
    static let minimumStaleDays = 90
    static let mismatchMessage = "This rule does not match its simulator command"

    static func status(for failure: CommandDiscovery.Failure) -> String {
        switch failure {
        case .toolMissing: return "Xcode command-line tools (xcrun) are not available"
        case .failed(let reason): return reason
        }
    }

    static let undoNote = "This cannot be undone. Xcode will re-download what it needs."
}

// MARK: - simulator.unavailable

/// `simulator.unavailable` (Green): ONE command item (no argument) for
/// `xcrun simctl delete unavailable`, proposed only when `simctl list devices unavailable -j` lists at
/// least one device. Its size is the sum of those devices' folders under
/// `{HOME}/Library/Developer/CoreSimulator/Devices` (measured by the Scanner).
public struct SimctlUnavailableInspector: Inspector {
    public init() {}

    public var id: InspectorID { .simulatorUnavailable }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == SimulatorRules.unavailableID,
              CommandDiscovery.ruleMatches(rule, tool: SimctlClient.tool, arguments: SimulatorRules.unavailableArguments,
                                           required: SimulatorRules.requiredPreconditions) else {
            return InspectorOutput(candidates: [], status: .unavailable(SimulatorRules.mismatchMessage))
        }
        let devices: [SimctlClient.Device]
        switch await SimctlClient(environment: environment).devices(unavailableOnly: true) {
        case .failure(let failure): return InspectorOutput(candidates: [], status: .unavailable(SimulatorRules.status(for: failure)))
        case .success(let list): devices = list
        }
        // SAFETY-DECISION: a device simctl explicitly calls available in the "unavailable" listing
        // means iMop does not understand the output → fail closed.
        if devices.contains(where: { $0.isAvailable == true }) {
            return InspectorOutput(candidates: [], status: .unavailable("The simulator list was not what iMop expected"))
        }
        guard !devices.isEmpty else { return InspectorOutput(candidates: [], status: .ok) }

        let folders = SimulatorDeviceFolders(environment: environment)
        var sizePaths: [String] = []
        var names: [String] = []
        for device in devices {
            names.append("\(device.name) (\(SimctlClient.runtimeDisplayName(device.runtimeKey)))")
            // SAFETY-DECISION: the command removes every unavailable device at once, so every
            // existing folder is handed to the Scanner, which withholds the whole item if any of them
            // is protected or contains a protected item.
            if let folder = folders.folder(udid: device.udid) { sizePaths.append(folder) }
        }
        var notes = [
            "\(devices.count) simulator device\(devices.count == 1 ? "" : "s") no longer supported by the installed Xcode.",
        ]
        notes += names.prefix(20).map { "• \($0)" }
        if names.count > 20 { notes.append("… and \(names.count - 20) more") }
        if sizePaths.isEmpty { notes.append("Their folders were not found; the space they use is unknown.") }
        notes.append(SimulatorRules.undoNote)

        let path = folders.devicesDirectory ?? CommandDiscovery.informationalPath("simctl", "unavailable devices")
        let candidate = DiscoveredCandidate(
            commandItem: nil, path: path, displayName: "Unavailable simulators (\(devices.count))",
            sizePaths: sizePaths, reportedBytes: sizePaths.isEmpty ? 0 : nil, notes: notes)
        return InspectorOutput(candidates: [candidate], status: .ok)
    }
}

// MARK: - simulator.devices.stale

/// `simulator.devices.stale` (Yellow): one command item per simulator device (argument = UDID)
/// whose folder has not been used in over 90 days (or the rule's longer `olderThan`).
public struct SimctlDevicesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .simulatorDevices }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == SimulatorRules.staleDevicesID,
              CommandDiscovery.ruleMatches(rule, tool: SimctlClient.tool, arguments: SimulatorRules.staleDevicesArguments,
                                           required: SimulatorRules.requiredPreconditions) else {
            return InspectorOutput(candidates: [], status: .unavailable(SimulatorRules.mismatchMessage))
        }
        // SAFETY-DECISION: the rule's own `olderThan` may only raise the 90-day threshold.
        var days = SimulatorRules.minimumStaleDays
        for case .olderThan(days: let declared) in rule.preconditions where declared > days { days = declared }

        let devices: [SimctlClient.Device]
        switch await SimctlClient(environment: environment).devices(unavailableOnly: false) {
        case .failure(let failure): return InspectorOutput(candidates: [], status: .unavailable(SimulatorRules.status(for: failure)))
        case .success(let list): devices = list
        }

        let folders = SimulatorDeviceFolders(environment: environment)
        let now = environment.clock.now
        var candidates: [DiscoveredCandidate] = []
        for device in devices {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed("Scan cancelled")) }
            // SAFETY-DECISION: only devices that are fully shut down (never Booted, Booting,
            // Shutting Down, Creating or an unknown state).
            guard device.state.lowercased() == "shutdown" else { continue }
            // Unavailable devices belong to `simulator.unavailable`; a device of unknown
            // availability is not offered.
            guard device.isAvailable == true else { continue }
            guard folders.dataPathAgrees(device.dataPath, udid: device.udid) else { continue }
            guard let folder = folders.folder(udid: device.udid) else { continue }
            // SAFETY-DECISION: the age is computed exactly like the `olderThan` precondition; an
            // unreadable folder has no known age and is not offered. Exactly N days is not "older".
            guard let lastUsed = folders.lastUsed(folder),
                  now.timeIntervalSince(lastUsed) > TimeInterval(days) * 86_400 else { continue }

            let runtime = SimctlClient.runtimeDisplayName(device.runtimeKey)
            let notes = [
                "Runtime: \(runtime)",
                "UDID: \(device.udid)",
                "Not used in over \(days) days.",
                "Apps and data installed in this simulator are lost.",
                SimulatorRules.undoNote,
            ]
            candidates.append(DiscoveredCandidate(
                commandItem: device.udid, path: folder, displayName: "\(device.name) (\(runtime))",
                sizePaths: [folder], lastUsed: lastUsed, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}

// MARK: - simulator.runtimes

/// `simulator.runtimes` (Yellow, never preselected): one command item per deletable runtime image
/// (argument = its disk-image identifier) from `simctl runtime list -j`, sized by simctl's own
/// figure. iMop never reads or touches `/Library/Developer/CoreSimulator` itself.
public struct SimctlRuntimesInspector: Inspector {
    public init() {}

    public var id: InspectorID { .simulatorRuntimes }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == SimulatorRules.runtimesID,
              CommandDiscovery.ruleMatches(rule, tool: SimctlClient.tool, arguments: SimulatorRules.runtimesArguments,
                                           required: SimulatorRules.requiredPreconditions) else {
            return InspectorOutput(candidates: [], status: .unavailable(SimulatorRules.mismatchMessage))
        }
        let runtimes: [SimctlClient.Runtime]
        switch await SimctlClient(environment: environment).runtimes() {
        case .failure(let failure): return InspectorOutput(candidates: [], status: .unavailable(SimulatorRules.status(for: failure)))
        case .success(let list): runtimes = list
        }

        var candidates: [DiscoveredCandidate] = []
        for runtime in runtimes {
            // SAFETY-DECISION: only images simctl itself reports as deletable (bundled / system
            // runtimes report `deletable: false`).
            guard runtime.deletable else { continue }
            let platform = SimctlClient.platformDisplayName(runtime.platformIdentifier)
                ?? runtime.runtimeIdentifier.map(SimctlClient.runtimeDisplayName) ?? "Simulator"
            let version = runtime.version ?? "unknown version"
            var notes = ["Platform: \(platform)", "Version: \(version)"]
            if let build = runtime.build { notes.append("Build: \(build)") }
            if let state = runtime.state { notes.append("State: \(state)") }
            if let size = runtime.sizeBytes {
                notes.append("Size reported by simctl: \(CommandDiscovery.formatBytes(size)).")
            } else {
                notes.append("Size unknown: simctl did not report one.")
            }
            notes.append("Simulator devices that use this runtime become unavailable.")
            notes.append(SimulatorRules.undoNote)
            candidates.append(DiscoveredCandidate(
                commandItem: runtime.identifier,
                path: CommandDiscovery.informationalPath("simctl runtime", runtime.identifier),
                displayName: "\(platform) \(version) simulator runtime" + (runtime.build.map { " (\($0))" } ?? ""),
                reportedBytes: runtime.sizeBytes ?? 0, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}
