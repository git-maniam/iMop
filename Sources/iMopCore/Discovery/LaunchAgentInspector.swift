import Foundation

// Read-only inspector for orphaned per-user LaunchAgents (spec §6.9 `leftovers.launchAgents`, Red).
//
// Lists `{HOME}/Library/LaunchAgents/*.plist` through `SafeCleanEnvironment.fileSystem` only, parses
// each plist (bounded read) and proposes the agent ONLY when its program (`Program`, else
// `ProgramArguments[0]`) is an absolute path PROVEN absent. Never looks at `/Library/LaunchAgents` or
// `/Library/LaunchDaemons` (root-owned, Advisory only). The action (`launchctl bootout gui/<uid>
// <plist>` then Trash) is performed by the Executor; nothing here modifies anything.

/// `leftovers.launchAgents` (Red): `{HOME}/Library/LaunchAgents/<name>.plist` whose program no longer exists.
public struct OrphanedLaunchAgentsInspector: Inspector {
    public static let ruleID = "leftovers.launchAgents"
    static let launchAgentsComponents = ["Library", "LaunchAgents"]
    /// SAFETY-DECISION: at most this many plists are examined per scan (bounded work).
    public static let maximumAgents = 2_000
    static let plistSuffix = ".plist"

    public init() {}

    public var id: InspectorID { .orphanedLaunchAgents }

    /// Label and program of a parsed agent plist.
    public struct ParsedAgent: Sendable, Equatable {
        public let label: String
        /// Absolute path of the program launchd would run.
        public let program: String
    }

    /// Parses an agent plist dictionary. `nil` (the agent is not offered) when:
    /// - `Label` is missing, not a string, empty, padded, holds control characters, or is Apple's;
    /// - `BundleProgram` is present (relative to an app bundle);
    /// - `Program` is present but not a string, or absent and `ProgramArguments` is not a non-empty
    ///   string array;
    /// - the program is not an absolute, clean path (no `~`, `..`, NUL, relative names resolved by PATH).
    public static func parseAgent(_ plist: [String: Any]) -> ParsedAgent? {
        guard let label = plist["Label"] as? String, !label.isEmpty, label.count <= 1024,
              label.trimmingCharacters(in: .whitespacesAndNewlines) == label,
              !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !OrphanEvaluator.isAppleIdentifier(label) else { return nil }
        // SAFETY-DECISION: SMAppService-style agents name their program relative to an app bundle;
        // whether it exists cannot be decided here.
        guard plist["BundleProgram"] == nil else { return nil }
        let program: String
        if let raw = plist["Program"] {
            guard let text = raw as? String else { return nil }
            program = text
        } else {
            guard let arguments = plist["ProgramArguments"] as? [Any], let first = arguments.first as? String,
                  arguments.allSatisfy({ $0 is String }) else { return nil }
            program = first
        }
        guard isCleanAbsolutePath(program) else { return nil }
        return ParsedAgent(label: label, program: program)
    }

    /// Absolute, no NUL, no empty / `.` / `..` component (one trailing slash is tolerated).
    static func isCleanAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), path.count > 1, path.count <= 4096, !path.contains("\0") else { return false }
        var parts = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        if parts.last == "" { parts.removeLast() }
        return !parts.isEmpty && parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    /// Whether the agent's program is missing.
    public enum ProgramState: Sendable, Equatable {
        case exists
        /// Proven absent (its nearest existing ancestor was listed and the next component is missing).
        case missing
        /// Existence could not be proven either way (permission, symlink on the way, mount area, …).
        case unknown
    }

    /// SAFETY-DECISION: reuses the DerivedData existence proof: an `lstat` failure alone is never
    /// proof of absence, a path through a symlink or under a mount area (`/Volumes`, …: a drive that
    /// may simply be disconnected) is `unknown`, and a dangling symlink at the end counts as existing.
    public static func programState(_ program: String, fileSystem: any FileSystemProbe) -> ProgramState {
        switch XcodeDerivedDataInspector.existence(of: program, fileSystem: fileSystem) {
        case .exists: return .exists
        case .absent: return .missing
        case .unknown: return .unknown
        }
    }

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        // SAFETY-DECISION: an unknown rule id bound to this inspector gets nothing.
        guard rule.id == Self.ruleID else {
            return InspectorOutput(candidates: [], status: .unavailable("Not the launch agents rule"))
        }
        let walker = InspectorWalker(environment: environment)
        let home = environment.homePath
        guard let homeStat = walker.realDirectory(home),
              let directory = walker.descend(from: home, through: Self.launchAgentsComponents, device: homeStat.device) else {
            return InspectorOutput(candidates: [], status: .ok)
        }
        let device = homeStat.device
        let entries: [InspectorWalker.Entry]
        switch walker.list(directory, device: device) {
        case .absent: return InspectorOutput(candidates: [], status: .ok)
        case .declined: return InspectorOutput(candidates: [], status: .unavailable("Access was declined"))
        case .entries(let list): entries = list
        }
        let denyFilter = InspectorDenyFilter(environment: environment)
        let ruleExcluded = Set(rule.excludedNames.map(PathComparison.normalize))

        var candidates: [DiscoveredCandidate] = []
        for entry in entries.prefix(Self.maximumAgents) {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage)) }
            guard Self.isAgentFileName(entry.name),
                  entry.stat.isRegularFile, !entry.stat.isSymlink, entry.stat.device == device,
                  !ruleExcluded.contains(PathComparison.normalize(entry.name)),
                  !denyFilter.isDenied(entry.path, ruleID: rule.id) else { continue }
            // SAFETY-DECISION: any read / parse failure → not offered.
            guard let plist = DevToolsFileReader.readPlistDictionary(entry.path, fileSystem: environment.fileSystem),
                  let agent = Self.parseAgent(plist) else { continue }
            guard Self.programState(agent.program, fileSystem: environment.fileSystem) == .missing else { continue }
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: agent.label,
                owningBundleID: nil,
                notes: [
                    "Label: \(agent.label)",
                    "Missing program: \(agent.program)",
                    "The program this background item starts no longer exists, so it can no longer run.",
                    "iMop first unloads it (launchctl bootout) and then moves \(entry.name) to the Trash.",
                ]
            ))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    /// `<name>.plist`: a plain, non-hidden name with the exact lowercase `.plist` extension whose
    /// base is not Apple's.
    static func isAgentFileName(_ name: String) -> Bool {
        guard InspectorWalker.isPlainName(name), !name.hasPrefix("."),
              name.hasSuffix(plistSuffix), name.count > plistSuffix.count else { return false }
        let base = String(name.dropLast(plistSuffix.count))
        return !OrphanEvaluator.isAppleIdentifier(base)
    }

    /// Target shape for `RuleTargetMatcher`: exactly `Library/LaunchAgents/<name>.plist` (never deeper,
    /// never Apple's).
    public static func matchesTargetShape(relative: [String]) -> Bool {
        relative.count == launchAgentsComponents.count + 1
            && XcodeInspectorSupport.hasPrefix(relative, launchAgentsComponents)
            && isAgentFileName(relative[relative.count - 1])
    }
}
