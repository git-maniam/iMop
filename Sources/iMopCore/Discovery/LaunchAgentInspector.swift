import Foundation

// Read-only inspector for orphaned per-user LaunchAgents (spec §6.9 `leftovers.launchAgents`, Red).
//
// Lists `{HOME}/Library/LaunchAgents/*.plist` through `SafeCleanEnvironment.fileSystem` only, parses
// each plist (bounded read) and proposes the agent ONLY when its program (`Program`, else
// `ProgramArguments[0]`) is an absolute path PROVEN absent and no other agent plist (in
// `{HOME}/Library/LaunchAgents` or the system-wide `/Library/LaunchAgents`) declares the same Label.
// `/Library/LaunchAgents` and `/Library/LaunchDaemons` are only READ (to find such duplicates and, for
// the OrphanDetector, still-installed background jobs); nothing there is ever offered. The action
// (`launchctl bootout gui/<uid> <plist>` then Trash) is performed by the Executor; nothing here
// modifies anything.

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

    // MARK: Job definitions (review M6)

    /// One job definition read from a launchd folder.
    public struct LaunchdJob: Sendable, Equatable {
        /// Absolute path of the plist.
        public let path: String
        public let label: String
        /// `Program`, else `ProgramArguments[0]`; `nil` when neither is a string (e.g. `BundleProgram`).
        public let program: String?
    }

    /// Every job of a set of launchd folders, or why they could not all be read.
    public enum JobListing: Sendable, Equatable {
        case jobs([LaunchdJob])
        case unreadable(String)
    }

    /// The user's own LaunchAgents folder plus the system-wide agent folders: every plist whose job
    /// `launchctl bootout gui/<uid>` could reach.
    public static func guiDomainAgentDirectories(environment: SafeCleanEnvironment) -> [String] {
        [environment.homePath + "/" + launchAgentsComponents.joined(separator: "/")] + environment.systemLocations.launchAgentDirectories
    }

    /// Reads the Label and program of every `*.plist` in `directories` (read-only, bounded).
    ///
    /// SAFETY-DECISION (review M6, fail closed): a folder that is PROVEN absent is skipped; a folder
    /// that cannot be listed (or whose existence cannot be decided, or that is a symlink), more than
    /// `maximumAgents` plists, or any plist that cannot be read makes the whole listing `.unreadable` —
    /// a duplicate Label or a still-installed job could hide in it. (A plist that was read but is no
    /// job definition launchd could load — not a dictionary, no string Label — is skipped.)
    public static func readJobs(in directories: [String], environment: SafeCleanEnvironment) -> JobListing {
        let fs = environment.fileSystem
        var jobs: [LaunchdJob] = []
        for directory in directories {
            switch XcodeDerivedDataInspector.existence(of: directory, fileSystem: fs) {
            case .absent: continue
            case .unknown: return .unreadable("Could not check \(directory)")
            case .exists: break
            }
            guard let info = fs.lstat(directory), info.isDirectory, !info.isSymlink,
                  let names = fs.contentsOfDirectory(directory) else {
                return .unreadable("Could not read \(directory)")
            }
            let plists = names.filter { InspectorWalker.isPlainName($0) && !$0.hasPrefix(".") && $0.hasSuffix(plistSuffix) }
            guard plists.count <= maximumAgents else { return .unreadable("Too many items in \(directory)") }
            for name in plists.sorted() {
                let path = directory + "/" + name
                // SAFETY-DECISION: a plist that cannot be READ (symlink, not a regular file, too large,
                // permission) may still be loaded by launchd → the listing is unreadable. One that was
                // read but is not a property-list dictionary with a string Label cannot be loaded by
                // launchd as a job at all, so it can neither collide with a Label nor run → skipped.
                guard let entryInfo = fs.lstat(path), entryInfo.isRegularFile, !entryInfo.isSymlink,
                      entryInfo.logicalSize >= 0, entryInfo.logicalSize <= DevToolsFileReader.maxMetadataBytes,
                      let data = fs.readFile(path), Int64(data.count) <= DevToolsFileReader.maxMetadataBytes else {
                    return .unreadable("Could not read \(path)")
                }
                guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                      let plist = object as? [String: Any],
                      let label = plist["Label"] as? String, !label.isEmpty else { continue }
                var program: String?
                if let text = plist["Program"] as? String {
                    program = text
                } else if let arguments = plist["ProgramArguments"] as? [Any], let first = arguments.first as? String {
                    program = first
                }
                jobs.append(LaunchdJob(path: path, label: label, program: program))
            }
        }
        return .jobs(jobs)
    }

    /// Why the agent at `path` with `label` may not be booted out because another plist declares the
    /// same Label (case-insensitive), or the folders could not all be read; `nil` when it is unique.
    public static func duplicateLabelProblem(label: String, path: String, jobs listing: JobListing) -> String? {
        let jobs: [LaunchdJob]
        switch listing {
        case .unreadable(let why): return "Could not make sure no other background item uses this label (\(why))"
        case .jobs(let list): jobs = list
        }
        let wanted = PathComparison.normalize(label)
        let own = PathComparison.normalize(path)
        for job in jobs where PathComparison.normalize(job.path) != own && PathComparison.normalize(job.label) == wanted {
            return "Another background item (\((job.path as NSString).lastPathComponent)) uses the same label \(label)"
        }
        return nil
    }

    /// Why the LaunchAgent plist at `path` is NOT (or no longer provably) orphaned, or `nil` when it
    /// still parses exactly like the scan saw it, its Label is exactly `expectedLabel` (the label the
    /// user confirmed, pinned as the target's owner), no other agent plist declares that Label, and its
    /// program is still PROVEN missing.
    ///
    /// SAFETY-DECISION: the scan's own parser and existence proof are reused, so execute is never
    /// more permissive than discovery: any read / parse problem, another Label, a duplicate Label, a
    /// program that exists again, or one whose absence cannot be proven (permission, symlink,
    /// `/Volumes/…` drive that may only be disconnected) means the agent is left alone.
    public static func orphanProblem(path: String, expectedLabel: String?, environment: SafeCleanEnvironment) -> String? {
        let fileSystem = environment.fileSystem
        guard let info = fileSystem.lstat(path), info.isRegularFile, !info.isSymlink,
              let plist = DevToolsFileReader.readPlistDictionary(path, fileSystem: fileSystem) else {
            return "The LaunchAgent could not be read"
        }
        guard let agent = parseAgent(plist) else {
            return "The LaunchAgent's label or program could not be determined"
        }
        // SAFETY-DECISION (review M6): `launchctl bootout` acts on the Label inside the file; it must be
        // exactly the one the user reviewed.
        guard let expectedLabel, agent.label == expectedLabel else {
            return "The LaunchAgent's label changed since it was reviewed"
        }
        if let problem = duplicateLabelProblem(label: agent.label, path: path,
                                               jobs: readJobs(in: guiDomainAgentDirectories(environment: environment), environment: environment)) {
            return problem
        }
        switch programState(agent.program, fileSystem: fileSystem) {
        case .missing: return nil
        case .exists: return "The LaunchAgent's program (\(agent.program)) exists again"
        case .unknown: return "Could not prove that the LaunchAgent's program (\(agent.program)) is gone"
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
        case .declined: return InspectorOutput(candidates: [], status: .unavailable(SafeCleanScanner.accessDeclinedMessage))
        case .entries(let list): entries = list
        }
        let denyFilter = InspectorDenyFilter(environment: environment)
        let ruleExcluded = Set(rule.excludedNames.map(PathComparison.normalize))
        // SAFETY-DECISION (review M6): bootout acts on the Label; an agent whose Label any other plist
        // (here or in /Library/LaunchAgents) also declares is never offered, and if those folders
        // cannot all be read nothing is offered.
        let allJobs = Self.readJobs(in: Self.guiDomainAgentDirectories(environment: environment), environment: environment)
        if case .unreadable(let why) = allJobs {
            return InspectorOutput(candidates: [], status: .unavailable("Could not read every background item definition (\(why))"))
        }

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
            guard Self.programState(agent.program, fileSystem: environment.fileSystem) == .missing,
                  Self.duplicateLabelProblem(label: agent.label, path: entry.path, jobs: allJobs) == nil else { continue }
            candidates.append(DiscoveredCandidate(
                path: entry.path,
                displayName: agent.label,
                // SAFETY-DECISION (review M6): the Label is pinned as the owner (hashed into the
                // confirmed plan) and must still be exactly this at execute time.
                owningBundleID: agent.label,
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
