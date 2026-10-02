import Foundation

/// Outcome of one named precondition (spec §3.6), shown in the item detail view.
public struct PreconditionResult: Sendable, Hashable {
    /// `Precondition.name`.
    public let name: String
    public let passed: Bool
    /// User-facing explanation, e.g. "Xcode is running — quit it to clean".
    public let detail: String

    public init(name: String, passed: Bool, detail: String) {
        self.name = name
        self.passed = passed
        self.detail = detail
    }
}

/// Evaluates the named predicates of spec §3.6 against the injected environment.
///
/// Every predicate FAILS CLOSED: if anything it depends on is unavailable (nil, error, timeout,
/// malformed output), the result is `passed == false`.
public struct PreconditionEvaluator: Sendable {
    private let environment: SafeCleanEnvironment
    private let canonicalizer: PathCanonicalizer
    private let ageThresholdOverrides: [String: Int]
    /// Test-only (see `DenyList.init(homeDirectory:waivedSystemRoots:)`); used to validate project roots.
    private let waivedSystemRoots: [String]

    static let simctlTimeout: TimeInterval = 30
    static let dockerTimeout: TimeInterval = 5
    static let hdiutilTimeout: TimeInterval = 30
    static let xcodeSelectTimeout: TimeInterval = 30
    static let simulatorAppBundleID = "com.apple.iphonesimulator"
    static let secondsPerDay: TimeInterval = 86_400

    /// Timeout of the read-only `git ls-files` probe (`notTrackedByGit`).
    static let gitTimeout: TimeInterval = 30
    /// SAFETY-DECISION: the git probe only ever runs the SIP-protected system git.
    static let systemGitPath = "/usr/bin/git"

    /// - Parameter ageThresholdOverrides: rule ID → days (Settings → age thresholds). Merged with
    ///   `environment.scanSettings.ageThresholdOverrides`; the larger value wins.
    public init(environment: SafeCleanEnvironment, ageThresholdOverrides: [String: Int] = [:]) {
        self.environment = environment
        self.canonicalizer = PathCanonicalizer(environment: environment)
        // SAFETY-DECISION: both override sources may only RAISE a threshold, so merging keeps the larger.
        self.ageThresholdOverrides = ageThresholdOverrides.merging(environment.scanSettings.ageThresholdOverrides) { max($0, $1) }
        self.waivedSystemRoots = []
    }

    /// Test-only: fixture homes live under `/private/var/folders`, which is deny-listed.
    @_spi(FixtureTesting)
    public init(environment: SafeCleanEnvironment, ageThresholdOverrides: [String: Int], waivedSystemRoots: [String]) {
        self.environment = environment
        self.canonicalizer = PathCanonicalizer(environment: environment)
        self.ageThresholdOverrides = ageThresholdOverrides.merging(environment.scanSettings.ageThresholdOverrides) { max($0, $1) }
        self.waivedSystemRoots = waivedSystemRoots
    }

    // MARK: - Public API

    /// Evaluates every precondition the rule declares, plus the implicit `ownedByUser` and
    /// `notInsideCloudRoot` for filesystem targets. Declared preconditions come first, in rule order.
    public func evaluateAll(rule: Rule, target: ScanTarget) async -> [PreconditionResult] {
        var list = rule.preconditions
        if case .filesystem = target.kind {
            for implicit in [Precondition.ownedByUser, .notInsideCloudRoot] where !list.contains(implicit) {
                list.append(implicit)
            }
        }
        var results: [PreconditionResult] = []
        results.reserveCapacity(list.count)
        for precondition in list {
            results.append(await evaluate(precondition, target: target, rule: rule))
        }
        return results
    }

    public func evaluate(_ precondition: Precondition, target: ScanTarget, rule: Rule) async -> PreconditionResult {
        let name = precondition.name
        let outcome: (passed: Bool, detail: String)
        switch precondition {
        case .appNotRunning(let ids):
            outcome = appNotRunning(ids)
        case .owningAppNotRunning:
            outcome = owningAppNotRunning(target)
        case .processNotRunning(let names):
            outcome = processNotRunning(names)
        case .notOpenByAnyProcess:
            outcome = notOpenByAnyProcess(target)
        case .olderThan(let days):
            outcome = olderThan(days: days, target: target, rule: rule)
        case .manifestPresent(let names):
            outcome = manifestPresent(names, target: target)
        case .notInsideCloudRoot:
            outcome = notInsideCloudRoot(target)
        case .ownedByUser:
            outcome = ownedByUser(target)
        case .simulatorIdle:
            outcome = await simulatorIdle()
        case .dockerDaemonReachable:
            outcome = await dockerDaemonReachable()
        case .notMounted:
            outcome = await notMounted(target)
        case .appleSigned:
            outcome = appleSigned(target)
        case .notSelectedXcode:
            outcome = await notSelectedXcode(target)
        case .projectOlderThan(let days):
            outcome = projectOlderThan(days: days, target: target, rule: rule)
        case .notTrackedByGit:
            outcome = await notTrackedByGit(target)
        case .stillOrphaned:
            outcome = await stillOrphaned(target)
        case .uploadedToCloud:
            // SAFETY-DECISION: always false in v1. iCloud eviction stays Advisory (Finder's
            // "Remove Download"); iMop never acts on ubiquitous items.
            outcome = (false, "iCloud items are never removed by iMop — use Finder's “Remove Download”")
        }
        return PreconditionResult(name: name, passed: outcome.passed, detail: outcome.detail)
    }

    // MARK: - Running applications

    private func appNotRunning(_ ids: [String]) -> (Bool, String) {
        // SAFETY-DECISION: an empty list is a malformed rule; it cannot prove anything → fail closed.
        guard !ids.isEmpty else { return (false, "No application to check was specified") }
        guard let running = environment.runningApplications.runningBundleIdentifiers() else {
            return (false, "Could not check which apps are running")
        }
        for pattern in ids {
            guard let matcher = BundleIDPattern(pattern) else {
                // SAFETY-DECISION: a malformed pattern cannot be evaluated → treat as running.
                return (false, "Could not check whether \(pattern) is running")
            }
            if let hit = running.first(where: matcher.matches) {
                return (false, "\(appDisplayName(hit)) is running — quit it to clean")
            }
        }
        return (true, "Not running")
    }

    private func owningAppNotRunning(_ target: ScanTarget) -> (Bool, String) {
        guard let owner = target.owningBundleID?.trimmingCharacters(in: .whitespacesAndNewlines),
              !owner.isEmpty else {
            return (false, "The app that owns this item is unknown")
        }
        guard let running = environment.runningApplications.runningBundleIdentifiers() else {
            return (false, "Could not check which apps are running")
        }
        // SAFETY-DECISION: the owning bundle ID is data, not a pattern — matched exactly
        // (case-insensitive); a "*" in it is never treated as a wildcard.
        let wanted = PathComparison.normalize(owner)
        if let hit = running.first(where: { PathComparison.normalize($0) == wanted }) {
            return (false, "\(appDisplayName(hit)) is running — quit it to clean")
        }
        return (true, "Not running")
    }

    /// Display name for a running bundle ID ("Xcode"), falling back to the identifier itself.
    private func appDisplayName(_ bundleID: String) -> String {
        if let url = environment.applications.applicationURLs(forBundleIdentifier: bundleID)?.first {
            let name = url.deletingPathExtension().lastPathComponent
            if !name.isEmpty { return name }
        }
        return bundleID
    }

    // MARK: - Processes

    private func processNotRunning(_ names: [String]) -> (Bool, String) {
        guard !names.isEmpty else { return (false, "No process to check was specified") }
        guard let running = environment.processes.runningProcessNames() else {
            return (false, "Could not check which processes are running")
        }
        let runningNormalized = running.map(PathComparison.normalize).filter { !$0.isEmpty }
        for name in names {
            let wanted = PathComparison.normalize(name)
            // SAFETY-DECISION: an empty name cannot be checked → fail closed.
            guard !wanted.isEmpty else { return (false, "Could not check an unnamed process") }
            // SAFETY-DECISION: names are compared case-insensitively (matches more → fails more).
            // proc_name truncates long names, so a running name of 15+ characters that is a prefix of
            // the requested name counts as the requested process.
            let isRunning = runningNormalized.contains { candidate in
                candidate == wanted || (candidate.count >= 15 && wanted.hasPrefix(candidate))
            }
            if isRunning {
                return (false, "\(name) is running — wait for it to finish or quit it to clean")
            }
        }
        return (true, "Not running")
    }

    private func notOpenByAnyProcess(_ target: ScanTarget) -> (Bool, String) {
        guard let path = lexicalPath(target) else {
            return (false, "Could not check whether this item is in use")
        }
        guard let pids = environment.processes.pidsWithOpenFiles(under: path.path) else {
            return (false, "Could not check whether this item is in use")
        }
        guard pids.isEmpty else {
            return (false, "In use by \(pids.count) process\(pids.count == 1 ? "" : "es") — quit them to clean")
        }
        return (true, "Not in use")
    }

    // MARK: - Age

    private func olderThan(days declared: Int, target: ScanTarget, rule: Rule) -> (Bool, String) {
        // SAFETY-DECISION: a negative day count is a malformed rule → fail closed.
        guard declared >= 0 else { return (false, "Invalid age threshold") }
        // SAFETY-DECISION: a user override may only RAISE the rule's threshold, never lower it.
        var days = declared
        if let override = ageThresholdOverrides[rule.id], override > days {
            days = override
        }
        guard let lastUsed = lastUsedDate(target) else {
            return (false, "Could not determine when this was last used")
        }
        let age = environment.clock.now.timeIntervalSince(lastUsed)
        // "Older than N days" is strict: exactly N days old does not qualify. A future mtime
        // (clock skew) gives a negative age and fails.
        guard age > TimeInterval(days) * Self.secondsPerDay else {
            return (false, "Used within the last \(days) day\(days == 1 ? "" : "s")")
        }
        return (true, "Not used in over \(days) day\(days == 1 ? "" : "s")")
    }

    /// `max(mtime(target), mtime(each immediate child))`, all via `lstat` (never atime, never
    /// following symlinks). `nil` when anything cannot be read.
    func lastUsedDate(_ target: ScanTarget) -> Date? {
        let fs = environment.fileSystem
        guard let path = lexicalPath(target), let stat = fs.lstat(path.path) else { return nil }
        var latest = stat.modificationDate
        if stat.isDirectory {
            // SAFETY-DECISION: an unreadable directory listing, or a child that vanished between
            // listing and lstat, means "last used" is unknown → nil (fail closed).
            guard let children = fs.contentsOfDirectory(path.path) else { return nil }
            for child in children {
                guard Self.isPlainName(child), let childStat = fs.lstat(path.appending(child).path) else {
                    return nil
                }
                latest = max(latest, childStat.modificationDate)
            }
        }
        return latest
    }

    // MARK: - Projects (spec §6.5)

    /// Every rebuild manifest of every ProjectScanner artifact kind (at most one `*` each).
    ///
    /// SAFETY-DECISION: `projectOlderThan` considers ALL of these that are present beside the artifact
    /// (plus the rule's own `manifestPresent` names), not only the artifact's own manifest: more files
    /// can only make the project look more recently used.
    static let projectManifestPatterns: [String] = [
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock",
        "Cargo.toml", "Cargo.lock",
        "pyproject.toml", "requirements*.txt", "uv.lock", "poetry.lock", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
        "Podfile", "Podfile.lock",
        "next.config.*",
        "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
        "Package.swift", "Package.resolved",
    ]

    private func projectOlderThan(days declared: Int, target: ScanTarget, rule: Rule) -> (Bool, String) {
        guard declared >= 0 else { return (false, "Invalid age threshold") }
        var days = declared
        if let override = ageThresholdOverrides[rule.id], override > days { days = override }
        guard let lastUsed = projectLastUsedDate(target, rule: rule) else {
            return (false, "Could not determine when this project was last used")
        }
        let age = environment.clock.now.timeIntervalSince(lastUsed)
        guard age > TimeInterval(days) * Self.secondsPerDay else {
            return (false, "Project used within the last \(days) day\(days == 1 ? "" : "s")")
        }
        return (true, "Project not used in over \(days) day\(days == 1 ? "" : "s")")
    }

    /// Max `lstat` mtime of every manifest beside the artifact, `.git/index` and `.git/HEAD`.
    ///
    /// SAFETY-DECISION (fail closed → nil): an unreadable project listing; a listed manifest or git
    /// file that cannot be lstat'ed; a manifest or git file that is a symlink; a `.git` that is not a
    /// plain directory (worktree / submodule `.git` files point elsewhere, so the real activity cannot
    /// be measured); or none of the files present at all.
    func projectLastUsedDate(_ target: ScanTarget, rule: Rule) -> Date? {
        let fs = environment.fileSystem
        guard let path = lexicalPath(target), let project = path.parent, !project.components.isEmpty else { return nil }
        guard let siblings = fs.contentsOfDirectory(project.path) else { return nil }
        var patterns = Self.projectManifestPatterns
        for case .manifestPresent(let names) in rule.preconditions {
            for name in names where !patterns.contains(name) { patterns.append(name) }
        }
        var latest: Date?
        func include(_ date: Date) { latest = max(latest ?? date, date) }

        let artifactName = path.lastComponent.map(PathComparison.normalize)
        for name in siblings where Self.isPlainName(name) {
            guard PathComparison.normalize(name) != artifactName else { continue }
            guard patterns.contains(where: { Self.manifestPatternMatches($0, name) }) else { continue }
            guard let stat = fs.lstat(project.appending(name).path), !stat.isSymlink else { return nil }
            include(stat.modificationDate)
        }
        if let gitName = siblings.first(where: { PathComparison.normalize($0) == ".git" }) {
            let git = project.appending(gitName)
            guard let gitStat = fs.lstat(git.path), gitStat.isDirectory, !gitStat.isSymlink,
                  let gitChildren = fs.contentsOfDirectory(git.path) else { return nil }
            for wanted in ["index", "HEAD"] {
                guard let child = gitChildren.first(where: { PathComparison.normalize($0) == PathComparison.normalize(wanted) }) else {
                    continue // missing optional file
                }
                guard Self.isPlainName(child), let stat = fs.lstat(git.appending(child).path), !stat.isSymlink else { return nil }
                include(stat.modificationDate)
            }
        }
        return latest
    }

    private func notTrackedByGit(_ target: ScanTarget) async -> (Bool, String) {
        let tracked = (false, "Could not confirm that git does not track it — treated as tracked")
        let fs = environment.fileSystem
        guard let path = lexicalPath(target), let name = path.lastComponent, let project = path.parent,
              !project.components.isEmpty else { return tracked }
        // SAFETY-DECISION: the artifact name must be exactly one of the reviewed ProjectScanner names
        // (it becomes a git pathspec argument).
        guard CommandAllowList.projectArtifactNames.contains(name) else { return tracked }

        // SAFETY-DECISION: the project directory must be canonical (no symlink on the way) and inside
        // (or equal to) one of the user's validated project roots before git is ever pointed at it.
        guard case .success(let resolvedProject) = canonicalizer.canonicalize(project.path), resolvedProject == project else {
            return tracked
        }
        let roots = ProjectRoots.resolve(environment: environment, waivedSystemRoots: waivedSystemRoots)
        guard roots.contains(where: { project.isInsideOrEqual($0) }) else {
            return (false, "Not inside one of your project folders")
        }

        // SAFETY-DECISION: a repository can live in the project folder or in any folder above it
        // (monorepos, a dotfiles repository in the home folder): every directory from the project up
        // to and including the home folder is checked for `.git`. Git itself then discovers the
        // repository from the project directory. A directory on the way that cannot be listed could
        // hide a repository → treated as tracked.
        let homes = Self.homeForms(environment: environment, canonicalizer: canonicalizer)
        guard homes.contains(where: { project.isStrictlyInside($0) }) else { return tracked }
        var current: CanonicalPath? = project
        var repository: CanonicalPath?
        while let directory = current, !directory.components.isEmpty {
            guard let entries = fs.contentsOfDirectory(directory.path) else { return tracked }
            // SAFETY-DECISION (review M5): git is not the only version-control system. A Mercurial,
            // Subversion, Jujutsu, Sapling, Fossil, Bazaar, … checkout anywhere from the project up to
            // the home folder may track the artifact, and iMop never runs those tools: treated as
            // tracked. (Checked before `.git`, so a colocated checkout is refused too.)
            if entries.contains(where: Self.isOtherVersionControlMarker) {
                return (false, "Inside a non-git version-control checkout — treated as tracked")
            }
            if entries.contains(where: { PathComparison.normalize($0) == ".git" }) {
                repository = directory
                break
            }
            if homes.contains(directory) { break }
            current = directory.parent
        }
        guard let repository else { return (true, "Not in a git repository") }
        // SAFETY-DECISION (review M5): git is only asked when the artifact's OWN folder is the
        // repository's top level (like ProjectScanner's `mayPropose`). Inside a monorepo the probe's
        // `-C` prefix would be matched case-sensitively by git even with `--icase-pathspecs`, so a
        // differently-cased index prefix could read as "untracked": treated as tracked instead.
        guard repository == project else {
            return (false, "Part of a git repository in a parent folder — treated as tracked")
        }

        // SAFETY-DECISION: only the SIP-protected system git is ever run, read-only, through the
        // allow-listed probe; every outcome except a clean "did not match" counts as tracked.
        guard let git = environment.commands.resolveExecutable("git"), git == Self.systemGitPath else { return tracked }
        // SAFETY-DECISION (review M5): `/usr/bin/git` is the xcode-select shim. Without Xcode or the
        // Command Line Tools, running it opens the "install developer tools" dialog (a visible side
        // effect, once per validation). The active developer directory (`xcode-select -p`, read-only,
        // no dialog) must contain `usr/bin/git` first; otherwise git is never run → tracked.
        guard await developerToolsProvideGit() else {
            return (false, "Git is not available (no developer tools installed) — treated as tracked")
        }
        let arguments = CommandAllowList.gitTrackedProbeArguments(projectDirectory: project.path, artifactName: name)
        guard CommandAllowList.gitProbeAllowed(arguments: arguments, projectRoots: roots) else { return tracked }
        let result = await environment.commands.run(executable: git, arguments: arguments, timeout: Self.gitTimeout,
                                                    purpose: .readOnly)
        guard Self.gitReportsUntracked(result) else {
            if result.exitCode == 0 && !result.timedOut {
                return (false, "Tracked by git — iMop never removes files that are part of your repository")
            }
            return tracked
        }
        return (true, "Not tracked by git")
    }

    /// Names (compared case- and Unicode-insensitively) of the working-copy markers of version-control
    /// systems other than git.
    static let otherVersionControlMarkers: Set<String> = [
        ".hg", ".svn", ".jj", ".sl", ".fslckout", "_fossil_", ".bzr", "_darcs", ".pijul", "cvs",
    ]

    /// `true` when `name` is a non-git version-control marker (`otherVersionControlMarkers`).
    public static func isOtherVersionControlMarker(_ name: String) -> Bool {
        otherVersionControlMarkers.contains(PathComparison.normalize(name))
    }

    /// `true` when the active developer directory (`xcode-select -p`) holds a `usr/bin/git` file, so
    /// running the `/usr/bin/git` shim cannot open the developer-tools install dialog.
    private func developerToolsProvideGit() async -> Bool {
        guard let tool = environment.commands.resolveExecutable("xcode-select") else { return false }
        let result = await environment.commands.run(executable: tool, arguments: ["-p"], timeout: Self.xcodeSelectTimeout,
                                                    purpose: .readOnly)
        guard result.succeeded, !result.timedOut else { return false }
        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !output.isEmpty, !output.contains("\n"), output.hasPrefix("/"),
              case .success(let developer) = PathCanonicalizer.clean(output, home: nil) else { return false }
        let git = developer.appending("usr").appending("bin").appending("git")
        guard let info = environment.fileSystem.stat(git.path), info.isRegularFile else { return false }
        return true
    }

    /// `true` only for a completed run with exit status 1 whose stderr is git's pathspec "did not
    /// match" error (`error: pathspec 'X' did not match any file(s) known to git`).
    static func gitReportsUntracked(_ result: CommandResult) -> Bool {
        guard !result.timedOut, result.exitCode == 1 else { return false }
        let stderr = result.stderr.lowercased()
        return stderr.contains("pathspec") && stderr.contains("did not match")
    }

    // MARK: - OrphanDetector (spec §6.9, Milestone 6)

    /// Conditions 2, 3 and 4 of spec §6.9 (plus the identifier shape, Apple prefix, disconnected
    /// drives, Setapp, background jobs and — for Group Containers — app groups / Team IDs; review M6)
    /// for `target.owningBundleID` at `target.path`, re-checked at plan AND execute time by the OrphanDetector's
    /// own evaluator (`OrphanEvaluator.stillOrphaned`), so scan and execute share one implementation.
    ///
    /// SAFETY-DECISION: fails closed — no owner, an owner that is not an orphan-candidate identifier
    /// (`RuleTargetMatcher.isOrphanCandidateIdentifier`), or any lookup that errs / times out / answers
    /// ambiguously means "not orphaned".
    private func stillOrphaned(_ target: ScanTarget) async -> (Bool, String) {
        guard let owner = target.owningBundleID, !owner.isEmpty,
              owner == owner.trimmingCharacters(in: .whitespacesAndNewlines),
              RuleTargetMatcher.isOrphanCandidateIdentifier(owner) else {
            return (false, "The app this belongs to is unknown — treated as installed")
        }
        let outcome = await OrphanEvaluator.preconditionOutcome(owningBundleID: owner, targetPath: target.path, environment: environment)
        return (outcome.passed, outcome.detail)
    }

    // MARK: - Manifests

    private func manifestPresent(_ patterns: [String], target: ScanTarget) -> (Bool, String) {
        let fs = environment.fileSystem
        guard let path = lexicalPath(target), let parent = path.parent else {
            return (false, "Could not look for a rebuild manifest")
        }
        guard let siblings = fs.contentsOfDirectory(parent.path) else {
            return (false, "Could not look for a rebuild manifest")
        }
        for pattern in patterns {
            for name in siblings where Self.isPlainName(name) && Self.manifestPatternMatches(pattern, name) {
                // SAFETY-DECISION: the manifest must be a regular file (not a directory, not a
                // symlink that could point anywhere).
                if let stat = fs.lstat(parent.appending(name).path), stat.isRegularFile {
                    return (true, "Rebuild manifest present (\(name))")
                }
            }
        }
        return (false, "No rebuild manifest found next to it")
    }

    /// Case/normalization-insensitive match of a file name against a pattern with at most one `*`.
    static func manifestPatternMatches(_ pattern: String, _ name: String) -> Bool {
        // SAFETY-DECISION: patterns containing "/" or more than one "*" are malformed → never match.
        guard !pattern.isEmpty, !pattern.contains("/") else { return false }
        let p = PathComparison.normalize(pattern)
        let n = PathComparison.normalize(name)
        let pieces = p.split(separator: "*", omittingEmptySubsequences: false)
        switch pieces.count {
        case 1:
            return p == n
        case 2:
            let head = String(pieces[0]), tail = String(pieces[1])
            return n.count >= head.count + tail.count && n.hasPrefix(head) && n.hasSuffix(tail)
        default:
            return false
        }
    }

    // MARK: - Cloud & ownership

    private func notInsideCloudRoot(_ target: ScanTarget) -> (Bool, String) {
        guard let path = lexicalPath(target) else {
            return (false, "Could not verify that this item is not cloud-synced")
        }
        var candidates = [path]
        // SAFETY-DECISION: check both the lexical and the resolved form (when resolvable) of the target.
        if case .success(let resolved) = canonicalizer.canonicalize(target.path), resolved != path {
            candidates.append(resolved)
        }
        let roots = cloudRoots()
        guard !roots.isEmpty else { return (false, "Could not verify that this item is not cloud-synced") }
        for candidate in candidates where roots.contains(where: { candidate.isInsideOrEqual($0) }) {
            return (false, "Inside a cloud-synced folder")
        }
        switch Self.cloudAttributesVerdict(fileSystem: environment.fileSystem, path: path.path) {
        case .clean:
            return (true, "Not cloud-synced")
        case .ubiquitous:
            return (false, "iCloud item")
        case .unknownUbiquity, .unreadableAttributes:
            return (false, "Could not verify that this item is not cloud-synced")
        case .fileProvider:
            return (false, "Managed by a cloud File Provider")
        }
    }

    /// Cloud roots under every form of the home directory (lexical and resolved).
    func cloudRoots() -> [CanonicalPath] {
        var roots: [CanonicalPath] = []
        for home in Self.homeForms(environment: environment, canonicalizer: canonicalizer) {
            for relative in DenyList.cloudRootsRelativeToHome {
                var root = home
                for component in relative.split(separator: "/") { root = root.appending(String(component)) }
                if !roots.contains(root) { roots.append(root) }
            }
        }
        return roots
    }

    enum CloudAttributesVerdict: Equatable {
        case clean
        case ubiquitous
        case unknownUbiquity
        case unreadableAttributes
        case fileProvider(attribute: String)
    }

    /// `isUbiquitousItem` + File Provider extended attributes of one path (no recursion).
    static func cloudAttributesVerdict(fileSystem fs: any FileSystemProbe, path: String) -> CloudAttributesVerdict {
        guard let ubiquitous = fs.isUbiquitousItem(path) else { return .unknownUbiquity }
        if ubiquitous { return .ubiquitous }
        guard let names = fs.extendedAttributeNames(path) else { return .unreadableAttributes }
        if let attribute = names.first(where: isFileProviderAttribute) { return .fileProvider(attribute: attribute) }
        return .clean
    }

    /// `com.apple.fileprovider.*` and `com.apple.file-provider-domain-id`.
    static func isFileProviderAttribute(_ name: String) -> Bool {
        let n = name.lowercased()
        // SAFETY-DECISION: any attribute in the com.apple.fileprovider / com.apple.file-provider
        // namespaces counts (a superset of the two forms named in the spec).
        return n.hasPrefix("com.apple.fileprovider") || n.hasPrefix("com.apple.file-provider")
    }

    private func ownedByUser(_ target: ScanTarget) -> (Bool, String) {
        guard let path = lexicalPath(target), let stat = environment.fileSystem.lstat(path.path) else {
            return (false, "Could not check who owns this item")
        }
        guard stat.uid == environment.userID else {
            return (false, "Owned by another user (uid \(stat.uid))")
        }
        return (true, "Owned by you")
    }

    // MARK: - Vendor tools (read-only queries)

    private func simulatorIdle() async -> (Bool, String) {
        let unknown = (false, "Could not check whether a simulator is running")
        guard let xcrun = environment.commands.resolveExecutable("xcrun") else { return unknown }
        let result = await environment.commands.run(
            executable: xcrun, arguments: ["simctl", "list", "devices", "-j"], timeout: Self.simctlTimeout)
        guard result.succeeded else { return unknown }
        guard let states = Self.simulatorDeviceStates(fromJSON: result.stdout) else { return unknown }
        // SAFETY-DECISION: only "Shutdown" counts as idle. "Booted", "Booting", "Shutting Down",
        // "Creating" or any unknown state means a simulator may be in use.
        if states.contains(where: { $0.lowercased() != "shutdown" }) {
            return (false, "A simulator is running — shut it down to clean")
        }
        guard let running = environment.runningApplications.runningBundleIdentifiers() else { return unknown }
        let simulatorApp = PathComparison.normalize(Self.simulatorAppBundleID)
        if running.contains(where: { PathComparison.normalize($0) == simulatorApp }) {
            return (false, "Simulator is running — quit it to clean")
        }
        return (true, "No simulator is running")
    }

    /// States of every device in `simctl list devices -j` output, or `nil` if the output does not
    /// have the expected shape (`{"devices": {runtime: [{"state": String, ...}]}}`).
    static func simulatorDeviceStates(fromJSON json: String) -> [String]? {
        guard let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let devices = root["devices"] as? [String: Any] else { return nil }
        var states: [String] = []
        for (_, value) in devices {
            guard let list = value as? [Any] else { return nil }
            for entry in list {
                // SAFETY-DECISION: a device entry without a readable state makes the whole answer unknown.
                guard let device = entry as? [String: Any], let state = device["state"] as? String else {
                    return nil
                }
                states.append(state)
            }
        }
        return states
    }

    private func dockerDaemonReachable() async -> (Bool, String) {
        // SAFETY-DECISION: iMop never starts Docker; if it is not already reachable the rule is skipped.
        guard let docker = environment.commands.resolveExecutable("docker") else {
            return (false, "Docker is not available")
        }
        let result = await environment.commands.run(executable: docker, arguments: ["info"], timeout: Self.dockerTimeout)
        guard result.succeeded else { return (false, "Docker is not running (iMop never starts it)") }
        return (true, "Docker is running")
    }

    private func notMounted(_ target: ScanTarget) async -> (Bool, String) {
        let unknown = (false, "Could not check whether this disk image is mounted")
        guard let path = lexicalPath(target) else { return unknown }
        guard let hdiutil = environment.commands.resolveExecutable("hdiutil") else { return unknown }
        let result = await environment.commands.run(
            executable: hdiutil, arguments: ["info", "-plist"], timeout: Self.hdiutilTimeout)
        guard result.succeeded, let imagePaths = Self.mountedImagePaths(fromPlist: result.stdout) else { return unknown }

        var targetForms = [path]
        if case .success(let resolved) = canonicalizer.canonicalize(target.path), resolved != path {
            targetForms.append(resolved)
        }
        for imagePath in imagePaths {
            var imageForms: [CanonicalPath] = []
            if case .success(let p) = canonicalizer.lexical(imagePath) { imageForms.append(p) }
            if case .success(let p) = canonicalizer.canonicalize(imagePath) { imageForms.append(p) }
            // SAFETY-DECISION: an image path that cannot be interpreted might be this item → fail closed.
            guard !imageForms.isEmpty else { return unknown }
            // SAFETY-DECISION: also fails when a mounted image lies INSIDE the target (a folder holding it).
            let hit = imageForms.contains { image in targetForms.contains { image.isInsideOrEqual($0) } }
            if hit { return (false, "Disk image is mounted — eject it to clean") }
        }
        return (true, "Not mounted")
    }

    /// `images[].image-path` from `hdiutil info -plist`, or `nil` if the plist is malformed.
    static func mountedImagePaths(fromPlist plist: String) -> [String]? {
        guard let data = plist.data(using: .utf8),
              let root = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              // SAFETY-DECISION: a missing "images" key is treated as malformed output, not "nothing mounted".
              let images = root["images"] as? [Any] else { return nil }
        var paths: [String] = []
        for entry in images {
            guard let image = entry as? [String: Any], let path = image["image-path"] as? String, !path.isEmpty else {
                return nil
            }
            paths.append(path)
        }
        return paths
    }

    private func appleSigned(_ target: ScanTarget) -> (Bool, String) {
        guard let path = lexicalPath(target) else { return (false, "Could not verify the code signature") }
        switch environment.codeSignatures.isAppleSigned(path: path.path) {
        case .some(true): return (true, "Signed by Apple")
        case .some(false): return (false, "Not signed by Apple")
        case .none: return (false, "Could not verify the code signature")
        }
    }

    private func notSelectedXcode(_ target: ScanTarget) async -> (Bool, String) {
        let unknown = (false, "Could not determine the active Xcode (xcode-select)")
        guard let path = lexicalPath(target) else { return unknown }
        guard let tool = environment.commands.resolveExecutable("xcode-select") else { return unknown }
        let result = await environment.commands.run(executable: tool, arguments: ["-p"], timeout: Self.xcodeSelectTimeout)
        guard result.succeeded else { return unknown }
        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !output.isEmpty, !output.contains("\n") else { return unknown }

        var developerForms: [CanonicalPath] = []
        if case .success(let p) = canonicalizer.lexical(output) { developerForms.append(p) }
        if case .success(let p) = canonicalizer.canonicalize(output) { developerForms.append(p) }
        guard !developerForms.isEmpty else { return unknown }

        var targetForms = [path]
        if case .success(let resolved) = canonicalizer.canonicalize(target.path), resolved != path {
            targetForms.append(resolved)
        }
        // SAFETY-DECISION: fails if the developer dir is inside-or-equal the target (the target is the
        // selected Xcode) and also if the target lies inside the developer dir.
        let selected = developerForms.contains { dev in
            targetForms.contains { dev.isInsideOrEqual($0) || $0.isInsideOrEqual(dev) }
        }
        if selected { return (false, "This is the active Xcode (xcode-select) — switch first to remove it") }
        return (true, "Not the active Xcode")
    }

    // MARK: - Helpers

    /// The target path after the §3.4 text rules (expands `~`/`{HOME}`); `nil` if unacceptable.
    private func lexicalPath(_ target: ScanTarget) -> CanonicalPath? {
        guard case .success(let path) = canonicalizer.lexical(target.path) else { return nil }
        return path
    }

    /// A directory-listing entry usable as one path component.
    static func isPlainName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
    }

    /// The home directory in its lexical form and (when resolvable and different) its resolved form.
    static func homeForms(environment: SafeCleanEnvironment, canonicalizer: PathCanonicalizer) -> [CanonicalPath] {
        var forms: [CanonicalPath] = []
        if case .success(let lexical) = canonicalizer.lexical(environment.homePath), !lexical.components.isEmpty {
            forms.append(lexical)
        }
        if case .success(let resolved) = canonicalizer.canonicalize(environment.homePath),
           !resolved.components.isEmpty, !forms.contains(resolved) {
            forms.append(resolved)
        }
        return forms
    }
}

/// Bundle-ID pattern with an optional trailing `*` ("com.adobe.*"). Case-insensitive.
struct BundleIDPattern: Sendable {
    private let fixed: String
    private let isPrefix: Bool

    /// `nil` for empty patterns or a `*` anywhere but the end.
    init?(_ pattern: String) {
        let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let stars = trimmed.filter { $0 == "*" }.count
        if stars == 0 {
            fixed = PathComparison.normalize(trimmed)
            isPrefix = false
        } else if stars == 1, trimmed.hasSuffix("*") {
            fixed = PathComparison.normalize(String(trimmed.dropLast()))
            isPrefix = true
        } else {
            return nil
        }
    }

    func matches(_ bundleID: String) -> Bool {
        let candidate = PathComparison.normalize(bundleID)
        return isPrefix ? candidate.hasPrefix(fixed) : candidate == fixed
    }
}

