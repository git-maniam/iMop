import Foundation

// ProjectScanner (spec §6.5): read-only discovery of rebuildable project build artifacts
// (`node_modules`, Rust `target/`, Python virtualenvs, `Pods/`, `.next/`, Gradle `build/`, SwiftPM
// `.build/`) inside the project roots the USER selected in Settings.
//
// It walks ONLY `environment.scanSettings.projectRoots`, through `fileSystem.contentsOfDirectory` +
// `lstat`; it never follows a symlink, never crosses a volume, never descends into hidden folders
// (`.git` is only detected, by name), bundles/packages, deny-listed or cloud locations, or into a
// recognised artifact. It is bounded in depth and in total entries visited, and honours
// cancellation. It runs no command: whether git tracks an artifact is the `notTrackedByGit`
// precondition's job (SafetyGate), as is the project age (`projectOlderThan`).

/// Discovers the artifacts of one `project.*` rule (inspector `projectArtifacts`).
public struct ProjectArtifactsInspector: Inspector {
    /// Spec §6.5: maximum depth of an artifact below its project root.
    public static let maxDepth = 8
    /// Bound on the directory entries visited per discovery (all roots together).
    public static let defaultMaxEntriesVisited = 200_000

    static let noRootsMessage = "No project folders are selected in Settings"
    static let noUsableRootsMessage = "None of the selected project folders can be scanned"
    static let unknownRuleMessage = "Not a reviewed project-artifact rule"

    private let maxEntriesVisited: Int

    /// - Parameter maxEntriesVisited: entry budget (tests use a small one); at least 1.
    public init(maxEntriesVisited: Int = ProjectArtifactsInspector.defaultMaxEntriesVisited) {
        self.maxEntriesVisited = max(1, maxEntriesVisited)
    }

    public var id: InspectorID { .projectArtifacts }

    // MARK: - Artifact kinds (Swift-pinned, spec §6.5 table)

    /// How a manifest beside the artifact is recognised. Names are compared EXACTLY (case-sensitive).
    public enum ManifestName: Sendable, Hashable {
        case exact(String)
        /// `prefix` + at least one character + `suffix` (e.g. `requirements` … `.txt`) — or exactly
        /// `prefix` + `suffix` when `allowsEmptyMiddle`.
        case pattern(prefix: String, suffix: String, allowsEmptyMiddle: Bool)

        public func matches(_ name: String) -> Bool {
            switch self {
            case .exact(let value):
                return name == value
            case .pattern(let prefix, let suffix, let allowsEmptyMiddle):
                guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { return false }
                let middle = name.count - prefix.count - suffix.count
                return allowsEmptyMiddle ? middle >= 0 : middle > 0
            }
        }
    }

    /// One `project.*` rule's artifact shape.
    public struct ArtifactKind: Sendable, Hashable {
        public let ruleID: String
        /// Exact folder names of the artifact (case-sensitive).
        public let artifactNames: [String]
        /// At least one of these must be a regular file (not a symlink) BESIDE the artifact.
        public let manifests: [ManifestName]
        /// When non-empty, at least one of these must be a regular file (not a symlink) directly
        /// INSIDE the artifact.
        public let requiredInsideAnyOf: [String]
        /// Tools whose running processes block the rule (`processNotRunning`, spec §6.5).
        public let tools: [String]

        public func isArtifactName(_ name: String) -> Bool { artifactNames.contains(name) }
        public func isManifest(_ name: String) -> Bool { manifests.contains { $0.matches(name) } }
    }

    /// SAFETY-DECISION: generic names (`build`, `target`) are only ever matched together with their
    /// manifest pairing; every kind requires a manifest beside it, and some a marker inside.
    public static let artifactKinds: [ArtifactKind] = [
        ArtifactKind(ruleID: "project.nodeModules", artifactNames: ["node_modules"],
                     manifests: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"].map { .exact($0) },
                     requiredInsideAnyOf: [], tools: ["node", "npm", "yarn", "pnpm", "bun"]),
        ArtifactKind(ruleID: "project.rustTarget", artifactNames: ["target"],
                     manifests: [.exact("Cargo.toml")],
                     requiredInsideAnyOf: [cacheDirTagName, ".rustc_info.json"], tools: ["cargo", "rustc"]),
        ArtifactKind(ruleID: "project.pythonVenv", artifactNames: [".venv", "venv"],
                     manifests: [.exact("pyproject.toml"), .pattern(prefix: "requirements", suffix: ".txt", allowsEmptyMiddle: true),
                                 .exact("uv.lock"), .exact("poetry.lock")],
                     requiredInsideAnyOf: ["pyvenv.cfg"], tools: ["python", "python3"]),
        ArtifactKind(ruleID: "project.pods", artifactNames: ["Pods"],
                     manifests: [.exact("Podfile.lock")], requiredInsideAnyOf: [], tools: ["pod"]),
        ArtifactKind(ruleID: "project.nextBuild", artifactNames: [".next"],
                     manifests: [.pattern(prefix: "next.config.", suffix: "", allowsEmptyMiddle: false)],
                     requiredInsideAnyOf: [], tools: ["node"]),
        ArtifactKind(ruleID: "project.gradleBuild", artifactNames: ["build"],
                     manifests: [.exact("build.gradle"), .exact("build.gradle.kts")],
                     requiredInsideAnyOf: [], tools: ["java", "gradle"]),
        ArtifactKind(ruleID: "project.swiftBuild", artifactNames: [".build"],
                     manifests: [.exact("Package.swift")], requiredInsideAnyOf: [], tools: ["swift-build", "swift-package"]),
    ]

    /// Every artifact folder name of every kind (the `{NAME}` values `notTrackedByGit` may pass to git).
    public static let allArtifactNames: [String] = artifactKinds.flatMap(\.artifactNames)

    /// The kind of `ruleID`, or `nil` for any other rule.
    public static func kind(forRuleID ruleID: String) -> ArtifactKind? {
        artifactKinds.first { $0.ruleID == ruleID }
    }

    /// `CACHEDIR.TAG` (https://bford.info/cachedir/), written by cargo into `target/`.
    static let cacheDirTagName = "CACHEDIR.TAG"
    static let cacheDirTagSignature = "Signature: 8a477f597d28d172789f06886806bc55"
    static let maximumMarkerBytes: Int64 = 64 * 1024

    /// Folder extensions never descended into (packages / bundles / protected libraries), compared
    /// normalized, in addition to `SafetyGate.bundleExtensions` and `DenyList.protectedExtensions`.
    static let packageExtensions: Set<String> = [
        "xcodeproj", "xcworkspace", "xcarchive", "playground", "xcassets", "lrdata", "lrlibrary",
        "rtfd", "pages", "numbers", "key", "pkg", "mpkg", "dmg", "sparseimage", "docarchive",
        "photoslibrary", "musiclibrary", "tvlibrary", "fcpbundle", "logicx", "band", "sparsebundle",
        "lrcat", "app", "framework", "bundle", "plugin", "kext", "systemextension", "appex",
        "xpc", "qlgenerator", "mdimporter", "prefpane", "saver", "wdgt", "component", "vst", "vst3", "aaxplugin",
    ]

    // MARK: - Discovery

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard let kind = Self.kind(forRuleID: rule.id) else {
            // SAFETY-DECISION: only the Swift-pinned project rules are served; any other rule using
            // this inspector discovers nothing.
            return InspectorOutput(candidates: [], status: .unavailable(Self.unknownRuleMessage))
        }
        guard !environment.scanSettings.projectRoots.isEmpty else {
            return InspectorOutput(candidates: [], status: .unavailable(Self.noRootsMessage))
        }
        let denyFilter = InspectorDenyFilter(environment: environment)
        let roots = Self.resolvedProjectRoots(environment: environment, ruleID: rule.id, denyFilter: denyFilter)
        guard !roots.isEmpty else {
            return InspectorOutput(candidates: [], status: .unavailable(Self.noUsableRootsMessage))
        }

        var walk = Walk(environment: environment, kind: kind, ruleID: rule.id, denyFilter: denyFilter,
                        budget: maxEntriesVisited)
        rootLoop: for root in roots {
            switch walk.run(root: root) {
            case .finished:
                continue rootLoop
            case .truncated:
                break rootLoop
            case .cancelled:
                return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage))
            }
        }
        if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage)) }

        var candidates = walk.found.sorted { $0.path < $1.path }
        if walk.truncated {
            let message = "Project scan stopped after \(maxEntriesVisited) entries; some project folders were not checked."
            if candidates.isEmpty {
                return InspectorOutput(candidates: [], status: .unavailable(message))
            }
            candidates = candidates.map { candidate in
                DiscoveredCandidate(path: candidate.path, displayName: candidate.displayName,
                                    owningBundleID: candidate.owningBundleID, notes: candidate.notes + [message])
            }
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }

    // MARK: - Project roots

    struct ProjectRoot: Sendable {
        let path: CanonicalPath
        let device: Int64
        /// Some strict ancestor of the root (up to and including the home directory) holds a `.git`.
        let insideAncestorRepository: Bool
        /// Some strict ancestor of the root (up to and including the home directory) holds a non-git
        /// version-control marker (`.hg`, `.svn`, …), or could not be listed.
        let insideOtherVersionControl: Bool
    }

    /// The user's project roots that may be scanned: each must clean (no `..`, `~`/`{HOME}` expanded
    /// from the environment), resolve to itself (no symlink on the way), lie STRICTLY inside the home
    /// directory (never the home itself), not be deny-listed (cloud roots, Documents, `~/Library`, …),
    /// not be or lie inside a bundle, and be a real directory on the home volume. Duplicates and roots
    /// nested in another selected root are dropped (the outer root's walk covers them).
    ///
    /// SAFETY-DECISION: a root that fails any check is ignored, never "repaired".
    static func resolvedProjectRoots(environment: SafeCleanEnvironment, ruleID: String,
                                     denyFilter: InspectorDenyFilter) -> [ProjectRoot] {
        let fs = environment.fileSystem
        let canonicalizer = PathCanonicalizer(environment: environment)
        let homeForms = PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        guard !homeForms.isEmpty else { return [] }

        // SAFETY-DECISION (M5 integration): start from the SAME validated roots SafetyGate expands
        // `{PROJECT_ROOTS}` to (`ProjectRoots.resolve`: canonical, strictly inside home, not deny-listed,
        // not cloud-synced), so the walk can never cover a folder the gate would not accept. The home
        // folder is passed as the fixture waiver, which `DenyList` honours only for an `iMopTests-*`
        // fixture root in the temporary directory (a real home gets the complete deny-list). The
        // checks below only narrow that set further.
        let validated = ProjectRoots.resolve(environment: environment, waivedSystemRoots: [environment.homePath])
        var accepted: [(CanonicalPath, CanonicalPath, Int64)] = [] // (root, home form, device)
        for canonical in validated {
            guard let home = homeForms.first(where: { canonical.isStrictlyInside($0) }) else { continue }
            guard !denyFilter.isDenied(canonical, ruleID: ruleID) else { continue }
            // SAFETY-DECISION: a root at or inside a folder named like an artifact (e.g.
            // `~/code/app/node_modules`) would let nested artifacts be proposed; it is ignored.
            guard !canonical.components.dropFirst(home.components.count).contains(where: isArtifactLikeName) else { continue }
            guard let name = canonical.lastComponent, !isPackageName(name),
                  SafetyGate.bundleAncestor(of: canonical, fileSystem: fs) == nil else { continue }
            guard let homeStat = fs.lstat(home.path), homeStat.isDirectory, !homeStat.isSymlink,
                  let info = fs.lstat(canonical.path), info.isDirectory, !info.isSymlink,
                  info.device == homeStat.device else { continue }
            accepted.append((canonical, home, info.device))
        }

        var roots: [ProjectRoot] = []
        for (index, entry) in accepted.enumerated() {
            let (root, home, device) = entry
            // Drop duplicates (keep the first) and roots inside another accepted root.
            let shadowed = accepted.enumerated().contains { other in
                other.offset != index && (root.isStrictlyInside(other.element.0) || (root == other.element.0 && other.offset < index))
            }
            if shadowed { continue }
            roots.append(ProjectRoot(path: root, device: device,
                                     insideAncestorRepository: hasRepositoryAncestor(root, home: home, fileSystem: fs),
                                     insideOtherVersionControl: hasOtherVersionControlAncestor(root, home: home, fileSystem: fs)))
        }
        return roots
    }

    /// `true` when `<ancestor>/.git` exists (any type, via `lstat`) for a strict ancestor of `root`
    /// up to and including `home`.
    static func hasRepositoryAncestor(_ root: CanonicalPath, home: CanonicalPath, fileSystem: any FileSystemProbe) -> Bool {
        var current = root.parent
        while let directory = current, directory.isInsideOrEqual(home) {
            if fileSystem.lstat(directory.appending(".git").path) != nil { return true }
            current = directory.parent
        }
        return false
    }

    /// `true` when a strict ancestor of `root` up to and including `home` holds a non-git
    /// version-control marker, or cannot be listed (fail closed: it might hold one).
    static func hasOtherVersionControlAncestor(_ root: CanonicalPath, home: CanonicalPath,
                                               fileSystem: any FileSystemProbe) -> Bool {
        var current = root.parent
        while let directory = current, directory.isInsideOrEqual(home) {
            guard let names = fileSystem.contentsOfDirectory(directory.path) else { return true }
            if names.contains(where: PreconditionEvaluator.isOtherVersionControlMarker) { return true }
            current = directory.parent
        }
        return false
    }

    // MARK: - Walk

    enum WalkOutcome {
        case finished
        case truncated
        case cancelled
    }

    /// One bounded, depth-first, read-only walk over the project roots.
    struct Walk {
        let environment: SafeCleanEnvironment
        let kind: ArtifactKind
        let ruleID: String
        let denyFilter: InspectorDenyFilter
        let budget: Int
        let walker: InspectorWalker
        var visited = 0
        var truncated = false
        var found: [DiscoveredCandidate] = []
        var seen = Set<CanonicalPath>()

        init(environment: SafeCleanEnvironment, kind: ArtifactKind, ruleID: String,
             denyFilter: InspectorDenyFilter, budget: Int) {
            self.environment = environment
            self.kind = kind
            self.ruleID = ruleID
            self.denyFilter = denyFilter
            self.budget = budget
            self.walker = InspectorWalker(environment: environment)
        }

        struct Frame {
            let path: CanonicalPath
            /// Components below the project root (the root itself is 0).
            let depth: Int
            /// Some strict ancestor of this directory holds a `.git`.
            let insideAncestorRepository: Bool
            /// Some strict ancestor of this directory holds a non-git version-control marker.
            let insideOtherVersionControl: Bool
        }

        mutating func run(root: ProjectRoot) -> WalkOutcome {
            var stack = [Frame(path: root.path, depth: 0, insideAncestorRepository: root.insideAncestorRepository,
                               insideOtherVersionControl: root.insideOtherVersionControl)]
            while let frame = stack.popLast() {
                if Task.isCancelled { return .cancelled }
                let entries: [InspectorWalker.Entry]
                switch walker.list(frame.path.path, device: root.device) {
                case .absent, .declined:
                    // SAFETY-DECISION: an unlistable folder is skipped (nothing below it is proposed).
                    continue
                case .entries(let list):
                    entries = list
                }
                visited += entries.count
                if visited > budget {
                    truncated = true
                    return .truncated
                }

                let isRepository = entries.contains { $0.name == ".git" }
                let underOtherVersionControl = frame.insideOtherVersionControl
                    || entries.contains { PreconditionEvaluator.isOtherVersionControlMarker($0.name) }
                var pushed: [Frame] = []
                for entry in entries {
                    // Only real directories on the root's volume are artifacts or walked into.
                    guard InspectorWalker.isDescendable(entry, device: root.device) else { continue }
                    let path = frame.path.appending(entry.name)

                    if let match = ProjectArtifactsInspector.classify(entry, siblings: entries, fileSystem: environment.fileSystem) {
                        // SAFETY-DECISION: a recognised artifact (of ANY kind) is never descended into,
                        // so nested artifacts (node_modules inside node_modules, …) are never proposed.
                        if match.kind.ruleID == ruleID,
                           ProjectArtifactsInspector.mayPropose(projectIsRepository: isRepository,
                                                                insideAncestorRepository: frame.insideAncestorRepository,
                                                                underOtherVersionControl: underOtherVersionControl),
                           !denyFilter.isDenied(path, ruleID: ruleID),
                           seen.insert(path).inserted {
                            found.append(candidate(path: path, artifactName: entry.name, project: frame.path,
                                                   manifests: match.manifests, siblings: entries, isRepository: isRepository))
                        }
                        continue
                    }
                    guard frame.depth + 1 < ProjectArtifactsInspector.maxDepth,
                          ProjectArtifactsInspector.mayDescend(into: entry.name),
                          !denyFilter.isDenied(path, ruleID: ruleID),
                          !SafetyGate.isBundle(path, name: entry.name, isDirectory: true, fileSystem: environment.fileSystem)
                    else { continue }
                    pushed.append(Frame(path: path, depth: frame.depth + 1,
                                        insideAncestorRepository: frame.insideAncestorRepository || isRepository,
                                        insideOtherVersionControl: underOtherVersionControl))
                }
                // Depth-first in listing (sorted) order.
                stack.append(contentsOf: pushed.reversed())
            }
            return .finished
        }

        private func candidate(path: CanonicalPath, artifactName: String, project: CanonicalPath, manifests: [String],
                               siblings: [InspectorWalker.Entry], isRepository: Bool) -> DiscoveredCandidate {
            let projectName = project.lastComponent ?? project.path
            var notes = ["Project folder: \(ProjectArtifactsInspector.displayPath(project, home: environment.homePath))",
                         "Rebuild manifest: \(manifests.joined(separator: ", "))"]
            if let lastUsed = ProjectArtifactsInspector.projectLastChanged(project: project, manifests: manifests,
                                                                          siblings: siblings, fileSystem: environment.fileSystem) {
                notes.append("Project last changed: \(ProjectArtifactsInspector.formatDay(lastUsed))")
            } else {
                notes.append("When the project was last changed could not be determined.")
            }
            if isRepository {
                notes.append("The project is a git repository; it is only cleaned if git does not track \(artifactName).")
            }
            return DiscoveredCandidate(path: path.path, displayName: "\(projectName) — \(artifactName)",
                                       owningBundleID: nil, notes: notes)
        }
    }

    // MARK: - Classification (read-only)

    struct Match {
        let kind: ArtifactKind
        /// Names of the manifests found beside the artifact (sorted).
        let manifests: [String]
    }

    /// The artifact kind `entry` (a real directory) belongs to, given its parent's listing.
    static func classify(_ entry: InspectorWalker.Entry, siblings: [InspectorWalker.Entry],
                         fileSystem: any FileSystemProbe) -> Match? {
        for kind in artifactKinds where kind.isArtifactName(entry.name) {
            // SAFETY-DECISION: a manifest only counts when it is a regular file (never a symlink).
            let manifests = siblings
                .filter { $0.stat.isRegularFile && !$0.stat.isSymlink && kind.isManifest($0.name) }
                .map(\.name)
                .sorted()
            guard !manifests.isEmpty else { continue }
            if !kind.requiredInsideAnyOf.isEmpty {
                let hasMarker = kind.requiredInsideAnyOf.contains { marker in
                    hasMarkerFile(marker, inside: entry.path, device: entry.stat.device, fileSystem: fileSystem)
                }
                guard hasMarker else { continue }
            }
            return Match(kind: kind, manifests: manifests)
        }
        return nil
    }

    /// `<directory>/<marker>` is a regular file (not a symlink) on `device`; a `CACHEDIR.TAG` must
    /// also start with the standard signature.
    static func hasMarkerFile(_ marker: String, inside directory: String, device: Int64,
                              fileSystem: any FileSystemProbe) -> Bool {
        let path = directory + "/" + marker
        guard let info = fileSystem.lstat(path), info.isRegularFile, !info.isSymlink, info.device == device else { return false }
        guard marker == cacheDirTagName else { return true }
        guard info.logicalSize <= maximumMarkerBytes, let data = fileSystem.readFile(path),
              Int64(data.count) <= maximumMarkerBytes,
              let text = String(data: data, encoding: .utf8) else { return false }
        return text.hasPrefix(cacheDirTagSignature)
    }

    /// SAFETY-DECISION: `notTrackedByGit` only asks git when the artifact's own parent holds `.git`.
    /// An artifact whose project is not itself a repository but lies inside one further up (a
    /// monorepo, or a repository at the home folder) could be tracked by that outer repository
    /// without git ever being asked, so it is not proposed.
    ///
    /// SAFETY-DECISION (review M5): an artifact in (or below) a checkout of another version-control
    /// system (`.hg`, `.svn`, `.jj`, …) may be committed there, and iMop never runs those tools: it is
    /// never proposed.
    static func mayPropose(projectIsRepository: Bool, insideAncestorRepository: Bool,
                           underOtherVersionControl: Bool) -> Bool {
        guard !underOtherVersionControl else { return false }
        return projectIsRepository || !insideAncestorRepository
    }

    /// Whether the walk may enter a (non-artifact) directory named `name`.
    ///
    /// SAFETY-DECISION: never hidden folders (`.git` is only detected by name), never a folder named
    /// like ANY artifact even when it did not match (an unmatched `node_modules` may hold nested
    /// artifacts, which must never be proposed), never a package / bundle / protected library.
    static func mayDescend(into name: String) -> Bool {
        guard InspectorWalker.isPlainName(name), !name.hasPrefix(".") else { return false }
        if isArtifactLikeName(name) { return false }
        return !isPackageName(name)
    }

    /// `name` equals any artifact folder name, compared case- and Unicode-insensitively.
    static func isArtifactLikeName(_ name: String) -> Bool {
        let normalized = PathComparison.normalize(name)
        return allArtifactNames.contains { PathComparison.normalize($0) == normalized }
    }

    /// `true` for names with a package, bundle or protected-library extension.
    static func isPackageName(_ name: String) -> Bool {
        if SafetyGate.isBundleComponent(name) { return true }
        guard let ext = SafetyGate.pathExtension(of: name) else { return false }
        return packageExtensions.contains(ext) || DenyList.protectedExtensions.contains(ext)
    }

    /// Max `lstat` mtime of the manifests beside the artifact, `.git/index` and `.git/HEAD` (the same
    /// inputs as the `projectOlderThan` precondition). Informational only; `nil` when none is readable.
    static func projectLastChanged(project: CanonicalPath, manifests: [String], siblings: [InspectorWalker.Entry],
                                   fileSystem: any FileSystemProbe) -> Date? {
        var dates = siblings.filter { manifests.contains($0.name) }.map(\.stat.modificationDate)
        for file in ["index", "HEAD"] {
            let path = project.appending(".git").appending(file).path
            if let info = fileSystem.lstat(path), info.isRegularFile, !info.isSymlink { dates.append(info.modificationDate) }
        }
        return dates.max()
    }

    static func displayPath(_ path: CanonicalPath, home: String) -> String {
        if case .success(let homePath) = PathCanonicalizer.clean(home, home: nil), path.isStrictlyInside(homePath) {
            return "~/" + path.components.dropFirst(homePath.components.count).joined(separator: "/")
        }
        return path.path
    }

    /// `YYYY-MM-DD` (UTC).
    static func formatDay(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle().year().month().day())
    }

    // MARK: - Identity re-check (for SafetyGate)

    /// SAFETY-DECISION (review M5): SafetyGate re-proves on the file system, at every validation and
    /// independently of the rule's declared preconditions, everything this scanner checked before
    /// offering `target` for `ruleID`. Returns why it is no longer (or never was) such an artifact, or
    /// `nil` when it still is:
    /// - `target` lies strictly inside one of the validated project roots, at most `maxDepth` below
    ///   the OUTERMOST containing root (the root the walk would have started from);
    /// - its parent can be listed and `classify` recognises it as THIS rule's kind: exact artifact
    ///   name, a regular (non-symlink) manifest beside it, the required marker inside it
    ///   (`CACHEDIR.TAG` with its signature / `.rustc_info.json` / `pyvenv.cfg`);
    /// - `mayPropose` holds: its own folder holds the `.git` when any folder up to the home folder
    ///   does, and no folder from its project up to the home folder holds a non-git version-control
    ///   marker. Any listing that fails fails the check.
    public static func identityProblem(target: CanonicalPath, ruleID: String, environment: SafeCleanEnvironment,
                                       waivedSystemRoots: [String]) -> String? {
        guard kind(forRuleID: ruleID) != nil else { return "not a reviewed project-artifact rule" }
        let fs = environment.fileSystem
        let canonicalizer = PathCanonicalizer(environment: environment)
        let homes = PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        guard let name = target.lastComponent, let project = target.parent,
              let home = homes.first(where: { project.isStrictlyInside($0) }) else { return "not inside the home folder" }
        let roots = ProjectRoots.resolve(environment: environment, waivedSystemRoots: waivedSystemRoots)
            .filter { target.isStrictlyInside($0) }
        guard let outermost = roots.min(by: { $0.components.count < $1.components.count }),
              let depth = target.depth(below: outermost) else { return "not inside one of your project folders" }
        guard depth <= maxDepth else { return "deeper than \(maxDepth) folders below the project folder" }

        let walker = InspectorWalker(environment: environment)
        guard let rootStat = walker.realDirectory(outermost.path) else { return "the project folder cannot be read" }
        guard case .entries(let siblings) = walker.list(project.path, device: rootStat.device) else {
            return "its project folder cannot be listed"
        }
        guard let entry = siblings.first(where: { $0.name == name }), InspectorWalker.isDescendable(entry, device: rootStat.device),
              let match = classify(entry, siblings: siblings, fileSystem: fs), match.kind.ruleID == ruleID else {
            return "no longer has this artifact's manifest pairing"
        }

        let isRepository = siblings.contains { $0.name == ".git" }
        var underOtherVersionControl = siblings.contains { PreconditionEvaluator.isOtherVersionControlMarker($0.name) }
        if !underOtherVersionControl {
            underOtherVersionControl = hasOtherVersionControlAncestor(project, home: home, fileSystem: fs)
        }
        let insideAncestorRepository = hasRepositoryAncestor(project, home: home, fileSystem: fs)
        guard mayPropose(projectIsRepository: isRepository, insideAncestorRepository: insideAncestorRepository,
                         underOtherVersionControl: underOtherVersionControl) else {
            return "its project is part of a repository the artifact's folder is not the top of"
        }
        return nil
    }

    // MARK: - Shape (for RuleTargetMatcher)

    /// Pure shape check: `componentsBelowProjectRoot` are the target's components below the project
    /// root it lies in. The target must be an artifact name of `ruleID`'s kind at most `maxDepth`
    /// below the root, and no folder on the way may be hidden, a package/bundle, or named like any
    /// artifact (so nothing nested inside an artifact ever matches). Manifest pairing needs the file
    /// system and is checked by discovery.
    public static func shapeMatches(ruleID: String, componentsBelowProjectRoot components: [String]) -> Bool {
        guard let kind = kind(forRuleID: ruleID), let last = components.last,
              components.count >= 1, components.count <= maxDepth, kind.isArtifactName(last) else { return false }
        return components.dropLast().allSatisfy { mayDescend(into: $0) }
    }
}
