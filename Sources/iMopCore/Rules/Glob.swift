import Foundation

// Spec §4 glob grammar, deliberately tiny:
//   {HOME}/literal/segments/with*wildcards
// - The pattern starts with "{HOME}/" (or, only for the Swift-coded exception roots, one of
//   `GlobPattern.nonHomeRoots`).
// - Segments are separated by single "/"; no empty, "." or ".." segments, no trailing "/".
// - "*" matches any run of characters (possibly empty) WITHIN one segment; it never matches "/".
// - Rejected anywhere: "**", "?", "[", "]", "{", "}" (other than the leading {HOME}), "\", NUL.
// There is no recursion, no regex and no brace expansion. Recursive discovery lives only in
// dedicated Inspectors with explicit depth limits.
//
// Read-only: this file only lists directories and lstat()s entries through the injected probe.

/// A parsed glob pattern.
public struct GlobPattern: Sendable, Hashable, CustomStringConvertible {
    public enum Anchor: Sendable, Hashable {
        /// `{HOME}/…`
        case home
        /// One of `GlobPattern.nonHomeRoots` (e.g. `/cores/core.*`).
        case absolute
    }

    public static let homeToken = "{HOME}"

    /// Absolute (non-home) roots a pattern may start with. Whether a given rule may use one is
    /// decided by `RuleCatalog` (Swift-coded per-rule exception table); the deny-list and SafetyGate
    /// still apply to every match.
    public static let nonHomeRoots: [String] = ["/cores", "/Applications"]

    /// The pattern as written.
    public let pattern: String
    public let anchor: Anchor
    /// Segments after the anchor. For `.home` these follow the home directory; for `.absolute` they
    /// include the root's own components (e.g. `["cores", "core.*"]`).
    public let segments: [String]
    /// For `.absolute`: how many leading segments spell the non-home root. 0 for `.home`.
    public let rootSegmentCount: Int
    private let normalizedSegments: [String]

    /// `nil` when the pattern violates the grammar.
    public init?(_ pattern: String) {
        guard !pattern.isEmpty, !pattern.contains("\0") else { return nil }

        let body: Substring
        let anchor: Anchor
        let prefix = Self.homeToken + "/"
        if pattern.hasPrefix(prefix) {
            anchor = .home
            body = pattern.dropFirst(prefix.count)
        } else if pattern.hasPrefix("/") {
            anchor = .absolute
            body = pattern.dropFirst()
        } else {
            return nil
        }

        // Split WITHOUT omitting empty pieces so "a//b" and a trailing "/" are rejected.
        let segments = body.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !segments.isEmpty else { return nil }
        for segment in segments {
            guard Self.isValidSegment(segment) else { return nil }
        }

        var rootCount = 0
        if anchor == .absolute {
            // SAFETY-DECISION: an absolute pattern must start with one of the Swift-coded non-home
            // roots, spelled with literal segments, and must reach strictly below it.
            var matched: Int?
            for root in Self.nonHomeRoots {
                let rootParts = root.split(separator: "/").map(String.init)
                guard segments.count > rootParts.count else { continue }
                let head = Array(segments.prefix(rootParts.count))
                if !head.contains(where: { $0.contains("*") }), PathComparison.equal(head, rootParts) {
                    matched = rootParts.count
                    break
                }
            }
            guard let matched else { return nil }
            rootCount = matched
        }

        self.pattern = pattern
        self.anchor = anchor
        self.segments = segments
        self.rootSegmentCount = rootCount
        self.normalizedSegments = segments.map(PathComparison.normalize)
    }

    private static let forbiddenCharacters: Set<Character> = ["?", "[", "]", "{", "}", "\\", "\0"]

    private static func isValidSegment(_ segment: String) -> Bool {
        guard !segment.isEmpty, segment != ".", segment != "..", segment != "~" else { return false }
        guard !segment.contains("**") else { return false }
        guard !segment.contains(where: { forbiddenCharacters.contains($0) }) else { return false }
        // Control characters (newline, tab, …) are never part of a rule pattern.
        guard !segment.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return false }
        return true
    }

    public var description: String { pattern }

    public var isHomeAnchored: Bool { anchor == .home }

    /// `true` if the segment at `index` contains a wildcard.
    public func isWildcard(at index: Int) -> Bool {
        segments.indices.contains(index) && segments[index].contains("*")
    }

    /// Every path component of the pattern with `{HOME}` expanded (the home directory's own
    /// components first). Empty when the home directory is unusable.
    public func resolved(home: String) -> [String] {
        switch anchor {
        case .absolute:
            return segments
        case .home:
            guard let cleanHome = PathCanonicalizer.validHome(home) else { return [] }
            let homeParts = cleanHome.split(separator: "/").map(String.init)
            return homeParts + segments
        }
    }

    /// The pattern with `{HOME}` expanded, as an absolute path string (wildcards kept). `nil` when
    /// the home directory is unusable.
    public func resolvedPath(home: String) -> String? {
        let parts = resolved(home: home)
        return parts.isEmpty ? nil : "/" + parts.joined(separator: "/")
    }

    /// Whether `segment` (one directory-entry name) matches the pattern segment at `index`
    /// (an index into `segments`). Case- and Unicode-normalization-insensitive.
    ///
    /// SAFETY-DECISION: a wildcard never matches a name starting with "." unless the pattern segment
    /// itself starts with "." (shell semantics) — hidden entries are only ever matched by name.
    public func matches(segment name: String, at index: Int) -> Bool {
        guard segments.indices.contains(index) else { return false }
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else { return false }
        let patternSegment = normalizedSegments[index]
        let candidate = PathComparison.normalize(name)
        guard patternSegment.contains("*") else { return candidate == patternSegment }
        if candidate.hasPrefix("."), !patternSegment.hasPrefix(".") { return false }
        return Self.wildcardMatch(Array(patternSegment), Array(candidate))
    }

    /// Classic iterative `*` matcher over Characters (no other metacharacters exist).
    private static func wildcardMatch(_ pattern: [Character], _ text: [Character]) -> Bool {
        var p = 0, t = 0
        var starP = -1, starT = 0
        while t < text.count {
            if p < pattern.count, pattern[p] != "*", pattern[p] == text[t] {
                p += 1; t += 1
            } else if p < pattern.count, pattern[p] == "*" {
                starP = p; starT = t; p += 1
            } else if starP >= 0 {
                p = starP + 1; starT += 1; t = starT
            } else {
                return false
            }
        }
        while p < pattern.count, pattern[p] == "*" { p += 1 }
        return p == pattern.count
    }
}

/// Expands a `GlobPattern` against the injected file system. Read-only.
public struct GlobExpander: Sendable {
    private let environment: SafeCleanEnvironment

    public init(environment: SafeCleanEnvironment) {
        self.environment = environment
    }

    /// Absolute paths of every match (directory-listing spelling), sorted.
    public func expand(_ pattern: GlobPattern) -> [String] {
        expand(pattern, excludedNames: [])
    }

    /// Like `expand(_:)`, skipping any entry whose name (at any level below the base) equals one of
    /// `excludedNames` (case/Unicode-insensitive).
    ///
    /// - Lists directories with `contentsOfDirectory` and inspects entries with `lstat` only.
    /// - Never descends through a symlink; a symlink may be returned only as a final match (the
    ///   SafetyGate decides whether it can be acted on).
    /// - Never crosses volumes: every directory descended into, and every non-symlink final match,
    ///   must have the `st_dev` of the base (the home directory, or the non-home root).
    public func expand(_ pattern: GlobPattern, excludedNames: [String]) -> [String] {
        let fs = environment.fileSystem
        let excluded = Set(excludedNames.map(PathComparison.normalize))

        let basePath: String
        let firstIndex: Int
        switch pattern.anchor {
        case .home:
            guard let home = PathCanonicalizer.validHome(environment.homePath) else { return [] }
            basePath = home
            firstIndex = 0
        case .absolute:
            basePath = "/" + pattern.segments.prefix(pattern.rootSegmentCount).joined(separator: "/")
            firstIndex = pattern.rootSegmentCount
        }
        guard firstIndex < pattern.segments.count else { return [] }

        RealHomeGuard.check(basePath)
        // SAFETY-DECISION: the base itself must be a real directory (not a symlink); otherwise the
        // whole pattern yields nothing.
        guard let baseStat = fs.lstat(basePath), baseStat.isDirectory, !baseStat.isSymlink else { return [] }
        let baseDevice = baseStat.device

        var frontier = [basePath]
        var matches: [String] = []
        let lastIndex = pattern.segments.count - 1

        for index in firstIndex...lastIndex {
            if Task.isCancelled { return [] }
            let isLast = index == lastIndex
            var next: [String] = []
            for directory in frontier {
                if Task.isCancelled { return [] }
                guard let names = fs.contentsOfDirectory(directory) else { continue }
                for name in names.sorted() {
                    guard pattern.matches(segment: name, at: index) else { continue }
                    if excluded.contains(PathComparison.normalize(name)) { continue }
                    let child = directory == "/" ? "/" + name : directory + "/" + name
                    guard let st = fs.lstat(child) else { continue }
                    if isLast {
                        if st.isSymlink {
                            matches.append(child)
                        } else if st.device == baseDevice {
                            matches.append(child)
                        }
                        // SAFETY-DECISION: a final match on another volume (a mount point) is dropped.
                    } else if st.isDirectory, !st.isSymlink, st.device == baseDevice {
                        // SAFETY-DECISION (review M2, spec §7.2): never descend into a package/bundle
                        // (`.app`, `.framework`, `.bundle`, …; same test as SafetyGate check 11).
                        // Deny-listed intermediate directories are not pruned here: every final match
                        // is deny-list-checked by the Scanner and SafetyGate, and the deny-list's
                        // prefix semantics cover everything below a protected directory (rule
                        // exceptions such as Mail Downloads need the full rule context).
                        if SafetyGate.isBundle(CanonicalPath(validatedPath: child), name: name,
                                               isDirectory: true, fileSystem: fs) { continue }
                        next.append(child)
                    }
                }
            }
            frontier = next
            if frontier.isEmpty && !isLast { return [] }
        }

        // Deduplicate normalized spellings (defensive; a case-insensitive listing has no duplicates).
        var seen = Set<[String]>()
        var unique: [String] = []
        for path in matches {
            let key = path.split(separator: "/").map { PathComparison.normalize(String($0)) }
            if seen.insert(key).inserted { unique.append(path) }
        }
        return unique
    }
}
