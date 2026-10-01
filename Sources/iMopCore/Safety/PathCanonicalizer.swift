import Foundation

// `Result<CanonicalPath, SafetyRejection>` (the agreed canonicalizer API) requires `Failure: Error`.
// Declared here, once, for the whole module; do not repeat it elsewhere.
extension SafetyRejection: Error {}

// MARK: - Comparison

/// Spec §3.4: every path comparison is case-insensitive and Unicode-normalization-insensitive,
/// performed component-wise. Never compare paths with raw `hasPrefix`.
public enum PathComparison {
    /// Normalizes one path component for comparison: NFC (`precomposedStringWithCanonicalMapping`)
    /// then `lowercased()`.
    public static func normalize(_ component: String) -> String {
        // SAFETY-DECISION: re-apply NFC after lowercasing. Some lowercase mappings (e.g. U+0130)
        // produce decomposed sequences; normalizing again guarantees both sides of every comparison
        // end up in the same form regardless of the input's original normalization.
        component.precomposedStringWithCanonicalMapping.lowercased().precomposedStringWithCanonicalMapping
    }

    /// Normalized, component-wise equality of two component arrays.
    static func equal(_ lhs: [String], _ rhs: [String]) -> Bool {
        lhs.count == rhs.count && zip(lhs, rhs).allSatisfy { normalize($0) == normalize($1) }
    }
}

// MARK: - CanonicalPath

/// An absolute, logical, cleaned path (firmlink prefix stripped, `/var` `/tmp` `/etc` mapped to their
/// `/private` forms, no `.`/`..`/empty components, no trailing slash).
///
/// Equality and hashing are normalized (case- and Unicode-normalization-insensitive), matching
/// APFS's default semantics.
public struct CanonicalPath: Sendable, Hashable, CustomStringConvertible {
    /// Absolute path, no trailing slash (the root is `/`).
    public let path: String
    private let storedComponents: [String]
    private let normalizedComponents: [String]

    /// Path components excluding the leading "/".
    public var components: [String] { storedComponents }

    /// Builds a `CanonicalPath` from an already-clean absolute path.
    ///
    /// Empty and `.` components (duplicate/trailing slashes) are dropped.
    /// - Precondition: `validatedPath` is absolute, contains no `..` component and no NUL byte.
    public init(validatedPath: String) {
        // SAFETY-DECISION: this initializer cannot fail, so malformed input is a programmer error and
        // traps (also in release builds) rather than producing a path whose containment checks could
        // be fooled (e.g. "/a/b/.." would otherwise look "inside" /a/b). Untrusted input must go
        // through `PathCanonicalizer`, which returns a rejection instead.
        precondition(validatedPath.hasPrefix("/"), "CanonicalPath requires an absolute path")
        precondition(!validatedPath.contains("\0"), "CanonicalPath must not contain NUL")
        let parts = validatedPath.split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
            .filter { $0 != "." }
        precondition(!parts.contains(".."), "CanonicalPath must not contain '..'")
        self.init(components: parts)
    }

    /// Internal: components already verified clean.
    init(components: [String]) {
        self.storedComponents = components
        self.normalizedComponents = components.map(PathComparison.normalize)
        self.path = "/" + components.joined(separator: "/")
    }

    public var description: String { path }

    /// Normalized components, for callers inside the module that do their own matching.
    var comparisonComponents: [String] { normalizedComponents }

    /// The last component (`nil` for `/`).
    public var lastComponent: String? { storedComponents.last }

    /// `true` if `self` is `other` or lies beneath it (component-wise, normalized).
    public func isInsideOrEqual(_ other: CanonicalPath) -> Bool {
        let base = other.normalizedComponents
        guard normalizedComponents.count >= base.count else { return false }
        return Array(normalizedComponents.prefix(base.count)) == base
    }

    /// `true` if `self` lies beneath `other` and is not equal to it.
    public func isStrictlyInside(_ other: CanonicalPath) -> Bool {
        normalizedComponents.count > other.normalizedComponents.count && isInsideOrEqual(other)
    }

    /// Number of components below `root`, or `nil` when `self` is not inside-or-equal to `root`.
    public func depth(below root: CanonicalPath) -> Int? {
        guard isInsideOrEqual(root) else { return nil }
        return normalizedComponents.count - root.normalizedComponents.count
    }

    /// Appends a single path component.
    /// - Precondition: `component` is a single, non-empty name other than `.`/`..`, without `/` or NUL.
    public func appending(_ component: String) -> CanonicalPath {
        // SAFETY-DECISION: a component that could change the meaning of the path (traversal,
        // separators, NUL) is a programmer error and traps instead of being silently accepted.
        precondition(!component.isEmpty && component != "." && component != "..",
                     "invalid path component")
        precondition(!component.contains("/") && !component.contains("\0"), "invalid path component")
        return CanonicalPath(components: storedComponents + [component])
    }

    /// The parent directory (`nil` for `/`).
    public var parent: CanonicalPath? {
        guard !storedComponents.isEmpty else { return nil }
        return CanonicalPath(components: Array(storedComponents.dropLast()))
    }

    public static func == (lhs: CanonicalPath, rhs: CanonicalPath) -> Bool {
        lhs.normalizedComponents == rhs.normalizedComponents
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(normalizedComponents)
    }
}

// MARK: - PathCanonicalizer

/// Spec §3.4 path canonicalization.
public struct PathCanonicalizer: Sendable {
    private let environment: SafeCleanEnvironment

    public init(environment: SafeCleanEnvironment) {
        self.environment = environment
    }

    /// Full canonicalization: lexical rules, then resolution through the file system
    /// (`URLResourceKey.canonicalPathKey` and `realpath(3)` must both succeed and agree).
    ///
    /// The returned path uses `realpath`'s spelling, mapped to its logical form. Callers that need to
    /// detect symlink traversal compare it with `lexical(_:)` of the same input.
    public func canonicalize(_ rawPath: String) -> Result<CanonicalPath, SafetyRejection> {
        let lexicalResult = lexical(rawPath)
        guard case .success(let lexicalPath) = lexicalResult else { return lexicalResult }

        RealHomeGuard.check(lexicalPath.path)

        // The logical form is resolved (never a /System/Volumes/Data form, which was already mapped):
        // firmlinks and the /var, /tmp, /etc symlinks make both forms name the same object.
        let fs = environment.fileSystem
        guard let viaURL = fs.canonicalPath(lexicalPath.path) else {
            return .failure(.canonicalizationFailed("canonical path unavailable"))
        }
        guard let viaRealpath = fs.realpath(lexicalPath.path) else {
            return .failure(.canonicalizationFailed("realpath failed"))
        }

        // SAFETY-DECISION: resolver outputs are run through the same text rules (but never get "~"
        // or "{HOME}" expansion); a resolver output that is relative, contains "..", or maps into
        // /System is rejected rather than trusted.
        let urlForm: CanonicalPath
        switch Self.clean(viaURL, home: nil) {
        case .success(let p): urlForm = p
        case .failure(let rejection): return .failure(Self.resolverRejection(rejection))
        }
        let realForm: CanonicalPath
        switch Self.clean(viaRealpath, home: nil) {
        case .success(let p): realForm = p
        case .failure(let rejection): return .failure(Self.resolverRejection(rejection))
        }

        guard urlForm == realForm else {
            return .failure(.canonicalizationFailed("canonical path and realpath disagree"))
        }

        RealHomeGuard.check(realForm.path)
        return .success(realForm)
    }

    /// Same text rules as `canonicalize(_:)` without touching the file system.
    public func lexical(_ rawPath: String) -> Result<CanonicalPath, SafetyRejection> {
        let home = environment.homePath
        return Self.clean(rawPath, home: home)
    }

    // MARK: Text rules (shared with DenyList)

    /// Applies every §3.4 text rule.
    /// - Parameter home: when non-nil, a leading `~` / `{HOME}` is expanded from it; when nil, a
    ///   leading `~` or `{HOME}` is rejected (resolver outputs and deny-list homes never expand).
    static func clean(_ rawPath: String, home: String?) -> Result<CanonicalPath, SafetyRejection> {
        guard !rawPath.isEmpty else { return .failure(.canonicalizationFailed("empty path")) }
        guard !rawPath.contains("\0") else { return .failure(.canonicalizationFailed("NUL in path")) }

        // Spec: reject any ".." component BEFORE standardizing (and before expansion).
        if rawPath.split(separator: "/", omittingEmptySubsequences: true).contains("..") {
            return .failure(.parentTraversal)
        }

        var expanded = rawPath
        if rawPath == "~" || rawPath.hasPrefix("~/") || rawPath == "{HOME}" || rawPath.hasPrefix("{HOME}/") {
            guard let home else {
                return .failure(.canonicalizationFailed("unexpected home placeholder"))
            }
            guard let homePath = validHome(home) else {
                return .failure(.canonicalizationFailed("invalid home directory"))
            }
            let rest = rawPath.hasPrefix("~") ? rawPath.dropFirst(1) : rawPath.dropFirst("{HOME}".count)
            expanded = homePath + rest
        } else if rawPath.hasPrefix("~") {
            // SAFETY-DECISION: "~otheruser" forms are never expanded; they are rejected.
            return .failure(.canonicalizationFailed("unsupported '~user' form"))
        }

        guard expanded.hasPrefix("/") else {
            return .failure(.canonicalizationFailed("path is not absolute"))
        }

        var parts = expanded.split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
            .filter { $0 != "." }
        if parts.contains("..") { return .failure(.parentTraversal) }

        // Firmlinks: /System/Volumes/Data/<x> is the logical /<x>. Stripped exactly once; anything
        // still under /System afterwards is denied below.
        if parts.count >= 3,
           PathComparison.normalize(parts[0]) == "system",
           PathComparison.normalize(parts[1]) == "volumes",
           PathComparison.normalize(parts[2]) == "data" {
            parts.removeFirst(3)
        }

        // /var, /tmp, /etc -> /private/...
        if let first = parts.first {
            let n = PathComparison.normalize(first)
            if n == "var" || n == "tmp" || n == "etc" {
                parts[0] = n
                parts.insert("private", at: 0)
            }
        }

        if let first = parts.first, PathComparison.normalize(first) == "system" {
            return .failure(.denyListed(entry: "/System"))
        }

        return .success(CanonicalPath(components: parts))
    }

    /// The home directory as a cleaned absolute string, or nil if unusable.
    static func validHome(_ home: String) -> String? {
        // SAFETY-DECISION: a home directory that is relative, contains "..", NUL, or is "/" itself is
        // unusable; anything that would expand from it is rejected.
        guard home.hasPrefix("/"), !home.contains("\0") else { return nil }
        guard case .success(let cleaned) = clean(home, home: nil) else { return nil }
        guard !cleaned.components.isEmpty else { return nil }
        return cleaned.path
    }

    private static func resolverRejection(_ rejection: SafetyRejection) -> SafetyRejection {
        switch rejection {
        case .denyListed: return rejection
        default: return .canonicalizationFailed("resolved path is malformed")
        }
    }
}
