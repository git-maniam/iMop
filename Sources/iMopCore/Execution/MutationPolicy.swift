import Darwin
import Foundation

/// Spec §0.5: whether this build may mutate the file system at all.
///
/// Builds without the compile-time flag `IMOP_ALLOW_MUTATION` (every debug build, `swift run iMop`)
/// are dry-run only: every mutating code path asks `permits(path:environment:)` first and, when it is
/// denied, mutates nothing and reports `ErrorCategory.mutationDisabled` with `disabledMessage`.
public struct MutationPolicy: Sendable {
    private enum Mode: Sendable, Equatable {
        case disabled
        case enabled
        /// Test-only: mutation strictly inside one `iMopTests-*` fixture root.
        case fixture(root: CanonicalPath)
    }

    private let mode: Mode

    private init(mode: Mode) {
        self.mode = mode
    }

    /// The message every refused mutation reports and audits.
    public static let disabledMessage = "mutation disabled in this build"

    /// The policy fixed at compile time by `-DIMOP_ALLOW_MUTATION` (release packaging only).
    public static var compiledIn: MutationPolicy {
        #if IMOP_ALLOW_MUTATION
        return MutationPolicy(mode: .enabled)
        #else
        return MutationPolicy(mode: .disabled)
        #endif
    }

    /// A policy that refuses every mutation.
    public static var disabled: MutationPolicy { MutationPolicy(mode: .disabled) }

    // SAFETY-DECISION: `isEnabled` is read-only (computed). A settable flag would let any caller turn
    // a dry-run policy into a mutating one; the only ways to obtain an enabled policy are the
    // compile-time flag and the SPI-gated fixture policy below.
    public var isEnabled: Bool { mode != .disabled }

    /// Test-only policy. Permits mutation ONLY when the canonical path being mutated and the
    /// environment's `homePath` are both strictly inside `root`, `root` is an existing, symlink-free
    /// directory named `iMopTests-<something>` directly inside the temporary directory and outside the
    /// real home, and `homePath` is not (inside) the real `NSHomeDirectory()`. Anything else is denied.
    ///
    /// When `root` itself does not qualify, the returned policy is disabled.
    @_spi(FixtureTesting)
    public static func fixtureOnly(root: String) -> MutationPolicy {
        guard let validated = validatedFixtureRoot(root) else { return MutationPolicy(mode: .disabled) }
        return MutationPolicy(mode: .fixture(root: validated))
    }

    /// `true` only when mutating `path` is allowed by this policy in `environment`.
    public func permits(path: String, environment: SafeCleanEnvironment) -> Bool {
        permits(path: path, homePath: environment.homePath)
    }

    /// Same as `permits(path:environment:)` for primitives that have no environment. `homePath` is
    /// the home the mutation is performed for; `nil` means "unknown".
    // SAFETY-DECISION: with an unknown home the fixture policy always refuses (it can only permit
    // a mutation when the home is proven to be inside the fixture root).
    func permits(path: String, homePath: String?) -> Bool {
        // Test-suite tripwire (no-op in production): resolving a real-home path aborts the test run.
        RealHomeGuard.check(path)

        // SAFETY-DECISION: every policy refuses a path that is relative, contains "..", NUL, a
        // `~`/`{HOME}` placeholder, or maps into /System — mutation targets are always canonical.
        guard case .success(let target) = PathCanonicalizer.clean(path, home: nil), !target.components.isEmpty else {
            return false
        }

        switch mode {
        case .disabled:
            return false

        case .enabled:
            // SAFETY-DECISION: while the test-suite guard is installed (a test run), a build compiled
            // with IMOP_ALLOW_MUTATION still refuses; tests may mutate only through `fixtureOnly`.
            if RealHomeGuard.isActive { return false }
            return true

        case .fixture(let root):
            guard let homePath else { return false }
            return fixturePermits(target: target, root: root, homePath: homePath)
        }
    }

    // MARK: - Fixture policy

    private func fixturePermits(target: CanonicalPath, root: CanonicalPath, homePath: String) -> Bool {
        // The root must still be exactly what was validated (not swapped for a symlink since).
        guard let revalidated = Self.validatedFixtureRoot(root.path), revalidated == root else { return false }

        // Lexical containment of the mutated path and of the environment's home.
        guard target.isStrictlyInside(root) else { return false }
        guard case .success(let home) = PathCanonicalizer.clean(homePath, home: nil),
              home.isStrictlyInside(root) else { return false }

        // Never the real home (or anything inside it).
        for realHome in Self.realHomeForms() {
            if home.isInsideOrEqual(realHome) || realHome.isInsideOrEqual(home) { return false }
            if target.isInsideOrEqual(realHome) || realHome.isInsideOrEqual(target) { return false }
        }

        // SAFETY-DECISION: lexical containment is not enough — an intermediate symlink could point
        // out of the fixture. The nearest existing ancestor of the mutated path (its parent first;
        // the final component itself may legitimately be a symlink that is being removed) and the
        // home must resolve (realpath(3), not the injectable probe, which tests may fake) inside the
        // root. Resolution failure denies.
        guard let parent = target.parent, let resolvedParent = Self.resolveNearestExisting(parent),
              resolvedParent.isInsideOrEqual(root) else { return false }
        guard let resolvedHome = Self.resolve(home.path), resolvedHome.isStrictlyInside(root) else { return false }
        for realHome in Self.realHomeForms() {
            if resolvedHome.isInsideOrEqual(realHome) || resolvedParent.isInsideOrEqual(realHome) { return false }
        }
        return true
    }

    private static let fixturePrefix = "iMopTests-"

    /// The root as a canonical path when it qualifies as a fixture root, else nil.
    private static func validatedFixtureRoot(_ root: String) -> CanonicalPath? {
        guard case .success(let lexical) = PathCanonicalizer.clean(root, home: nil) else { return nil }
        guard let name = lexical.lastComponent, name.hasPrefix(fixturePrefix), name.count > fixturePrefix.count else {
            return nil
        }
        // Exists, is a real directory (not a symlink), and is already in resolved form.
        var st = Darwin.stat()
        guard lstat(lexical.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return nil }
        guard let resolved = resolve(lexical.path), resolved == lexical else { return nil }

        // Directly inside the temporary directory.
        guard let tmp = resolve(FileManager.default.temporaryDirectory.path), !tmp.components.isEmpty,
              let parent = resolved.parent, parent == tmp else { return nil }

        // Never inside (or containing) the real home.
        let realHomes = realHomeForms()
        guard !realHomes.isEmpty else { return nil }
        for realHome in realHomes {
            if resolved.isInsideOrEqual(realHome) || realHome.isInsideOrEqual(resolved) { return nil }
        }
        return resolved
    }

    /// The real home directory, lexically and resolved. Empty when it cannot be determined (callers
    /// treat that as a denial).
    private static func realHomeForms() -> [CanonicalPath] {
        let raw = NSHomeDirectory()
        var forms: [CanonicalPath] = []
        if case .success(let lexical) = PathCanonicalizer.clean(raw, home: nil), !lexical.components.isEmpty {
            forms.append(lexical)
        }
        if let resolved = resolve(raw), !resolved.components.isEmpty, !forms.contains(resolved) {
            forms.append(resolved)
        }
        return forms
    }

    /// realpath(3) of an existing path, cleaned to a canonical path.
    private static func resolve(_ path: String) -> CanonicalPath? {
        guard let pointer = realpath(path, nil) else { return nil }
        defer { free(pointer) }
        guard case .success(let cleaned) = PathCanonicalizer.clean(String(cString: pointer), home: nil) else { return nil }
        return cleaned
    }

    /// Resolves `path`, or its nearest existing ancestor when it does not exist yet.
    private static func resolveNearestExisting(_ path: CanonicalPath) -> CanonicalPath? {
        var current: CanonicalPath? = path
        while let candidate = current {
            var st = Darwin.stat()
            if lstat(candidate.path, &st) == 0 { return resolve(candidate.path) }
            // SAFETY-DECISION: only a missing component is skipped; any other lstat error denies.
            guard errno == ENOENT else { return nil }
            current = candidate.parent
        }
        return nil
    }
}
