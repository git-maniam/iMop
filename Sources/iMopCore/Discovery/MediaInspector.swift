import Foundation

// Read-only inspectors for creative & media caches (spec §6.7).

// MARK: - lightroom.previews

/// The standard previews of Lightroom Classic catalogs (spec §6.7 `lightroom.previews`, Yellow).
///
/// For every `.lrcat` that Spotlight reports inside the home folder, ONLY the sibling folder named
/// exactly `<catalog name> Previews.lrdata` is proposed. Never `<catalog name> Smart Previews.lrdata`
/// (Smart Previews let the user edit offline photos), never the `.lrcat` itself (deny-listed by
/// extension), never anything inside the `.lrdata` package.
///
/// Spotlight results are hints: every catalog path is cleaned and must lie strictly inside the home
/// folder, be reachable from it through real directories only (no symlink, same volume) and be a
/// regular file; the previews folder must be a real directory on the same volume and not deny-listed
/// (catalogs under `~/Pictures`, `~/Documents`, cloud folders, … therefore yield nothing).
public struct LightroomPreviewsInspector: Inspector {
    public init() {}

    public var id: InspectorID { .lightroomPreviews }

    public static let lightroomBundleID = "com.adobe.LightroomClassicCC7"
    static let catalogExtension = "lrcat"
    static let previewsSuffix = " Previews.lrdata"
    static let smartPreviewsSuffix = " Smart Previews.lrdata"
    /// Bound on the Spotlight results considered.
    static let maximumCatalogs = 10_000

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        let walker = InspectorWalker(environment: environment)
        let canonicalizer = PathCanonicalizer(environment: environment)
        let homeForms = PreconditionEvaluator.homeForms(environment: environment, canonicalizer: canonicalizer)
        guard !homeForms.isEmpty else { return InspectorOutput(candidates: [], status: .ok) }

        // SAFETY-DECISION: Spotlight failing or timing out (nil) is reported, never guessed around
        // with a file-system crawl.
        guard let reported = environment.spotlight.paths(withExtension: Self.catalogExtension, under: [environment.homePath]) else {
            return InspectorOutput(candidates: [], status: .unavailable("Spotlight search is unavailable"))
        }

        let denyFilter = InspectorDenyFilter(environment: environment)
        var candidates: [DiscoveredCandidate] = []
        var seen = Set<CanonicalPath>()
        for raw in reported.sorted().prefix(Self.maximumCatalogs) {
            if Task.isCancelled { return InspectorOutput(candidates: [], status: .failed(SafeCleanScanner.cancelledMessage)) }
            guard SafeCleanScanner.isPlainLabel(raw), raw.hasPrefix("/"),
                  case .success(let catalog) = canonicalizer.lexical(raw),
                  let catalogFile = catalog.lastComponent, let directory = catalog.parent,
                  let baseName = Self.catalogBaseName(catalogFile),
                  let home = homeForms.first(where: { catalog.isStrictlyInside($0) }),
                  let homeStat = walker.realDirectory(home.path) else { continue }
            let device = homeStat.device

            // The catalog's folder, reached from the home folder through real directories only.
            let below = Array(directory.components.dropFirst(home.components.count))
            guard let folder = walker.descend(from: home.path, through: below, device: device),
                  case .entries(let entries) = walker.list(folder, device: device) else { continue }
            guard entries.contains(where: { $0.name == catalogFile && $0.stat.isRegularFile && !$0.stat.isSymlink }) else {
                continue
            }

            let previewsName = baseName + Self.previewsSuffix
            guard Self.isPreviewsFolderName(previewsName),
                  let previews = entries.first(where: { $0.name == previewsName }),
                  InspectorWalker.isDescendable(previews, device: device) else { continue }
            let path = directory.appending(previewsName)
            guard !denyFilter.isDenied(path, ruleID: rule.id), seen.insert(path).inserted else { continue }

            candidates.append(DiscoveredCandidate(
                path: path.path,
                displayName: "\(baseName) — Previews",
                owningBundleID: Self.lightroomBundleID,
                notes: [
                    "Standard previews of the Lightroom Classic catalog “\(catalogFile)”.",
                    "The catalog and its Smart Previews are not touched.",
                ]
            ))
        }
        return InspectorOutput(candidates: candidates.sorted { $0.path < $1.path }, status: .ok)
    }

    /// `"<name>"` for a file named `"<name>.lrcat"` (extension compared case-insensitively; the name
    /// must be non-empty and plain). `nil` otherwise.
    static func catalogBaseName(_ fileName: String) -> String? {
        guard InspectorWalker.isPlainName(fileName),
              SafetyGate.pathExtension(of: fileName) == catalogExtension,
              let dot = fileName.lastIndex(of: ".") else { return nil }
        let base = String(fileName[..<dot])
        return base.isEmpty ? nil : base
    }

    /// `true` for `"<name> Previews.lrdata"` with a non-empty name that is NOT a Smart Previews folder.
    ///
    /// SAFETY-DECISION: any name ending in " Smart Previews.lrdata" is rejected, even when it would be
    /// the standard previews of a catalog whose own name ends in " Smart" — the two cannot be told
    /// apart by name, so neither is proposed.
    public static func isPreviewsFolderName(_ name: String) -> Bool {
        guard InspectorWalker.isPlainName(name), name.hasSuffix(previewsSuffix),
              name.count > previewsSuffix.count else { return false }
        let normalized = PathComparison.normalize(name)
        // SAFETY-DECISION (M5 integration): "Smart Previews.lrdata" itself (the standard previews of a
        // catalog named "Smart") is refused too — spec §6.7: never "Smart Previews.lrdata".
        return !normalized.hasSuffix(PathComparison.normalize(smartPreviewsSuffix))
            && normalized != PathComparison.normalize(String(smartPreviewsSuffix.dropFirst()))
    }

    /// SafetyGate re-check (review M5): `target` is `<name> Previews.lrdata` and its parent holds the
    /// EXACT catalog `<name>.lrcat` (extension case-insensitive) as a regular file, not a symlink —
    /// the identity discovery proved, not merely "some catalog beside it". `nil` when it holds.
    public static func identityProblem(target: CanonicalPath, fileSystem: any FileSystemProbe) -> String? {
        guard let name = target.lastComponent, isPreviewsFolderName(name), let parent = target.parent else {
            return "not a Lightroom previews folder"
        }
        let base = String(name.dropLast(previewsSuffix.count))
        guard let names = fileSystem.contentsOfDirectory(parent.path) else { return "its folder cannot be listed" }
        let hasCatalog = names.contains { sibling in
            guard catalogBaseName(sibling) == base, let info = fileSystem.lstat(parent.appending(sibling).path) else { return false }
            return info.isRegularFile && !info.isSymlink
        }
        return hasCatalog ? nil : "its catalog \(base).lrcat is not beside it"
    }

    /// Pure shape check for `RuleTargetMatcher`: the last component is a standard previews folder
    /// and the owner is Lightroom Classic. (Whether its catalog exists beside it is checked by
    /// discovery.)
    public static func shapeMatches(target: CanonicalPath, owner: String?) -> Bool {
        guard let owner, PathComparison.normalize(owner) == PathComparison.normalize(lightroomBundleID),
              let name = target.lastComponent else { return false }
        return isPreviewsFolderName(name)
    }
}
