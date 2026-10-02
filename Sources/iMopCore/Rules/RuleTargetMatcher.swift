import Foundation

// SAFETY-DECISION (review M2): the "shape" of what a rule may target, re-checked by SafetyGate (and
// by the Scanner) on the canonical target path. An allow-root plus a minimum depth is far wider than
// what most rules mean: `apps.electronCaches` may only touch `<known app>/<exact cache folder>`,
// never `Application Support/Slack/Local Storage`; `vscode.caches` only the six named folders, never
// `Code/User`. Discovery makes that narrow selection; this matcher makes the LAST check before acting
// enforce it too, so the guarantee does not rest on the Scanner alone.
//
// - Glob rules: the target must match one of the rule's patterns (component-wise, case- and
//   Unicode-insensitive, wildcards within one component) and no component below the home directory
//   (or below the non-home root) may be one of the rule's `excludedNames`.
// - Inspector rules: a Swift-coded predicate per inspector, mirroring exactly what that inspector
//   emits, including the owning bundle identifier. An inspector without a predicate here matches
//   NOTHING (fail closed) — later milestones add a predicate together with the inspector.
// - Command-discovered rules have no file-system target shape: nothing matches.
// - Vendor-command rules (Milestone 4) never have file-system targets either (their inspectors have
//   no predicate below, so nothing matches). Their command items are checked by
//   `commandItemMismatch(argument:rule:)`: the rule must be one of the Swift-pinned command rules
//   (`commandRuleShapes`: rule id → inspector, tier, exact tool + argument array) and the per-item
//   argument must pass that command's `{ITEM}` validator (`CommandItemKind`, shared with the
//   `CommandAllowList` the live `CommandRunner` enforces).
//
// Pure computation over path components; it never touches the file system.

public struct RuleTargetMatcher: Sendable {
    /// Every spelling of the home directory (as configured, and resolved when different).
    public let homeForms: [CanonicalPath]

    public init(homeForms: [CanonicalPath]) {
        self.homeForms = homeForms.filter { !$0.components.isEmpty }
    }

    /// `nil` when `target` has the shape `rule` may act on; otherwise why not.
    ///
    /// - Parameter owningBundleID: the owner recorded on the scan target (inspectors set it; it must
    ///   be the owner the inspector would have reported for this exact path).
    public func mismatch(_ target: CanonicalPath, rule: Rule, owningBundleID: String?) -> String? {
        switch rule.discovery {
        case .glob(let patterns):
            return globMismatch(target, patterns: patterns, excludedNames: rule.excludedNames)
        case .inspector(let inspector):
            if let problem = Self.pinnedInspectorRuleMismatch(rule, inspector: inspector) { return problem }
            return inspectorMismatch(target, inspector: inspector, ruleID: rule.id, owner: owningBundleID)
        case .command:
            return "command-discovered rules have no file-system targets"
        }
    }

    // MARK: Glob rules

    private func globMismatch(_ target: CanonicalPath, patterns: [String], excludedNames: [String]) -> String? {
        let comps = target.components
        let excluded = Set(excludedNames.map(PathComparison.normalize))
        for raw in patterns {
            guard let pattern = GlobPattern(raw) else { continue } // unparsable pattern matches nothing
            var below: ArraySlice<String>?
            switch pattern.anchor {
            case .absolute:
                if comps.count == pattern.segments.count, Self.matchesSegments(comps[...], pattern: pattern) {
                    below = comps.dropFirst(pattern.rootSegmentCount)
                }
            case .home:
                for home in homeForms {
                    let homeCount = home.components.count
                    guard comps.count == homeCount + pattern.segments.count,
                          PathComparison.equal(Array(comps.prefix(homeCount)), home.components),
                          Self.matchesSegments(comps.dropFirst(homeCount), pattern: pattern) else { continue }
                    below = comps.dropFirst(homeCount)
                    break
                }
            }
            guard let below else { continue }
            if let name = below.first(where: { excluded.contains(PathComparison.normalize($0)) }) {
                return "\"\(name)\" is excluded from this rule"
            }
            return nil
        }
        return "does not match any of this rule's patterns"
    }

    /// `components[i]` matches pattern segment `i` for every i (counts already equal).
    private static func matchesSegments(_ components: ArraySlice<String>, pattern: GlobPattern) -> Bool {
        guard components.count == pattern.segments.count else { return false }
        for (index, component) in components.enumerated() where !pattern.matches(segment: component, at: index) {
            return false
        }
        return true
    }

    // MARK: Inspector rules

    /// SAFETY-DECISION (M5): defence in depth on top of catalog validation. A rule bound to a
    /// Milestone 5 inspector is acceptable only under a pinned rule id, with that id's inspector and
    /// tier and every pinned precondition declared (`RuleCatalog.inspectorRuleSpecs`, or
    /// `projectArtifactSpecs` for the ProjectScanner), so a rule built in code with another id,
    /// a Green tier or fewer preconditions can never act on a Milestone 5 target.
    public static func pinnedInspectorRuleMismatch(_ rule: Rule, inspector: InspectorID) -> String? {
        if inspector == .projectArtifacts {
            guard let spec = projectArtifactSpecs[rule.id] else { return "the projectArtifacts inspector is not reviewed for this rule" }
            guard rule.tier == .yellow else { return "tier must be yellow for this rule" }
            let required: [Precondition] = [.projectOlderThan(days: 90), .notTrackedByGit, .processNotRunning(spec.tools)]
            for precondition in required where !declares(rule.preconditions, precondition) {
                return "must declare the reviewed \(precondition.name) precondition"
            }
            // SAFETY-DECISION (review M5): like `RuleCatalog.validateProjectArtifactRule`, the rule must
            // also declare manifestPresent with a non-empty subset of the reviewed manifests. (SafetyGate
            // check 11d re-proves the manifest pairing on disk regardless.)
            var manifests: [String] = []
            for case .manifestPresent(let names) in rule.preconditions { manifests.append(contentsOf: names) }
            guard !manifests.isEmpty, manifests.allSatisfy({ spec.manifestPatterns.contains($0) }) else {
                return "must declare manifestPresent with the reviewed manifests"
            }
            return nil
        }
        // SAFETY-DECISION (M6): the whole-app Trash inspectors serve only their Swift-pinned non-home
        // rules (`RuleCatalog.nonHomeRuleSpecs`), with exactly the pinned tier, action and preconditions.
        if Self.nonHomeInspectors.contains(inspector) {
            guard let spec = RuleCatalog.nonHomeRuleSpecs[rule.id], spec.discovery == .inspector(inspector) else {
                return "the \(inspector.rawValue) inspector is not reviewed for this rule"
            }
            guard rule.tier == spec.tier else { return "tier must be \(spec.tier.rawValue) for this rule" }
            guard rule.action == spec.action else { return "action is not the one reviewed for this rule" }
            for required in spec.requiredPreconditions where !required.isSatisfied(by: rule.preconditions) {
                return "must declare the reviewed \(required) precondition"
            }
            return nil
        }
        // SAFETY-DECISION (M6): the advisory inspector only ever serves the pinned advisory rules.
        if inspector == .advisory {
            guard let kind = RuleCatalog.advisoryRuleSpecs[rule.id], rule.tier == .advisory, rule.action == .advisory(kind) else {
                return "the advisory inspector is not reviewed for this rule"
            }
            return nil
        }
        guard RuleCatalog.pinnedM5Inspectors.contains(inspector) else { return nil }
        guard let spec = RuleCatalog.inspectorRuleSpecs[rule.id], spec.inspector == inspector else {
            return "the \(inspector.rawValue) inspector is not reviewed for this rule"
        }
        guard rule.tier == spec.tier else { return "tier must be \(spec.tier.rawValue) for this rule" }
        // Review M6: the pinned action too (M5 rules quarantine; M6 rules trash / boot out / delete).
        guard rule.action == spec.action else { return "action is not the one reviewed for this rule" }
        for precondition in spec.requiredPreconditions where !declares(rule.preconditions, precondition) {
            return "must declare the reviewed \(precondition.name) precondition"
        }
        return nil
    }

    /// Inspectors whose targets are whole `.app` bundles outside (or inside) the home folder.
    static let nonHomeInspectors: Set<InspectorID> = [.xcodeExtraInstalls, .macOSInstallers]

    private func inspectorMismatch(_ target: CanonicalPath, inspector: InspectorID, ruleID: String, owner: String?) -> String? {
        if Self.nonHomeInspectors.contains(inspector) {
            return appBundleShapeMatches(target, inspector: inspector, owner: owner)
                ? nil : "is not an item the \(inspector.rawValue) inspector may offer"
        }
        for home in homeForms where target.isStrictlyInside(home) {
            let relative = Array(target.components.dropFirst(home.components.count))
            if Self.inspectorShapeMatches(inspector, ruleID: ruleID, relative: relative, owner: owner) { return nil }
        }
        return "is not an item the \(inspector.rawValue) inspector may offer"
    }

    /// Components below the home directory, compared normalized.
    static func inspectorShapeMatches(_ inspector: InspectorID, relative: [String], owner: String?) -> Bool {
        inspectorShapeMatches(inspector, ruleID: nil, relative: relative, owner: owner)
    }

    /// Components below the home directory, compared normalized. `ruleID` selects rule-specific
    /// shapes (ProjectScanner artifacts); `nil` matches no rule-specific shape.
    static func inspectorShapeMatches(_ inspector: InspectorID, ruleID: String?, relative: [String], owner: String?) -> Bool {
        let rel = relative.map(PathComparison.normalize)
        let trimmedOwner = owner?.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedOwner = trimmedOwner.flatMap { $0.isEmpty ? nil : PathComparison.normalize($0) }

        func hasPrefix(_ parts: [String]) -> Bool {
            rel.count >= parts.count && Array(rel.prefix(parts.count)) == parts.map(PathComparison.normalize)
        }
        /// SAFETY-DECISION (M5): for inspectors whose owner is implied by the location, an owner is
        /// optional, but when one is recorded it must be exactly the expected app.
        func ownerIsNilOr(_ expected: String) -> Bool {
            normalizedOwner == nil || normalizedOwner == PathComparison.normalize(expected)
        }
        /// No component below the home directory (except the last) is hidden.
        func noHiddenAncestor() -> Bool {
            !relative.dropLast().contains { $0.hasPrefix(".") }
        }

        // Milestone 5 inspectors (owner optional or not used).
        switch inspector {
        case .xcodeDerivedData:
            // Library/Developer/Xcode/DerivedData/<folder>
            guard ownerIsNilOr(xcodeBundleID), rel.count == 5,
                  hasPrefix(["Library", "Developer", "Xcode", "DerivedData"]) else { return false }
            // SAFETY-DECISION (M5 integration): the inspector's own pure shape check must agree too
            // (it requires the Xcode owner), so matcher and inspector can never drift apart.
            return !relative[4].hasPrefix(".") && XcodeDerivedDataInspector.matchesTargetShape(relative: relative, owner: owner)

        case .xcodeArchives:
            // Library/Developer/Xcode/Archives/<date folder>/<name>.xcarchive
            guard ownerIsNilOr(xcodeBundleID), rel.count == 6,
                  hasPrefix(["Library", "Developer", "Xcode", "Archives"]) else { return false }
            return !relative[4].hasPrefix(".") && !relative[5].hasPrefix(".")
                && rel[5].hasSuffix(".xcarchive") && rel[5].count > ".xcarchive".count
                && XcodeArchivesInspector.matchesTargetShape(relative: relative, owner: owner)

        case .xcodeDeviceSupport:
            // Library/Developer/Xcode/<Platform> DeviceSupport/<version folder>
            guard ownerIsNilOr(xcodeBundleID), rel.count == 5, hasPrefix(["Library", "Developer", "Xcode"]) else { return false }
            let platforms = Set(Self.deviceSupportFolderNames.map(PathComparison.normalize))
            return platforms.contains(rel[3]) && !relative[4].hasPrefix(".")
                && XcodeDeviceSupportInspector.matchesTargetShape(relative: relative, owner: owner)

        case .vscodeOldExtensions:
            // .vscode/extensions/<publisher.name>-<version>
            guard ownerIsNilOr("com.microsoft.VSCode"), rel.count == 3, hasPrefix([".vscode", "extensions"]) else { return false }
            return Self.looksLikeVersionedExtensionFolder(relative[2])
                && VSCodeExtensionsInspector.matchesTargetShape(relative: relative, owner: owner)

        case .jetbrainsCaches:
            // Library/Caches/JetBrains/<Product><Version>
            if let normalizedOwner {
                guard normalizedOwner.hasPrefix("com.jetbrains.") || normalizedOwner == "com.google.android.studio" else { return false }
            }
            guard rel.count == 4, hasPrefix(["Library", "Caches", "JetBrains"]) else { return false }
            guard Self.looksLikeProductVersionFolder(relative[3]) else { return false }
            // SAFETY-DECISION (M5 integration): the Green "orphaned version" rule only ever acts on a
            // KNOWN product owned by exactly that product's bundle id (the inspector's own shape). An
            // unknown product (owner nil) can only appear under the Yellow "current" rule.
            if ruleID == JetBrainsCachesInspector.orphanedRuleID {
                return JetBrainsCachesInspector.matchesTargetShape(relative: relative, owner: owner)
            }
            return JetBrainsCachesInspector.parseFolderName(relative[3]) != nil

        case .lightroomPreviews:
            // <anywhere below home>/<catalog> Previews.lrdata (never Smart Previews, never the .lrcat)
            guard ownerIsNilOr(lightroomBundleID), rel.count >= 1, noHiddenAncestor() else { return false }
            guard Self.isLightroomPreviewsName(relative[relative.count - 1]),
                  LightroomPreviewsInspector.isPreviewsFolderName(relative[relative.count - 1]) else { return false }
            // SAFETY-DECISION (M5 integration): never inside a package (e.g. inside another .lrdata).
            return !relative.dropLast().contains { ProjectArtifactsInspector.isPackageName($0) }

        case .appUserCachesUnknownOwner:
            // Library/Caches/<folder> that is not reserved by another rule or by Apple.
            guard rel.count == 3, hasPrefix(["Library", "Caches"]) else { return false }
            let name = relative[2]
            if let normalizedOwner, normalizedOwner != PathComparison.normalize(name) { return false }
            // SAFETY-DECISION (M5 integration): both reserved-name tables (matcher and inspector) apply.
            return !name.hasPrefix(".") && !Self.isReservedUnknownOwnerCacheName(name)
                && UnknownOwnerCachesInspector.shapeMatches(relative: relative)

        case .chromiumServiceWorkerCaches:
            // Library/Application Support/<browser>/<profile>/Service Worker/CacheStorage, owned by
            // that browser (owner required, like browser.chromium.cache).
            guard let normalizedOwner else { return false }
            for browser in ChromiumCachesInspector.knownBrowsers
            where PathComparison.normalize(browser.bundleID) == normalizedOwner {
                let base = ["Library", "Application Support"] + browser.supportComponents
                guard rel.count == base.count + 3, hasPrefix(base) else { continue }
                let profile = relative[base.count]
                if ChromiumCachesInspector.isProfileName(profile),
                   rel[base.count + 1] == PathComparison.normalize("Service Worker"),
                   rel[base.count + 2] == PathComparison.normalize("CacheStorage") {
                    return ChromiumServiceWorkerInspector.shapeMatches(relative: relative, owner: owner)
                }
            }
            return false

        case .projectArtifacts:
            // <project root …>/<project>/<artifact name of THIS rule>; never nested in another
            // artifact, never below a hidden folder. The allow-root ({PROJECT_ROOTS}) and the
            // manifest / git / age preconditions are checked separately by SafetyGate.
            guard let ruleID, let spec = projectArtifactSpecs[ruleID], rel.count >= 2, noHiddenAncestor() else { return false }
            let names = Set(spec.artifactNames.map(PathComparison.normalize))
            guard names.contains(rel[rel.count - 1]) else { return false }
            let allArtifactNames = Set(projectArtifactSpecs.values.flatMap(\.artifactNames).map(PathComparison.normalize))
            guard !rel.dropLast().contains(where: { allArtifactNames.contains($0) }) else { return false }
            // SAFETY-DECISION (M5 integration): the same descent rule as the ProjectScanner walk — no
            // ancestor below the home folder may be hidden, artifact-like or a package / bundle.
            return relative.dropLast().allSatisfy { ProjectArtifactsInspector.mayDescend(into: $0) }

        // Milestone 6 inspectors.
        case .orphanedAppData:
            // Library/<container>/<identifier> (Preferences: <identifier>.plist); owner REQUIRED and
            // equal to the identifier (the `stillOrphaned` / `owningAppNotRunning` checks use it).
            guard rel.count == 3, rel[0] == "library", let normalizedOwner else { return false }
            guard let container = Self.orphanContainerFolders.first(where: { PathComparison.normalize($0) == rel[1] }),
                  let identifier = Self.orphanIdentifier(container: container, name: relative[2]) else { return false }
            return PathComparison.normalize(identifier) == normalizedOwner

        case .orphanedLaunchAgents:
            // Library/LaunchAgents/<name>.plist, never Apple's; a recorded owner (the label) is never Apple's.
            guard rel.count == 3, hasPrefix(["Library", "LaunchAgents"]) else { return false }
            let name = relative[2]
            let suffix = ".plist"
            guard !name.hasPrefix("."), rel[2].hasSuffix(suffix), name.count > suffix.count,
                  !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return false }
            let base = String(name.dropLast(suffix.count))
            if BundleIdentifierHeuristics.isApple(base) || Self.isAppleOrphanIdentifier(base) { return false }
            if let normalizedOwner, normalizedOwner.hasPrefix("com.apple") { return false }
            return true

        case .jetbrainsConfig:
            // Library/Application Support/JetBrains/<Product><major>.<minor> of a KNOWN product, owned
            // by exactly that product's bundle identifier (the same classification as the Green
            // orphaned-caches rule; the folder holds IDE settings, so the rule is Red).
            guard rel.count == 4, hasPrefix(["Library", "Application Support", "JetBrains"]), let normalizedOwner,
                  Self.looksLikeProductVersionFolder(relative[3]),
                  let parsed = JetBrainsCachesInspector.parseFolderName(relative[3]),
                  let expected = JetBrainsCachesInspector.bundleID(forProduct: parsed.product) else { return false }
            return PathComparison.normalize(expected) == normalizedOwner && normalizedOwner.hasPrefix("com.jetbrains.")

        case .trashContents:
            // .Trash/<child>: direct children only, no owner.
            guard rel.count == 2, rel[0] == ".trash", normalizedOwner == nil else { return false }
            let name = relative[1]
            return !name.isEmpty && name != "." && name != ".."
                && !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control })

        default:
            break
        }

        guard let normalizedOwner else { return false } // every M2 inspector names the owner

        switch inspector {
        case .appUserCaches:
            // Library/Caches/<bundleID> of an installed non-Apple app, owned by that bundle id.
            guard rel.count == 3, hasPrefix(["Library", "Caches"]) else { return false }
            let name = relative[2]
            return BundleIdentifierHeuristics.looksReverseDNS(name) && !BundleIdentifierHeuristics.isApple(name)
                && PathComparison.normalize(name) == normalizedOwner

        case .appContainerCaches:
            // Library/Containers/<id>/Data/Library/Caches/<child>, owned by <id>.
            guard rel.count == 7, hasPrefix(["Library", "Containers"]),
                  Array(rel[3...5]) == ["data", "library", "caches"] else { return false }
            let id = relative[2]
            return BundleIdentifierHeuristics.looksReverseDNS(id) && !BundleIdentifierHeuristics.isApple(id)
                && PathComparison.normalize(id) == normalizedOwner

        case .electronCaches:
            // Library/Application Support/<known app folder>/<exact cache folder name>.
            guard rel.count == 4, hasPrefix(["Library", "Application Support"]) else { return false }
            let cacheNames = Set(ElectronCachesInspector.cacheFolderNames.map(PathComparison.normalize))
            guard cacheNames.contains(rel[3]) else { return false }
            return ElectronCachesInspector.knownApps.contains { app in
                PathComparison.normalize(app.folder) == rel[2] && PathComparison.normalize(app.bundleID) == normalizedOwner
            }

        case .chromiumCaches:
            for browser in ChromiumCachesInspector.knownBrowsers
            where PathComparison.normalize(browser.bundleID) == normalizedOwner {
                let layouts: [([String], [String])] = [
                    (["Library", "Application Support"] + browser.supportComponents, ChromiumCachesInspector.profileCacheNames),
                    (["Library", "Caches"] + browser.cachesComponents, ChromiumCachesInspector.cachesRootCacheNames),
                ]
                for (base, names) in layouts {
                    guard rel.count == base.count + 2, hasPrefix(base) else { continue }
                    let profile = relative[base.count]
                    let allowed = Set(names.map(PathComparison.normalize))
                    if ChromiumCachesInspector.isProfileName(profile), allowed.contains(rel[base.count + 1]) {
                        return true
                    }
                }
            }
            return false

        default:
            // SAFETY-DECISION: no predicate yet → nothing this inspector proposes can be acted on.
            return false
        }
    }

    // MARK: Milestone 6: whole-app bundles (xcode.extraInstalls, installers.macOS)

    /// SAFETY-DECISION (M6): a whole `.app` is a target only as a DIRECT child of `/Applications`
    /// (`xcode.extraInstalls` also `{HOME}/Applications`), never in a subfolder, never hidden, and the
    /// recorded owner (when present) must be the expected Apple bundle identifier.
    /// - `xcodeExtraInstalls`: `<name>.app`, owner nil or `com.apple.dt.Xcode`.
    /// - `macOSInstallers`: `Install macOS <name>.app` in `/Applications` only, owner nil or
    ///   `com.apple.InstallAssistant.*`.
    /// The bundle itself must still pass `appleSigned`, `notSelectedXcode` and the app-not-running
    /// checks (preconditions) and every SafetyGate check.
    func appBundleShapeMatches(_ target: CanonicalPath, inspector: InspectorID, owner: String?) -> Bool {
        let comps = target.components
        guard let name = comps.last else { return false }
        let n = PathComparison.normalize(name)
        guard !name.hasPrefix("."), n.hasSuffix(".app"), n.count > ".app".count,
              !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return false }
        let normalizedOwner = owner?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty.map(PathComparison.normalize)

        let inSystemApplications = comps.count == 2 && PathComparison.normalize(comps[0]) == "applications"
        let inHomeApplications = homeForms.contains { home in
            comps.count == home.components.count + 2
                && PathComparison.equal(Array(comps.prefix(home.components.count)), home.components)
                && PathComparison.normalize(comps[home.components.count]) == "applications"
        }
        switch inspector {
        case .xcodeExtraInstalls:
            guard inSystemApplications || inHomeApplications else { return false }
            return normalizedOwner == nil || normalizedOwner == PathComparison.normalize(Self.xcodeBundleID)
        case .macOSInstallers:
            guard inSystemApplications, n.hasPrefix("install macos "), n.count > "install macos .app".count else { return false }
            let prefix = PathComparison.normalize(String(RuleCatalog.macOSInstallerBundleIDPattern.dropLast()))
            return normalizedOwner.map { $0.hasPrefix(prefix) && $0.count > prefix.count } ?? true
        default:
            return false
        }
    }

    // MARK: Milestone 6: OrphanDetector shapes (spec §6.9)

    /// Folders of `~/Library` whose `<identifier>` children `leftovers.appData` may offer (spec §6.9).
    /// SAFETY-DECISION: `HTTPStorages` is deny-listed as a whole and therefore not listed here.
    public static let orphanContainerFolders = ["Application Support", "Preferences", "Containers",
                                                "Group Containers", "Caches", "WebKit"]

    /// Spec §6.9 condition 6: known CLI / tool / system folder names that are never orphan candidates
    /// (compared case-insensitively against the whole identifier and against its last label).
    public static let orphanKnownToolNames: [String] = [
        "Homebrew", "pip", "node-gyp", "typescript", "Jupyter", "npm", "yarn", "pnpm", "Code", "Cursor",
        "JetBrains", "Google", "Microsoft", "Adobe", "Mozilla", "Firefox", "Docker", "iMop", "CrashReporter",
        "AddressBook", "CallHistoryDB", "Knowledge", "Dock",
    ]

    /// Reverse-DNS identifiers that are never orphan candidates (iMop itself and tool caches other
    /// rules manage).
    public static let orphanReservedIdentifiers: [String] = [
        "com.imop.cleaner", "org.swift.swiftpm", "org.carthage.CarthageKit",
    ]

    /// SAFETY-DECISION (M6, spec §6.9 condition 6): only reverse-DNS-looking identifiers are ever
    /// considered — at least two dots (three labels), every label 1–63 ASCII letters, digits or "-",
    /// not starting or ending with "-", at most 255 characters. Plain folder names are never orphan
    /// candidates.
    public static func isOrphanCandidateIdentifier(_ identifier: String) -> Bool {
        let scalars = identifier.unicodeScalars
        guard !identifier.isEmpty, scalars.count <= 255, scalars.allSatisfy(\.isASCII) else { return false }
        let labels = identifier.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 3 else { return false }
        for label in labels {
            let chars = Array(label.unicodeScalars)
            guard (1...63).contains(chars.count), chars.first != "-", chars.last != "-" else { return false }
            guard chars.allSatisfy({ ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "-" })
            else { return false }
        }
        if isAppleOrphanIdentifier(identifier) { return false }
        let n = PathComparison.normalize(identifier)
        if orphanReservedIdentifiers.contains(where: { PathComparison.normalize($0) == n }) { return false }
        let last = labels.last.map { PathComparison.normalize(String($0)) } ?? ""
        return !orphanKnownToolNames.contains { let tool = PathComparison.normalize($0); return tool == n || tool == last }
    }

    /// SAFETY-DECISION (M6, spec §6.9 condition 1): `com.apple`, `com.apple.*`, `group.com.apple.*`
    /// and any identifier that contains the `com.apple` labels anywhere (e.g. `<TEAMID>.com.apple.x`).
    public static func isAppleOrphanIdentifier(_ identifier: String) -> Bool {
        let labels = PathComparison.normalize(identifier).split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard labels.count >= 2 else { return false }
        for index in 0..<(labels.count - 1) where labels[index] == "com" && labels[index + 1] == "apple" { return true }
        return false
    }

    /// The identifier a `leftovers.appData` candidate stands for: the folder name, or for
    /// `Preferences` the `<identifier>.plist` file name without `.plist`. `nil` when it has no
    /// acceptable identifier.
    public static func orphanIdentifier(container: String, name: String) -> String? {
        guard !name.hasPrefix(".") else { return nil }
        let identifier: String
        if PathComparison.normalize(container) == PathComparison.normalize("Preferences") {
            let suffix = ".plist"
            guard PathComparison.normalize(name).hasSuffix(suffix), name.count > suffix.count else { return nil }
            identifier = String(name.dropLast(suffix.count))
        } else {
            identifier = name
        }
        guard isOrphanCandidateIdentifier(identifier) else { return nil }
        if PathComparison.normalize(container) == PathComparison.normalize("Caches"), isReservedUnknownOwnerCacheName(name) {
            return nil
        }
        return identifier
    }

    // MARK: Milestone 5 shape tables

    static let xcodeBundleID = "com.apple.dt.Xcode"
    static let lightroomBundleID = "com.adobe.LightroomClassicCC7"

    /// Spec §6.1 `xcode.deviceSupport`, expanded explicitly.
    public static let deviceSupportFolderNames = ["iOS DeviceSupport", "watchOS DeviceSupport", "tvOS DeviceSupport", "visionOS DeviceSupport"]

    /// `<publisher>.<name>-<version>`: a "." in the id part, and a version starting with a digit after
    /// the last "-" (e.g. `ms-python.python-2024.2.1`, `golang.go-0.41.0-darwin-arm64` is accepted
    /// through its first "-<digit>" boundary).
    static func looksLikeVersionedExtensionFolder(_ name: String) -> Bool {
        guard !name.hasPrefix("."), !name.contains("/"), name.unicodeScalars.allSatisfy(\.isASCII) else { return false }
        let scalars = Array(name)
        for index in scalars.indices where scalars[index] == "-" && index > 0 && index + 1 < scalars.count {
            let id = String(scalars[..<index])
            if scalars[index + 1].isNumber, id.contains("."), !id.hasPrefix("."), !id.hasSuffix(".") { return true }
        }
        return false
    }

    /// `<Product><major>.<minor>…`: ASCII letters, then digits and dots starting with a digit.
    static func looksLikeProductVersionFolder(_ name: String) -> Bool {
        let scalars = Array(name.unicodeScalars)
        guard scalars.allSatisfy(\.isASCII), let firstDigit = scalars.firstIndex(where: { ("0"..."9").contains($0) }),
              firstDigit > 0 else { return false }
        let product = scalars[..<firstDigit], version = scalars[firstDigit...]
        return product.allSatisfy { ("a"..."z").contains($0) || ("A"..."Z").contains($0) }
            && version.allSatisfy { ("0"..."9").contains($0) || $0 == "." }
            && version.last != "."
    }

    /// `"<catalog> Previews.lrdata"` with a non-empty catalog name and NOT `"… Smart Previews.lrdata"`.
    public static func isLightroomPreviewsName(_ name: String) -> Bool {
        let n = PathComparison.normalize(name)
        let suffix = " previews.lrdata"
        guard n.hasSuffix(suffix), n.count > suffix.count, !n.hasPrefix(".") else { return false }
        // SAFETY-DECISION: Smart Previews are used for offline editing; they are never offered.
        return !n.hasSuffix(" smart previews.lrdata") && n != "smart previews.lrdata"
    }

    /// Folder names directly in `~/Library/Caches` that `apps.userCaches.unknownOwner` must never offer:
    /// the allow-roots / glob bases of other rules and well-known tool caches (so the overlap rule never
    /// lets a Yellow unknown-owner folder swallow a Green target, or a tool's own cache).
    public static let unknownOwnerReservedCacheNames: [String] = [
        // Other rules' roots / glob bases under Library/Caches.
        "Homebrew", "pip", "CocoaPods", "org.swift.swiftpm", "org.carthage.CarthageKit", "pypoetry", "ms-playwright",
        "JetBrains", "Firefox", "Google", "Microsoft Edge", "BraveSoftware", "Vivaldi", "Arc", "com.apple.Safari",
        "Yarn", "go-build",
        // Well-known tool caches that other rules or vendor commands manage.
        "Mozilla", "node-gyp", "typescript", "pnpm", "deno", "bazel", "ccache", "sccache", "Bun",
        "com.microsoft.VSCode.ShipIt", "Cypress", "electron", "electron-builder", "puppeteer", "huggingface",
        "Unity", "com.unity3d.UnityEditor5.x", "AndroidStudio", "Adobe",
        // iMop itself.
        "iMop", "com.imop.cleaner",
    ] + UnknownOwnerCachesInspector.appleSystemCacheNames // review M5: plain-named Apple caches

    /// `true` for names `apps.userCaches.unknownOwner` never offers: Apple's, reserved names, and
    /// names matching another rule's pattern directly in `~/Library/Caches` (`*.ShipIt`).
    public static func isReservedUnknownOwnerCacheName(_ name: String) -> Bool {
        let n = PathComparison.normalize(name)
        if n.isEmpty || n.hasPrefix(".") { return true }
        if BundleIdentifierHeuristics.isApple(name) || n.hasPrefix("com.apple") { return true }
        if n.hasSuffix(".shipit") { return true }
        return unknownOwnerReservedCacheNames.contains { PathComparison.normalize($0) == n }
    }

    /// One ProjectScanner artifact kind (spec §6.5).
    public struct ProjectArtifactSpec: Sendable, Hashable {
        public let ruleID: String
        /// Folder names this rule may offer (exact names, compared case-insensitively).
        public let artifactNames: [String]
        /// At least one must be a regular file beside the artifact (patterns may hold one `*`).
        public let manifestPatterns: [String]
        /// When non-empty, at least one of these must exist directly inside the artifact (re-proven
        /// by SafetyGate check 11d through `ProjectArtifactsInspector.identityProblem`; must equal the
        /// scanner kind's `requiredInsideAnyOf`, see the regression tests).
        public let markersInside: [String]
        /// Tools that must not be running (`processNotRunning`).
        public let tools: [String]
    }

    /// SAFETY-DECISION (spec §6.5): every ProjectScanner rule is pinned here; a Rules.json rule bound
    /// to the projectArtifacts inspector must be one of these ids, and generic names (`build`,
    /// `target`) only ever match together with their manifest.
    public static let projectArtifactSpecs: [String: ProjectArtifactSpec] = {
        let specs = [
            ProjectArtifactSpec(ruleID: "project.nodeModules", artifactNames: ["node_modules"],
                                manifestPatterns: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
                                markersInside: [], tools: ["node", "npm", "yarn", "pnpm", "bun"]),
            ProjectArtifactSpec(ruleID: "project.rustTarget", artifactNames: ["target"], manifestPatterns: ["Cargo.toml"],
                                markersInside: ["CACHEDIR.TAG", ".rustc_info.json"], tools: ["cargo", "rustc"]),
            ProjectArtifactSpec(ruleID: "project.pythonVenv", artifactNames: [".venv", "venv"],
                                manifestPatterns: ["pyproject.toml", "requirements*.txt", "uv.lock", "poetry.lock"],
                                markersInside: ["pyvenv.cfg"], tools: ["python", "python3"]),
            ProjectArtifactSpec(ruleID: "project.pods", artifactNames: ["Pods"], manifestPatterns: ["Podfile.lock"],
                                markersInside: [], tools: ["pod"]),
            ProjectArtifactSpec(ruleID: "project.nextBuild", artifactNames: [".next"], manifestPatterns: ["next.config.*"],
                                markersInside: [], tools: ["node"]),
            ProjectArtifactSpec(ruleID: "project.gradleBuild", artifactNames: ["build"], manifestPatterns: ["build.gradle", "build.gradle.kts"],
                                markersInside: [], tools: ["java", "gradle"]),
            ProjectArtifactSpec(ruleID: "project.swiftBuild", artifactNames: [".build"], manifestPatterns: ["Package.swift"],
                                markersInside: [], tools: ["swift-build", "swift-package"]),
        ]
        return Dictionary(uniqueKeysWithValues: specs.map { ($0.ruleID, $0) })
    }()
}

// MARK: - Vendor-command rules (Milestone 4)

extension RuleTargetMatcher {
    /// The complete, Swift-coded shape of a vendor-command rule.
    public struct CommandRuleShape: Sendable, Hashable {
        /// The only inspector that may discover the rule's items.
        public let inspector: InspectorID
        public let tier: Tier
        /// Exact executable name and argument array of the rule's action.
        public let tool: String
        public let arguments: [String]
        /// Preconditions the rule must declare (spec §6 tables). A rule may declare more, never fewer;
        /// `processNotRunning` names and `olderThan` days are minimums.
        public let requiredPreconditions: [Precondition]

        init(_ inspector: InspectorID, _ tier: Tier, _ tool: String, _ arguments: [String], requires: [Precondition] = []) {
            self.inspector = inspector
            self.tier = tier
            self.tool = tool
            self.arguments = arguments
            self.requiredPreconditions = requires
        }

        /// `true` when the command has a `{ITEM}` slot (one invocation per item).
        public var isPerItem: Bool { arguments.contains(CommandSpec.itemToken) }

        /// Validator of the `{ITEM}` slot, from the shared `CommandAllowList` (the same validator the
        /// live `CommandRunner` applies). `nil` for whole-rule commands.
        public var itemKind: CommandItemKind? { CommandAllowList.itemKind(tool: tool, template: arguments) }
    }

    /// SAFETY-DECISION: every vendor-command rule of spec §6 is pinned here (inspector, tier, exact
    /// command). A command item is only ever offered for, and accepted by, the rule it belongs to;
    /// a Rules.json entry that maps a rule id to another command, inspector or tier yields nothing.
    public static let commandRuleShapes: [String: CommandRuleShape] = {
        let item = CommandSpec.itemToken
        // SAFETY-DECISION (review M4): the spec §6 preconditions are pinned too, so a Rules.json edit
        // that drops one (e.g. `processNotRunning(npm, node)`) makes the rule offer nothing.
        func idle(_ names: String...) -> [Precondition] { [.processNotRunning(names)] }
        let simulator: [Precondition] = [.simulatorIdle]
        let docker: [Precondition] = [.dockerDaemonReachable]
        return [
            // §6.1 Simulators.
            "simulator.unavailable": CommandRuleShape(.simulatorUnavailable, .green, "xcrun", ["simctl", "delete", "unavailable"], requires: simulator),
            "simulator.devices.stale": CommandRuleShape(.simulatorDevices, .yellow, "xcrun", ["simctl", "delete", item],
                                                        requires: simulator + [.olderThan(days: 90)]),
            "simulator.runtimes": CommandRuleShape(.simulatorRuntimes, .yellow, "xcrun", ["simctl", "runtime", "delete", item], requires: simulator),
            // §6.2 Package managers & toolchains.
            "homebrew.cleanup": CommandRuleShape(.packageManagerCaches, .green, "brew", ["cleanup", "--prune=all"], requires: idle("brew")),
            "npm.cache": CommandRuleShape(.packageManagerCaches, .green, "npm", ["cache", "clean", "--force"], requires: idle("npm", "node")),
            "yarn.cache": CommandRuleShape(.packageManagerCaches, .green, "yarn", ["cache", "clean"], requires: idle("yarn")),
            "pnpm.store": CommandRuleShape(.packageManagerCaches, .green, "pnpm", ["store", "prune"], requires: idle("pnpm")),
            "bun.cache": CommandRuleShape(.packageManagerCaches, .green, "bun", ["pm", "cache", "rm"], requires: idle("bun")),
            "uv.cache.prune": CommandRuleShape(.packageManagerCaches, .green, "uv", ["cache", "prune"], requires: idle("uv")),
            "uv.cache.clean": CommandRuleShape(.packageManagerCaches, .yellow, "uv", ["cache", "clean"], requires: idle("uv")),
            "go.buildCache": CommandRuleShape(.packageManagerCaches, .green, "go", ["clean", "-cache"], requires: idle("go")),
            "go.modCache": CommandRuleShape(.packageManagerCaches, .yellow, "go", ["clean", "-modcache"], requires: idle("go")),
            "cocoapods.cache.command": CommandRuleShape(.packageManagerCaches, .green, "pod", ["cache", "clean", "--all"], requires: idle("pod")),
            "flutter.pubCache": CommandRuleShape(.packageManagerCaches, .yellow, "flutter", ["pub", "cache", "clean", "-f"],
                                                 requires: idle("dart", "flutter")),
            "android.avd": CommandRuleShape(.packageManagerCaches, .yellow, "avdmanager", ["delete", "avd", "-n", item],
                                            requires: idle("emulator", "qemu-system-aarch64")),
            // §6.4 Docker.
            "docker.danglingImages": CommandRuleShape(.dockerSystem, .green, "docker", ["image", "prune", "-f"], requires: docker),
            "docker.buildCache": CommandRuleShape(.dockerSystem, .green, "docker", ["builder", "prune", "-f"], requires: docker),
            "docker.unusedImages": CommandRuleShape(.dockerSystem, .yellow, "docker", ["image", "prune", "-a", "-f"], requires: docker),
            "docker.stoppedContainers": CommandRuleShape(.dockerSystem, .yellow, "docker", ["container", "prune", "-f"], requires: docker),
            "docker.volumes": CommandRuleShape(.dockerSystem, .red, "docker", ["volume", "rm", item], requires: docker),
            // §6.8 Local AI models.
            "ai.ollama": CommandRuleShape(.ollamaModels, .yellow, "ollama", ["rm", item]),
        ]
    }()

    /// `nil` when `rule` is exactly one of the pinned vendor-command rules; otherwise why not.
    public static func commandRuleMismatch(_ rule: Rule) -> String? {
        guard let shape = commandRuleShapes[rule.id] else { return "is not one of the reviewed vendor-command rules" }
        guard case .command(let spec) = rule.action else { return "action is not the reviewed command" }
        guard spec.tool == shape.tool, spec.arguments == shape.arguments else { return "command is not the one reviewed for this rule" }
        guard rule.discovery == .inspector(shape.inspector) else { return "discovery must be the \(shape.inspector.rawValue) inspector" }
        guard rule.tier == shape.tier else { return "tier must be \(shape.tier.rawValue) for this rule" }
        for required in shape.requiredPreconditions where !declares(rule.preconditions, required) {
            return "must declare the reviewed \(required.name) precondition"
        }
        return nil
    }

    /// `true` when `declared` includes `required` (or a stricter form of it).
    static func declares(_ declared: [Precondition], _ required: Precondition) -> Bool {
        switch required {
        case .processNotRunning(let names):
            var declaredNames = Set<String>()
            for case .processNotRunning(let list) in declared { declaredNames.formUnion(list) }
            return Set(names).isSubset(of: declaredNames)
        case .olderThan(days: let days):
            return declared.contains { if case .olderThan(days: let value) = $0 { return value >= days } else { return false } }
        case .projectOlderThan(days: let days):
            return declared.contains { if case .projectOlderThan(days: let value) = $0 { return value >= days } else { return false } }
        case .appNotRunning(let ids):
            // Every required bundle id (or pattern, spelled exactly) appears in a declared appNotRunning list.
            var declaredIDs = Set<String>()
            for case .appNotRunning(let list) in declared { declaredIDs.formUnion(list.map(PathComparison.normalize)) }
            return !ids.isEmpty && Set(ids.map(PathComparison.normalize)).isSubset(of: declaredIDs)
        default:
            return declared.contains(required)
        }
    }

    /// `nil` when a command item with `argument` may be acted on by `rule`; otherwise why not.
    ///
    /// SAFETY-DECISION: whole-rule commands accept only `argument == nil`; per-item commands accept
    /// only a non-nil argument of the slot's shape.
    public func commandItemMismatch(argument: String?, rule: Rule) -> String? {
        if let problem = Self.commandRuleMismatch(rule) { return problem }
        guard let shape = Self.commandRuleShapes[rule.id] else { return "is not one of the reviewed vendor-command rules" }
        guard shape.isPerItem else {
            return argument == nil ? nil : "this command takes no per-item argument"
        }
        guard let argument else { return "this command needs a per-item argument" }
        // SAFETY-DECISION: a per-item command without a reviewed validator accepts nothing.
        guard let kind = shape.itemKind else { return "this command has no reviewed item validator" }
        // Defence in depth on top of the validator: never an option-looking or control-character value.
        guard !argument.hasPrefix("-"),
              !argument.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }),
              kind.accepts(argument) else {
            return "\"\(argument)\" is not a valid \(kind.rawValue)"
        }
        return nil
    }

    /// `nil` when `target` (a command item) belongs to `rule` and has its command's shape.
    public func commandItemMismatch(_ target: ScanTarget, rule: Rule) -> String? {
        guard target.ruleID == rule.id else { return "item does not belong to this rule" }
        guard case .commandItem(let argument) = target.kind else { return "is not a command item" }
        return commandItemMismatch(argument: argument, rule: rule)
    }
}


private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
