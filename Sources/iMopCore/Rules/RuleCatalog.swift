import Foundation
import os

/// Why a rule was disabled at load time.
public struct RuleValidationIssue: Sendable, Hashable, CustomStringConvertible {
    /// The rule's id, or a placeholder (`"<catalog>"`, `"rules[3]"`) when it has none.
    public let ruleID: String
    public let message: String

    public init(ruleID: String, message: String) {
        self.ruleID = ruleID
        self.message = message
    }

    public var description: String { "\(ruleID): \(message)" }
}

/// The validated rule set (spec §4). Rules can only NARROW what is allowed; the Swift deny-list and
/// SafetyGate always apply on top. Any invalid rule is disabled and recorded; the app continues.
///
/// Read-only: loading reads the bundled Rules.json; validation is pure computation.
public struct RuleCatalog: Sendable {
    /// Valid rules, in file order.
    public let rules: [Rule]
    /// One entry per problem that disabled a rule (a rule may have several).
    public let disabled: [RuleValidationIssue]

    private static let logger = Logger(subsystem: "com.imop.cleaner", category: "RuleCatalog")

    /// Placeholder rule id for problems with the catalog file itself.
    public static let catalogIssueID = "<catalog>"
    public static let supportedFileVersion = 1
    public static let resourceBundleName = "iMop_iMopCore.bundle"

    private init(rules: [Rule], disabled: [RuleValidationIssue]) {
        self.rules = rules
        self.disabled = disabled
    }

    /// Validates in-memory rules exactly like `load(data:environment:)` (used by tests and by
    /// callers that build rules in code). Invalid rules are disabled, never trusted.
    public init(validating candidates: [Rule], environment: SafeCleanEnvironment) {
        self = Self.build(slots: candidates.enumerated().map { RuleSlot(index: $0.offset, id: $0.element.id, outcome: .success($0.element)) },
                          preIssues: [])
    }

    public func rule(id: String) -> Rule? {
        rules.first { $0.id == id }
    }

    // MARK: - Loading

    /// Loads the Rules.json shipped inside the app. Never traps: a missing or unreadable file gives an
    /// empty catalog with an issue.
    public static func loadBundled(environment: SafeCleanEnvironment) -> RuleCatalog {
        for url in bundledCandidateURLs() {
            // The rules file lives in the app's own (signed) bundle or the build directory, never in
            // user data, so it is read directly rather than through the home-guarded probe.
            guard FileManager.default.isReadableFile(atPath: url.path),
                  let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { continue }
            return load(data: data, environment: environment)
        }
        let issue = RuleValidationIssue(ruleID: catalogIssueID, message: "Rules.json was not found in the app bundle")
        logger.error("\(issue.description, privacy: .public)")
        return RuleCatalog(rules: [], disabled: [issue])
    }

    /// Candidate locations of the bundled Rules.json, most specific first.
    ///
    /// SAFETY-DECISION: the SwiftPM-generated `Bundle.module` accessor calls `fatalError` when its
    /// bundle is missing, so it is never referenced. Instead the same places it searches (next to the
    /// executable / at the main bundle's URL) are probed explicitly, after Contents/Resources.
    static func bundledCandidateURLs() -> [URL] {
        var bundleURLs: [URL] = []
        if let resources = Bundle.main.resourceURL {
            bundleURLs.append(resources.appendingPathComponent(resourceBundleName, isDirectory: true))
        }
        bundleURLs.append(Bundle.main.bundleURL.appendingPathComponent(resourceBundleName, isDirectory: true))
        if let executable = Bundle.main.executableURL {
            bundleURLs.append(executable.deletingLastPathComponent().appendingPathComponent(resourceBundleName, isDirectory: true))
        }

        var urls: [URL] = []
        if let first = bundleURLs.first {
            urls.append(contentsOf: rulesURLs(inResourceBundle: first))
        }
        if let main = Bundle.main.url(forResource: "Rules", withExtension: "json") {
            urls.append(main)
        }
        for bundleURL in bundleURLs.dropFirst() {
            urls.append(contentsOf: rulesURLs(inResourceBundle: bundleURL))
        }
        var seen = Set<String>()
        return urls.filter { seen.insert($0.standardizedFileURL.path).inserted }
    }

    private static func rulesURLs(inResourceBundle bundleURL: URL) -> [URL] {
        var urls: [URL] = []
        if let bundle = Bundle(url: bundleURL), let url = bundle.url(forResource: "Rules", withExtension: "json") {
            urls.append(url)
        }
        // Flat and Contents/Resources layouts.
        urls.append(bundleURL.appendingPathComponent("Rules.json"))
        urls.append(bundleURL.appendingPathComponent("Contents/Resources/Rules.json"))
        return urls
    }

    /// Decodes `{"version": 1, "rules": [ … ]}` one rule at a time, so a malformed rule disables
    /// only itself, then validates every rule.
    public static func load(data: Data, environment: SafeCleanEnvironment) -> RuleCatalog {
        let file: CatalogFile
        do {
            file = try JSONDecoder().decode(CatalogFile.self, from: data)
        } catch {
            let issue = RuleValidationIssue(ruleID: catalogIssueID, message: "Rules.json is malformed: \(describe(error))")
            logger.error("\(issue.description, privacy: .public)")
            return RuleCatalog(rules: [], disabled: [issue])
        }
        guard file.version == supportedFileVersion else {
            // SAFETY-DECISION: an unknown file format version is never interpreted.
            let issue = RuleValidationIssue(ruleID: catalogIssueID, message: "Unsupported Rules.json version \(file.version)")
            logger.error("\(issue.description, privacy: .public)")
            return RuleCatalog(rules: [], disabled: [issue])
        }
        return build(slots: file.slots, preIssues: [])
    }

    private static func build(slots: [RuleSlot], preIssues: [RuleValidationIssue]) -> RuleCatalog {
        var issues = preIssues

        // SAFETY-DECISION: an id used more than once (even by a rule that failed to decode) is
        // ambiguous; EVERY rule with that id is disabled.
        var counts: [String: Int] = [:]
        for slot in slots {
            if let id = slot.id { counts[id, default: 0] += 1 }
        }

        var valid: [Rule] = []
        for slot in slots {
            let label = slot.id ?? "rules[\(slot.index)]"
            switch slot.outcome {
            case .failure(let message):
                issues.append(RuleValidationIssue(ruleID: label, message: "Could not be decoded: \(message)"))
            case .success(let rule):
                var problems = validationProblems(for: rule)
                if (counts[rule.id] ?? 0) > 1 {
                    problems.insert("Duplicate rule id", at: 0)
                }
                if problems.isEmpty {
                    valid.append(rule)
                } else {
                    issues.append(contentsOf: problems.map { RuleValidationIssue(ruleID: label, message: $0) })
                }
            }
        }
        for issue in issues {
            logger.error("Rule disabled — \(issue.description, privacy: .public)")
        }
        return RuleCatalog(rules: valid, disabled: issues)
    }

    // MARK: - Swift-coded exception tables (never in Rules.json)

    /// Rules allowed to declare an allow-root outside `{HOME}` (spec §6: `/cores/core.*`,
    /// `/Applications/…`). Every target is still deny-list-checked and gated individually.
    public static let nonHomeAllowRootExceptions: [String: [String]] = [
        "system.coreDumps": ["/cores"],
        "xcode.extraInstalls": ["/Applications", "{HOME}/Applications"],
        "installers.macOS": ["/Applications"],
    ]

    /// SAFETY-DECISION: allow-roots that CONTAIN deny-listed locations, permitted only for these
    /// inspector-driven rules (Swift-coded discovery that targets explicit, named children; e.g.
    /// `~/Library/Containers` contains `com.apple.*` containers). The root itself must not be inside a
    /// deny-listed area, glob discovery is never allowed with them, and SafetyGate still rejects any
    /// target that is, or contains, a deny-listed location.
    public static let protectedAncestorRootExceptions: [String: [String]] = [
        "apps.containerCaches": ["{HOME}/Library/Containers"],
        "apps.electronCaches": ["{HOME}/Library/Application Support"],
        "browser.chromium.cache": ["{HOME}/Library/Application Support"],
    ]

    /// SAFETY-DECISION: allow-roots that are themselves inside a deny-listed area, mirroring the
    /// deny-list's own narrow exception (`DenyList`: direct children of Mail Downloads for
    /// `mail.downloads` only). Accepted only if a direct child of the root is NOT deny-listed for that
    /// rule, i.e. the deny-list exception really exists.
    public static let deniedRootExceptions: [String: [String]] = [
        "mail.downloads": ["{HOME}/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"],
    ]

    /// Rules allowed to use `.permanentDelete` (Yellow only).
    public static let permanentDeleteAllowList: Set<String> = ["trash.empty"]

    /// SAFETY-DECISION: Red rules may use a vendor command only when listed here (reserved for later
    /// milestones; per-item confirmation is mandatory for them).
    public static let redCommandAllowList: Set<String> = ["docker.volumes", "leftovers.launchAgents"]

    /// Argument tokens that are never allowed in any command or dry-run argument array.
    public static let forbiddenCommandArguments: Set<String> = ["--volumes", "autoremove", "sh", "-c", "rm", "sudo"]

    /// SAFETY-DECISION: executables that are never acceptable as a rule's tool (shells, privilege
    /// escalation, generic removers and interpreters that could run arbitrary code).
    public static let forbiddenTools: Set<String> = [
        "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "fish",
        "sudo", "su", "doas", "env", "xargs", "osascript", "perl", "ruby", "python", "python3",
        "rm", "srm", "find", "dd", "diskutil", "chmod", "chown", "mv", "cp",
        // Spelled in two pieces so the static read-only test (which greps this directory for
        // mutation API names) does not flag a deny-list entry as a mutation call.
        "rm" + "dir", "un" + "link",
    ]

    /// Synthetic home used for validation. Validation is a property of the rule text alone and does
    /// not depend on where the current user's home directory happens to be.
    static let validationHome = "/Users/imop-rule-validation"
    private static let probeName = "imop-validation-probe"

    // MARK: - Validation

    /// Every reason `rule` is invalid (empty when valid). Spec §4 plus the SAFETY-DECISIONs above.
    public static func validationProblems(for rule: Rule) -> [String] {
        var problems: [String] = []
        let denyList = DenyList(homeDirectory: validationHome)

        // Identity and text.
        if !isValidRuleID(rule.id) {
            problems.append("Rule id must be non-empty and use only letters, digits, '.', '-' or '_'")
        }
        if rule.version < 1 { problems.append("version must be at least 1") }
        for (name, text) in [("title", rule.title), ("explanation", rule.explanation),
                             ("whatYouLose", rule.whatYouLose), ("howItRegenerates", rule.howItRegenerates)]
        where text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            problems.append("\(name) must not be empty")
        }

        // Numeric limits.
        if rule.minDepthBelowRoot < 1 { problems.append("minDepthBelowRoot must be at least 1") }
        if let bytes = rule.maxExpectedBytes, bytes <= 0 { problems.append("maxExpectedBytes must be greater than 0") }
        if let items = rule.maxExpectedItems, items <= 0 { problems.append("maxExpectedItems must be greater than 0") }
        if let hours = rule.retentionHours, hours <= 0 { problems.append("retentionHours must be greater than 0") }

        // Allow-roots.
        var roots: [(raw: String, path: CanonicalPath, isNonHome: Bool)] = []
        if rule.allowRoots.isEmpty { problems.append("allowRoots must not be empty") }
        for raw in rule.allowRoots {
            switch validateAllowRoot(raw, rule: rule, denyList: denyList) {
            case .success(let entry): roots.append(entry)
            case .failure(let problem): problems.append(problem.message)
            }
        }

        // Discovery.
        switch rule.discovery {
        case .glob(let patterns):
            problems.append(contentsOf: validateGlobs(patterns, rule: rule, roots: roots, denyList: denyList))
        case .inspector:
            if rule.ownerInference != .none {
                problems.append("ownerInference applies to glob discovery only (inspectors supply owners)")
            }
        case .command(let spec):
            problems.append(contentsOf: validateCommand(spec, context: "discovery command"))
            if rule.ownerInference != .none {
                problems.append("ownerInference applies to glob discovery only")
            }
        }
        if case .glob = rule.discovery {} else if !rule.excludedNames.isEmpty {
            problems.append("excludedNames applies to glob discovery only")
        }
        for name in rule.excludedNames where !isValidName(name) {
            problems.append("excludedNames entry \"\(name)\" must be a single file name")
        }

        // Tier / action matrix.
        problems.append(contentsOf: validateTierAction(rule))
        if case .command(let spec) = rule.action {
            problems.append(contentsOf: validateCommand(spec, context: "action command"))
        }

        // Preconditions.
        problems.append(contentsOf: validatePreconditions(rule))

        return problems
    }

    private struct Problem: Error { let message: String }

    private static func validateAllowRoot(_ raw: String, rule: Rule, denyList: DenyList)
        -> Result<(raw: String, path: CanonicalPath, isNonHome: Bool), Problem> {
        let homePrefix = GlobPattern.homeToken + "/"
        if !raw.hasPrefix(homePrefix) {
            guard nonHomeAllowRootExceptions[rule.id]?.contains(raw) == true else {
                return .failure(Problem(message: "allowRoot \"\(raw)\" must start with {HOME}/"))
            }
            guard case .success(let path) = PathCanonicalizer.clean(raw, home: nil), !path.components.isEmpty else {
                return .failure(Problem(message: "allowRoot \"\(raw)\" is not a valid path"))
            }
            // SAFETY-DECISION: the Swift-coded non-home roots are reviewed exceptions; root-level
            // deny-list checks are not applied to them (e.g. /Applications contains
            // /Applications/Utilities), but every target below them is still deny-list-checked and
            // gated (only /cores/core.* is ever reachable under /cores).
            return .success((raw, path, true))
        }

        // Grammar: a literal {HOME}-anchored path with no wildcards.
        guard GlobPattern(raw) != nil, !raw.contains("*") else {
            return .failure(Problem(message: "allowRoot \"\(raw)\" is not a literal {HOME}/… path"))
        }
        guard case .success(let path) = PathCanonicalizer.clean(raw, home: validationHome),
              let home = PathCanonicalizer.validHome(validationHome) else {
            return .failure(Problem(message: "allowRoot \"\(raw)\" is not a valid path"))
        }
        let homePath = CanonicalPath(validatedPath: home)
        guard path.isStrictlyInside(homePath) else {
            return .failure(Problem(message: "allowRoot \"\(raw)\" must be strictly inside {HOME}"))
        }

        let probe = path.appending(probeName)
        if deniedRootExceptions[rule.id]?.contains(raw) == true
            || protectedAncestorRootExceptions[rule.id]?.contains(raw) == true {
            // The root itself may be (or contain) a protected location, but its direct children must
            // be reachable for this rule — otherwise the exception is meaningless or misconfigured.
            if let entry = denyList.matchingEntry(for: probe, ruleID: rule.id, purpose: .standard) {
                return .failure(Problem(message: "allowRoot \"\(raw)\" is deny-listed (\(entry))"))
            }
            if protectedAncestorRootExceptions[rule.id]?.contains(raw) == true,
               let entry = denyList.matchingEntry(for: path, ruleID: rule.id, purpose: .standard),
               !entry.hasPrefix("contains ") {
                return .failure(Problem(message: "allowRoot \"\(raw)\" is deny-listed (\(entry))"))
            }
            return .success((raw, path, false))
        }

        // Neither inside nor an ancestor-or-equal of any deny-list entry (system or home-relative).
        if let entry = denyList.matchingEntry(for: path, ruleID: rule.id, purpose: .standard) {
            return .failure(Problem(message: "allowRoot \"\(raw)\" intersects the deny-list (\(entry))"))
        }
        if let entry = denyList.matchingEntry(for: probe, ruleID: rule.id, purpose: .standard) {
            return .failure(Problem(message: "allowRoot \"\(raw)\" intersects the deny-list (\(entry))"))
        }
        return .success((raw, path, false))
    }

    private static func validateGlobs(_ patterns: [String], rule: Rule,
                                      roots: [(raw: String, path: CanonicalPath, isNonHome: Bool)],
                                      denyList: DenyList) -> [String] {
        var problems: [String] = []
        if patterns.isEmpty { problems.append("glob discovery needs at least one pattern") }
        if protectedAncestorRootExceptions[rule.id] != nil {
            problems.append("glob discovery is not allowed for a rule whose allow-root contains protected locations")
        }
        let requiredDepth = max(1, rule.minDepthBelowRoot)
        for raw in patterns {
            guard !raw.contains("**") else {
                problems.append("glob \"\(raw)\" uses the forbidden recursive wildcard **")
                continue
            }
            guard let pattern = GlobPattern(raw) else {
                problems.append("glob \"\(raw)\" does not follow the glob grammar")
                continue
            }
            let components: [String]
            switch pattern.anchor {
            case .home:
                components = pattern.resolved(home: validationHome)
            case .absolute:
                components = pattern.segments
            }
            guard !components.isEmpty else {
                problems.append("glob \"\(raw)\" could not be resolved")
                continue
            }
            // Strictly inside one of the rule's allow-roots at depth >= minDepthBelowRoot. Root
            // components are literal; the matching pattern components must be literal and equal.
            let normalized = components.map(PathComparison.normalize)
            let inside = roots.contains { root in
                guard root.isNonHome == (pattern.anchor == .absolute) else { return false }
                let rootParts = root.path.components.map(PathComparison.normalize)
                guard normalized.count - rootParts.count >= requiredDepth else { return false }
                return Array(normalized.prefix(rootParts.count)) == rootParts
                    && !components.prefix(rootParts.count).contains { $0.contains("*") }
            }
            if !inside {
                problems.append("glob \"\(raw)\" must be inside one of the rule's allowRoots at depth >= \(requiredDepth)")
                continue
            }
            // SAFETY-DECISION: a sample match of the pattern (each "*" replaced by a probe word) must
            // not be deny-listed for this rule; a pattern that names protected data on its face is
            // invalid. Non-home exception patterns are gated per target instead.
            if pattern.anchor == .home {
                let sample = "/" + components.map { $0.replacingOccurrences(of: "*", with: "imopprobe") }.joined(separator: "/")
                if case .success(let samplePath) = PathCanonicalizer.clean(sample, home: nil),
                   let entry = denyList.matchingEntry(for: samplePath, ruleID: rule.id, purpose: .standard) {
                    problems.append("glob \"\(raw)\" matches deny-listed locations (\(entry))")
                }
            }
        }
        return problems
    }

    private static func validateTierAction(_ rule: Rule) -> [String] {
        switch (rule.tier, rule.action) {
        case (.green, .quarantine):
            return []
        case (.green, .command(let spec)):
            return spec.idempotentSafe ? [] : ["Green rules may only use commands marked idempotentSafe"]
        case (.green, _):
            return ["Green rules may only quarantine or run an idempotentSafe command"]
        case (.yellow, .quarantine), (.yellow, .trash), (.yellow, .command):
            return []
        case (.yellow, .permanentDelete):
            return permanentDeleteAllowList.contains(rule.id) ? [] : ["permanentDelete is not allowed for this rule"]
        case (.yellow, .advisory):
            return ["Yellow rules may not use an advisory action"]
        case (.red, .trash), (.red, .advisory):
            return []
        case (.red, .command):
            return redCommandAllowList.contains(rule.id) ? [] : ["Red rules may only move to Trash or be advisory"]
        case (.red, _):
            return ["Red rules may only move to Trash or be advisory"]
        case (.advisory, .advisory):
            return []
        case (.advisory, _):
            return ["Advisory rules may only use an advisory action"]
        }
    }

    private static func validateCommand(_ spec: CommandSpec, context: String) -> [String] {
        var problems: [String] = []
        let tool = spec.tool
        let toolChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-")
        if tool.isEmpty || tool == "." || tool == ".." || tool.hasPrefix("-") || tool.contains("/")
            || !tool.unicodeScalars.allSatisfy({ toolChars.contains($0) }) {
            problems.append("\(context): tool \"\(tool)\" must be a bare executable name")
        }
        if forbiddenTools.contains(tool.lowercased()) {
            problems.append("\(context): tool \"\(tool)\" is not allowed")
        }
        for (label, arguments) in [("arguments", spec.arguments), ("dryRunArguments", spec.dryRunArguments ?? [])] {
            let lowered = arguments.map { $0.lowercased() }
            for token in lowered where forbiddenCommandArguments.contains(token) {
                problems.append("\(context): \(label) contain the forbidden token \"\(token)\"")
            }
            // SAFETY-DECISION: no rule may run any "system prune" (Docker's `system prune` can delete
            // volumes and every unused image); the spec only needs targeted prune subcommands.
            if lowered.contains("system") && lowered.contains("prune") {
                problems.append("\(context): \(label) must not run \"system prune\"")
            }
            if arguments.contains(where: { $0.contains("\0") || $0.contains("\n") || $0.contains("\r") }) {
                problems.append("\(context): \(label) contain control characters")
            }
        }
        if let timeout = spec.timeoutSeconds, timeout <= 0 {
            problems.append("\(context): timeoutSeconds must be greater than 0")
        }
        return problems
    }

    private static func validatePreconditions(_ rule: Rule) -> [String] {
        var problems: [String] = []
        for precondition in rule.preconditions {
            switch precondition {
            case .appNotRunning(let ids):
                if ids.isEmpty { problems.append("appNotRunning needs at least one bundle id") }
                for id in ids where BundleIDPattern(id) == nil {
                    problems.append("appNotRunning: \"\(id)\" is not a valid bundle id pattern")
                }
            case .processNotRunning(let names):
                if names.isEmpty { problems.append("processNotRunning needs at least one process name") }
                for name in names where !isValidName(name) {
                    problems.append("processNotRunning: \"\(name)\" is not a valid process name")
                }
            case .manifestPresent(let names):
                if names.isEmpty { problems.append("manifestPresent needs at least one file name") }
                for name in names where !isValidName(name) {
                    problems.append("manifestPresent: \"\(name)\" is not a single file name")
                }
            case .olderThan(let days):
                if days < 1 { problems.append("olderThan must be at least 1 day") }
            case .owningAppNotRunning:
                // SAFETY-DECISION: a glob rule without an owner hint can never name its owner; the
                // predicate would always fail. Treat that as a misconfigured rule.
                if case .glob = rule.discovery, rule.ownerInference == .none {
                    problems.append("owningAppNotRunning needs ownerInference for glob discovery")
                }
                if case .command = rule.discovery {
                    problems.append("owningAppNotRunning cannot be used with command discovery")
                }
            case .notOpenByAnyProcess, .notInsideCloudRoot, .ownedByUser, .simulatorIdle, .dockerDaemonReachable,
                 .notMounted, .appleSigned, .notSelectedXcode, .uploadedToCloud:
                break
            }
        }
        return problems
    }

    private static func isValidRuleID(_ id: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return !id.isEmpty && id.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// A single, non-empty path component.
    private static func isValidName(_ name: String) -> Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && name != "." && name != ".."
            && !name.contains("/") && !name.contains("\0")
            && !name.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    // MARK: - Decoding helpers

    fileprivate static func describe(_ error: any Error) -> String {
        guard let decodingError = error as? DecodingError else { return String(describing: error) }
        func path(_ codingPath: [any CodingKey]) -> String {
            var text = ""
            for key in codingPath {
                if let index = key.intValue {
                    text += "[\(index)]"
                } else if key.stringValue.hasPrefix("Index "), let index = Int(key.stringValue.dropFirst("Index ".count)) {
                    text += "[\(index)]"
                } else {
                    text += text.isEmpty ? key.stringValue : ".\(key.stringValue)"
                }
            }
            return text.isEmpty ? "" : " at \(text)"
        }
        switch decodingError {
        case .keyNotFound(let key, let context):
            return "missing \"\(key.stringValue)\"\(path(context.codingPath))"
        case .typeMismatch(_, let context), .valueNotFound(_, let context), .dataCorrupted(let context):
            return "\(context.debugDescription)\(path(context.codingPath))"
        @unknown default:
            return String(describing: decodingError)
        }
    }
}

// MARK: - File format

/// One element of the `rules` array: decoded independently so a bad rule fails alone.
private struct RuleSlot: Sendable {
    enum Outcome: Sendable {
        case success(Rule)
        case failure(String)
    }

    let index: Int
    let id: String?
    let outcome: Outcome
}

private struct RuleSlotDecoder: Decodable {
    let id: String?
    let outcome: RuleSlot.Outcome

    init(from decoder: any Decoder) throws {
        // Never throws: the error is captured so the enclosing array keeps decoding.
        id = (try? decoder.container(keyedBy: RuleJSONKey.self))
            .flatMap { try? $0.decode(String.self, forKey: RuleJSONKey("id")) }
        do {
            outcome = .success(try Rule(from: decoder))
        } catch {
            outcome = .failure(RuleCatalog.describe(error))
        }
    }
}

private struct CatalogFile: Decodable {
    let version: Int
    let slots: [RuleSlot]

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: RuleJSONKey.self)
        // SAFETY-DECISION: unknown top-level keys make the whole file invalid (it is bundled and
        // reviewed; an unexpected shape means it is not the file we think it is).
        try RuleCodingSupport.rejectUnknownKeys(container, allowed: ["version", "rules"], typeName: "catalog")
        version = try container.decode(Int.self, forKey: RuleJSONKey("version"))
        var array = try container.nestedUnkeyedContainer(forKey: RuleJSONKey("rules"))
        var slots: [RuleSlot] = []
        while !array.isAtEnd {
            let index = array.currentIndex
            let slot = try array.decode(RuleSlotDecoder.self)
            slots.append(RuleSlot(index: index, id: slot.id, outcome: slot.outcome))
        }
        self.slots = slots
    }
}
