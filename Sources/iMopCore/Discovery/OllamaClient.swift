import Foundation

// Read-only discovery for the `ai.ollama` command rule (spec §6.8).
//
// Models are listed with the Ollama CLI's read-only `ollama list` (through
// `SafeCleanEnvironment.commands`, purpose `.readOnly`) and are only ever removed by `ollama rm
// <model>` in the Executor. iMop never reads, sizes or touches Ollama's blob store itself: layers are
// shared between models, so deleting files by hand could break other models.

// MARK: - ollama client

/// Read-only `ollama list` query and its defensive parser.
public struct OllamaClient: Sendable {
    public static let tool = "ollama"
    public static let listArguments = ["list"]
    static let timeout: TimeInterval = 30

    public struct Model: Sendable, Hashable {
        public let name: String
        public let id: String
        public let sizeBytes: Int64
        /// As printed by Ollama (relative, e.g. "3 weeks ago").
        public let modified: String
    }

    /// Result of parsing `ollama list`.
    public struct Listing: Sendable, Hashable {
        /// Models whose names are valid `ollama rm` arguments.
        public let models: [Model]
        /// Listed names that are NOT valid item arguments (never offered).
        public let skippedNames: [String]
    }

    let environment: SafeCleanEnvironment

    public init(environment: SafeCleanEnvironment) {
        self.environment = environment
    }

    func list() async -> Result<Listing, CommandDiscovery.Failure> {
        switch await CommandDiscovery.readOnly(Self.tool, Self.listArguments, timeout: Self.timeout, environment: environment) {
        case .failure(let failure): return .failure(failure)
        case .success(let text):
            guard let listing = Self.parseList(text) else { return .failure(.failed("Could not read the Ollama model list")) }
            return .success(listing)
        }
    }

    /// Parses the `ollama list` table:
    ///
    ///     NAME               ID              SIZE      MODIFIED
    ///     llama3.2:latest    a80c4f17acd5    2.0 GB    3 weeks ago
    ///
    /// SAFETY-DECISION: all or nothing for the table itself — `nil` without the exact header, for a
    /// row whose ID, size or shape does not parse, or for a name listed twice. A well-formed row whose
    /// name is not a valid `ollama rm` argument (`CommandItemKind.ollamaModelName`, e.g. upper-case
    /// letters) is reported in `skippedNames` and never offered.
    @_spi(FixtureTesting)
    public static func parseList(_ text: String) -> Listing? {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard let header = lines.first else { return nil }
        guard header.split(whereSeparator: \.isWhitespace).map({ $0.uppercased() }) == ["NAME", "ID", "SIZE", "MODIFIED"] else {
            return nil
        }
        var models: [Model] = []
        var skipped: [String] = []
        var seen = Set<String>()
        for line in lines.dropFirst() {
            let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
            // NAME ID <number> <unit> MODIFIED…
            guard tokens.count >= 5 else { return nil }
            let name = tokens[0]
            let id = tokens[1]
            guard id.count >= 12, id.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { return nil }
            guard let size = CommandDiscovery.parseHumanSize(tokens[2] + " " + tokens[3]) else { return nil }
            guard seen.insert(name).inserted else { return nil }
            let modified = tokens.dropFirst(4).joined(separator: " ")
            if CommandItemKind.ollamaModelName.accepts(name) {
                models.append(Model(name: name, id: id, sizeBytes: size, modified: modified))
            } else {
                skipped.append(name)
            }
        }
        return Listing(models: models, skippedNames: skipped)
    }
}

// MARK: - ai.ollama inspector

/// `ai.ollama` (Yellow, never preselected): one command item per model (argument = model name) for
/// `ollama rm {ITEM}`, sized by Ollama's own figure.
public struct OllamaModelsInspector: Inspector {
    public init() {}

    public var id: InspectorID { .ollamaModels }

    static let ruleID = "ai.ollama"
    static let actionArguments = ["rm", CommandSpec.itemToken]

    public func discover(rule: Rule, environment: SafeCleanEnvironment) async -> InspectorOutput {
        guard rule.id == Self.ruleID,
              CommandDiscovery.ruleMatches(rule, tool: OllamaClient.tool, arguments: Self.actionArguments, required: []) else {
            return InspectorOutput(candidates: [], status: .unavailable("This rule does not match its Ollama command"))
        }
        let listing: OllamaClient.Listing
        switch await OllamaClient(environment: environment).list() {
        case .failure(.toolMissing):
            return InspectorOutput(candidates: [], status: .unavailable("Ollama is not installed"))
        case .failure(.failed(let reason)):
            // `ollama list` needs the Ollama app / server; iMop never starts it.
            return InspectorOutput(candidates: [], status: .unavailable("Ollama is not running or did not answer (\(reason))"))
        case .success(let value):
            listing = value
        }

        var candidates: [DiscoveredCandidate] = []
        for model in listing.models {
            let notes = [
                "Size reported by Ollama: \(CommandDiscovery.formatBytes(model.sizeBytes)).",
                "Layers shared with other models are freed only when no remaining model uses them, so less space may be freed.",
                "Last modified: \(model.modified)",
                "ID: \(model.id)",
                "This cannot be undone. Ollama will re-download what it needs (ollama pull \(model.name)).",
            ]
            candidates.append(DiscoveredCandidate(
                commandItem: model.name, path: CommandDiscovery.informationalPath("ollama model", model.name),
                displayName: model.name, reportedBytes: model.sizeBytes, notes: notes))
        }
        return InspectorOutput(candidates: candidates, status: .ok)
    }
}
