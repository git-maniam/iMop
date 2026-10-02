import Foundation

// Readable, strict JSON coding for the rule model (spec §4).
//
// `Tier`, `RuleCategory`, `InspectorID`, `AdvisoryKind` and `OwnerInference` are raw-string
// enums whose synthesized `Codable` conformances already encode as their raw value and reject any
// unknown value. `CommandSpec` uses its synthesized conformance; the enclosing decoders below check
// its keys first so an unknown key is an error.
//
// SAFETY-DECISION: decoding is STRICT. Unknown keys, unknown cases, objects with more than one case
// key and wrongly typed values are decoding errors. RuleCatalog decodes each rule on its own, so an
// error disables only that rule.

/// A coding key for arbitrary JSON object keys.
struct RuleJSONKey: CodingKey, Hashable {
    let stringValue: String
    var intValue: Int? { nil }

    init(_ string: String) { self.stringValue = string }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

enum RuleCodingSupport {
    /// Keys a `CommandSpec` object may carry.
    static let commandSpecKeys: Set<String> = ["tool", "arguments", "dryRunArguments", "timeoutSeconds", "idempotentSafe"]

    /// Decodes a value that is either a bare string (`"quarantine"`) or a single-key object
    /// (`{"command": {...}}`).
    enum Shape {
        case name(String)
        case keyed(String, KeyedDecodingContainer<RuleJSONKey>)
    }

    static func shape(of decoder: any Decoder, typeName: String) throws -> Shape {
        if let single = try? decoder.singleValueContainer(), let name = try? single.decode(String.self) {
            return .name(name)
        }
        let container: KeyedDecodingContainer<RuleJSONKey>
        do {
            container = try decoder.container(keyedBy: RuleJSONKey.self)
        } catch {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "\(typeName) must be a string or an object with exactly one key"))
        }
        let keys = container.allKeys
        guard keys.count == 1, let key = keys.first else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "\(typeName) object must have exactly one key, found \(keys.map(\.stringValue).sorted())"))
        }
        return .keyed(key.stringValue, container)
    }

    static func unknownCase(_ value: String, typeName: String, decoder: any Decoder) -> DecodingError {
        DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                          debugDescription: "unknown \(typeName) \"\(value)\""))
    }

    /// Rejects unknown keys in a `CommandSpec` object, then decodes it.
    static func decodeCommand(from container: KeyedDecodingContainer<RuleJSONKey>, key: RuleJSONKey) throws -> CommandSpec {
        let nested = try container.nestedContainer(keyedBy: RuleJSONKey.self, forKey: key)
        let unknown = nested.allKeys.map(\.stringValue).filter { !commandSpecKeys.contains($0) }
        guard unknown.isEmpty else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: nested.codingPath,
                debugDescription: "unknown command key(s) \(unknown.sorted())"))
        }
        return try container.decode(CommandSpec.self, forKey: key)
    }

    /// Rejects any key of `container` not in `allowed`.
    static func rejectUnknownKeys(_ container: KeyedDecodingContainer<RuleJSONKey>, allowed: Set<String>, typeName: String) throws {
        let unknown = container.allKeys.map(\.stringValue).filter { !allowed.contains($0) }
        guard unknown.isEmpty else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: container.codingPath,
                debugDescription: "unknown \(typeName) key(s) \(unknown.sorted())"))
        }
    }
}

// MARK: - Discovery

/// `{"glob": ["{HOME}/…"]}` | `{"command": {CommandSpec}}` | `{"inspector": "appUserCaches"}`.
extension Discovery: Codable {
    public init(from decoder: any Decoder) throws {
        switch try RuleCodingSupport.shape(of: decoder, typeName: "discovery") {
        case .name(let name):
            throw RuleCodingSupport.unknownCase(name, typeName: "discovery", decoder: decoder)
        case .keyed(let name, let container):
            let key = RuleJSONKey(name)
            switch name {
            case "glob":
                self = .glob(try container.decode([String].self, forKey: key))
            case "command":
                self = .command(try RuleCodingSupport.decodeCommand(from: container, key: key))
            case "inspector":
                self = .inspector(try container.decode(InspectorID.self, forKey: key))
            default:
                throw RuleCodingSupport.unknownCase(name, typeName: "discovery", decoder: decoder)
            }
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: RuleJSONKey.self)
        switch self {
        case .glob(let patterns): try container.encode(patterns, forKey: RuleJSONKey("glob"))
        case .command(let spec): try container.encode(spec, forKey: RuleJSONKey("command"))
        case .inspector(let id): try container.encode(id, forKey: RuleJSONKey("inspector"))
        }
    }
}

// MARK: - Action

/// `"quarantine"` | `"trash"` | `"permanentDelete"` | `"bootoutAndTrash"` | `{"command": {…}}` | `{"advisory": "instructions"}`.
extension Action: Codable {
    public init(from decoder: any Decoder) throws {
        switch try RuleCodingSupport.shape(of: decoder, typeName: "action") {
        case .name(let name):
            switch name {
            case "quarantine": self = .quarantine
            case "trash": self = .trash
            case "permanentDelete": self = .permanentDelete
            case "bootoutAndTrash": self = .bootoutAndTrash
            default: throw RuleCodingSupport.unknownCase(name, typeName: "action", decoder: decoder)
            }
        case .keyed(let name, let container):
            let key = RuleJSONKey(name)
            switch name {
            case "command":
                self = .command(try RuleCodingSupport.decodeCommand(from: container, key: key))
            case "advisory":
                self = .advisory(try container.decode(AdvisoryKind.self, forKey: key))
            default:
                throw RuleCodingSupport.unknownCase(name, typeName: "action", decoder: decoder)
            }
        }
    }

    public func encode(to encoder: any Encoder) throws {
        switch self {
        case .quarantine:
            var single = encoder.singleValueContainer(); try single.encode("quarantine")
        case .trash:
            var single = encoder.singleValueContainer(); try single.encode("trash")
        case .permanentDelete:
            var single = encoder.singleValueContainer(); try single.encode("permanentDelete")
        case .bootoutAndTrash:
            var single = encoder.singleValueContainer(); try single.encode("bootoutAndTrash")
        case .command(let spec):
            var container = encoder.container(keyedBy: RuleJSONKey.self)
            try container.encode(spec, forKey: RuleJSONKey("command"))
        case .advisory(let kind):
            var container = encoder.container(keyedBy: RuleJSONKey.self)
            try container.encode(kind, forKey: RuleJSONKey("advisory"))
        }
    }
}

// MARK: - Precondition

/// Argument-free predicates are bare strings (`"notOpenByAnyProcess"`); the others are single-key
/// objects: `{"appNotRunning": ["com.apple.dt.Xcode"]}`, `{"processNotRunning": ["npm"]}`,
/// `{"olderThan": 14}`, `{"projectOlderThan": 90}`, `{"manifestPresent": ["Cargo.lock"]}`. Keys are `Precondition.name`.
extension Precondition: Codable {
    static let argumentFree: [String: Precondition] = [
        "owningAppNotRunning": .owningAppNotRunning,
        "notOpenByAnyProcess": .notOpenByAnyProcess,
        "notInsideCloudRoot": .notInsideCloudRoot,
        "ownedByUser": .ownedByUser,
        "simulatorIdle": .simulatorIdle,
        "dockerDaemonReachable": .dockerDaemonReachable,
        "notMounted": .notMounted,
        "appleSigned": .appleSigned,
        "notSelectedXcode": .notSelectedXcode,
        "uploadedToCloud": .uploadedToCloud,
        "notTrackedByGit": .notTrackedByGit,
        "stillOrphaned": .stillOrphaned,
    ]

    public init(from decoder: any Decoder) throws {
        switch try RuleCodingSupport.shape(of: decoder, typeName: "precondition") {
        case .name(let name):
            guard let value = Self.argumentFree[name] else {
                throw RuleCodingSupport.unknownCase(name, typeName: "precondition", decoder: decoder)
            }
            self = value
        case .keyed(let name, let container):
            let key = RuleJSONKey(name)
            switch name {
            case "appNotRunning":
                self = .appNotRunning(try container.decode([String].self, forKey: key))
            case "processNotRunning":
                self = .processNotRunning(try container.decode([String].self, forKey: key))
            case "olderThan":
                self = .olderThan(days: try container.decode(Int.self, forKey: key))
            case "projectOlderThan":
                self = .projectOlderThan(days: try container.decode(Int.self, forKey: key))
            case "manifestPresent":
                self = .manifestPresent(try container.decode([String].self, forKey: key))
            default:
                // An argument-free predicate written as an object is malformed too.
                throw RuleCodingSupport.unknownCase(name, typeName: "precondition object", decoder: decoder)
            }
        }
    }

    public func encode(to encoder: any Encoder) throws {
        switch self {
        case .appNotRunning(let ids):
            var container = encoder.container(keyedBy: RuleJSONKey.self)
            try container.encode(ids, forKey: RuleJSONKey(name))
        case .processNotRunning(let names), .manifestPresent(let names):
            var container = encoder.container(keyedBy: RuleJSONKey.self)
            try container.encode(names, forKey: RuleJSONKey(name))
        case .olderThan(let days), .projectOlderThan(let days):
            var container = encoder.container(keyedBy: RuleJSONKey.self)
            try container.encode(days, forKey: RuleJSONKey(name))
        case .owningAppNotRunning, .notOpenByAnyProcess, .notInsideCloudRoot, .ownedByUser, .simulatorIdle,
             .dockerDaemonReachable, .notMounted, .appleSigned, .notSelectedXcode, .uploadedToCloud,
             .notTrackedByGit, .stillOrphaned:
            var single = encoder.singleValueContainer()
            try single.encode(name)
        }
    }
}

// MARK: - Rule

extension Rule: Codable {
    enum Key: String, CaseIterable {
        case id, version, category, tier, title, explanation, whatYouLose, howItRegenerates, discovery
        case allowRoots, minDepthBelowRoot, preconditions, action, retentionHours, maxExpectedBytes
        case maxExpectedItems, allowSymlinkTarget, excludedNames, requiresFullDiskAccess, ownerInference

        var json: RuleJSONKey { RuleJSONKey(rawValue) }
    }

    static let allowedKeys: Set<String> = Set(Key.allCases.map(\.rawValue))

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: RuleJSONKey.self)
        try RuleCodingSupport.rejectUnknownKeys(c, allowed: Self.allowedKeys, typeName: "rule")

        self.init(
            id: try c.decode(String.self, forKey: Key.id.json),
            version: try c.decodeIfPresent(Int.self, forKey: Key.version.json) ?? 1,
            category: try c.decode(RuleCategory.self, forKey: Key.category.json),
            tier: try c.decode(Tier.self, forKey: Key.tier.json),
            title: try c.decode(String.self, forKey: Key.title.json),
            explanation: try c.decode(String.self, forKey: Key.explanation.json),
            whatYouLose: try c.decode(String.self, forKey: Key.whatYouLose.json),
            howItRegenerates: try c.decode(String.self, forKey: Key.howItRegenerates.json),
            discovery: try c.decode(Discovery.self, forKey: Key.discovery.json),
            allowRoots: try c.decode([String].self, forKey: Key.allowRoots.json),
            minDepthBelowRoot: try c.decodeIfPresent(Int.self, forKey: Key.minDepthBelowRoot.json) ?? 1,
            preconditions: try c.decodeIfPresent([Precondition].self, forKey: Key.preconditions.json) ?? [],
            action: try c.decode(Action.self, forKey: Key.action.json),
            retentionHours: try c.decodeIfPresent(Int.self, forKey: Key.retentionHours.json),
            maxExpectedBytes: try c.decodeIfPresent(Int64.self, forKey: Key.maxExpectedBytes.json),
            maxExpectedItems: try c.decodeIfPresent(Int.self, forKey: Key.maxExpectedItems.json),
            allowSymlinkTarget: try c.decodeIfPresent(Bool.self, forKey: Key.allowSymlinkTarget.json) ?? false,
            excludedNames: try c.decodeIfPresent([String].self, forKey: Key.excludedNames.json) ?? [],
            requiresFullDiskAccess: try c.decodeIfPresent(Bool.self, forKey: Key.requiresFullDiskAccess.json) ?? false,
            ownerInference: try c.decodeIfPresent(OwnerInference.self, forKey: Key.ownerInference.json) ?? OwnerInference.none
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: RuleJSONKey.self)
        try c.encode(id, forKey: Key.id.json)
        try c.encode(version, forKey: Key.version.json)
        try c.encode(category, forKey: Key.category.json)
        try c.encode(tier, forKey: Key.tier.json)
        try c.encode(title, forKey: Key.title.json)
        try c.encode(explanation, forKey: Key.explanation.json)
        try c.encode(whatYouLose, forKey: Key.whatYouLose.json)
        try c.encode(howItRegenerates, forKey: Key.howItRegenerates.json)
        try c.encode(discovery, forKey: Key.discovery.json)
        try c.encode(allowRoots, forKey: Key.allowRoots.json)
        try c.encode(minDepthBelowRoot, forKey: Key.minDepthBelowRoot.json)
        try c.encode(preconditions, forKey: Key.preconditions.json)
        try c.encode(action, forKey: Key.action.json)
        try c.encodeIfPresent(retentionHours, forKey: Key.retentionHours.json)
        try c.encodeIfPresent(maxExpectedBytes, forKey: Key.maxExpectedBytes.json)
        try c.encodeIfPresent(maxExpectedItems, forKey: Key.maxExpectedItems.json)
        try c.encode(allowSymlinkTarget, forKey: Key.allowSymlinkTarget.json)
        try c.encode(excludedNames, forKey: Key.excludedNames.json)
        try c.encode(requiresFullDiskAccess, forKey: Key.requiresFullDiskAccess.json)
        try c.encode(ownerInference, forKey: Key.ownerInference.json)
    }
}
