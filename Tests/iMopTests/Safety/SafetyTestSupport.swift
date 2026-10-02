import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Shared helpers for the Milestone 1 (spec §12.1) safety suites.
@MainActor
enum M1 {
    static let cachesRoot = "{HOME}/Library/Caches"

    static func rule(
        id: String = "test.caches",
        tier: Tier = .green,
        allowRoots: [String] = [cachesRoot],
        minDepth: Int = 1,
        preconditions: [Precondition] = [],
        action: Action = .quarantine,
        maxBytes: Int64? = nil,
        maxItems: Int? = nil,
        allowSymlinkTarget: Bool = false,
        discovery: Discovery? = nil
    ) -> Rule {
        Rule(
            id: id, category: .apps, tier: tier, title: "Test rule \(id)",
            explanation: "test", whatYouLose: "nothing", howItRegenerates: "automatically",
            discovery: discovery ?? derivedGlobs(allowRoots: allowRoots, minDepth: minDepth),
            allowRoots: allowRoots, minDepthBelowRoot: minDepth,
            preconditions: preconditions, action: action, maxExpectedBytes: maxBytes,
            maxExpectedItems: maxItems, allowSymlinkTarget: allowSymlinkTarget
        )
    }

    /// Since review M2, SafetyGate check 11b requires a target to match one of the rule's glob
    /// patterns. The M1 suites test the other checks at many depths, so their default rule matches
    /// every item from `minDepth` to `minDepth + 7` levels below each allow-root.
    static func derivedGlobs(allowRoots: [String], minDepth: Int) -> Discovery {
        var patterns: [String] = []
        let first = max(1, minDepth)
        for root in allowRoots {
            let base = root.hasSuffix("/") ? String(root.dropLast()) : root
            for depth in first...(first + 7) {
                patterns.append(base + String(repeating: "/*", count: depth))
            }
        }
        return .glob(patterns)
    }

    /// Creates a fresh fixture tree + fake environment, runs `body`, and always removes the tree.
    static func withEnv(_ body: (FakeEnvironment) async throws -> Void) async throws {
        let fixture = try FixtureBuilder()
        defer { fixture.cleanup() }
        let env = FakeEnvironment(fixture: fixture)
        try await body(env)
    }

    static func expectRejected(_ verdict: SafetyVerdict, _ expected: SafetyRejection, _ context: String = "",
                               file: StaticString = #file, line: UInt = #line) throws {
        guard case .rejected(let actual) = verdict else {
            throw TestError("Expected .rejected(\(expected)) but got \(verdict). \(context) (\(file):\(line))")
        }
        guard actual == expected else {
            throw TestError("Expected rejection \(expected) but got \(actual). \(context) (\(file):\(line))")
        }
    }

    static func expectAllowed(_ verdict: SafetyVerdict, _ context: String = "",
                              file: StaticString = #file, line: UInt = #line) throws {
        guard case .allowed = verdict else {
            throw TestError("Expected .allowed but got \(verdict). \(context) (\(file):\(line))")
        }
    }

    static func expectDenyListed(_ verdict: SafetyVerdict, _ entry: String, _ context: String = "",
                                 file: StaticString = #file, line: UInt = #line) throws {
        try expectRejected(verdict, .denyListed(entry: entry), context, file: file, line: line)
    }

    /// Validates at plan time with the fixture-waived gate.
    static func validate(_ env: FakeEnvironment, _ target: ScanTarget, _ rule: Rule,
                         phase: ValidationPhase = .plan, userExclusions: [String] = [],
                         ageThresholdOverrides: [String: Int] = [:]) async -> SafetyVerdict {
        await env.makeGate(userExclusions: userExclusions, ageThresholdOverrides: ageThresholdOverrides)
            .validate(target: target, rule: rule, phase: phase)
    }

    static func expectSuccess(_ result: Result<CanonicalPath, SafetyRejection>, _ context: String = "",
                              file: StaticString = #file, line: UInt = #line) throws -> CanonicalPath {
        switch result {
        case .success(let path): return path
        case .failure(let rejection):
            throw TestError("Expected success but got \(rejection). \(context) (\(file):\(line))")
        }
    }

    static func expectFailure(_ result: Result<CanonicalPath, SafetyRejection>, _ expected: SafetyRejection,
                              _ context: String = "", file: StaticString = #file, line: UInt = #line) throws {
        switch result {
        case .success(let path):
            throw TestError("Expected failure \(expected) but got success \(path). \(context) (\(file):\(line))")
        case .failure(let rejection):
            guard rejection == expected else {
                throw TestError("Expected \(expected) but got \(rejection). \(context) (\(file):\(line))")
            }
        }
    }

    static func expectCanonicalizationFailed(_ result: Result<CanonicalPath, SafetyRejection>, _ context: String = "",
                                             file: StaticString = #file, line: UInt = #line) throws {
        guard case .failure(.canonicalizationFailed) = result else {
            throw TestError("Expected .canonicalizationFailed but got \(result). \(context) (\(file):\(line))")
        }
    }

    /// Swaps the case of every ASCII letter ("Library/Keychains" → "lIBRARY/kEYCHAINS").
    static func swapCase(_ s: String) -> String {
        String(s.map { c -> Character in
            let str = String(c)
            if str.lowercased() != str { return Character(str.lowercased()) }
            if str.uppercased() != str { return Character(str.uppercased()) }
            return c
        })
    }

    /// A uid different from the current user's.
    static var otherUID: UInt32 { getuid() == 501 ? 502 : 501 }

    /// Path relative to the home (without "~/") for a deny-list home entry: wildcard entries get a
    /// concrete child, others are used as-is.
    static func concreteRelative(_ entry: String) -> String {
        guard entry.hasSuffix("*") else { return entry }
        var parts = entry.split(separator: "/").map(String.init)
        var last = String(parts.removeLast().dropLast())
        // "*text*" (contains) gets a TeamID-style prefix.
        if last.hasPrefix("*") { last = "243LU875E5.groups." + last.dropFirst() }
        return (parts + [last + "Example"]).joined(separator: "/")
    }
}
