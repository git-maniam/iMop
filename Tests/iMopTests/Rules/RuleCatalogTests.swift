import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §4: Rule JSON coding, the bundled Rules.json (Green rules only) and RuleCatalog validation.
struct RuleCatalogTests {
    @MainActor
    static func runAll() async {
        print("\n📜 Running RuleCatalog Tests (spec §4, §6)...")

        // MARK: Milestone 4 — vendor-command rules

        await TestSuite.run("RuleCatalog (M4): every vendor-command rule loads, is pinned, and uses only allow-listed commands") {
            try await M1.withEnv { env in
                let catalog = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                try TestSuite.assertEqual(catalog.disabled, [])
                for (id, tier) in M2.m4CommandRuleTiers {
                    guard let rule = catalog.rule(id: id) else { throw TestError("missing \(id)") }
                    try TestSuite.assertEqual(rule.tier, tier, id)
                    try TestSuite.assertNil(RuleTargetMatcher.commandRuleMismatch(rule), id)
                    guard case .command(let spec) = rule.action else { throw TestError("\(id) must be a command rule") }
                    try TestSuite.assertTrue(CommandAllowList.standard.actionEntries.contains { $0.matchesTemplate(tool: spec.tool, arguments: spec.arguments) },
                                             "\(id): \(spec.arguments)")
                    if let dryRun = spec.dryRunArguments {
                        try TestSuite.assertTrue(CommandAllowList.matches(tool: spec.tool, arguments: dryRun, purpose: .readOnly), "\(id) dry run")
                    }
                    try TestSuite.assertFalse(rule.allowRoots.isEmpty, id)
                    try TestSuite.assertTrue(rule.allowRoots.allSatisfy { $0.hasPrefix("{HOME}/") }, id)
                }
                // Spec tables: preconditions.
                func pre(_ id: String) throws -> [Precondition] {
                    guard let r = catalog.rule(id: id) else { throw TestError("missing \(id)") }
                    return r.preconditions
                }
                for id in ["simulator.unavailable", "simulator.devices.stale", "simulator.runtimes"] {
                    try TestSuite.assertTrue(try pre(id).contains(.simulatorIdle), id)
                }
                try TestSuite.assertTrue(try pre("simulator.devices.stale").contains(.olderThan(days: 90)))
                for id in M2.m4CommandRuleIDs where id.hasPrefix("docker.") {
                    try TestSuite.assertTrue(try pre(id).contains(.dockerDaemonReachable), id)
                }
                let processes: [String: [String]] = [
                    "homebrew.cleanup": ["brew"], "npm.cache": ["npm", "node"], "yarn.cache": ["yarn"], "pnpm.store": ["pnpm"],
                    "bun.cache": ["bun"], "uv.cache.prune": ["uv"], "uv.cache.clean": ["uv"], "go.buildCache": ["go"],
                    "go.modCache": ["go"], "cocoapods.cache.command": ["pod"], "flutter.pubCache": ["dart", "flutter"],
                ]
                for (id, names) in processes {
                    try TestSuite.assertTrue(try pre(id).contains(.processNotRunning(names)), "\(id): \(try pre(id))")
                }
                let avd = try pre("android.avd")
                try TestSuite.assertTrue(avd.contains { if case .processNotRunning(let n) = $0 { return n.contains("emulator") && n.contains("qemu-system-aarch64") } else { return false } })
                // Only simctl runtime delete gets the 30-minute timeout.
                for id in M2.m4CommandRuleIDs {
                    guard case .command(let spec) = catalog.rule(id: id)?.action else { continue }
                    try TestSuite.assertEqual(spec.timeout, id == "simulator.runtimes" ? 1800 : 600, id)
                }
                // Red command: docker.volumes only.
                let redCommands = catalog.rules.filter { if case .command = $0.action { return $0.tier == .red } else { return false } }
                try TestSuite.assertEqual(redCommands.map(\.id), ["docker.volumes"])
            }
        }

        await TestSuite.run("RuleCatalog (M4): forbidden commands are disabled — system prune, --volumes, autoremove, shells, paths, wrappers, rm -rf") {
            try await M1.withEnv { env in
                func commandRule(_ id: String, tier: String = "yellow", _ tool: String, _ arguments: [String],
                                 dryRun: [String]? = nil, timeout: Int? = nil) -> [String: Any] {
                    var spec: [String: Any] = ["tool": tool, "arguments": arguments, "idempotentSafe": true]
                    if let dryRun { spec["dryRunArguments"] = dryRun }
                    if let timeout { spec["timeoutSeconds"] = timeout }
                    return M2.ruleJSON(id, overrides: ["tier": tier, "action": ["command": spec]])
                }
                let bad: [[String: Any]] = [
                    commandRule("f.prune", "docker", ["system", "prune", "--volumes", "-f"]),
                    commandRule("f.prune2", "docker", ["system", "prune", "-a", "-f"]),
                    commandRule("f.prune3", "docker", ["system", "prune", "-f"]),
                    commandRule("f.volumesFlag", "docker", ["volume", "prune", "--volumes"]),
                    commandRule("f.autoremove", "brew", ["autoremove"]),
                    commandRule("f.sh", "sh", ["-c", "brew cleanup"]),
                    commandRule("f.zsh", "zsh", ["-c", "true"]),
                    commandRule("f.binsh", "/bin/sh", ["-c", "true"]),
                    commandRule("f.absTool", "/opt/homebrew/bin/brew", ["cleanup", "--prune=all"]),
                    commandRule("f.relTool", "./brew", ["cleanup", "--prune=all"]),
                    commandRule("f.pathArg", "brew", ["cleanup", "--prune=all", "/Users/x"]),
                    commandRule("f.pathItem", "docker", ["volume", "rm", "/var/lib/docker/volumes/x"]),
                    commandRule("f.sudo", "sudo", ["brew", "cleanup", "--prune=all"]),
                    commandRule("f.env", "env", ["brew", "cleanup", "--prune=all"]),
                    commandRule("f.nohup", "nohup", ["brew", "cleanup", "--prune=all"]),
                    commandRule("f.xargs", "xargs", ["rm", "-rf"]),
                    commandRule("f.rm", "rm", ["-rf", "{ITEM}"]),
                    commandRule("f.rmViaBun", "bun", ["pm", "cache", "rm", "-rf"]),
                    commandRule("f.simctlAll", "xcrun", ["simctl", "delete", "all"]),
                    commandRule("f.twoItems", "xcrun", ["simctl", "delete", "{ITEM}", "{ITEM}"]),
                    commandRule("f.ollamaRmAll", "ollama", ["rm", "-a"]),
                    commandRule("f.greenModcache", tier: "green", "go", ["clean", "-modcache"]),
                    commandRule("f.greenAvd", tier: "green", "avdmanager", ["delete", "avd", "-n", "{ITEM}"]),
                    commandRule("f.longTimeout", "brew", ["cleanup", "--prune=all"], timeout: 3600),
                    commandRule("f.runtimeTooLong", "xcrun", ["simctl", "runtime", "delete", "{ITEM}"], timeout: 1801),
                    commandRule("f.dryRunAction", "brew", ["cleanup", "--prune=all"], dryRun: ["cleanup", "--prune=all"]),
                    commandRule("f.probe", "xcode-select", ["-p"]),
                ]
                for json in bad {
                    let catalog = RuleCatalog.load(data: try M2.catalogData([json]), environment: env.environment)
                    try TestSuite.assertEqual(catalog.rules.count, 0, "\(json["id"] ?? "") must be disabled")
                    try TestSuite.assertEqual(M2.disabledIDs(catalog), [json["id"] as? String ?? ""], "\(json["id"] ?? "")")
                }
                // A discovery command must be read-only and never per item.
                var destructive = M2.ruleJSON("f.discovery", overrides: ["tier": "yellow"])
                destructive["discovery"] = ["command": ["tool": "docker", "arguments": ["volume", "rm", "{ITEM}"], "idempotentSafe": true]]
                try TestSuite.assertEqual(RuleCatalog.load(data: try M2.catalogData([destructive]), environment: env.environment).rules.count, 0)

                // The M4 exact entries that replaced the blanket "rm" token load.
                let good: [[String: Any]] = [
                    commandRule("g.bun", tier: "green", "bun", ["pm", "cache", "rm"]),
                    commandRule("g.ollama", "ollama", ["rm", "{ITEM}"]),
                    commandRule("g.simctlUnavailable", tier: "green", "xcrun", ["simctl", "delete", "unavailable"]),
                    commandRule("g.simctlItem", "xcrun", ["simctl", "delete", "{ITEM}"]),
                    commandRule("g.runtime", "xcrun", ["simctl", "runtime", "delete", "{ITEM}"], timeout: 1800),
                    commandRule("g.avd", "avdmanager", ["delete", "avd", "-n", "{ITEM}"]),
                ]
                let loaded = RuleCatalog.load(data: try M2.catalogData(good), environment: env.environment)
                try TestSuite.assertEqual(Set(loaded.rules.map(\.id)), Set(good.compactMap { $0["id"] as? String }), "\(loaded.disabled)")
            }
        }

        await TestSuite.run("RuleCatalog (M4): a Red command is allowed only for docker.volumes with docker volume rm {ITEM}") {
            try await M1.withEnv { env in
                func red(_ id: String, tier: String = "red", _ tool: String, _ arguments: [String]) -> [String: Any] {
                    // docker.volumes pins dockerDaemonReachable (review M4).
                    M2.ruleJSON(id, overrides: ["tier": tier, "preconditions": ["dockerDaemonReachable"],
                                                "action": ["command": ["tool": tool, "arguments": arguments, "idempotentSafe": false]]])
                }
                let ok = RuleCatalog.load(data: try M2.catalogData([red("docker.volumes", "docker", ["volume", "rm", "{ITEM}"])]),
                                          environment: env.environment)
                try TestSuite.assertEqual(ok.rules.map(\.id), ["docker.volumes"], "\(ok.disabled)")
                let refused: [[String: Any]] = [
                    red("docker.other", "docker", ["volume", "rm", "{ITEM}"]),
                    red("leftovers.launchAgents", "docker", ["volume", "rm", "{ITEM}"]),
                    red("docker.volumes", tier: "yellow", "docker", ["volume", "rm", "{ITEM}"]),
                    red("docker.volumes", tier: "green", "docker", ["volume", "rm", "{ITEM}"]),
                    red("red.brew", "brew", ["cleanup", "--prune=all"]),
                    red("docker.volumes", "docker", ["volume", "prune", "-f"]),
                ]
                for json in refused {
                    let catalog = RuleCatalog.load(data: try M2.catalogData([json]), environment: env.environment)
                    try TestSuite.assertEqual(catalog.rules.count, 0, "\(json["id"] ?? "") \(json["tier"] ?? "")")
                }
            }
        }

        // MARK: Bundled catalog

        await TestSuite.run("RuleCatalog: bundled Rules.json loads via loadBundled with every rule valid") {
            try await M1.withEnv { env in
                let catalog = RuleCatalog.loadBundled(environment: env.environment)
                try TestSuite.assertEqual(catalog.disabled, [], "disabled: \(catalog.disabled)")
                try TestSuite.assertEqual(Set(catalog.rules.map(\.id)), M2.expectedBundledRuleIDs)
                try TestSuite.assertEqual(catalog.rules.count, M2.expectedBundledRuleIDs.count, "ids must be unique")
            }
        }

        await TestSuite.run("RuleCatalog: Rules.json from the source tree loads with zero disabled and equals the bundled copy") {
            try await M1.withEnv { env in
                let source = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                try TestSuite.assertEqual(source.disabled, [], "disabled: \(source.disabled)")
                try TestSuite.assertEqual(Set(source.rules.map(\.id)), M2.expectedBundledRuleIDs)
                let bundled = RuleCatalog.loadBundled(environment: env.environment)
                try TestSuite.assertEqual(source.rules, bundled.rules, "bundled Rules.json is stale: rebuild")
            }
        }

        await TestSuite.run("RuleCatalog: every bundled file rule is Green, command rules have their spec tier; texts and a safe action") {
            try await M1.withEnv { env in
                let catalog = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                try TestSuite.assertFalse(catalog.rules.isEmpty)
                for rule in catalog.rules {
                    try TestSuite.assertEqual(rule.tier, M2.m4CommandRuleTiers[rule.id] ?? M2.m5RuleTiers[rule.id]
                                              ?? M6.ruleTiers[rule.id] ?? .green, rule.id)
                    for (name, text) in [("title", rule.title), ("explanation", rule.explanation),
                                         ("whatYouLose", rule.whatYouLose), ("howItRegenerates", rule.howItRegenerates)] {
                        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                        try TestSuite.assertTrue(trimmed.count >= 10, "\(rule.id).\(name) is too short: \"\(text)\"")
                    }
                    switch rule.action {
                    case .quarantine:
                        try TestSuite.assertFalse(M2.m4CommandRuleIDs.contains(rule.id), rule.id)
                    // Milestone 6: the Trash / bootout / permanent-delete / advisory rules.
                    case .trash:
                        try TestSuite.assertTrue(M6.actionableRuleIDs.contains(rule.id), rule.id)
                        try TestSuite.assertTrue(rule.tier == .yellow || rule.tier == .red, rule.id)
                    case .bootoutAndTrash:
                        try TestSuite.assertEqual(rule.id, "leftovers.launchAgents")
                        try TestSuite.assertEqual(rule.tier, .red, rule.id)
                    case .permanentDelete:
                        try TestSuite.assertTrue(RuleCatalog.permanentDeleteAllowList.contains(rule.id), rule.id)
                        try TestSuite.assertEqual(rule.tier, .yellow, rule.id)
                    case .advisory:
                        try TestSuite.assertTrue(M6.advisoryRuleIDs.contains(rule.id), rule.id)
                        try TestSuite.assertEqual(rule.tier, .advisory, rule.id)
                        try TestSuite.assertEqual(rule.allowRoots, [], rule.id)
                    case .command(let spec):
                        try TestSuite.assertTrue(M2.m4CommandRuleIDs.contains(rule.id), rule.id)
                        if rule.tier == .green { try TestSuite.assertTrue(spec.idempotentSafe, rule.id) }
                        // Spec §5.3: command actions are not restorable, and the rule text says so.
                        try TestSuite.assertTrue(rule.whatYouLose.contains("cannot be undone"), "\(rule.id): \(rule.whatYouLose)")
                        try TestSuite.assertTrue(rule.whatYouLose.contains("nothing can be restored"), rule.id)
                    default: throw TestError("\(rule.id): unexpected action \(rule.action)")
                    }
                    try TestSuite.assertTrue(rule.minDepthBelowRoot >= 1, rule.id)
                    for root in rule.allowRoots {
                        // M5: ProjectScanner rules use the dynamic {PROJECT_ROOTS} token; only
                        // lightroom.previews (pinned to its inspector) may use {HOME} itself.
                        if rule.id.hasPrefix("project.") {
                            try TestSuite.assertEqual(rule.allowRoots, [Rule.projectRootsToken], rule.id)
                        } else if rule.id == "lightroom.previews" {
                            try TestSuite.assertEqual(rule.allowRoots, ["{HOME}"], rule.id)
                        } else if M6.nonHomeRuleIDs.contains(rule.id) {
                            // M6: only the Swift-pinned non-home rules (RuleCatalog.nonHomeRuleSpecs).
                            try TestSuite.assertTrue(RuleCatalog.nonHomeRuleSpecs[rule.id] != nil, rule.id)
                        } else {
                            try TestSuite.assertTrue(root.hasPrefix("{HOME}/"), "\(rule.id): \(root)")
                        }
                    }
                    if case .glob(let patterns) = rule.discovery {
                        for raw in patterns {
                            try TestSuite.assertFalse(raw.contains("**"), "\(rule.id): \(raw)")
                            try TestSuite.assertFalse(raw.contains("{") && !raw.hasPrefix("{HOME}/"), "\(rule.id): \(raw)")
                            try TestSuite.assertTrue(GlobPattern(raw) != nil, "\(rule.id): \(raw)")
                        }
                    }
                    try TestSuite.assertTrue(catalog.rule(id: rule.id) == rule, rule.id)
                }
                try TestSuite.assertTrue(catalog.rule(id: "no.such.rule") == nil)
            }
        }

        await TestSuite.run("RuleCatalog: spot-check rule details required by spec §6") {
            try await M1.withEnv { env in
                let catalog = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                func rule(_ id: String) throws -> Rule {
                    guard let r = catalog.rule(id: id) else { throw TestError("missing rule \(id)") }
                    return r
                }
                try TestSuite.assertTrue(try rule("xcode.previews").preconditions.contains(.appNotRunning(["com.apple.dt.Xcode"])))
                try TestSuite.assertEqual(try rule("poetry.cache").excludedNames, ["virtualenvs"])
                if case .glob(let patterns) = try rule("poetry.cache").discovery {
                    try TestSuite.assertFalse(patterns.contains { $0.contains("virtualenvs") || $0.hasSuffix("pypoetry/*") }, "\(patterns)")
                } else { throw TestError("poetry.cache must be glob") }
                try TestSuite.assertEqual(Set(try rule("logs.user").excludedNames), ["iMop", "DiagnosticReports", "JetBrains"])
                try TestSuite.assertTrue(try rule("logs.user").preconditions.contains(.olderThan(days: 7)))
                try TestSuite.assertTrue(try rule("logs.user").preconditions.contains(.notOpenByAnyProcess))
                try TestSuite.assertTrue(try rule("logs.diagnosticReports").preconditions.contains(.olderThan(days: 30)))
                try TestSuite.assertTrue(try rule("mail.downloads").requiresFullDiskAccess)
                try TestSuite.assertTrue(try rule("mail.downloads").preconditions.contains(.olderThan(days: 7)))
                try TestSuite.assertTrue(try rule("browser.safari.cache").requiresFullDiskAccess)
                try TestSuite.assertTrue(try rule("apps.containerCaches").requiresFullDiskAccess)
                try TestSuite.assertEqual(try rule("apps.sparkleUpdates").ownerInference, .parentDirectoryName)
                try TestSuite.assertEqual(try rule("apps.squirrelShipIt").ownerInference, .nameBeforeShipIt)
                try TestSuite.assertEqual(try rule("apps.savedState").ownerInference, .nameWithoutExtension)
                for id in ["apps.sparkleUpdates", "apps.squirrelShipIt", "apps.savedState", "apps.userCaches"] {
                    try TestSuite.assertTrue(try rule(id).preconditions.contains(.owningAppNotRunning), id)
                }
                try TestSuite.assertTrue(try rule("apps.userCaches").preconditions.contains(.notOpenByAnyProcess))
                try TestSuite.assertTrue(try rule("ios.firmware").preconditions.contains(.olderThan(days: 1)))
                if case .glob(let patterns) = try rule("vscode.caches").discovery {
                    let names = Set(patterns.map { ($0 as NSString).lastPathComponent })
                    try TestSuite.assertEqual(names, ["Cache", "CachedData", "CachedExtensionVSIXs", "Code Cache", "GPUCache", "logs"])
                } else { throw TestError("vscode.caches must be glob") }
                if case .glob(let patterns) = try rule("ios.firmware").discovery {
                    try TestSuite.assertEqual(patterns.count, 3)
                    try TestSuite.assertTrue(patterns.allSatisfy { $0.hasSuffix("/*.ipsw") })
                } else { throw TestError("ios.firmware must be glob") }
                for (id, inspector) in [("apps.userCaches", InspectorID.appUserCaches), ("apps.containerCaches", .appContainerCaches),
                                        ("apps.electronCaches", .electronCaches), ("browser.chromium.cache", .chromiumCaches)] {
                    try TestSuite.assertEqual(try rule(id).discovery, .inspector(inspector), id)
                }
            }
        }

        await TestSuite.run("RuleCatalog: every bundled rule round-trips through JSON unchanged") {
            try await M1.withEnv { env in
                let catalog = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                for rule in catalog.rules {
                    let data = try JSONEncoder().encode(rule)
                    let decoded = try JSONDecoder().decode(Rule.self, from: data)
                    try TestSuite.assertEqual(decoded, rule, rule.id)
                }
            }
        }

        // MARK: Coding shapes

        await TestSuite.run("RuleCoding: readable JSON shapes for discovery, action and preconditions") {
            let decoder = JSONDecoder()
            func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
                try decoder.decode(T.self, from: Data(json.utf8))
            }
            try TestSuite.assertEqual(try decode(Discovery.self, #"{"glob":["{HOME}/a/*"]}"#), .glob(["{HOME}/a/*"]))
            try TestSuite.assertEqual(try decode(Discovery.self, #"{"inspector":"appUserCaches"}"#), .inspector(.appUserCaches))
            try TestSuite.assertEqual(try decode(Discovery.self, #"{"command":{"tool":"brew","arguments":["cleanup"],"idempotentSafe":true}}"#),
                                      .command(CommandSpec(tool: "brew", arguments: ["cleanup"], idempotentSafe: true)))
            try TestSuite.assertEqual(try decode(Action.self, #""quarantine""#), .quarantine)
            try TestSuite.assertEqual(try decode(Action.self, #""trash""#), .trash)
            try TestSuite.assertEqual(try decode(Action.self, #""permanentDelete""#), .permanentDelete)
            try TestSuite.assertEqual(try decode(Action.self, #"{"advisory":"instructions"}"#), .advisory(.instructions))
            try TestSuite.assertEqual(try decode([Precondition].self,
                #"[{"appNotRunning":["com.apple.dt.Xcode"]},{"processNotRunning":["npm"]},{"olderThan":14},{"manifestPresent":["Cargo.lock"]},"notOpenByAnyProcess","owningAppNotRunning","notInsideCloudRoot","ownedByUser","simulatorIdle","dockerDaemonReachable","notMounted","appleSigned","notSelectedXcode","uploadedToCloud"]"#),
                [.appNotRunning(["com.apple.dt.Xcode"]), .processNotRunning(["npm"]), .olderThan(days: 14), .manifestPresent(["Cargo.lock"]),
                 .notOpenByAnyProcess, .owningAppNotRunning, .notInsideCloudRoot, .ownedByUser, .simulatorIdle,
                 .dockerDaemonReachable, .notMounted, .appleSigned, .notSelectedXcode, .uploadedToCloud])
            // Malformed shapes are errors.
            for (type, json) in [("Action", #""delete""#), ("Action", #"{"quarantine":true}"#), ("Action", #"{"command":{"tool":"x","arguments":[],"idempotentSafe":true,"shell":true}}"#),
                                 ("Discovery", #""glob""#), ("Discovery", #"{"glob":["a"],"inspector":"appUserCaches"}"#),
                                 ("Discovery", #"{"inspector":"nope"}"#), ("Precondition", #""olderThan""#),
                                 ("Precondition", #"{"notOpenByAnyProcess":true}"#), ("Precondition", #"{"olderThan":"7"}"#)] {
                let failed: Bool
                switch type {
                case "Action": failed = (try? decode(Action.self, json)) == nil
                case "Discovery": failed = (try? decode(Discovery.self, json)) == nil
                default: failed = (try? decode(Precondition.self, json)) == nil
                }
                try TestSuite.assertTrue(failed, "\(type) \(json) must not decode")
            }
        }

        await TestSuite.run("RuleCoding: optional rule fields take their documented defaults") {
            let data = try JSONSerialization.data(withJSONObject: M2.ruleJSON("defaults.rule"))
            let rule = try JSONDecoder().decode(Rule.self, from: data)
            try TestSuite.assertEqual(rule.version, 1)
            try TestSuite.assertEqual(rule.minDepthBelowRoot, 1)
            try TestSuite.assertEqual(rule.preconditions, [])
            try TestSuite.assertFalse(rule.allowSymlinkTarget)
            try TestSuite.assertEqual(rule.excludedNames, [])
            try TestSuite.assertFalse(rule.requiresFullDiskAccess)
            try TestSuite.assertEqual(rule.ownerInference, .none)
            try TestSuite.assertTrue(rule.maxExpectedBytes == nil && rule.maxExpectedItems == nil && rule.retentionHours == nil)
        }

        // MARK: Malformed rules are disabled individually

        await TestSuite.run("RuleCatalog: each malformed rule is disabled on its own while the rest load") {
            try await M1.withEnv { env in
                let idempotentCommand: [String: Any] = ["command": ["tool": "xcrun", "arguments": ["simctl", "delete", "unavailable"], "idempotentSafe": false]]
                func yellowCommand(_ tool: String, _ arguments: [String], dryRun: [String]? = nil) -> [String: Any] {
                    var spec: [String: Any] = ["tool": tool, "arguments": arguments, "idempotentSafe": true]
                    if let dryRun { spec["dryRunArguments"] = dryRun }
                    return ["tier": "yellow", "action": ["command": spec]]
                }

                let bad: [(String, [String: Any])] = [
                    // Bad JSON shapes.
                    ("bad.unknownKey", M2.ruleJSON("bad.unknownKey", overrides: ["shellCommand": "rm -rf ~"])),
                    ("bad.unknownTier", M2.ruleJSON("bad.unknownTier", overrides: ["tier": "blue"])),
                    ("bad.unknownCategory", M2.ruleJSON("bad.unknownCategory", overrides: ["category": "everything"])),
                    ("bad.missingTitle", M2.ruleJSON("bad.missingTitle", removing: ["title"])),
                    ("bad.actionShape", M2.ruleJSON("bad.actionShape", overrides: ["action": ["quarantine": true, "trash": true]])),
                    ("bad.discoveryShape", M2.ruleJSON("bad.discoveryShape", overrides: ["discovery": "glob"])),
                    ("bad.unknownPrecondition", M2.ruleJSON("bad.unknownPrecondition", overrides: ["preconditions": ["alwaysTrue"]])),
                    ("bad.typeMismatch", M2.ruleJSON("bad.typeMismatch", overrides: ["minDepthBelowRoot": "one"])),
                    // Empty texts.
                    ("bad.emptyExplanation", M2.ruleJSON("bad.emptyExplanation", overrides: ["explanation": "   "])),
                    ("bad.emptyWhatYouLose", M2.ruleJSON("bad.emptyWhatYouLose", overrides: ["whatYouLose": ""])),
                    // Globs.
                    ("bad.recursiveGlob", M2.ruleJSON("bad.recursiveGlob", overrides: ["discovery": ["glob": ["{HOME}/Library/Caches/com.example.bad.recursiveGlob/**"]]])),
                    ("bad.braceGlob", M2.ruleJSON("bad.braceGlob", overrides: ["discovery": ["glob": ["{HOME}/Library/Caches/com.example.bad.braceGlob/{a,b}"]]])),
                    ("bad.globOutsideRoot", M2.ruleJSON("bad.globOutsideRoot", overrides: ["discovery": ["glob": ["{HOME}/Library/Caches/*"]]])),
                    ("bad.globTooShallow", M2.ruleJSON("bad.globTooShallow", overrides: ["minDepthBelowRoot": 2])),
                    ("bad.globDotDot", M2.ruleJSON("bad.globDotDot", overrides: ["discovery": ["glob": ["{HOME}/Library/Caches/com.example.bad.globDotDot/../../Keychains"]]])),
                    // Allow-roots.
                    ("bad.rootOutsideHome", M2.ruleJSON("bad.rootOutsideHome", overrides: ["allowRoots": ["/tmp/stuff"], "discovery": ["glob": ["/tmp/stuff/*"]]])),
                    ("bad.rootIsHome", M2.ruleJSON("bad.rootIsHome", overrides: ["allowRoots": ["{HOME}"], "discovery": ["glob": ["{HOME}/*"]]])),
                    ("bad.rootIsHomeSlash", M2.ruleJSON("bad.rootIsHomeSlash", overrides: ["allowRoots": ["{HOME}/"], "discovery": ["glob": ["{HOME}/*"]]])),
                    ("bad.rootDenied", M2.ruleJSON("bad.rootDenied", overrides: ["allowRoots": ["{HOME}/Library/Keychains"], "discovery": ["glob": ["{HOME}/Library/Keychains/*"]]])),
                    ("bad.rootInsideDenied", M2.ruleJSON("bad.rootInsideDenied", overrides: ["allowRoots": ["{HOME}/Documents/Caches"], "discovery": ["glob": ["{HOME}/Documents/Caches/*"]]])),
                    ("bad.rootAncestorOfDenied", M2.ruleJSON("bad.rootAncestorOfDenied", overrides: ["allowRoots": ["{HOME}/Library"], "discovery": ["glob": ["{HOME}/Library/Caches/*"]]])),
                    ("bad.rootAncestorOfSsh", M2.ruleJSON("bad.rootAncestorOfSsh", overrides: ["allowRoots": ["{HOME}/.ssh"], "discovery": ["glob": ["{HOME}/.ssh/*"]]])),
                    ("bad.rootWildcard", M2.ruleJSON("bad.rootWildcard", overrides: ["allowRoots": ["{HOME}/Library/Caches/*"]])),
                    ("bad.nonHomeRootNotExcepted", M2.ruleJSON("bad.nonHomeRootNotExcepted", overrides: ["allowRoots": ["/cores"], "discovery": ["glob": ["/cores/core.*"]]])),
                    // Tier / action matrix.
                    ("bad.greenTrash", M2.ruleJSON("bad.greenTrash", overrides: ["action": "trash"])),
                    ("bad.greenPermanentDelete", M2.ruleJSON("bad.greenPermanentDelete", overrides: ["action": "permanentDelete"])),
                    ("bad.greenAdvisory", M2.ruleJSON("bad.greenAdvisory", overrides: ["action": ["advisory": "instructions"]])),
                    ("bad.greenNonIdempotentCommand", M2.ruleJSON("bad.greenNonIdempotentCommand", overrides: ["action": idempotentCommand])),
                    ("bad.yellowPermanentDelete", M2.ruleJSON("bad.yellowPermanentDelete", overrides: ["tier": "yellow", "action": "permanentDelete"])),
                    ("bad.redQuarantine", M2.ruleJSON("bad.redQuarantine", overrides: ["tier": "red"])),
                    ("bad.redCommand", M2.ruleJSON("bad.redCommand", overrides: ["tier": "red", "action": ["command": ["tool": "brew", "arguments": ["cleanup"], "idempotentSafe": true]]])),
                    ("bad.advisoryQuarantine", M2.ruleJSON("bad.advisoryQuarantine", overrides: ["tier": "advisory"])),
                    ("bad.advisoryTrash", M2.ruleJSON("bad.advisoryTrash", overrides: ["tier": "advisory", "action": "trash"])),
                    // Forbidden commands.
                    ("bad.cmdVolumes", M2.ruleJSON("bad.cmdVolumes", overrides: yellowCommand("docker", ["system", "df", "--volumes"]))),
                    ("bad.cmdAutoremove", M2.ruleJSON("bad.cmdAutoremove", overrides: yellowCommand("brew", ["autoremove"]))),
                    ("bad.cmdShellTool", M2.ruleJSON("bad.cmdShellTool", overrides: yellowCommand("sh", ["-c", "true"]))),
                    ("bad.cmdShellArg", M2.ruleJSON("bad.cmdShellArg", overrides: yellowCommand("env", ["sh", "-c", "true"]))),
                    ("bad.cmdDashC", M2.ruleJSON("bad.cmdDashC", overrides: yellowCommand("npm", ["-c", "cache clean"]))),
                    ("bad.cmdRm", M2.ruleJSON("bad.cmdRm", overrides: yellowCommand("xcrun", ["rm", "x"]))),
                    ("bad.cmdSudo", M2.ruleJSON("bad.cmdSudo", overrides: yellowCommand("npm", ["sudo", "cache", "clean"]))),
                    ("bad.cmdSystemPrune", M2.ruleJSON("bad.cmdSystemPrune", overrides: yellowCommand("docker", ["system", "prune"]))),
                    ("bad.cmdSystemPruneAll", M2.ruleJSON("bad.cmdSystemPruneAll", overrides: yellowCommand("docker", ["system", "prune", "--all"]))),
                    ("bad.cmdSystemPruneA", M2.ruleJSON("bad.cmdSystemPruneA", overrides: yellowCommand("docker", ["system", "prune", "-a"]))),
                    ("bad.cmdAbsoluteTool", M2.ruleJSON("bad.cmdAbsoluteTool", overrides: yellowCommand("/usr/bin/xcrun", ["simctl", "list"]))),
                    ("bad.cmdDryRunForbidden", M2.ruleJSON("bad.cmdDryRunForbidden", overrides: yellowCommand("brew", ["cleanup"], dryRun: ["sh", "-c", "x"]))),
                    // Numbers.
                    ("bad.minDepthZero", M2.ruleJSON("bad.minDepthZero", overrides: ["minDepthBelowRoot": 0])),
                    ("bad.maxBytesZero", M2.ruleJSON("bad.maxBytesZero", overrides: ["maxExpectedBytes": 0])),
                    ("bad.maxItemsNegative", M2.ruleJSON("bad.maxItemsNegative", overrides: ["maxExpectedItems": -5])),
                    // Duplicate ids (both copies disabled).
                    ("bad.duplicate", M2.ruleJSON("bad.duplicate")),
                    ("bad.duplicate", M2.ruleJSON("bad.duplicate")),
                ]
                let good = [M2.ruleJSON("good.first"), M2.ruleJSON("good.second", overrides: ["tier": "yellow", "action": "trash"]),
                            M2.ruleJSON("good.yellowCommand", overrides: yellowCommand("docker", ["image", "prune", "-a", "-f"],
                                                                                         dryRun: ["system", "df"]))]

                var all: [[String: Any]] = [good[0]]
                all += bad.map(\.1)
                all += good.dropFirst()
                let catalog = RuleCatalog.load(data: try M2.catalogData(all), environment: env.environment)

                try TestSuite.assertEqual(Set(catalog.rules.map(\.id)), ["good.first", "good.second", "good.yellowCommand"],
                                          "disabled: \(catalog.disabled)")
                let disabled = M2.disabledIDs(catalog)
                for (id, _) in bad {
                    try TestSuite.assertTrue(disabled.contains(id), "\(id) must be disabled; disabled = \(disabled.sorted())")
                }
                try TestSuite.assertTrue(catalog.disabled.allSatisfy { !$0.message.isEmpty })
            }
        }

        await TestSuite.run("RuleCatalog: bundled rules plus one malformed rule still load every bundled rule") {
            try await M1.withEnv { env in
                let object = try JSONSerialization.jsonObject(with: try M2.sourceRulesData()) as? [String: Any]
                guard var rules = object?["rules"] as? [[String: Any]] else { throw TestError("unexpected Rules.json shape") }
                rules.insert(M2.ruleJSON("bad.inTheMiddle", overrides: ["action": "trash"]), at: rules.count / 2)
                rules.append(["id": 42])
                let catalog = RuleCatalog.load(data: try M2.catalogData(rules), environment: env.environment)
                try TestSuite.assertEqual(Set(catalog.rules.map(\.id)), M2.expectedBundledRuleIDs)
                try TestSuite.assertTrue(M2.disabledIDs(catalog).contains("bad.inTheMiddle"))
                try TestSuite.assertEqual(catalog.disabled.count, 2, "\(catalog.disabled)")
            }
        }

        await TestSuite.run("RuleCatalog: a broken file gives an empty catalog with an issue, never a crash") {
            try await M1.withEnv { env in
                for data in [Data("not json".utf8), Data(#"{"rules":[]}"#.utf8), Data(#"{"version":2,"rules":[]}"#.utf8),
                             Data(#"[1,2,3]"#.utf8), Data()] {
                    let catalog = RuleCatalog.load(data: data, environment: env.environment)
                    try TestSuite.assertTrue(catalog.rules.isEmpty)
                    try TestSuite.assertEqual(catalog.disabled.map(\.ruleID), [RuleCatalog.catalogIssueID])
                }
            }
        }

        await TestSuite.run("RuleCatalog: in-code rules are validated too (validating:)") {
            try await M1.withEnv { env in
                let ok = M1.rule(id: "code.ok", discovery: .glob(["{HOME}/Library/Caches/com.example/*"]))
                let badRoot = M1.rule(id: "code.badRoot", allowRoots: ["{HOME}/Library"], discovery: .glob(["{HOME}/Library/Caches/*"]))
                let badAction = M1.rule(id: "code.badAction", action: .trash, discovery: .glob(["{HOME}/Library/Caches/x/*"]))
                let catalog = RuleCatalog(validating: [ok, badRoot, badAction], environment: env.environment)
                try TestSuite.assertEqual(catalog.rules.map(\.id), ["code.ok"])
                try TestSuite.assertEqual(M2.disabledIDs(catalog), ["code.badRoot", "code.badAction"])
            }
        }

        await TestSuite.run("RuleCatalog: Swift-coded non-home exceptions apply only to their own rule ids") {
            try await M1.withEnv { env in
                // Review M2: the exception id must also have its complete Swift-pinned shape.
                // Milestone 6: installers.macOS is pinned to its read-only inspector.
                let pinned: [String: Any] = [
                    "tier": "yellow", "action": "trash", "allowRoots": ["/Applications"],
                    "discovery": ["inspector": "macOSInstallers"],
                    "preconditions": ["appleSigned", ["appNotRunning": ["com.apple.InstallAssistant.*"]]],
                ]
                let installers = M2.ruleJSON("installers.macOS", overrides: pinned)
                let other = M2.ruleJSON("other.installers", overrides: pinned)
                let catalog = RuleCatalog.load(data: try M2.catalogData([installers, other]), environment: env.environment)
                try TestSuite.assertEqual(catalog.rules.map(\.id), ["installers.macOS"], "\(catalog.disabled)")
                try TestSuite.assertEqual(M2.disabledIDs(catalog), ["other.installers"])
            }
        }
    }
}
