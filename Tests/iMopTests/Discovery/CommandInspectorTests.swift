import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Milestone 4: the vendor-command inspectors end to end — bundled Rules.json → SafeCleanScanner →
/// inspector → `FakeCommandRunner` canned outputs (`CommandFixtures`) → command-item targets.
/// Nothing here runs a real command; every query the inspectors issue is checked to be read-only
/// and on the read-only allow-list.
struct CommandInspectorTests {
    static let tools = ["xcrun", "docker", "ollama", "brew", "npm", "yarn", "pnpm", "bun", "uv", "go", "pod", "flutter", "avdmanager"]

    static func ok(_ stdout: String) -> CommandResult { CommandResult(exitCode: 0, stdout: stdout, stderr: "") }

    /// Every tool resolves to a fake path; every read-only query has a realistic answer.
    static func installEverything(_ env: FakeEnvironment) throws {
        let f = env.fixture
        env.commands.executables = Dictionary(uniqueKeysWithValues: tools.map { ($0, "/opt/fake/bin/" + $0) })
        // Simulators.
        env.commands.setResponse(ok(CommandFixtures.devicesJSON(home: f.home)), for: SimctlClient.listDevicesArguments)
        env.commands.setResponse(ok(CommandFixtures.unavailableDevicesJSON(home: f.home)), for: SimctlClient.listUnavailableDevicesArguments)
        env.commands.setResponse(ok(CommandFixtures.runtimeListJSON), for: SimctlClient.listRuntimesArguments)
        let base = "Library/Developer/CoreSimulator/Devices/"
        for udid in [CommandFixtures.staleUDID, CommandFixtures.freshUDID, CommandFixtures.bootedUDID,
                     CommandFixtures.unavailableUDID1, CommandFixtures.unavailableUDID2] {
            try f.file(base + udid + "/data/Library/payload.bin", bytes: 6_000)
            try f.file(base + udid + "/device.plist", bytes: 300)
        }
        for udid in [CommandFixtures.staleUDID, CommandFixtures.bootedUDID] {
            for rel in ["", "/data", "/device.plist"] {
                try f.setModificationDate(base + udid + rel, daysAgo: 200, clock: env.clock)
            }
        }
        // Docker.
        env.commands.setResponse(ok(CommandFixtures.dockerSystemDF), for: DockerClient.systemDFArguments)
        env.commands.setResponse(ok(CommandFixtures.dockerSystemDFVerbose), for: DockerClient.systemDFVerboseArguments)
        env.commands.setResponse(ok(CommandFixtures.dockerImageListJSON), for: DockerClient.imageListArguments)
        env.commands.setResponse(ok(CommandFixtures.dockerExitedContainersJSON), for: DockerClient.exitedContainersArguments)
        env.commands.setResponse(ok(CommandFixtures.dockerDanglingVolumesJSON), for: DockerClient.danglingVolumesArguments)
        // Ollama.
        env.commands.setResponse(ok(CommandFixtures.ollamaList), for: OllamaClient.listArguments)
        // Package managers.
        env.commands.setResponse(ok("Would remove: \(f.home)/Library/Caches/Homebrew/wget--1.21.bottle.tar.gz (1.2MB)\n==> This operation would free approximately 1.5GB of disk space.\n"),
                                 for: ["cleanup", "--prune=all", "-n"])
        env.commands.setResponse(ok(f.home + "/.npm\n"), for: ["config", "get", "cache"])
        env.commands.setResponse(ok(f.home + "/Library/Caches/Yarn/v6\n"), for: ["cache", "dir"]) // yarn and uv share the key
        env.commands.setResponse(ok(f.home + "/Library/pnpm/store/v3\n"), for: ["store", "path"])
        env.commands.setResponse(ok(f.home + "/Library/Caches/go-build\n"), for: ["env", "GOCACHE"])
        env.commands.setResponse(ok(f.home + "/go/pkg/mod\n"), for: ["env", "GOMODCACHE"])
        env.commands.setResponse(ok(f.home + "/.bun/install/cache\n"), for: ["pm", "cache"])
        for rel in [".npm/_cacache/content-v2/sha512/ab/blob", "Library/Caches/Yarn/v6/npm-left-pad/index.js",
                    "Library/pnpm/store/v3/files/00/abc", ".bun/install/cache/react@18/index.js",
                    "Library/Caches/go-build/00/a-d", "go/pkg/mod/golang.org/x/text@v0.3.0/go.mod",
                    "Library/Caches/CocoaPods/Pods/Release/AFNetworking/x.m", ".pub-cache/hosted/pub.dev/http-1.0.0/pubspec.yaml",
                    ".android/avd/Pixel_7_API_34.avd/userdata.img"] {
            try f.file(rel, bytes: 9_000)
        }
        try f.file(".android/avd/Pixel_7_API_34.ini", contents: Data("avd.ini.encoding=UTF-8\npath=\(f.home)/.android/avd/Pixel_7_API_34.avd\npath.rel=avd/Pixel_7_API_34.avd\ntarget=android-34\n".utf8))
        // A decoy without its .ini file and one with a hostile name: never offered.
        try f.file(".android/avd/Orphan.avd/userdata.img", bytes: 100)
        try f.file(".android/avd/-rf.avd/userdata.img", bytes: 100)
        try f.file(".android/avd/-rf.ini", bytes: 100)
    }

    static func scan(_ env: FakeEnvironment, _ ids: Set<String>) async throws -> [String: RuleScanResult] {
        SafeCleanScannerTests.byRule(try await SafeCleanScannerTests.makeScanner(env).scan(ruleIDs: ids))
    }

    static func result(_ results: [String: RuleScanResult], _ id: String) throws -> RuleScanResult {
        guard let result = results[id] else { throw TestError("no result for \(id)") }
        return result
    }

    @MainActor
    static func expectUnavailable(_ result: RuleScanResult, _ context: String = "", file: StaticString = #file, line: UInt = #line) throws {
        guard case .unavailable = result.status else {
            throw TestError("\(result.rule.id): expected .unavailable, got \(result.status) \(context) (\(file):\(line))")
        }
        try TestSuite.assertEqual(result.targets.count, 0, "\(result.rule.id): \(context)", file: file, line: line)
    }

    /// Every command the inspectors issued is read-only and on the read-only allow-list.
    @MainActor
    static func expectOnlyReadOnly(_ env: FakeEnvironment) throws {
        let invocations = env.commands.invocations
        for invocation in invocations {
            let tool = (invocation.executable as NSString).lastPathComponent
            try TestSuite.assertEqual(invocation.purpose, .readOnly, "\(tool) \(invocation.arguments)")
            try TestSuite.assertTrue(CommandAllowList.standard.matches(tool: tool, arguments: invocation.arguments, purpose: .readOnly),
                                     "not on the read-only allow-list: \(tool) \(invocation.arguments)")
            try TestSuite.assertTrue(invocation.executable.hasPrefix("/"), "by bare name: \(invocation.executable)")
        }
    }

    static func notes(_ target: ScanTarget) -> String { target.notes.joined(separator: "\n") }

    @MainActor
    static func runAll() async {
        print("\n🔧 Running vendor-command inspector tests (spec §6.1, §6.2, §6.4, §6.8)...")

        await TestSuite.run("Inspectors: simulators — unavailable (one item), stale devices (per UDID, Booted skipped), runtimes (never touched on disk)") {
            try await M1.withEnv { env in
                try installEverything(env)
                let f = env.fixture
                let base = "Library/Developer/CoreSimulator/Devices/"
                let results = try await scan(env, ["simulator.unavailable", "simulator.devices.stale", "simulator.runtimes"])

                let unavailable = try result(results, "simulator.unavailable")
                try TestSuite.assertEqual(unavailable.status, .ok)
                try TestSuite.assertEqual(unavailable.targets.map(\.kind), [.commandItem(argument: nil)])
                let u = unavailable.targets[0]
                let unavailableBytes = M2.treeBlocksBytes(f.path(base + CommandFixtures.unavailableUDID1))
                    + M2.treeBlocksBytes(f.path(base + CommandFixtures.unavailableUDID2))
                try TestSuite.assertEqual(u.allocatedBytes, unavailableBytes)
                try TestSuite.assertTrue(u.allocatedBytes > 0)
                try TestSuite.assertTrue(notes(u).contains("This cannot be undone"), notes(u))
                try TestSuite.assertEqual(u.identity, nil)

                let stale = try result(results, "simulator.devices.stale")
                try TestSuite.assertEqual(stale.status, .ok)
                // The Booted device is just as old but never offered; the fresh one is too new.
                try TestSuite.assertEqual(stale.targets.map(\.kind), [.commandItem(argument: CommandFixtures.staleUDID)])
                let s = stale.targets[0]
                try TestSuite.assertEqual(s.path, f.path(base + CommandFixtures.staleUDID))
                try TestSuite.assertEqual(s.allocatedBytes, M2.treeBlocksBytes(s.path))
                try TestSuite.assertTrue(s.lastUsed != nil)
                try TestSuite.assertTrue(notes(s).contains("Apps and data installed in this simulator are lost."), notes(s))

                let runtimes = try result(results, "simulator.runtimes")
                try TestSuite.assertEqual(runtimes.status, .ok)
                try TestSuite.assertEqual(runtimes.targets.map(\.kind), [.commandItem(argument: CommandFixtures.deletableRuntimeID)])
                let r = runtimes.targets[0]
                try TestSuite.assertEqual(r.allocatedBytes, 8_067_000_161, "simctl's own size")
                try TestSuite.assertTrue(notes(r).contains("Platform:") && notes(r).contains("Version:"), notes(r))
                try TestSuite.assertFalse(r.path.hasPrefix("/"), "a runtime item has no file-system path: \(r.path)")
                // iMop never reads /Library/Developer/CoreSimulator itself.
                try TestSuite.assertFalse(env.fileSystem.recordedCalls.contains { $0.1.hasPrefix("/Library/Developer") })
                try expectOnlyReadOnly(env)
            }
        }

        await TestSuite.run("Inspectors: simulator failures — non-zero exit, timeout, garbage, missing xcrun → .unavailable, no targets") {
            try await M1.withEnv { env in
                try installEverything(env)
                let ids: Set<String> = ["simulator.unavailable", "simulator.devices.stale", "simulator.runtimes"]
                let failures: [CommandResult] = [
                    CommandResult(exitCode: 1, stdout: "", stderr: "boom"),
                    CommandResult(exitCode: 15, stdout: "", stderr: "", timedOut: true),
                    ok(CommandFixtures.simctlGarbage),
                    ok(CommandFixtures.devicesJSONLowercaseUDID),
                    ok(String(repeating: " ", count: 70_000) + "{}"),
                ]
                for failure in failures {
                    for key in [SimctlClient.listDevicesArguments, SimctlClient.listUnavailableDevicesArguments, SimctlClient.listRuntimesArguments] {
                        env.commands.setResponse(failure, for: key)
                    }
                    let results = try await scan(env, ids)
                    for id in ids { try expectUnavailable(try result(results, id), "\(failure)") }
                }
                env.commands.executables = [:]
                let missing = try await scan(env, ids)
                for id in ids { try expectUnavailable(try result(missing, id), "no xcrun") }
            }
        }

        await TestSuite.run("Inspectors: simulator items pass the gate only when simulatorIdle holds (Booted device or Simulator app → refused)") {
            try await M3.withContext { ctx in
                let env = ctx.env
                try installEverything(env)
                let catalog = RuleCatalog.load(data: try M2.sourceRulesData(), environment: env.environment)
                let scanner = SafeCleanScanner(environment: env.environment, catalog: catalog,
                                               inspectors: try M6.fixtureInspectors(env.fixture), hasFullDiskAccess: true,
                                               waivedSystemRoots: [env.fixture.root])
                let results = await scanner.scan(ruleIDs: ["simulator.unavailable", "simulator.devices.stale"])
                try TestSuite.assertEqual(results.flatMap(\.targets).count, 2)
                let busy = await ctx.planBuilder().build(from: results)
                for item in busy.items {
                    guard case .rejected(.preconditionFailed(name: "simulatorIdle", _)) = item.planVerdict else {
                        throw TestError("a Booted simulator must block \(item.rule.id): \(item.planVerdict)")
                    }
                }
                env.commands.setResponse(ok(CommandFixtures.devicesJSONAllShutdown(home: env.fixture.home)), for: SimctlClient.listDevicesArguments)
                let idle = await ctx.planBuilder().build(from: results)
                try TestSuite.assertTrue(idle.items.allSatisfy { $0.planVerdict.isAllowed }, "\(idle.items.map(\.planVerdict))")
                env.runningApplications.ids = ["com.apple.iphonesimulator"]
                let appOpen = await ctx.planBuilder().build(from: results)
                try TestSuite.assertFalse(appOpen.items.contains { $0.planVerdict.isAllowed })
                try expectOnlyReadOnly(env)
            }
        }

        await TestSuite.run("Inspectors: Docker — whole-command items sized from docker's own figures; volumes per item, Red, never --volumes") {
            try await M1.withEnv { env in
                try installEverything(env)
                let ids: Set<String> = ["docker.danglingImages", "docker.buildCache", "docker.unusedImages", "docker.stoppedContainers", "docker.volumes"]
                let results = try await scan(env, ids)
                let expectedBytes: [String: Int64] = [
                    "docker.danglingImages": CommandFixtures.dockerDanglingBytes,
                    "docker.buildCache": 3_110_000_000,
                    // Images reclaimable minus the dangling estimate counted by docker.danglingImages (review M4).
                    "docker.unusedImages": 11_630_000_000 - CommandFixtures.dockerDanglingBytes,
                    "docker.stoppedContainers": 98_300,
                ]
                for (id, bytes) in expectedBytes {
                    let r = try result(results, id)
                    try TestSuite.assertEqual(r.status, .ok, id)
                    try TestSuite.assertEqual(r.targets.map(\.kind), [.commandItem(argument: nil)], id)
                    try TestSuite.assertEqual(r.targets[0].allocatedBytes, bytes, id)
                    try TestSuite.assertTrue(notes(r.targets[0]).contains("This cannot be undone"), id)
                }
                let volumes = try result(results, "docker.volumes")
                try TestSuite.assertEqual(volumes.rule.tier, .red)
                try TestSuite.assertEqual(volumes.status, .ok)
                let anonymous = "3f1c9e0a7b2d4c6e8f0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e"
                try TestSuite.assertEqual(Set(volumes.targets.map(\.kind)), [.commandItem(argument: "old_pgdata"), .commandItem(argument: anonymous)])
                try TestSuite.assertEqual(volumes.targets.first { $0.kind == .commandItem(argument: "old_pgdata") }?.allocatedBytes, 1_850_000_000)
                for target in volumes.targets {
                    try TestSuite.assertTrue(notes(target).contains("permanently deleted"), notes(target))
                }
                if case .command(let spec) = volumes.rule.action {
                    try TestSuite.assertEqual(spec.arguments, ["volume", "rm", CommandSpec.itemToken])
                } else { throw TestError("docker.volumes must be a command rule") }
                try TestSuite.assertFalse(env.commands.invocations.contains { $0.arguments.contains("--volumes") || $0.arguments.contains("prune") })
                try expectOnlyReadOnly(env)

                // Red items need per-item confirmation in the plan.
                let gate = env.makeGate()
                let plan = await PlanBuilder(environment: env.environment, gate: gate, settings: PlanSettings()).build(from: [volumes])
                try TestSuite.assertTrue(plan.items.allSatisfy { $0.requiresPerItemConfirmation }, "Red volumes need per-item confirmation")
            }
        }

        await TestSuite.run("Inspectors: Docker failures — daemon down, malformed tables, df -v unavailable, injected names → .unavailable / nothing") {
            try await M1.withEnv { env in
                try installEverything(env)
                let ids: Set<String> = ["docker.danglingImages", "docker.buildCache", "docker.unusedImages", "docker.stoppedContainers", "docker.volumes"]
                let down = CommandResult(exitCode: 1, stdout: "", stderr: CommandFixtures.dockerDaemonDownStderr)
                for key in [DockerClient.systemDFArguments, DockerClient.systemDFVerboseArguments, DockerClient.imageListArguments,
                            DockerClient.exitedContainersArguments, DockerClient.danglingVolumesArguments] {
                    env.commands.setResponse(down, for: key)
                }
                let downResults = try await scan(env, ids)
                for id in ids { try expectUnavailable(try result(downResults, id), "daemon down") }
                // Docker is never started.
                try TestSuite.assertFalse(env.commands.invocations.contains { $0.arguments.first == "start" || $0.arguments.first == "run" })

                try installEverything(env)
                env.commands.setResponse(ok(CommandFixtures.dockerSystemDFUnknownHeader), for: DockerClient.systemDFArguments)
                env.commands.setResponse(ok(CommandFixtures.dockerImageListNotJSON), for: DockerClient.imageListArguments)
                env.commands.setResponse(ok(CommandFixtures.dockerSystemDFUnknownHeader), for: DockerClient.systemDFVerboseArguments)
                let malformed = try await scan(env, ["docker.danglingImages", "docker.buildCache", "docker.unusedImages", "docker.stoppedContainers"])
                for (_, r) in malformed { try expectUnavailable(r, "malformed") }

                // Volumes: the df -v cross-check is mandatory.
                try installEverything(env)
                env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: "x"), for: DockerClient.systemDFVerboseArguments)
                try expectUnavailable(try result(try await scan(env, ["docker.volumes"]), "docker.volumes"), "no df -v")
                try installEverything(env)
                env.commands.setResponse(ok(CommandFixtures.dockerDanglingVolumesJSONInjected), for: DockerClient.danglingVolumesArguments)
                try expectUnavailable(try result(try await scan(env, ["docker.volumes"]), "docker.volumes"), "injected")
                env.commands.setResponse(ok(CommandFixtures.dockerDanglingVolumesJSONDisagreeing), for: DockerClient.danglingVolumesArguments)
                let disagreeing = try result(try await scan(env, ["docker.volumes"]), "docker.volumes")
                try TestSuite.assertEqual(disagreeing.targets.count, 0, "linked or unknown volumes are never offered")
                env.commands.executables = [:]
                for (_, r) in try await scan(env, ids) { try expectUnavailable(r, "no docker") }
            }
        }

        await TestSuite.run("Inspectors: Ollama — one item per model with size/modified notes; failures and hostile names → nothing") {
            try await M1.withEnv { env in
                try installEverything(env)
                // Review M7: `ollama list` runs only while an Ollama process is already running.
                env.processes.names = ["launchd", "iMopTests"]
                let notRunning = try result(try await scan(env, ["ai.ollama"]), "ai.ollama")
                try TestSuite.assertEqual(notRunning.status, .unavailable(OllamaModelsInspector.notRunningMessage))
                try TestSuite.assertFalse(env.commands.invocations.contains { $0.arguments == OllamaClient.listArguments },
                                          "the CLI (which would start Ollama.app) is never run when Ollama is not running")
                env.processes.failing = true
                try expectUnavailable(try result(try await scan(env, ["ai.ollama"]), "ai.ollama"), "process list unavailable")
                try TestSuite.assertFalse(env.commands.invocations.contains { $0.arguments == OllamaClient.listArguments })
                env.processes.failing = false
                env.processes.names = ["launchd", "iMopTests", "Ollama", "ollama"]

                let r = try result(try await scan(env, ["ai.ollama"]), "ai.ollama")
                try TestSuite.assertEqual(r.status, .ok)
                try TestSuite.assertEqual(r.rule.tier, .yellow)
                try TestSuite.assertEqual(r.targets.map(\.kind), CommandFixtures.ollamaOfferedNames.map { .commandItem(argument: $0) })
                let first = r.targets[0]
                try TestSuite.assertEqual(first.allocatedBytes, 2_000_000_000)
                try TestSuite.assertTrue(notes(first).contains("Last modified: 3 weeks ago"), notes(first))
                try TestSuite.assertTrue(notes(first).contains("This cannot be undone"), notes(first))
                // iMop never looks at Ollama's blob store.
                try TestSuite.assertFalse(env.fileSystem.recordedCalls.contains { $0.1.contains(".ollama") })

                for bad in [CommandResult(exitCode: 1, stdout: "", stderr: CommandFixtures.ollamaNotRunningStderr),
                            CommandResult(exitCode: 0, stdout: "", stderr: "", timedOut: true),
                            ok(CommandFixtures.ollamaListMalformedRow)] {
                    env.commands.setResponse(bad, for: OllamaClient.listArguments)
                    try expectUnavailable(try result(try await scan(env, ["ai.ollama"]), "ai.ollama"), "\(bad)")
                }
                env.commands.setResponse(ok(CommandFixtures.ollamaListInjectedName), for: OllamaClient.listArguments)
                try TestSuite.assertEqual(try result(try await scan(env, ["ai.ollama"]), "ai.ollama").targets.count, 0)
                try expectOnlyReadOnly(env)
            }
        }

        await TestSuite.run("Inspectors: package managers — one whole-command item per rule, sized on the reported cache folder") {
            try await M1.withEnv { env in
                try installEverything(env)
                let f = env.fixture
                let folders: [String: String] = [
                    "npm.cache": ".npm/_cacache", "yarn.cache": "Library/Caches/Yarn/v6", "pnpm.store": "Library/pnpm/store/v3",
                    "bun.cache": ".bun/install/cache", "go.buildCache": "Library/Caches/go-build", "go.modCache": "go/pkg/mod",
                    "cocoapods.cache.command": "Library/Caches/CocoaPods/Pods", "flutter.pubCache": ".pub-cache",
                ]
                let results = try await scan(env, Set(folders.keys).union(["homebrew.cleanup", "android.avd"]))
                for (id, rel) in folders {
                    let r = try result(results, id)
                    try TestSuite.assertEqual(r.status, .ok, id)
                    try TestSuite.assertEqual(r.targets.map(\.kind), [.commandItem(argument: nil)], id)
                    let target = r.targets[0]
                    try TestSuite.assertEqual(target.path, f.path(rel), id)
                    try TestSuite.assertEqual(target.allocatedBytes, M2.treeBlocksBytes(f.path(rel)), id)
                    try TestSuite.assertTrue(target.allocatedBytes > 0, id)
                    guard case .command(let spec) = r.rule.action else { throw TestError("\(id) is not a command rule") }
                    try TestSuite.assertTrue(target.notes.contains("This cannot be undone. \(spec.tool) will re-download what it needs."),
                                             "\(id): \(target.notes)")
                }
                let brew = try result(results, "homebrew.cleanup")
                try TestSuite.assertEqual(brew.targets.map(\.kind), [.commandItem(argument: nil)])
                try TestSuite.assertEqual(brew.targets[0].allocatedBytes, Int64(1.5 * 1024 * 1024 * 1024), "brew's 'would free' estimate")
                let avd = try result(results, "android.avd")
                try TestSuite.assertEqual(avd.targets.map(\.kind), [.commandItem(argument: "Pixel_7_API_34")], "only a named AVD with its .ini")
                try TestSuite.assertEqual(avd.targets[0].allocatedBytes, M2.treeBlocksBytes(f.path(".android/avd/Pixel_7_API_34.avd")))
                // Without avdmanager the AVD is explanation only (advisory), never actionable.
                var executables = env.commands.executables
                executables["avdmanager"] = nil
                env.commands.executables = executables
                let advisory = try result(try await scan(env, ["android.avd"]), "android.avd")
                try TestSuite.assertEqual(advisory.targets.map(\.kind), [.advisory])
                let verdict = await env.makeGate().validate(target: advisory.targets[0], rule: advisory.rule, phase: .plan)
                try TestSuite.assertFalse(verdict.isAllowed, "an advisory AVD must never be actionable")
                try expectOnlyReadOnly(env)
            }
        }

        await TestSuite.run("Inspectors: uv prune (Green) and clean (Yellow) both size `uv cache dir`; Yellow is never Green") {
            try await M1.withEnv { env in
                try installEverything(env)
                env.commands.setResponse(ok(env.fixture.home + "/.cache/uv\n"), for: ["cache", "dir"])
                try env.fixture.file(".cache/uv/wheels-v5/pypi/x.whl", bytes: 20_000)
                let results = try await scan(env, ["uv.cache.prune", "uv.cache.clean"])
                try TestSuite.assertEqual(try result(results, "uv.cache.prune").rule.tier, .green)
                try TestSuite.assertEqual(try result(results, "uv.cache.clean").rule.tier, .yellow)
                for id in ["uv.cache.prune", "uv.cache.clean"] {
                    let r = try result(results, id)
                    try TestSuite.assertEqual(r.targets.first?.allocatedBytes, M2.treeBlocksBytes(env.fixture.path(".cache/uv")), id)
                }
            }
        }

        await TestSuite.run("Inspectors: CocoaPods — the quarantine rule when pod is missing, the command rule when it resolves; never both") {
            try await M1.withEnv { env in
                try installEverything(env)
                let ids: Set<String> = ["cocoapods.cache", "cocoapods.cache.command"]
                let withPod = try await scan(env, ids)
                try expectUnavailable(try result(withPod, "cocoapods.cache"), "pod resolves")
                try TestSuite.assertEqual(try result(withPod, "cocoapods.cache.command").targets.count, 1)
                // Scanning only one of the pair still rescans both, so the cache never holds both.
                _ = try await scan(env, ["cocoapods.cache.command"])

                var executables = env.commands.executables
                executables["pod"] = nil
                env.commands.executables = executables
                let scanner = try SafeCleanScannerTests.makeScanner(env)
                let withoutPod = SafeCleanScannerTests.byRule(await scanner.scan(ruleIDs: ["cocoapods.cache"]))
                try TestSuite.assertEqual(try result(withoutPod, "cocoapods.cache").targets.map { SafeCleanScannerTests.relative($0.path, env.fixture) },
                                          ["Library/Caches/CocoaPods/Pods"])
                let cached = SafeCleanScannerTests.byRule(await scanner.cachedResults() ?? [])
                try expectUnavailable(try result(cached, "cocoapods.cache.command"), "no pod")
                let offering = cached.values.filter { ids.contains($0.rule.id) && !$0.targets.isEmpty }
                try TestSuite.assertEqual(offering.count, 1, "both CocoaPods rules offered items")
            }
        }

        await TestSuite.run("Inspectors: yarn never reports a project .yarn/cache; a cache outside HOME is not sized; a deny-listed one is withheld") {
            try await M1.withEnv { env in
                try installEverything(env)
                let f = env.fixture
                // A project's zero-install cache.
                try f.file("Developer/app/.yarn/cache/left-pad.zip", bytes: 5_000)
                env.commands.setResponse(ok(f.path("Developer/app/.yarn/cache") + "\n"), for: ["cache", "dir"])
                try expectUnavailable(try result(try await scan(env, ["yarn.cache"]), "yarn.cache"), ".yarn/cache")
                // …also when it is reached through a symlink.
                _ = try f.symlink("Library/Caches/YarnLink", to: f.path("Developer/app/.yarn/cache"))
                env.commands.setResponse(ok(f.path("Library/Caches/YarnLink") + "\n"), for: ["cache", "dir"])
                try expectUnavailable(try result(try await scan(env, ["yarn.cache"]), "yarn.cache"), ".yarn via symlink")

                // GOCACHE outside the home folder: offered, but never sized.
                let outside = try f.dir("elsewhere/go-build", base: .root)
                try f.file("elsewhere/go-build/00/x", bytes: 50_000, base: .root)
                env.commands.setResponse(ok(outside + "\n"), for: ["env", "GOCACHE"])
                let go = try result(try await scan(env, ["go.buildCache"]), "go.buildCache")
                try TestSuite.assertEqual(go.targets.count, 1)
                try TestSuite.assertEqual(go.targets[0].allocatedBytes, 0)
                try TestSuite.assertTrue(notes(go.targets[0]).contains("outside your home folder"), notes(go.targets[0]))

                // GOCACHE inside a deny-listed folder (~/Documents): withheld, nothing offered.
                try f.file("Documents/gocache/00/x", bytes: 5_000)
                env.commands.setResponse(ok(f.path("Documents/gocache") + "\n"), for: ["env", "GOCACHE"])
                let denied = try result(try await scan(env, ["go.buildCache"]), "go.buildCache")
                try expectUnavailable(denied, "deny-listed")
                // A folder that contains a protected item (.git) is withheld too.
                try f.file("Library/Caches/go-build/repo/.git/HEAD", bytes: 10)
                env.commands.setResponse(ok(f.path("Library/Caches/go-build") + "\n"), for: ["env", "GOCACHE"])
                try expectUnavailable(try result(try await scan(env, ["go.buildCache"]), "go.buildCache"), ".git inside")

                // Unexpected answers fail closed.
                for answer in ["", "relative/path", f.home + "/a\n" + f.home + "/b", "warning: x\n" + f.home + "/.npm", "/", f.home + "/../x"] {
                    env.commands.setResponse(ok(answer), for: ["config", "get", "cache"])
                    try expectUnavailable(try result(try await scan(env, ["npm.cache"]), "npm.cache"), answer.debugDescription)
                }
                for failure in [CommandResult(exitCode: 1, stdout: f.home + "/.npm", stderr: ""),
                                CommandResult(exitCode: 0, stdout: f.home + "/.npm", stderr: "", timedOut: true)] {
                    env.commands.setResponse(failure, for: ["config", "get", "cache"])
                    try expectUnavailable(try result(try await scan(env, ["npm.cache"]), "npm.cache"), "\(failure)")
                }
                env.commands.setResponse(ok("garbage\n"), for: ["cleanup", "--prune=all", "-n"])
                let brewGarbage = try result(try await scan(env, ["homebrew.cleanup"]), "homebrew.cleanup")
                try TestSuite.assertEqual(brewGarbage.targets.count, 0)
                env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: "x"), for: ["cleanup", "--prune=all", "-n"])
                try expectUnavailable(try result(try await scan(env, ["homebrew.cleanup"]), "homebrew.cleanup"), "brew failed")
                env.commands.executables = [:]
                let none = try await scan(env, ["npm.cache", "bun.cache", "flutter.pubCache", "homebrew.cleanup"])
                for (_, r) in none { try expectUnavailable(r, "tool missing") }
                try expectOnlyReadOnly(env)
            }
        }

        await TestSuite.run("Inspectors: a full scan issues only read-only, allow-listed queries, and command items reference only their own rule") {
            try await M1.withEnv { env in
                try installEverything(env)
                let results = try await SafeCleanScannerTests.makeScanner(env).scan()
                try TestSuite.assertTrue(env.commands.invocations.count >= 15, "\(env.commands.invocations.count)")
                try expectOnlyReadOnly(env)
                let matcher = RuleTargetMatcher(homeForms: [])
                var commandItems = 0
                for result in results {
                    for target in result.targets {
                        try TestSuite.assertEqual(target.ruleID, result.rule.id)
                        if case .commandItem = target.kind {
                            commandItems += 1
                            try TestSuite.assertNil(matcher.commandItemMismatch(target, rule: result.rule), "\(result.rule.id) \(target.kind)")
                            try TestSuite.assertTrue(M2.m4CommandRuleIDs.contains(result.rule.id), result.rule.id)
                            try TestSuite.assertTrue(target.notes.contains { $0.hasPrefix("This cannot be undone") }, result.rule.id)
                            // A command item is never valid for another rule.
                            for other in results where other.rule.id != result.rule.id {
                                try TestSuite.assertTrue(matcher.commandItemMismatch(target, rule: other.rule) != nil, "\(result.rule.id) → \(other.rule.id)")
                            }
                        } else if M2.m4CommandRuleIDs.contains(result.rule.id) {
                            try TestSuite.assertEqual(target.kind, .advisory, result.rule.id)
                        }
                    }
                }
                try TestSuite.assertTrue(commandItems >= 20, "\(commandItems) command items")
                // Nothing was preselected for Yellow/Red command rules by the scanner (plan defaults decide).
                try TestSuite.assertFalse(env.commands.invocations.contains { $0.purpose == .action })
            }
        }
    }
}
