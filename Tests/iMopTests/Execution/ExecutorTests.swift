import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §0.5, §3.1, §3.3, §5.4, §7.3, §11: the Executor (the only component that acts) and its
/// double validation. Mutation only ever happens through `MutationPolicy.fixtureOnly`.
struct ExecutorTests {
    static let message = "mutation disabled in this build"

    /// Nothing from this plan reached the Quarantine or the fake Trash.
    @MainActor
    static func expectNothingActedOn(_ ctx: M3.Context, file: StaticString = #file, line: UInt = #line) async throws {
        let sessions = (try? await ctx.quarantine.sessions()) ?? []
        try TestSuite.assertTrue(sessions.allSatisfy { $0.entries.isEmpty }, "something was quarantined: \(sessions.map(\.entries))",
                                 file: file, line: line)
        try TestSuite.assertEqual(M3.children(ctx.fixture.path("FakeTrash", base: .root)), [], "something was trashed",
                                  file: file, line: line)
    }

    /// Plans and confirms one item, lets `mutate` change the fixture, executes, and returns the status.
    @MainActor
    static func mutateBetweenPlanAndExecute(
        rule: Rule = M1.rule(id: "test.caches"), owner: String? = nil,
        _ mutate: (M3.Context, String) throws -> Void,
        check: (M3.Context, String, ItemStatus, ExecutionReport) async throws -> Void
    ) async throws {
        try await M3.withContext { ctx in
            let path = try M3.cacheItem(ctx.env, "Victim")
            let target = M3.target(ctx.env, rule: rule, path: path, owner: owner)
            let confirmed = try await M3.confirmedPlan(ctx, [(rule, [target])])
            try mutate(ctx, path)
            let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
            try await check(ctx, path, try M3.status(run.report, target.id), run.report)
            try await expectNothingActedOn(ctx)
            try TestSuite.assertEqual(run.report.estimatedReclaimBytes, 0)
            // The rejection is audited with its reason.
            let events = try M3.auditEvents(ctx)
            try TestSuite.assertTrue(events.contains { $0.action == "item.validate" && $0.verdict == "rejected"
                && $0.path == path && $0.rejectionReason != nil }, "rejection not audited")
        }
    }

    @MainActor
    static func runAll() async {
        print("\n⚙️  Running Executor Tests (spec §0.5, §3.3, §5.4, §7.3, §11)...")

        // MARK: (a) default policy

        await TestSuite.run("Executor: without IMOP_ALLOW_MUTATION every item fails .mutationDisabled, fixture untouched, run audited") {
            try TestSuite.assertFalse(MutationPolicy.compiledIn.isEnabled, "this build must not define IMOP_ALLOW_MUTATION")
            try await M3.withContext(policy: .compiledIn) { ctx in
                let green = M1.rule(id: "test.caches")
                let red = M1.rule(id: "test.red", tier: .red, action: .trash)
                let command = M3.commandRule("homebrew.cleanup")
                ctx.env.commands.executables = ["brew": M3.fakeExecutable("brew")]
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: ""), for: ["cleanup", "--prune=all"])
                let a = M3.target(ctx.env, rule: green, path: try M3.cacheItem(ctx.env, "A"))
                let b = M3.target(ctx.env, rule: green, path: try M3.cacheItem(ctx.env, "B"))
                let r = M3.target(ctx.env, rule: red, path: try M3.cacheItem(ctx.env, "R"))
                let c = M3.commandTarget(rule: command, path: ctx.home)
                let confirmed = try await M3.confirmedPlan(ctx, [(green, [a, b]), (red, [r]), (command, [c])], irreversible: true)

                // The agreed public initializer: policy = MutationPolicy.compiledIn.
                let executor = Executor(environment: ctx.env.environment, gate: ctx.gate, quarantine: ctx.quarantine,
                                        auditLog: ctx.audit, trash: ctx.trash, remover: RefusingRemover())
                let run = try await M3.run(executor, confirmed)
                try TestSuite.assertEqual(run.report.outcomes.count, 4)
                for outcome in run.report.outcomes {
                    try TestSuite.assertEqual(outcome.status, .failed(.mutationDisabled, message: message), outcome.path)
                }
                try TestSuite.assertTrue(run.report.mutationDisabled)
                try TestSuite.assertEqual(run.report.estimatedReclaimBytes, 0)
                try TestSuite.assertEqual(run.report.quarantinedBytes, 0)
                try TestSuite.assertTrue(run.report.quarantineSessionID == nil)
                for p in [a.path, b.path, r.path] { try TestSuite.assertTrue(M3.exists(p + "/payload.bin"), p) }
                try TestSuite.assertFalse(M3.exists(ctx.quarantineRoot), "dry run created the Quarantine")
                try TestSuite.assertEqual(ctx.env.commands.invocations, [], "dry run ran a command")
                try await expectNothingActedOn(ctx)

                // Audited even though nothing may be mutated (SAFETY-DECISION: the log is bookkeeping).
                let events = try M3.auditEvents(ctx)
                let actions = events.map(\.action)
                try TestSuite.assertTrue(actions.first == "run.started" && actions.last == "run.finished", "\(actions)")
                try TestSuite.assertTrue(events.contains { $0.action == "run.mutationPolicy" && $0.rejectionReason == message })
                let refused = events.filter { $0.verdict == "mutationDisabled" && $0.rejectionReason == message && $0.path != nil }
                try TestSuite.assertEqual(Set(refused.compactMap(\.path)), [a.path, b.path, r.path, c.path])
                try TestSuite.assertTrue(events.allSatisfy { $0.sessionID == run.report.sessionID })
            }
        }

        // MARK: (b) fixture policy

        await TestSuite.run("Executor: fixture policy → Green items quarantined, originals gone, sizes and measured free space reported, restorable, purgeable") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A", bytes: 8_192), bytes: 8_192)
                let b = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "B"), bytes: 4_096)
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [a, b])])
                ctx.env.volumes.queueImportantCapacities([50_000_000, 50_000_000])
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                let report = run.report

                guard case .quarantined(let entryA) = try M3.status(report, a.id),
                      case .quarantined(let entryB) = try M3.status(report, b.id) else {
                    throw TestError("expected both quarantined: \(report.outcomes.map(\.status))")
                }
                try TestSuite.assertFalse(M3.exists(a.path) || M3.exists(b.path), "originals still present")
                try TestSuite.assertEqual(report.estimatedReclaimBytes, 12_288)
                try TestSuite.assertEqual(report.quarantinedBytes, 12_288)
                try TestSuite.assertEqual(report.measuredFreeBefore, 50_000_000)
                try TestSuite.assertEqual(report.measuredFreeAfter, 50_000_000)
                try TestSuite.assertEqual(report.measuredDelta, 0)
                try TestSuite.assertFalse(report.cancelled)
                try TestSuite.assertFalse(report.mutationDisabled)
                // §7.3 honest explanations (measured < estimated).
                try TestSuite.assertTrue(report.explanations.contains { $0.contains(Quarantine.spaceNotice) }, "\(report.explanations)")
                try TestSuite.assertTrue(report.explanations.contains { $0.contains("Time Machine") })
                try TestSuite.assertTrue(report.explanations.contains { $0.contains("APFS clones") })
                try TestSuite.assertTrue(report.explanations.contains { $0.contains("purgeable") })

                // Event order: started, (itemStarted, itemFinished)×2, finished.
                let shape = run.events.map { event -> String in
                    switch event {
                    case .started(_, let total): return "started\(total)"
                    case .itemStarted: return "itemStarted"
                    case .itemFinished: return "itemFinished"
                    case .finished: return "finished"
                    }
                }
                try TestSuite.assertEqual(shape, ["started2", "itemStarted", "itemFinished", "itemStarted", "itemFinished", "finished"])

                // Both items sit in one Quarantine session...
                guard let sessionID = report.quarantineSessionID else { throw TestError("no quarantine session") }
                let sessions = try await ctx.quarantine.sessions()
                try TestSuite.assertEqual(sessions.map(\.id), [sessionID])
                try TestSuite.assertEqual(Set(sessions[0].entries.map(\.id)), [entryA, entryB])
                try TestSuite.assertTrue(sessions[0].entries.allSatisfy { $0.status == .moved })

                // ...are restorable...
                let restored = await ctx.quarantine.restoreSession(sessionID)
                try TestSuite.assertEqual(try restored.map { try $0.get().status }, [.restored, .restored])
                try TestSuite.assertTrue(M3.exists(a.path + "/payload.bin") && M3.exists(b.path + "/payload.bin"))

                // ...and, cleaned again, purgeable.
                let again = try await M3.confirmedPlan(ctx, [(rule, [M3.target(ctx.env, rule: rule, path: a.path),
                                                                     M3.target(ctx.env, rule: rule, path: b.path)])])
                let second = try await M3.run(ctx.executor(remover: RefusingRemover()), again)
                try TestSuite.assertTrue(second.report.outcomes.allSatisfy { $0.status.succeeded }, "\(second.report.outcomes)")
                let purged = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(purged.map(\.status), [.purged, .purged])
                try TestSuite.assertEqual(M3.children(ctx.quarantineRoot), [".metadata_never_index"])
                try TestSuite.assertFalse(M3.exists(a.path) || M3.exists(b.path))
            }
        }

        await TestSuite.run("Executor: explanations — none when measured ≥ estimated; 'could not be measured' when capacity is unknown") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"), bytes: 4_096)
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [a])])
                ctx.env.volumes.queueImportantCapacities([1_000_000, 1_010_000])
                let run = try await M3.run(ctx.executor(), confirmed)
                try TestSuite.assertEqual(run.report.measuredDelta, 10_000)
                try TestSuite.assertEqual(run.report.explanations, [])

                let b = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "B"), bytes: 4_096)
                let second = try await M3.confirmedPlan(ctx, [(rule, [b])])
                ctx.env.volumes.queueImportantCapacities([nil, nil])
                let unmeasured = try await M3.run(ctx.executor(), second)
                try TestSuite.assertTrue(unmeasured.report.measuredDelta == nil)
                try TestSuite.assertTrue(unmeasured.report.explanations.contains { $0.contains("could not be measured") },
                                         "\(unmeasured.report.explanations)")
            }
        }

        // MARK: (c) double validation

        await TestSuite.run("Double validation: target folder replaced by a new folder (new inode) → skipped .changedSinceScan") {
            try await mutateBetweenPlanAndExecute({ ctx, path in
                let oldInode = M3.inode(path)
                try FileManager.default.moveItem(atPath: path, toPath: path + "-old")
                try ctx.fixture.file("Library/Caches/Victim/payload.bin", bytes: 4_096)
                try TestSuite.assertTrue(M3.inode(path) != oldInode, "fixture did not get a new inode")
            }, check: { _, path, status, _ in
                try M3.expectSkipped(status, .changedSinceScan)
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin") && M3.exists(path + "-old/payload.bin"))
            })
        }

        await TestSuite.run("Double validation: target replaced by a symlink to ~/Documents (deny-listed) → skipped, link and destination untouched") {
            try await mutateBetweenPlanAndExecute({ ctx, path in
                try ctx.fixture.file("Documents/secret.txt", bytes: 32)
                try FileManager.default.removeItem(atPath: path)
                try ctx.fixture.symlink("Library/Caches/Victim", to: ctx.fixture.path("Documents"))
            }, check: { ctx, path, status, _ in
                try M3.expectSkipped(status, .symlinkInPath(component: path))
                try TestSuite.assertTrue(M3.exists(ctx.fixture.path("Documents/secret.txt")), "deny-listed destination touched")
                try TestSuite.assertTrue(M3.lstatInfo(path).map { ($0.st_mode & S_IFMT) == S_IFLNK } == true, "link removed")
            })
        }

        await TestSuite.run("Double validation: target replaced by a symlink to /System → skipped, never followed") {
            try await mutateBetweenPlanAndExecute({ ctx, path in
                try FileManager.default.removeItem(atPath: path)
                try ctx.fixture.symlink("Library/Caches/Victim", to: "/System/Library")
            }, check: { _, path, status, _ in
                try M3.expectSkipped(status, .symlinkInPath(component: path))
                try TestSuite.assertTrue(M3.exists("/System/Library/CoreServices"))
            })
        }

        await TestSuite.run("Double validation: owner changed (fake uid) → skipped .notOwnedByUser") {
            try await mutateBetweenPlanAndExecute({ ctx, path in
                ctx.env.fileSystem.overrideStat(path, uid: ctx.env.userID + 1)
            }, check: { ctx, path, status, _ in
                try M3.expectSkipped(status, .notOwnedByUser(uid: ctx.env.userID + 1))
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
            })
        }

        await TestSuite.run("Double validation: moved onto another volume (fake st_dev) → skipped .crossVolume") {
            try await mutateBetweenPlanAndExecute({ ctx, path in
                ctx.env.fileSystem.overrideStat(path, device: 9_999)
            }, check: { _, path, status, _ in
                try M3.expectSkipped(status, .crossVolume)
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
            })
        }

        await TestSuite.run("Double validation: a process opened a file inside the target → skipped notOpenByAnyProcess") {
            try await mutateBetweenPlanAndExecute(rule: M1.rule(id: "test.caches", preconditions: [.notOpenByAnyProcess]), { ctx, path in
                ctx.env.processes.openFiles = [path + "/payload.bin": [4_242]]
            }, check: { _, path, status, _ in
                try M3.expectPreconditionSkipped(status, name: "notOpenByAnyProcess")
                guard case .skipped(let rejection) = status else { return }
                try TestSuite.assertEqual(rejection.errorCategory, .inUse)
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
            })
        }

        await TestSuite.run("Double validation: the owning app was started → skipped owningAppNotRunning") {
            try await mutateBetweenPlanAndExecute(rule: M1.rule(id: "test.caches", preconditions: [.owningAppNotRunning]),
                                                  owner: "com.example.Owner", { ctx, _ in
                ctx.env.runningApplications.ids += ["com.example.Owner"]
            }, check: { _, path, status, _ in
                try M3.expectPreconditionSkipped(status, name: "owningAppNotRunning")
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
            })
        }

        await TestSuite.run("Double validation: the target was deleted → skipped .itemMissing") {
            try await mutateBetweenPlanAndExecute({ _, path in
                try FileManager.default.removeItem(atPath: path)
            }, check: { _, path, status, _ in
                try M3.expectSkipped(status, .itemMissing)
                try TestSuite.assertFalse(M3.exists(path))
            })
        }

        await TestSuite.run("Double validation: running as root at execute time → skipped .runningAsRoot") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let target = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "Victim"))
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [target])])
                ctx.env.effectiveUserID = 0
                // The gate is rebuilt from the (now root) environment, as a relaunch would.
                let executor = Executor(environment: ctx.env.environment, gate: ctx.env.makeGate(), quarantine: ctx.quarantine,
                                        auditLog: ctx.audit, trash: ctx.trash, remover: RefusingRemover(), mutationPolicy: ctx.policy)
                let run = try await M3.run(executor, confirmed)
                try M3.expectSkipped(try M3.status(run.report, target.id), .runningAsRoot)
                try TestSuite.assertTrue(M3.exists(target.path + "/payload.bin"))
            }
        }

        await TestSuite.run("Double validation: failures are per-item — only the mutated item is skipped, the rest is quarantined") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let b = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "B"))
                let c = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "C"))
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [a, b, c])])
                ctx.env.fileSystem.overrideStat(b.path, uid: ctx.env.userID + 7)
                let run = try await M3.run(ctx.executor(), confirmed)
                guard case .quarantined = try M3.status(run.report, a.id), case .quarantined = try M3.status(run.report, c.id) else {
                    throw TestError("\(run.report.outcomes.map(\.status))")
                }
                try M3.expectSkipped(try M3.status(run.report, b.id), .notOwnedByUser(uid: ctx.env.userID + 7))
                try TestSuite.assertTrue(M3.exists(b.path + "/payload.bin"))
                try TestSuite.assertFalse(M3.exists(a.path) || M3.exists(c.path))
                try TestSuite.assertEqual(run.report.estimatedReclaimBytes, a.reclaimableBytes + c.reclaimableBytes)
            }
        }

        // MARK: (d) cancellation

        await TestSuite.run("Executor: cancel() is honoured between items, never mid-item") {
            try await M3.withContext { ctx in
                let gated = GatedCommandRunner(executables: ["brew": M3.fakeExecutable("brew")])
                let command = M3.commandRule("homebrew.cleanup")
                let rule = M1.rule(id: "test.caches")
                let c = M3.commandTarget(rule: command, path: ctx.home)
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let b = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "B"))
                let confirmed = try await M3.confirmedPlan(ctx, [(command, [c]), (rule, [a, b])], irreversible: true)
                let executor = ctx.executor(environment: M3.environment(ctx.env, commands: gated))

                let stream = await executor.execute(confirmed)
                try await gated.waitUntilStarted()
                await executor.cancel()          // while item 1 is in progress
                gated.release()
                var report: ExecutionReport?
                for await event in stream { if case .finished(let r) = event { report = r } }
                guard let report else { throw TestError("no report") }

                try TestSuite.assertTrue(report.cancelled)
                try TestSuite.assertEqual(report.outcomes.map(\.id), [c.id], "only the in-progress item finishes")
                try TestSuite.assertEqual(report.outcomes[0].status, .commandSucceeded(exitCode: 0), "the item in progress was interrupted")
                try TestSuite.assertTrue(M3.exists(a.path + "/payload.bin") && M3.exists(b.path + "/payload.bin"))
                try TestSuite.assertTrue(report.explanations.contains { $0.contains("2 item(s) were not processed") }, "\(report.explanations)")
                try TestSuite.assertTrue(try M3.auditEvents(ctx).contains { $0.action == "run.cancelled" })

                // The executor is idle again afterwards: a new run proceeds normally.
                let again = try await M3.confirmedPlan(ctx, [(rule, [M3.target(ctx.env, rule: rule, path: a.path)])])
                let next = try await M3.run(executor, again)
                try TestSuite.assertFalse(next.report.cancelled)
                try TestSuite.assertTrue(next.report.outcomes.allSatisfy { $0.status.succeeded }, "\(next.report.outcomes)")
            }
        }

        // MARK: (e) commands

        await TestSuite.run("Executor: commands — success, non-zero exit, timeout, unresolvable tool, per-item argument; output truncated in the audit") {
            try await M3.withContext { ctx in
                // pnpm deliberately does not resolve ("ghost").
                ctx.env.commands.executables = ["brew": M3.fakeExecutable("brew"), "npm": M3.fakeExecutable("npm"),
                                                "go": M3.fakeExecutable("go"), "ollama": M3.fakeExecutable("ollama")]
                // ai.ollama pins no precondition, so no read-only probe runs before its per-item command.
                let model = "library/llama3:8b"
                let big = String(repeating: "x", count: 200_000)
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: big, stderr: "warn"), for: ["cleanup", "--prune=all"])
                ctx.env.commands.setResponse(CommandResult(exitCode: 3, stdout: "", stderr: "boom"), for: ["cache", "clean", "--force"])
                ctx.env.commands.setResponse(CommandResult(exitCode: 15, stdout: "", stderr: "", timedOut: true), for: ["clean", "-cache"])
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: "deleted", stderr: ""), for: ["rm", model])
                let ok = M3.commandRule("homebrew.cleanup")
                let fail = M3.commandRule("npm.cache")
                let hang = M3.commandRule("go.buildCache", timeoutSeconds: 5)
                let ghost = M3.commandRule("pnpm.store")
                let perItem = M3.commandRule("ai.ollama")
                let tOk = M3.commandTarget(rule: ok, path: ctx.home)
                let tFail = M3.commandTarget(rule: fail, path: ctx.home)
                let tHang = M3.commandTarget(rule: hang, path: ctx.home)
                let tGhost = M3.commandTarget(rule: ghost, path: ctx.home)
                let tItem = M3.commandTarget(rule: perItem, path: "ollama model: " + model, argument: model)
                let confirmed = try await M3.confirmedPlan(ctx, [(ok, [tOk]), (fail, [tFail]), (hang, [tHang]), (ghost, [tGhost]),
                                                                 (perItem, [tItem])], irreversible: true)
                let run = try await M3.run(ctx.executor(), confirmed)

                try TestSuite.assertEqual(try M3.status(run.report, tOk.id), .commandSucceeded(exitCode: 0))
                try TestSuite.assertEqual(try M3.status(run.report, tFail.id), .failed(.commandFailed(3), message: "boom"))
                guard case .failed(.timeout, _) = try M3.status(run.report, tHang.id) else {
                    throw TestError("timeout: \(try M3.status(run.report, tHang.id))")
                }
                guard case .failed(.safetyRejected, _) = try M3.status(run.report, tGhost.id) else {
                    throw TestError("unresolvable: \(try M3.status(run.report, tGhost.id))")
                }
                try TestSuite.assertEqual(try M3.status(run.report, tItem.id), .commandSucceeded(exitCode: 0))

                let invocations = ctx.env.commands.invocations
                try TestSuite.assertEqual(invocations.map(\.arguments), [["cleanup", "--prune=all"], ["cache", "clean", "--force"],
                                                                         ["clean", "-cache"], ["rm", model]])
                try TestSuite.assertEqual(invocations.map(\.executable), ["brew", "npm", "go", "ollama"].map(M3.fakeExecutable),
                                          "never by bare name / shell")
                // Milestone 4: the Executor is the only caller that asks for `.action`.
                try TestSuite.assertEqual(ctx.env.commands.purposes, [.action, .action, .action, .action])
                try TestSuite.assertEqual(invocations[2].timeout, 5)
                try TestSuite.assertEqual(invocations[0].timeout, CommandSpec.defaultTimeout)

                let events = try M3.auditEvents(ctx)
                let okEvent = events.first { $0.action == "item.command" && $0.ruleID == "homebrew.cleanup" }
                try TestSuite.assertEqual(okEvent?.commandExitCode, 0)
                let detail = okEvent?.detail ?? ""
                try TestSuite.assertTrue(detail.utf8.count <= AuditEvent.maxDetailBytes, "detail \(detail.utf8.count) bytes")
                try TestSuite.assertTrue(detail.contains("stderr:\nwarn"), "stderr not captured")
                try TestSuite.assertTrue(detail.contains("[truncated]"))
                try TestSuite.assertEqual(events.first { $0.action == "item.command" && $0.ruleID == "npm.cache" }?.commandExitCode, 3)
                try TestSuite.assertTrue(events.contains { $0.ruleID == "go.buildCache" && $0.rejectionReason == "timeout" })
            }
        }

        await TestSuite.run("Executor: a per-item command with an option-like argument is skipped and never run") {
            try await M3.withContext { ctx in
                ctx.env.commands.executables = ["xcrun": M3.fakeExecutable("xcrun")]
                let rule = M3.commandRule("simulator.devices.stale")
                let target = M3.commandTarget(rule: rule, path: "--all", argument: "--all")
                let plan = await M3.plan(ctx, [(rule, [target])])
                try TestSuite.assertFalse(plan.items[0].isActionable, "an option-like argument reached the plan")
                try TestSuite.assertEqual(ctx.env.commands.invocations, [])
            }
        }

        await TestSuite.run("Executor (M4): per-item commands run with purpose .action and the validated {ITEM}; invalid items never reach the plan") {
            try await M3.withContext { ctx in
                ctx.env.commands.executables = ["docker": M3.fakeExecutable("docker"), "ollama": M3.fakeExecutable("ollama"),
                                                "xcrun": M3.fakeExecutable("xcrun")]
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: "old_pgdata", stderr: ""), for: ["volume", "rm", "old_pgdata"])
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: "deleted", stderr: ""), for: ["rm", "library/mistral:7b"])
                // docker.volumes pins dockerDaemonReachable (review M4): its read-only probe answers.
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: "Server Version: 27.0", stderr: ""), for: ["info"])
                let volumes = M3.commandRule("docker.volumes")
                let ollama = M3.commandRule("ai.ollama")
                let v = M3.commandTarget(rule: volumes, path: "docker volume: old_pgdata", argument: "old_pgdata")
                let o = M3.commandTarget(rule: ollama, path: "ollama model: library/mistral:7b", argument: "library/mistral:7b")
                let plan = await M3.plan(ctx, [(volumes, [v]), (ollama, [o])])
                try TestSuite.assertTrue(plan.items.allSatisfy(\.isActionable), "\(plan.items.map(\.planVerdict))")
                try TestSuite.assertTrue(plan.items.first { $0.target.id == v.id }?.requiresPerItemConfirmation == true, "Red volume")
                try TestSuite.assertFalse(plan.items.contains { $0.selectedByDefault }, "Yellow/Red command items are never preselected")
                let confirmed = try M3.confirmAll(plan, irreversible: true)
                let run = try await M3.run(ctx.executor(), confirmed)
                try TestSuite.assertEqual(try M3.status(run.report, v.id), .commandSucceeded(exitCode: 0))
                try TestSuite.assertEqual(try M3.status(run.report, o.id), .commandSucceeded(exitCode: 0))
                // Precondition probes (`docker info`) are read-only; the actions are exactly these.
                try TestSuite.assertTrue(ctx.env.commands.invocations.filter { $0.purpose == .readOnly }.allSatisfy { $0.arguments == ["info"] })
                let invocations = ctx.env.commands.invocations.filter { $0.purpose == .action }
                try TestSuite.assertEqual(invocations.map(\.arguments), [["volume", "rm", "old_pgdata"], ["rm", "library/mistral:7b"]])
                try TestSuite.assertEqual(invocations.map(\.purpose), [.action, .action])
                try TestSuite.assertEqual(invocations.map(\.executable), [M3.fakeExecutable("docker"), M3.fakeExecutable("ollama")])

                // Invalid / option-injecting / path-like items are refused at plan time and never run.
                let stale = M3.commandRule("simulator.devices.stale")
                let hostile: [(Rule, String?)] = [
                    (stale, "all"), (stale, "booted"), (stale, "a47cd2c9-0c68-4140-a0b1-925934040ad2"), (stale, "-rf"), (stale, nil),
                    (volumes, "--force"), (volumes, "a b"), (volumes, "../x"), (volumes, "x;rm"), (ollama, "../../etc"), (ollama, "-h"),
                    (M3.commandRule("homebrew.cleanup"), "extra"),
                ]
                let before = ctx.env.commands.invocations.count
                for (rule, argument) in hostile {
                    let target = M3.commandTarget(rule: rule, path: argument ?? "x", argument: argument)
                    let refused = await M3.plan(ctx, [(rule, [target])])
                    try TestSuite.assertFalse(refused.items[0].isActionable, "\(rule.id) \(argument ?? "nil") reached the plan")
                }
                try TestSuite.assertEqual(ctx.env.commands.invocations.count, before, "a refused item ran")
            }
        }

        await TestSuite.run("Executor (M4): a forged plan whose hash VERIFIES but carries a tampered {ITEM} or an unpinned command is refused before running") {
            try await M3.withContext { ctx in
                ctx.env.commands.executables = ["xcrun": M3.fakeExecutable("xcrun"), "faketool": M3.fakeExecutable("faketool"),
                                                "docker": M3.fakeExecutable("docker")]
                ctx.env.commands.setResponse(CommandResult(exitCode: 0, stdout: "", stderr: ""), for: ["simctl", "delete", "all"])
                let stale = M3.commandRule("simulator.devices.stale")
                let volumes = M3.commandRule("docker.volumes")
                let unpinned = M3.unpinnedCommandRule(spec: CommandSpec(tool: "faketool", arguments: ["clean"]))
                let wrongTier = M1.rule(id: "docker.volumes", tier: .yellow, allowRoots: [],
                                        action: volumes.action, discovery: volumes.discovery)
                @MainActor func forged(_ rule: Rule, _ argument: String?) -> PlanItem {
                    guard case .command(let spec) = rule.action else { fatalError("not a command rule") }
                    let target = M3.commandTarget(rule: rule, path: argument ?? "x", argument: argument)
                    return PlanItem.makeForTesting(target: target, rule: rule, effectiveTier: max(rule.tier, .yellow),
                                                   action: .command(spec, argument: argument), planVerdict: .allowed)
                }
                let items = [forged(stale, "all"), forged(stale, "-rf"), forged(stale, "UDID; rm -rf ~"),
                             forged(volumes, "--force"), forged(unpinned, nil), forged(wrongTier, "pgdata")]
                let planID = UUID()
                let plan = ConfirmedPlan.makeForTesting(planID: planID, items: items,
                                                        contentHash: ConfirmedPlan.hash(planID: planID, items: items), confirmedAt: Date())
                try TestSuite.assertTrue(plan.verifyHash(), "the forgery must pass the hash check to exercise the Executor's own checks")
                let run = try await M3.run(ctx.executor(), plan)
                try TestSuite.assertEqual(run.report.outcomes.count, items.count)
                for outcome in run.report.outcomes {
                    guard case .skipped = outcome.status else { throw TestError("\(outcome.path): \(outcome.status)") }
                }
                try TestSuite.assertEqual(ctx.env.commands.invocations, [], "a forged command ran")
            }
        }

        // MARK: (f) trash

        await TestSuite.run("Executor: Red trash items go through TrashMoving (a fixture fake — never the real Trash)") {
            try await M3.withContext { ctx in
                let red = M1.rule(id: "test.red", tier: .red, action: .trash)
                let target = M3.target(ctx.env, rule: red, path: try M3.cacheItem(ctx.env, "OldApp"))
                let inode = M3.inode(target.path)
                let confirmed = try await M3.confirmedPlan(ctx, [(red, [target])])
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                guard case .trashed(let result) = try M3.status(run.report, target.id) else {
                    throw TestError("\(run.report.outcomes.map(\.status))")
                }
                try TestSuite.assertTrue(result.hasPrefix(ctx.fixture.path("FakeTrash", base: .root) + "/"), result)
                try TestSuite.assertEqual(M3.inode(result), inode)
                try TestSuite.assertFalse(M3.exists(target.path))
                try TestSuite.assertEqual(run.report.quarantinedBytes, 0)
                try TestSuite.assertTrue(run.report.quarantineSessionID == nil)
                // The real FinderTrash refuses to run while the test guard is installed (even with the
                // fixture policy), refuses in this no-flag build by default, and never acts without a
                // pinned identity.
                let caches = ctx.fixture.path("Library/Caches")
                let cachesID = ctx.env.fileSystem.lstat(caches)!.identity
                let cases: [(any TrashMoving, String, FileActionError)] = [
                    (FinderTrash(mutationPolicy: ctx.policy, environment: ctx.env.environment), "fixture policy", .refusedInTestRun),
                    (FinderTrash(), "compiled-in policy", .mutationDisabled),
                ]
                for (trash, label, expected) in cases {
                    do {
                        _ = try trash.moveToTrash(path: caches, expectedIdentity: cachesID)
                        throw TestError("FinderTrash ran during a test (\(label))")
                    } catch let error as FileActionError {
                        try TestSuite.assertEqual(error, expected, label)
                    }
                }
                do {
                    _ = try FinderTrash().moveToTrash(path: caches)
                    throw TestError("FinderTrash acted without an identity")
                } catch let error as FileActionError {
                    try TestSuite.assertEqual(error, .identityRequired)
                }
                try TestSuite.assertTrue(M3.exists(caches))
            }
        }

        // MARK: (g) permanent delete

        await TestSuite.run("Executor: permanent delete only when 'Always quarantine' is OFF and the irreversible action is acknowledged") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "trash.empty", tier: .yellow, action: .permanentDelete)
                let target = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "Gone"))
                let plan = await M3.plan(ctx, [(rule, [target])], settings: PlanSettings(alwaysQuarantine: false))
                try TestSuite.assertTrue(plan.items[0].isActionable, "\(plan.items[0].planVerdict)")
                try TestSuite.assertFalse(plan.items[0].selectedByDefault)
                for (always, ack, expected) in [(true, true, ConfirmationError.permanentDeleteBlockedByAlwaysQuarantine(target.id)),
                                                (false, false, ConfirmationError.irreversibleNotAcknowledged)] {
                    do {
                        _ = try M3.confirmAll(plan, irreversible: ack, alwaysQuarantine: always)
                        throw TestError("confirmed with alwaysQuarantine=\(always) ack=\(ack)")
                    } catch let error as ConfirmationError {
                        try TestSuite.assertEqual(error, expected)
                    }
                }
                try TestSuite.assertTrue(M3.exists(target.path + "/payload.bin"))
                let confirmed = try M3.confirmAll(plan, irreversible: true, alwaysQuarantine: false)
                let run = try await M3.run(ctx.executor(), confirmed)
                try TestSuite.assertEqual(try M3.status(run.report, target.id), .permanentlyRemoved)
                try TestSuite.assertFalse(M3.exists(target.path))
                try TestSuite.assertFalse(M3.exists(ctx.quarantineRoot), "a permanent delete went through the Quarantine")
                try TestSuite.assertEqual(run.report.estimatedReclaimBytes, target.reclaimableBytes)
            }
        }

        // MARK: (h) fixture policy boundaries

        await TestSuite.run("MutationPolicy: fixtureOnly permits only paths strictly inside its root with a home inside it") {
            try await M1.withEnv { env in
                let other = try FixtureBuilder()
                defer { other.cleanup() }
                let policy = MutationPolicy.fixtureOnly(root: env.fixture.root)
                let e = env.environment
                try TestSuite.assertTrue(policy.isEnabled)
                try TestSuite.assertTrue(policy.permits(path: env.fixture.path("Library/Caches/x"), environment: e))
                try TestSuite.assertTrue(policy.permits(path: env.fixture.path("not-yet/created/deep"), environment: e))
                try TestSuite.assertFalse(policy.permits(path: env.fixture.root, environment: e), "the root itself")
                try TestSuite.assertFalse(policy.permits(path: other.path("Library/Caches/x"), environment: e), "another fixture")
                try TestSuite.assertFalse(policy.permits(path: "/private/tmp/iMop-elsewhere", environment: e))
                try TestSuite.assertFalse(policy.permits(path: "/System/Library/x", environment: e))
                // (Relative and ".." paths are not probed here: the test tripwire treats them as inside
                // the real home — the repository is the working directory — and aborts the run by design.)
                // A path that resolves out of the root through a symlink is refused.
                try env.fixture.symlink("Library/Caches/out", to: other.root)
                try TestSuite.assertFalse(policy.permits(path: env.fixture.path("Library/Caches/out/x"), environment: e))
                // The environment's home must be inside the root too.
                let otherEnv = FakeEnvironment(fixture: other).environment
                try TestSuite.assertFalse(policy.permits(path: env.fixture.path("Library/Caches/x"), environment: otherEnv))

                // Roots that do not qualify yield a disabled policy.
                let tmp = FixtureBuilder.realpath(FileManager.default.temporaryDirectory.path) ?? "/private/tmp"
                for bad in [tmp, env.fixture.home, "/private/tmp", "/", env.fixture.root + "/missing"] {
                    let p = MutationPolicy.fixtureOnly(root: bad)
                    try TestSuite.assertFalse(p.isEnabled, "root \(bad) accepted")
                    try TestSuite.assertFalse(p.permits(path: env.fixture.path("Library/Caches/x"), environment: e), bad)
                }
                try TestSuite.assertFalse(MutationPolicy.disabled.isEnabled)
                try TestSuite.assertFalse(MutationPolicy.compiledIn.isEnabled)
                try TestSuite.assertFalse(MutationPolicy.compiledIn.permits(path: env.fixture.path("Library/Caches/x"), environment: e))
            }
        }

        await TestSuite.run("Executor: a fixture policy for another root refuses — item untouched, .mutationDisabled") {
            try await M3.withContext { ctx in
                let other = try FixtureBuilder()
                defer { other.cleanup() }
                let rule = M1.rule(id: "test.caches")
                let target = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [target])])
                let run = try await M3.run(ctx.executor(policy: .fixtureOnly(root: other.root)), confirmed)
                try TestSuite.assertEqual(try M3.status(run.report, target.id), .failed(.mutationDisabled, message: message))
                try TestSuite.assertTrue(M3.exists(target.path + "/payload.bin"))
                try TestSuite.assertEqual(M3.children(other.root), ["home"])
            }
        }

        // MARK: (i) single run

        await TestSuite.run("Executor: a second execute while a run is in progress is refused without touching anything") {
            try await M3.withContext { ctx in
                let gated = GatedCommandRunner(executables: ["brew": M3.fakeExecutable("brew")])
                let command = M3.commandRule("homebrew.cleanup")
                let rule = M1.rule(id: "test.caches")
                let c = M3.commandTarget(rule: command, path: ctx.home)
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let confirmed = try await M3.confirmedPlan(ctx, [(command, [c]), (rule, [a])], irreversible: true)
                let executor = ctx.executor(environment: M3.environment(ctx.env, commands: gated))

                let first = await executor.execute(confirmed)
                try await gated.waitUntilStarted()
                var secondEvents: [ExecutionEvent] = []
                for await event in await executor.execute(confirmed) { secondEvents.append(event) }
                try TestSuite.assertEqual(secondEvents.count, 1)
                guard case .finished(let refused) = secondEvents[0] else { throw TestError("expected only .finished") }
                try TestSuite.assertEqual(refused.outcomes.map(\.status), [.failed(.inUse, message: "another cleanup is running"),
                                                                           .failed(.inUse, message: "another cleanup is running")])
                try TestSuite.assertTrue(M3.exists(a.path + "/payload.bin"), "the refused run touched an item")
                try TestSuite.assertEqual(gated.startedCount, 1, "the refused run ran a command")

                gated.release()
                var report: ExecutionReport?
                for await event in first { if case .finished(let r) = event { report = r } }
                guard let report else { throw TestError("first run did not finish") }
                try TestSuite.assertEqual(try M3.status(report, c.id), .commandSucceeded(exitCode: 0))
                guard case .quarantined = try M3.status(report, a.id) else { throw TestError("\(report.outcomes)") }
            }
        }

        // MARK: (j) hash mismatch

        await TestSuite.run("Executor: a plan whose hash does not verify is not acted on at all") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let a = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "A"))
                let decoyPath = try M3.cacheItem(ctx.env, "Decoy")
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [a])])
                // Swap the item's path for another (valid!) cache folder, keeping the confirmed hash.
                let original = confirmed.items[0]
                let swapped = ScanTarget(id: a.id, ruleID: a.ruleID, path: decoyPath, displayName: "Decoy",
                                         identity: ctx.env.fileSystem.lstat(decoyPath)?.identity, allocatedBytes: a.allocatedBytes,
                                         reclaimableBytes: a.reclaimableBytes, itemCount: 1, lastUsed: nil)
                let forgedItem = PlanItem.makeForTesting(target: swapped, rule: rule, effectiveTier: original.effectiveTier,
                                                         action: original.action, planVerdict: .allowed)
                let forged = ConfirmedPlan.makeForTesting(planID: confirmed.planID, items: [forgedItem],
                                                          contentHash: confirmed.contentHash, confirmedAt: confirmed.confirmedAt)
                let bogus = ConfirmedPlan.makeForTesting(planID: confirmed.planID, items: confirmed.items,
                                                         contentHash: String(repeating: "ab", count: 32), confirmedAt: confirmed.confirmedAt)
                for plan in [forged, bogus] {
                    try TestSuite.assertFalse(plan.verifyHash())
                    let run = try await M3.run(ctx.executor(remover: RefusingRemover()), plan)
                    try TestSuite.assertEqual(run.report.outcomes.map(\.status), [.skipped(.changedSinceScan)])
                    try TestSuite.assertEqual(run.report.estimatedReclaimBytes, 0)
                }
                try TestSuite.assertTrue(M3.exists(a.path + "/payload.bin") && M3.exists(decoyPath + "/payload.bin"))
                try TestSuite.assertFalse(M3.exists(ctx.quarantineRoot), "a Quarantine session was begun for a forged plan")
                let events = try M3.auditEvents(ctx)
                try TestSuite.assertEqual(events.filter { $0.action == "plan.verifyHash" && $0.verdict == "rejected" }.count, 2)
                try TestSuite.assertFalse(events.contains { $0.action == "item.validate" }, "a forged plan reached the gate")
            }
        }
    }
}
