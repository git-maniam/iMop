import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Regression tests for the adversarial review of Milestone 3. Every mutation happens strictly inside
/// the per-test fixture root (fixture policy); nothing touches the real Trash or the real ~/Library.
struct M3ReviewRegressionTests {
    @MainActor
    static func expectQuarantineError(_ body: () async throws -> Void, file: StaticString = #file, line: UInt = #line,
                                      _ check: (QuarantineError) -> Bool) async throws {
        do {
            try await body()
            throw TestError("expected a QuarantineError, but nothing was thrown (\(file):\(line))")
        } catch let error as QuarantineError {
            try TestSuite.assertTrue(check(error), "unexpected \(error) (\(file):\(line))")
        }
    }

    @MainActor
    static func expectActionError(_ expected: FileActionError, _ body: () throws -> Void,
                                  file: StaticString = #file, line: UInt = #line) throws {
        do {
            try body()
            throw TestError("expected \(expected), but nothing was thrown (\(file):\(line))")
        } catch let error as FileActionError {
            try TestSuite.assertEqual(error, expected, "", file: file, line: line)
        }
    }

    @MainActor
    static func identity(_ path: String) -> FileIdentity? {
        guard let st = M3.lstatInfo(path) else { return nil }
        return FileIdentity(device: Int64(st.st_dev), inode: UInt64(st.st_ino))
    }

    @MainActor
    static func sessionDir(_ ctx: M3.Context, _ id: UUID) -> String { ctx.quarantineRoot + "/" + id.uuidString }

    /// Rewrites one entry of a session manifest (crash simulations).
    @MainActor
    static func rewrite(_ ctx: M3.Context, session: UUID, _ change: (inout QuarantineEntry) -> Void) throws {
        let dir = sessionDir(ctx, session)
        var entries = try M3.readManifestEntries(sessionDir: dir)
        guard !entries.isEmpty else { throw TestError("no entry to rewrite") }
        change(&entries[0])
        try M3.writeManifest(sessionDir: dir, sessionID: session, createdAt: M3.wholeSeconds(ctx.env.clock.now), entries: entries)
    }

    static func auditFileName(_ date: Date) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let parts = calendar.dateComponents([.year, .month], from: date)
        return String(format: "audit-%04d-%02d.jsonl", parts.year!, parts.month!)
    }

    /// Runs `body` detached and waits (bounded) for it; `false` when it is still blocked.
    static func finishesPromptly(_ body: @escaping @Sendable () async -> Void, seconds: Double = 3) async throws -> Bool {
        let done = Flag()
        Task.detached {
            await body()
            done.set()
        }
        var waited = 0.0
        while !done.value && waited < seconds {
            try await Task.sleep(nanoseconds: 5_000_000)
            waited += 0.005
        }
        return done.value
    }

    @MainActor
    static func runAll() async {
        print("\n🛡️  Running Milestone 3 Review Regression Tests...")

        // #1 (critical)
        await TestSuite.run("Review M3 #1: Quarantine.quarantine re-runs SafetyGate — a deny-listed ~/Documents folder is refused, never moved, never purgeable") {
            try await M3.withContext { ctx in
                try ctx.fixture.file("Documents/Thesis/chapter1.docx", bytes: 512)
                let thesis = ctx.fixture.path("Documents/Thesis")
                let rule = M1.rule(id: "test.caches")
                let target = M3.target(ctx.env, rule: rule, path: thesis)
                try TestSuite.assertFalse(await ctx.gate.validate(target: target, rule: rule, phase: .execute).isAllowed)
                let session = try await ctx.quarantine.beginSession()
                try await expectQuarantineError({
                    _ = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                }) { if case .safetyRejected = $0 { return true } else { return false } }
                try TestSuite.assertTrue(M3.exists(thesis + "/chapter1.docx"), "the Documents folder was moved")
                try TestSuite.assertEqual(M3.children(sessionDir(ctx, session)), ["manifest.json"])
                await ctx.quarantine.endSession(session)
                try TestSuite.assertEqual(await ctx.quarantine.purgeAll().count, 0)
                try TestSuite.assertTrue(M3.exists(thesis + "/chapter1.docx"))

                // A rule whose action is not a removal (Trash) may not quarantine (auto-purge) either.
                let trashRule = M1.rule(id: "test.trash", tier: .red, action: .trash)
                let app = try M3.cacheItem(ctx.env, "SomeApp")
                let again = try await ctx.quarantine.beginSession()
                try await expectQuarantineError({
                    _ = try await ctx.quarantine.quarantine(target: M3.target(ctx.env, rule: trashRule, path: app), rule: trashRule,
                                                            tier: .red, sessionID: again)
                }) { $0 == .safetyRejected(.doesNotMatchRule(detail: "rule does not quarantine items")) }
                try TestSuite.assertTrue(M3.exists(app + "/payload.bin"))
            }
        }

        // #2 / #13
        await TestSuite.run("Review M3 #2/#13: RemovefileRemover and FinderTrash ask MutationPolicy themselves — refused in this no-flag build, identity required") {
            try TestSuite.assertFalse(MutationPolicy.compiledIn.isEnabled)
            try await M3.withContext { ctx in
                let victim = try M3.cacheItem(ctx.env, "Victim")
                guard let pinned = identity(victim) else { throw TestError("no identity") }
                try expectActionError(.mutationDisabled) { try RemovefileRemover().removePermanently(path: victim, expectedIdentity: pinned) }
                try expectActionError(.identityRequired) { try RemovefileRemover().removePermanently(path: victim) }
                let fixtureRemover = RemovefileRemover(mutationPolicy: ctx.policy, environment: ctx.env.environment)
                try expectActionError(.identityRequired) { try fixtureRemover.removePermanently(path: victim) }
                try expectActionError(.mutationDisabled) { _ = try FinderTrash().moveToTrash(path: victim, expectedIdentity: pinned) }
                try expectActionError(.identityRequired) { _ = try FinderTrash().moveToTrash(path: victim) }
                // A fixture policy for ANOTHER fixture refuses too.
                let other = try FixtureBuilder()
                defer { other.cleanup() }
                let foreign = RemovefileRemover(mutationPolicy: .fixtureOnly(root: other.root), environment: ctx.env.environment)
                try expectActionError(.mutationDisabled) { try foreign.removePermanently(path: victim, expectedIdentity: pinned) }
                try TestSuite.assertTrue(M3.exists(victim + "/payload.bin"), "a refused primitive removed the item")
                // With the fixture policy and the pinned identity it works.
                try fixtureRemover.removePermanently(path: victim, expectedIdentity: pinned)
                try TestSuite.assertFalse(M3.exists(victim))
            }
        }

        // #3
        await TestSuite.run("Review M3 #3: an item swapped in after the identity check is never moved into Quarantine or stranded there") {
            try await M3.withContext { ctx in
                let appCache = try M3.cacheItem(ctx.env, "com.example.App")
                try ctx.fixture.file("Documents/Secret/precious.txt", bytes: 64)
                let secret = ctx.fixture.path("Documents/Secret")
                let rule = M1.rule(id: "test.caches")
                let target = M3.target(ctx.env, rule: rule, path: appCache)

                let hooked = HookingProbe(base: ctx.env.fileSystem)
                let environment = M3.environment(ctx.env, fileSystem: hooked)
                let gate = SafetyGate(environment: environment, userExclusions: [], ageThresholdOverrides: [:],
                                      waivedSystemRoots: [ctx.fixture.root])
                let quarantine = Quarantine(environment: environment, gate: gate, mutationPolicy: ctx.policy)
                let session = try await quarantine.beginSession()
                // Fires on the probe's stat of the session folder, i.e. after SafetyGate and the probe's
                // own identity check: the app cache is renamed aside and ~/Documents/Secret put in its place.
                hooked.onStat(quarantine.rootPath + "/" + session.uuidString) {
                    _ = Darwin.rename(appCache, appCache + "-aside")
                    _ = Darwin.rename(secret, appCache)
                }
                try await expectQuarantineError({
                    _ = try await quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                }) { $0 == .safetyRejected(.changedSinceScan) }
                try TestSuite.assertTrue(hooked.firedCount == 1, "the swap hook did not run")
                try TestSuite.assertTrue(M3.exists(appCache + "/precious.txt"), "the swapped-in folder left its location")
                try TestSuite.assertTrue(M3.exists(appCache + "-aside/payload.bin"))
                try TestSuite.assertEqual(M3.children(sessionDir(ctx, session)), ["manifest.json"], "something was stranded")
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: sessionDir(ctx, session)), [])
                try TestSuite.assertEqual(try await quarantine.reconcile().count, 0)
            }
        }

        await TestSuite.run("Review M3 #3: a symlinked ancestor of the item is refused (the move is made relative to an O_NOFOLLOW parent)") {
            try await M3.withContext { ctx in
                let elsewhere = try ctx.fixture.dir("elsewhere", base: .root)
                try ctx.fixture.file("elsewhere/Item/payload.bin", contents: Data("keep".utf8), base: .root)
                try ctx.fixture.symlink("Library/Caches/Link", to: elsewhere)
                let path = ctx.fixture.path("Library/Caches/Link/Item")
                let rule = M1.rule(id: "test.caches", minDepth: 2)
                let target = ScanTarget(ruleID: rule.id, path: path, displayName: "Item", identity: identity(path),
                                        allocatedBytes: 4, reclaimableBytes: 4, itemCount: 1, lastUsed: nil)
                let session = try await ctx.quarantine.beginSession()
                try await expectQuarantineError({
                    _ = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                }) { if case .safetyRejected = $0 { return true } else { return false } }
                try TestSuite.assertTrue(M3.exists(elsewhere + "/Item/payload.bin"))
                // The permanent-removal primitive refuses the same shape.
                let remover = RemovefileRemover(mutationPolicy: ctx.policy, environment: ctx.env.environment)
                try expectActionError(.changedSinceScan) { try remover.removePermanently(path: path, expectedIdentity: target.identity!) }
                try TestSuite.assertTrue(M3.exists(elsewhere + "/Item/payload.bin"), "removefile followed the symlinked parent")
            }
        }

        // #4
        await TestSuite.run("Review M3 #4: a ConfirmedPlan is single-use — replaying it after a restore acts on nothing (same or new Executor)") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let path = try M3.cacheItem(ctx.env, "Replay")
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [M3.target(ctx.env, rule: rule, path: path)])])
                let executor = ctx.executor(remover: RefusingRemover())
                let first = try await M3.run(executor, confirmed)
                guard case .quarantined = first.report.outcomes[0].status, let session = first.report.quarantineSessionID else {
                    throw TestError("\(first.report.outcomes)")
                }
                let restored = await ctx.quarantine.restoreSession(session)
                try TestSuite.assertEqual(try restored.map { try $0.get().status }, [.restored])
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))

                let expected = ItemStatus.skipped(.doesNotMatchRule(detail: Executor.alreadyExecutedDetail))
                for (label, replayExecutor) in [("same executor", executor), ("new executor", ctx.executor(remover: RefusingRemover()))] {
                    let replay = try await M3.run(replayExecutor, confirmed)
                    try TestSuite.assertEqual(replay.report.outcomes.map(\.status), [expected], label)
                    try TestSuite.assertEqual(replay.report.estimatedReclaimBytes, 0, label)
                    try TestSuite.assertTrue(M3.exists(path + "/payload.bin"), "replay acted on the restored item (\(label))")
                }
                // Let the detached audit writes land, then check them.
                try await Task.sleep(nanoseconds: 50_000_000)
                let refused = try M3.auditEvents(ctx).filter { $0.action == "run.refused" }
                try TestSuite.assertEqual(refused.count, 2)
                // A freshly confirmed plan for the same item works.
                let fresh = try await M3.confirmedPlan(ctx, [(rule, [M3.target(ctx.env, rule: rule, path: path)])])
                guard case .quarantined = try await M3.run(executor, fresh).report.outcomes[0].status else {
                    throw TestError("a new confirmation was refused")
                }
            }
        }

        // #5
        await TestSuite.run("Review M3 #5: trash / permanent delete act only on the pinned item — a swapped item is refused, a mismatching Trash result is a failure") {
            try await M3.withContext { ctx in
                // Permanent removal: the item was replaced after the Executor's last check.
                let path = try M3.cacheItem(ctx.env, "Pinned")
                guard let pinned = identity(path) else { throw TestError("no identity") }
                try FileManager.default.moveItem(atPath: path, toPath: path + "-old")
                try ctx.fixture.file("Library/Caches/Pinned/new.bin", bytes: 8)
                let remover = RemovefileRemover(mutationPolicy: ctx.policy, environment: ctx.env.environment)
                try expectActionError(.changedSinceScan) { try remover.removePermanently(path: path, expectedIdentity: pinned) }
                try TestSuite.assertTrue(M3.exists(path + "/new.bin") && M3.exists(path + "-old/payload.bin"))

                // Trash: whatever the Trash reports must be the pinned item.
                let red = M1.rule(id: "test.red", tier: .red, action: .trash)
                let item = try M3.cacheItem(ctx.env, "OldApp")
                let decoy = try ctx.fixture.file("FakeTrash/decoy", bytes: 1, base: .root)
                let confirmed = try await M3.confirmedPlan(ctx, [(red, [M3.target(ctx.env, rule: red, path: item)])])
                let lying = LyingTrash(inner: ctx.trash, reportedPath: decoy)
                let run = try await M3.run(ctx.executor(remover: RefusingRemover(), trash: lying), confirmed)
                guard case .failed(.safetyRejected, let message) = run.report.outcomes[0].status else {
                    throw TestError("expected a failure, got \(run.report.outcomes[0].status)")
                }
                try TestSuite.assertTrue(message.contains("left in the Trash"), message)
                try TestSuite.assertEqual(run.report.estimatedReclaimBytes, 0)
            }
        }

        // #6
        await TestSuite.run("Review M3 #6: \"Always quarantine\" ON (default) blocks permanent deletion at plan time; plan and caller setting must both be OFF") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "trash.empty", tier: .yellow, action: .permanentDelete)
                let target = M3.target(ctx.env, rule: rule, path: try M3.cacheItem(ctx.env, "TrashItem"))
                let plan = await M3.plan(ctx, [(rule, [target])])
                try TestSuite.assertTrue(plan.alwaysQuarantine)
                try TestSuite.assertFalse(plan.items[0].isActionable)
                try TestSuite.assertEqual(plan.items[0].planVerdict, .rejected(PlanBuilder.alwaysQuarantineRejection))
                try TestSuite.assertTrue(plan.items[0].skipReason?.contains("Always quarantine") == true)
                do {
                    _ = try M3.confirmAll(plan, irreversible: true, alwaysQuarantine: false)
                    throw TestError("confirmed a permanent delete built with Always quarantine ON")
                } catch let error as ConfirmationError {
                    try TestSuite.assertEqual(error, .emptySelection) // nothing actionable
                }
                do {
                    _ = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [target.id],
                                                  confirmation: M3.confirmation(irreversible: true), alwaysQuarantine: false)
                    throw TestError("confirmed a blocked item")
                } catch let error as ConfirmationError {
                    try TestSuite.assertEqual(error, .notActionable(target.id))
                }

                // A plan recording Always quarantine ON refuses even when the caller passes OFF.
                let item = PlanItem.makeForTesting(target: target, rule: rule, effectiveTier: .yellow, action: .permanentDelete,
                                                   planVerdict: .allowed)
                let recorded = CleanupPlan.makeForTesting(createdAt: ctx.env.clock.now, items: [item], alwaysQuarantine: true)
                do {
                    _ = try ConfirmedPlan.confirm(plan: recorded, selectedItemIDs: [target.id],
                                                  confirmation: M3.confirmation(irreversible: true), alwaysQuarantine: false)
                    throw TestError("plan setting ignored")
                } catch let error as ConfirmationError {
                    try TestSuite.assertEqual(error, .permanentDeleteBlockedByAlwaysQuarantine(target.id))
                }
                // OFF in Settings: offered (not preselected) and confirmable once acknowledged. Review M6: the
                // persisted setting still ON blocks it whatever the caller passes.
                let stillOn = await M3.plan(ctx, [(rule, [target])], settings: PlanSettings(alwaysQuarantine: false))
                try TestSuite.assertEqual(stillOn.items[0].planVerdict, .rejected(PlanBuilder.alwaysQuarantineRejection))
                ctx.env.scanSettings.alwaysQuarantine = false
                let off = await M3.plan(ctx, [(rule, [target])], settings: PlanSettings(alwaysQuarantine: false))
                try TestSuite.assertFalse(off.alwaysQuarantine)
                try TestSuite.assertTrue(off.items[0].isActionable)
                try TestSuite.assertFalse(off.items[0].selectedByDefault)
                _ = try M3.confirmAll(off, irreversible: true, alwaysQuarantine: false)
                try TestSuite.assertTrue(M3.exists(target.path + "/payload.bin"))
            }
        }

        // #7
        await TestSuite.run("Review M3 #7: reconcile keeps a pending entry whose item reached Quarantine even after the app rebuilt its cache at the origin") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let session = try await ctx.quarantine.beginSession()
                let dir = sessionDir(ctx, session)
                let path = try M3.cacheItem(ctx.env, "com.example.Regen")
                let target = M3.target(ctx.env, rule: rule, path: path)
                let now = M3.wholeSeconds(ctx.env.clock.now)
                let id = UUID()
                let entry = QuarantineEntry(id: id, sessionID: session, originalPath: path,
                                            quarantinedName: id.uuidString + "/com.example.Regen", identity: target.identity!,
                                            allocatedBytes: 4_096, reclaimableBytes: 4_096, ruleID: rule.id, tier: .green,
                                            quarantinedAt: now, expiresAt: now.addingTimeInterval(86_400), status: .pending)
                try M3.writeManifest(sessionDir: dir, sessionID: session, createdAt: now, entries: [entry])
                await ctx.quarantine.endSession(session) // the crashed run is over
                try FileManager.default.createDirectory(atPath: dir + "/" + id.uuidString, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                try TestSuite.assertEqual(Darwin.rename(path, dir + "/" + entry.quarantinedName), 0)
                try ctx.fixture.file("Library/Caches/com.example.Regen/new.bin", bytes: 16) // the app rebuilt its cache

                let events = try await ctx.quarantine.reconcile()
                try TestSuite.assertEqual(events.map(\.kind), [.markedMoved])
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: dir).map(\.status), [.moved])
                let restored = try await ctx.quarantine.restore(entryID: id)
                try TestSuite.assertTrue(restored.restoredPath?.hasPrefix(path + " (restored ") == true, "\(String(describing: restored.restoredPath))")
                try TestSuite.assertTrue(M3.exists(restored.restoredPath! + "/payload.bin"))
                try TestSuite.assertTrue(M3.exists(path + "/new.bin"), "the rebuilt cache was overwritten")

                // Something else in the entry folder: kept for review, never dropped and never purged.
                let other = try await ctx.quarantine.beginSession()
                let otherDir = sessionDir(ctx, other)
                let item = try M3.cacheItem(ctx.env, "Foreign")
                let otherID = UUID()
                let pending = QuarantineEntry(id: otherID, sessionID: other, originalPath: ctx.fixture.path("Library/Caches/Gone"),
                                              quarantinedName: otherID.uuidString + "/Foreign",
                                              identity: FileIdentity(device: 1, inode: 1), allocatedBytes: 1, reclaimableBytes: 1,
                                              ruleID: rule.id, tier: .green, quarantinedAt: now, expiresAt: now, status: .pending)
                try M3.writeManifest(sessionDir: otherDir, sessionID: other, createdAt: now, entries: [pending])
                await ctx.quarantine.endSession(other)
                try FileManager.default.createDirectory(atPath: otherDir + "/" + otherID.uuidString, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                try TestSuite.assertEqual(Darwin.rename(item, otherDir + "/" + pending.quarantinedName), 0)
                // restoreSession reports a pending entry instead of silently skipping it.
                let early = await ctx.quarantine.restoreSession(other)
                try TestSuite.assertEqual(early.count, 1)
                guard case .failure = early[0] else { throw TestError("a pending entry was restored: \(early)") }
                let flagged = try await ctx.quarantine.reconcile()
                try TestSuite.assertEqual(flagged.map(\.kind), [.flaggedForReview])
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: otherDir).map(\.status), [.needsReview])
                ctx.env.clock.advance(days: 30)
                try TestSuite.assertEqual(await ctx.quarantine.purgeAll().filter { $0.entry.id == otherID }.count, 0)
                try TestSuite.assertTrue(M3.exists(otherDir + "/" + pending.quarantinedName + "/payload.bin"))
                try TestSuite.assertEqual(try await ctx.quarantine.sessions().first { $0.id == other }?.entries.map(\.status), [.needsReview])
            }
        }

        // #8
        await TestSuite.run("Review M3 #8: a purge that fails half-way is recorded (.purging): never 'restored', retried until complete") {
            try await M3.withContext { ctx in
                try ctx.fixture.file("Library/Caches/RO/z.bin", bytes: 64)
                try ctx.fixture.file("Library/Caches/RO/sub/a.bin", bytes: 64)
                let (entry, _) = try await QuarantineTests.quarantineOne(ctx, "RO")
                let item = QuarantineTests.quarantinedPath(ctx, entry)
                try TestSuite.assertEqual(Darwin.chmod(item + "/sub", 0o555), 0)
                defer { _ = Darwin.chmod(item + "/sub", 0o755) }

                let first = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(first.count, 1)
                guard case .incomplete = first[0].status else { throw TestError("expected .incomplete, got \(first[0].status)") }
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: sessionDir(ctx, entry.sessionID)).map(\.status), [.purging])
                try await expectQuarantineError({ _ = try await ctx.quarantine.restore(entryID: entry.id) }) {
                    if case .io(let message) = $0 { return message.contains("partly purged") } else { return false }
                }
                try TestSuite.assertTrue(M3.exists(item + "/sub/a.bin"), "restore moved a partly purged item")
                // Retried by both purges (even before its retention ends) once removal can succeed.
                try TestSuite.assertEqual(Darwin.chmod(item + "/sub", 0o755), 0)
                let second = await ctx.quarantine.purgeExpired()
                try TestSuite.assertEqual(second.map(\.status), [.purged])
                try TestSuite.assertFalse(M3.exists(item))
                try TestSuite.assertFalse(M3.exists(sessionDir(ctx, entry.sessionID)), "finished session left behind")
            }
        }

        // #9
        await TestSuite.run("Review M3 #9: a non-positive or mismatching retention is refused (no immediate, unconfirmed purge)") {
            try await M3.withContext { ctx in
                let rule = Rule(id: "test.negative", category: .apps, tier: .green, title: "Negative retention", explanation: "test",
                                whatYouLose: "nothing", howItRegenerates: "automatically",
                                discovery: .glob(["{HOME}/Library/Caches/*"]), allowRoots: ["{HOME}/Library/Caches"],
                                action: .quarantine, retentionHours: -5)
                let path = try M3.cacheItem(ctx.env, "Negative")
                let session = try await ctx.quarantine.beginSession()
                try await expectQuarantineError({
                    _ = try await ctx.quarantine.quarantine(target: M3.target(ctx.env, rule: rule, path: path), rule: rule, tier: .green,
                                                            sessionID: session)
                }) { $0 == .safetyRejected(.doesNotMatchRule(detail: "invalid quarantine retention")) }
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))

                // The Executor passes the confirmed (hashed) retention; it must equal the rule's.
                let green = M1.rule(id: "test.caches")
                let other = try M3.cacheItem(ctx.env, "ShortRetention")
                let target = M3.target(ctx.env, rule: green, path: other)
                let item = PlanItem.makeForTesting(target: target, rule: green, effectiveTier: .green,
                                                   action: .quarantine(retentionHours: 1), planVerdict: .allowed)
                let plan = CleanupPlan.makeForTesting(createdAt: ctx.env.clock.now, items: [item])
                let confirmed = try ConfirmedPlan.confirm(plan: plan, selectedItemIDs: [target.id], confirmation: M3.confirmation(),
                                                          alwaysQuarantine: true)
                let run = try await M3.run(ctx.executor(remover: RefusingRemover()), confirmed)
                try TestSuite.assertEqual(run.report.outcomes.map(\.status),
                                          [.skipped(.doesNotMatchRule(detail: "quarantine retention does not match the rule"))])
                try TestSuite.assertTrue(M3.exists(other + "/payload.bin"))
            }
        }

        // #10
        await TestSuite.run("Review M3 #10: restore / purge across launches match inode + recorded volume UUID, not the per-mount st_dev") {
            try await M3.withContext { ctx in
                let (entry, path) = try await QuarantineTests.quarantineOne(ctx, "Remounted")
                try TestSuite.assertTrue(entry.volumeUUID != nil, "no volume UUID recorded")
                // Same volume, mounted again with another device number.
                try rewrite(ctx, session: entry.sessionID) {
                    $0 = QuarantineEntry(id: $0.id, sessionID: $0.sessionID, originalPath: $0.originalPath,
                                         quarantinedName: $0.quarantinedName,
                                         identity: FileIdentity(device: $0.identity.device &+ 1_000, inode: $0.identity.inode),
                                         allocatedBytes: $0.allocatedBytes, reclaimableBytes: $0.reclaimableBytes, ruleID: $0.ruleID,
                                         tier: $0.tier, quarantinedAt: $0.quarantinedAt, expiresAt: $0.expiresAt, status: $0.status,
                                         volumeUUID: $0.volumeUUID)
                }
                let restored = try await ctx.quarantine.restore(entryID: entry.id)
                try TestSuite.assertEqual(restored.restoredPath, path)
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))

                // A different volume (UUID) with the same inode number is not the pinned item.
                let (second, _) = try await QuarantineTests.quarantineOne(ctx, "OtherVolume")
                try rewrite(ctx, session: second.sessionID) { $0.volumeUUID = "00000000-0000-0000-0000-000000000000" }
                try await expectQuarantineError({ _ = try await ctx.quarantine.restore(entryID: second.id) }) {
                    $0 == .safetyRejected(.changedSinceScan)
                }
                let refused = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(refused.map(\.status), [.rejected(.changedSinceScan)])

                // The same volume with a new device number purges normally.
                let (third, _) = try await QuarantineTests.quarantineOne(ctx, "PurgeRemounted")
                try rewrite(ctx, session: third.sessionID) {
                    $0 = QuarantineEntry(id: $0.id, sessionID: $0.sessionID, originalPath: $0.originalPath,
                                         quarantinedName: $0.quarantinedName,
                                         identity: FileIdentity(device: $0.identity.device &+ 7, inode: $0.identity.inode),
                                         allocatedBytes: $0.allocatedBytes, reclaimableBytes: $0.reclaimableBytes, ruleID: $0.ruleID,
                                         tier: $0.tier, quarantinedAt: $0.quarantinedAt, expiresAt: $0.expiresAt, status: $0.status,
                                         volumeUUID: $0.volumeUUID)
                }
                let outcomes = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(outcomes.first { $0.entry.id == third.id }?.status, .purged)
                try TestSuite.assertFalse(M3.exists(QuarantineTests.quarantinedPath(ctx, third)))
            }
        }

        // #11
        await TestSuite.run("Review M3 #11: an interrupted restore (.restoring, or .moved with the item back home) is reconciled to .restored") {
            try await M3.withContext { ctx in
                // Crash after the move back, before the manifest said .restored.
                let (entry, path) = try await QuarantineTests.quarantineOne(ctx, "Interrupted")
                try TestSuite.assertEqual(Darwin.rename(QuarantineTests.quarantinedPath(ctx, entry), path), 0)
                try rewrite(ctx, session: entry.sessionID) { $0.status = .restoring; $0.restoredPath = path }
                try TestSuite.assertEqual(try await ctx.quarantine.reconcile().map(\.kind), [.markedRestored])
                try TestSuite.assertFalse(M3.exists(sessionDir(ctx, entry.sessionID)), "finished session left behind")
                try TestSuite.assertEqual(await ctx.quarantine.purgeAll().count, 0)
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))

                // Old-style crash: still .moved, item already back at its origin.
                let (moved, movedPath) = try await QuarantineTests.quarantineOne(ctx, "StaleMoved")
                try TestSuite.assertEqual(Darwin.rename(QuarantineTests.quarantinedPath(ctx, moved), movedPath), 0)
                try TestSuite.assertEqual(try await ctx.quarantine.reconcile().map(\.kind), [.markedRestored])
                try TestSuite.assertEqual(await ctx.quarantine.purgeAll().count, 0)

                // Crash before the move back: still in Quarantine → .moved again, restorable.
                let (pending, pendingPath) = try await QuarantineTests.quarantineOne(ctx, "NotYetBack")
                try rewrite(ctx, session: pending.sessionID) { $0.status = .restoring; $0.restoredPath = pendingPath }
                try await expectQuarantineError({ _ = try await ctx.quarantine.restore(entryID: pending.id) }) {
                    if case .io = $0 { return true } else { return false }
                }
                try TestSuite.assertEqual(try await ctx.quarantine.reconcile().map(\.kind), [.revertedToMoved])
                let restored = try await ctx.quarantine.restore(entryID: pending.id)
                try TestSuite.assertEqual(restored.restoredPath, pendingPath)
                try TestSuite.assertTrue(M3.exists(pendingPath + "/payload.bin"))
            }
        }

        // #12
        await TestSuite.run("Review M3 #12: an existing Quarantine root with a loose mode (0755) is tightened to 0700") {
            try await M3.withContext { ctx in
                try ctx.fixture.dir("Library/Application Support/iMop/Quarantine")
                try TestSuite.assertEqual(Darwin.chmod(ctx.quarantineRoot, 0o755), 0)
                try TestSuite.assertEqual(Darwin.chmod(ctx.fixture.path("Library/Application Support/iMop"), 0o755), 0)
                // A dry-run Quarantine may not fix it, so it refuses to use the root.
                let dry = Quarantine(environment: ctx.env.environment, gate: ctx.gate)
                do {
                    _ = try await dry.sessions()
                    throw TestError("a dry run used a world-readable Quarantine root")
                } catch is QuarantineError {}
                try TestSuite.assertEqual(M3.permissions(ctx.quarantineRoot), 0o755)
                _ = try await ctx.quarantine.beginSession()
                try TestSuite.assertEqual(M3.permissions(ctx.quarantineRoot), 0o700)
            }
        }

        // #14
        await TestSuite.run("Review M3 #14: a FIFO at the audit log name never blocks record (counted as a failed write); export skips FIFOs and hard links") {
            try await M3.withContext { ctx in
                try ctx.fixture.dir("Library/Logs/iMop")
                _ = Darwin.chmod(ctx.logDirectory, 0o700)
                let current = ctx.logDirectory + "/" + auditFileName(ctx.env.clock.now)
                try TestSuite.assertEqual(Darwin.mkfifo(current, 0o600), 0)
                let audit = ctx.audit
                let now = ctx.env.clock.now
                let recorded = try await finishesPromptly {
                    await audit.record(AuditEvent(timestamp: now, action: "probe", verdict: "x"))
                }
                try TestSuite.assertTrue(recorded, "record blocked on a FIFO at the log path")
                try TestSuite.assertEqual(await ctx.audit.failedWrites, 1)

                // Export: an older month that is a hard link to another file, and a FIFO, are skipped.
                try TestSuite.assertEqual(Darwin.unlink(current), 0)
                await ctx.audit.record(AuditEvent(timestamp: now, action: "real.event", verdict: "ok"))
                let secret = try ctx.fixture.file("secret.txt", contents: Data("SECRET-NOT-A-LOG\n".utf8), base: .root)
                try TestSuite.assertEqual(Darwin.link(secret, ctx.logDirectory + "/audit-2000-01.jsonl"), 0)
                try TestSuite.assertEqual(Darwin.mkfifo(ctx.logDirectory + "/audit-2000-02.jsonl", 0o600), 0)
                let destination = URL(fileURLWithPath: ctx.fixture.path("export.jsonl", base: .root))
                let exported = try await finishesPromptly { try? await audit.export(to: destination) }
                try TestSuite.assertTrue(exported, "export blocked on a FIFO")
                let text = try String(contentsOf: destination, encoding: .utf8)
                try TestSuite.assertTrue(text.contains("real.event"), text)
                try TestSuite.assertFalse(text.contains("SECRET-NOT-A-LOG"), "a hard-linked file was exported")
            }
        }

        // #15
        await TestSuite.run("Review M3 #15: emptying the Quarantine between two items of a run never tears down the run's session") {
            try await M3.withContext { ctx in
                let session = try await ctx.quarantine.beginSession()
                let (first, _) = try await QuarantineTests.quarantineOne(ctx, "RunItem1", session: session)
                let purged = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(purged.map(\.entry.id), [first.id])
                try TestSuite.assertTrue(M3.exists(sessionDir(ctx, session)), "the active session was removed")
                let (second, _) = try await QuarantineTests.quarantineOne(ctx, "RunItem2", session: session)
                try TestSuite.assertEqual(second.status, .moved)
                let restored = await ctx.quarantine.restoreSession(session)
                try TestSuite.assertEqual(try restored.map { try $0.get().status }, [.restored])
                try TestSuite.assertTrue(M3.exists(sessionDir(ctx, session)), "the active session was removed by a restore")
                let (third, _) = try await QuarantineTests.quarantineOne(ctx, "RunItem3", session: session)
                try TestSuite.assertEqual(third.status, .moved)
                // The run ends: from now on the session is cleaned up once finished.
                await ctx.quarantine.endSession(session)
                try TestSuite.assertTrue(M3.exists(sessionDir(ctx, session)))
                _ = await ctx.quarantine.purgeAll()
                try TestSuite.assertFalse(M3.exists(sessionDir(ctx, session)))
            }
        }
    }
}

// MARK: - Fakes

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return _value }
    func set() { lock.lock(); _value = true; lock.unlock() }
}

/// A probe that runs a one-shot hook when `stat` is called for one path (race simulation).
final class HookingProbe: FileSystemProbe, @unchecked Sendable {
    let base: any FileSystemProbe
    private let lock = NSLock()
    private var hooks: [String: @Sendable () -> Void] = [:]
    private var fired = 0

    init(base: any FileSystemProbe) { self.base = base }

    var firedCount: Int { lock.lock(); defer { lock.unlock() }; return fired }

    func onStat(_ path: String, _ hook: @escaping @Sendable () -> Void) {
        lock.lock(); hooks[path] = hook; lock.unlock()
    }

    private func take(_ path: String) -> (@Sendable () -> Void)? {
        lock.lock(); defer { lock.unlock() }
        guard let hook = hooks.removeValue(forKey: path) else { return nil }
        fired += 1
        return hook
    }

    func lstat(_ path: String) -> FileStat? { base.lstat(path) }
    func stat(_ path: String) -> FileStat? {
        take(path)?()
        return base.stat(path)
    }
    func realpath(_ path: String) -> String? { base.realpath(path) }
    func canonicalPath(_ path: String) -> String? { base.canonicalPath(path) }
    func contentsOfDirectory(_ path: String) -> [String]? { base.contentsOfDirectory(path) }
    func extendedAttributeNames(_ path: String) -> [String]? { base.extendedAttributeNames(path) }
    func isUbiquitousItem(_ path: String) -> Bool? { base.isUbiquitousItem(path) }
    func readFile(_ path: String) -> Data? { base.readFile(path) }
}

/// Moves the item into the fixture trash but reports another path as the result.
struct LyingTrash: TrashMoving {
    let inner: FixtureTrash
    let reportedPath: String

    func moveToTrash(path: String) throws -> String {
        _ = try inner.moveToTrash(path: path)
        return reportedPath
    }

    func moveToTrash(path: String, expectedIdentity: FileIdentity) throws -> String {
        try moveToTrash(path: path)
    }
}
