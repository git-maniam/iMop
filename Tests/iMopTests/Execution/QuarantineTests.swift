import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §5.1 / §11: Quarantine move, restore, purge and crash reconciliation (fixture policy only).
struct QuarantineTests {
    /// Quarantines one fresh cache folder through the Quarantine API directly.
    @MainActor
    static func quarantineOne(_ ctx: M3.Context, _ name: String, rule: Rule = M1.rule(id: "test.caches"),
                              tier: Tier? = nil, session: UUID? = nil) async throws -> (QuarantineEntry, String) {
        let path = try M3.cacheItem(ctx.env, name)
        let target = M3.target(ctx.env, rule: rule, path: path)
        let sessionID: UUID
        if let session { sessionID = session } else { sessionID = try await ctx.quarantine.beginSession() }
        let entry = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: tier ?? rule.tier, sessionID: sessionID)
        // A session begun here is finished (as the Executor does at the end of its run).
        if session == nil { await ctx.quarantine.endSession(sessionID) }
        return (entry, path)
    }

    static func quarantinedPath(_ ctx: M3.Context, _ entry: QuarantineEntry) -> String {
        ctx.quarantineRoot + "/" + entry.sessionID.uuidString + "/" + entry.quarantinedName
    }

    @MainActor
    static func expectError(_ expected: QuarantineError, _ body: () async throws -> Void,
                            file: StaticString = #file, line: UInt = #line) async throws {
        do {
            try await body()
            throw TestError("expected \(expected), but nothing was thrown (\(file):\(line))")
        } catch let error as QuarantineError {
            try TestSuite.assertEqual(error, expected, "", file: file, line: line)
        }
    }

    @MainActor
    static func runAll() async {
        print("\n📦 Running Quarantine Tests (spec §5.1, §11)...")

        await TestSuite.run("Quarantine: move with renamex_np — item gone from origin, same inode in session, manifest .moved, 0700 dirs, .metadata_never_index") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let path = try M3.cacheItem(ctx.env, "com.example.Moved", bytes: 8_192)
                let inode = M3.inode(path)
                let target = M3.target(ctx.env, rule: rule, path: path, bytes: 8_192)
                let session = try await ctx.quarantine.beginSession()
                let sessionDir = ctx.quarantineRoot + "/" + session.uuidString
                try TestSuite.assertTrue(M3.exists(ctx.quarantineRoot + "/.metadata_never_index"), ".metadata_never_index missing")
                try TestSuite.assertEqual(M3.permissions(ctx.quarantineRoot), 0o700)
                try TestSuite.assertEqual(M3.permissions(sessionDir), 0o700)
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: sessionDir), [])

                let entry = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                try TestSuite.assertEqual(entry.status, .moved)
                try TestSuite.assertEqual(entry.originalPath, path)
                try TestSuite.assertEqual(entry.ruleID, rule.id)
                try TestSuite.assertEqual(entry.tier, .green)
                try TestSuite.assertEqual(entry.identity, target.identity!)
                try TestSuite.assertEqual(entry.reclaimableBytes, 8_192)
                try TestSuite.assertEqual(entry.expiresAt.timeIntervalSince(entry.quarantinedAt), 24 * 3600)
                try TestSuite.assertEqual(entry.quarantinedName, entry.id.uuidString + "/com.example.Moved")
                try TestSuite.assertFalse(M3.exists(path), "original still present")
                let moved = quarantinedPath(ctx, entry)
                try TestSuite.assertEqual(M3.inode(moved), inode, "moved, not copied")
                try TestSuite.assertTrue(M3.exists(moved + "/payload.bin"))
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: sessionDir), [entry])
                let sessions = try await ctx.quarantine.sessions()
                try TestSuite.assertEqual(sessions.map(\.id), [session])
                try TestSuite.assertEqual(sessions[0].entries, [entry])
                // No temp manifest files left behind.
                try TestSuite.assertEqual(M3.children(sessionDir), [entry.id.uuidString, "manifest.json"])
                try TestSuite.assertEqual(Quarantine.spaceNotice,
                                          "Space from quarantined items is freed when quarantine is emptied. Empty now to reclaim immediately.")
            }
        }

        await TestSuite.run("Quarantine: restore without conflict puts the same item back and removes the empty session") {
            try await M3.withContext { ctx in
                let (entry, path) = try await quarantineOne(ctx, "RestoreMe")
                let inode = M3.inode(quarantinedPath(ctx, entry))
                let restored = try await ctx.quarantine.restore(entryID: entry.id)
                try TestSuite.assertEqual(restored.status, .restored)
                try TestSuite.assertEqual(restored.restoredPath, path)
                try TestSuite.assertEqual(M3.inode(path), inode)
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
                try TestSuite.assertFalse(M3.exists(quarantinedPath(ctx, entry)))
                try TestSuite.assertFalse(M3.exists(ctx.quarantineRoot + "/" + entry.sessionID.uuidString),
                                          "finished session folder should be removed")
            }
        }

        await TestSuite.run("Quarantine: restore with conflict → '<name> (restored yyyy-MM-dd HH.mm.ss)' beside it, never overwrites") {
            try await M3.withContext { ctx in
                let (entry, path) = try await quarantineOne(ctx, "Conflict")
                // The app recreated its cache in the meantime.
                try ctx.fixture.file("Library/Caches/Conflict/new.bin", bytes: 10)
                let newInode = M3.inode(path)
                let restored = try await ctx.quarantine.restore(entryID: entry.id)
                let formatter = DateFormatter()
                formatter.locale = Locale(identifier: "en_US_POSIX")
                formatter.timeZone = TimeZone.current
                formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
                let expected = path + " (restored \(formatter.string(from: ctx.env.clock.now)))"
                try TestSuite.assertEqual(restored.restoredPath, expected)
                try TestSuite.assertTrue(M3.exists(expected + "/payload.bin"))
                try TestSuite.assertEqual(M3.inode(path), newInode, "the new item was replaced")
                try TestSuite.assertTrue(M3.exists(path + "/new.bin"))
                try TestSuite.assertFalse(M3.exists(path + "/payload.bin"))
            }
        }

        await TestSuite.run("Quarantine: restore refuses when the original parent folder is gone — item stays in Quarantine") {
            try await M3.withContext { ctx in
                try ctx.fixture.file("Library/Caches/Parent/Child/payload.bin", bytes: 100)
                let rule = M1.rule(id: "test.caches", minDepth: 2)
                let path = ctx.fixture.path("Library/Caches/Parent/Child")
                let target = M3.target(ctx.env, rule: rule, path: path)
                let session = try await ctx.quarantine.beginSession()
                let entry = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                try FileManager.default.removeItem(atPath: ctx.fixture.path("Library/Caches/Parent"))
                try await expectError(.originalParentMissing) { _ = try await ctx.quarantine.restore(entryID: entry.id) }
                try TestSuite.assertTrue(M3.exists(quarantinedPath(ctx, entry) + "/payload.bin"), "item left Quarantine")
                try TestSuite.assertFalse(M3.exists(ctx.fixture.path("Library/Caches/Parent")), "parent was recreated")
                let entries = try M3.readManifestEntries(sessionDir: ctx.quarantineRoot + "/" + session.uuidString)
                try TestSuite.assertEqual(entries.map(\.status), [.moved])
            }
        }

        await TestSuite.run("Quarantine: restoreSession restores every moved item of the session") {
            try await M3.withContext { ctx in
                let session = try await ctx.quarantine.beginSession()
                let (a, pathA) = try await quarantineOne(ctx, "SessA", session: session)
                let (b, pathB) = try await quarantineOne(ctx, "SessB", session: session)
                await ctx.quarantine.endSession(session)
                let results = await ctx.quarantine.restoreSession(session)
                try TestSuite.assertEqual(results.count, 2)
                let restored = try results.map { try $0.get() }
                try TestSuite.assertEqual(Set(restored.map(\.id)), [a.id, b.id])
                try TestSuite.assertTrue(restored.allSatisfy { $0.status == .restored })
                try TestSuite.assertTrue(M3.exists(pathA + "/payload.bin") && M3.exists(pathB + "/payload.bin"))
                try TestSuite.assertFalse(M3.exists(ctx.quarantineRoot + "/" + session.uuidString))
            }
        }

        await TestSuite.run("Quarantine: purgeExpired respects retention via FixedClock (Green 24 h, Yellow 7 d)") {
            try await M3.withContext { ctx in
                let session = try await ctx.quarantine.beginSession()
                let (green, _) = try await quarantineOne(ctx, "GreenItem", rule: M1.rule(id: "test.green"), session: session)
                let (yellow, _) = try await quarantineOne(ctx, "YellowItem", rule: M1.rule(id: "test.yellow", tier: .yellow),
                                                          session: session)
                try TestSuite.assertEqual(yellow.expiresAt.timeIntervalSince(yellow.quarantinedAt), 7 * 24 * 3600)
                await ctx.quarantine.endSession(session)

                ctx.env.clock.advance(days: 0.5)
                try TestSuite.assertEqual(await ctx.quarantine.purgeExpired().count, 0, "nothing is due after 12 h")
                try TestSuite.assertTrue(M3.exists(quarantinedPath(ctx, green)))

                ctx.env.clock.advance(days: 1)
                let first = await ctx.quarantine.purgeExpired()
                try TestSuite.assertEqual(first.map(\.entry.id), [green.id])
                try TestSuite.assertEqual(first.map(\.status), [.purged])
                try TestSuite.assertEqual(first[0].freedBytes, green.reclaimableBytes)
                try TestSuite.assertFalse(M3.exists(quarantinedPath(ctx, green)), "green item not purged")
                try TestSuite.assertTrue(M3.exists(quarantinedPath(ctx, yellow) + "/payload.bin"), "yellow item purged too early")

                ctx.env.clock.advance(days: 6)
                let second = await ctx.quarantine.purgeExpired()
                try TestSuite.assertEqual(second.map(\.entry.id), [yellow.id])
                try TestSuite.assertEqual(second.map(\.status), [.purged])
                try TestSuite.assertFalse(M3.exists(quarantinedPath(ctx, yellow)))
                try TestSuite.assertFalse(M3.exists(ctx.quarantineRoot + "/" + session.uuidString), "empty session folder left behind")
                try TestSuite.assertTrue(M3.exists(ctx.quarantineRoot + "/.metadata_never_index"))
            }
        }

        await TestSuite.run("Quarantine: purgeAll (Empty Quarantine Now) removes everything regardless of retention") {
            try await M3.withContext { ctx in
                let (a, _) = try await quarantineOne(ctx, "AllA")
                let (b, _) = try await quarantineOne(ctx, "AllB", rule: M1.rule(id: "test.yellow", tier: .yellow))
                let outcomes = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(Set(outcomes.map(\.entry.id)), [a.id, b.id])
                try TestSuite.assertTrue(outcomes.allSatisfy { $0.status == .purged }, "\(outcomes.map(\.status))")
                try TestSuite.assertEqual(M3.children(ctx.quarantineRoot), [".metadata_never_index"])
                try TestSuite.assertEqual(try await ctx.quarantine.sessions().count, 0)
                // A purged item can no longer be restored.
                do {
                    _ = try await ctx.quarantine.restore(entryID: a.id)
                    throw TestError("restored a purged item")
                } catch is QuarantineError {}
            }
        }

        await TestSuite.run("Quarantine: purge refuses an item replaced by a symlink pointing outside, and never follows it") {
            try await M3.withContext { ctx in
                let outside = try ctx.fixture.file("outside/precious.txt", bytes: 64, base: .root)
                let (entry, _) = try await quarantineOne(ctx, "Swapped")
                let item = quarantinedPath(ctx, entry)
                try FileManager.default.removeItem(atPath: item)
                try FileManager.default.createSymbolicLink(atPath: item, withDestinationPath: ctx.fixture.path("outside", base: .root))
                let outcomes = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(outcomes.count, 1)
                guard case .rejected = outcomes[0].status else { throw TestError("expected rejection, got \(outcomes[0].status)") }
                try TestSuite.assertTrue(M3.exists(outside), "symlink destination was touched")
                try TestSuite.assertTrue(M3.lstatInfo(item).map { ($0.st_mode & S_IFMT) == S_IFLNK } == true, "link removed")
            }
        }

        await TestSuite.run("Quarantine: purge removes a folder holding a symlink to outside without following the link") {
            try await M3.withContext { ctx in
                let outside = try ctx.fixture.file("outside/precious.txt", bytes: 64, base: .root)
                let (entry, _) = try await quarantineOne(ctx, "HasLink")
                let item = quarantinedPath(ctx, entry)
                try FileManager.default.createSymbolicLink(atPath: item + "/escape",
                                                           withDestinationPath: ctx.fixture.path("outside", base: .root))
                let outcomes = await ctx.quarantine.purgeAll()
                try TestSuite.assertEqual(outcomes.map(\.status), [.purged])
                try TestSuite.assertFalse(M3.exists(item))
                try TestSuite.assertTrue(M3.exists(outside), "removefile followed the symlink")
            }
        }

        await TestSuite.run("Quarantine: crash reconciliation — pending with source gone + destination present → moved; source present → dropped; both missing → dropped") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let session = try await ctx.quarantine.beginSession()
                let sessionDir = ctx.quarantineRoot + "/" + session.uuidString
                let now = M3.wholeSeconds(ctx.env.clock.now)

                @MainActor func pending(_ name: String) throws -> (QuarantineEntry, String) {
                    let path = try M3.cacheItem(ctx.env, name)
                    let target = M3.target(ctx.env, rule: rule, path: path)
                    let id = UUID()
                    let entry = QuarantineEntry(id: id, sessionID: session, originalPath: path,
                                                quarantinedName: id.uuidString + "/" + name, identity: target.identity!,
                                                allocatedBytes: 4_096, reclaimableBytes: 4_096, ruleID: rule.id, tier: .green,
                                                quarantinedAt: now, expiresAt: now.addingTimeInterval(86_400), status: .pending)
                    return (entry, path)
                }
                // 1. The crash happened after the rename: source gone, destination present.
                let (done, donePath) = try pending("CrashDone")
                try FileManager.default.createDirectory(atPath: sessionDir + "/" + done.id.uuidString, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                try TestSuite.assertEqual(Darwin.rename(donePath, sessionDir + "/" + done.quarantinedName), 0)
                // 2. The crash happened before the rename: source still in place.
                let (notDone, notDonePath) = try pending("CrashBefore")
                try FileManager.default.createDirectory(atPath: sessionDir + "/" + notDone.id.uuidString, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                // 3. Both gone.
                let (lost, lostPath) = try pending("CrashLost")
                try FileManager.default.removeItem(atPath: lostPath)

                try M3.writeManifest(sessionDir: sessionDir, sessionID: session, createdAt: now, entries: [done, notDone, lost])
                let events = try await ctx.quarantine.reconcile()
                let kinds = Dictionary(uniqueKeysWithValues: events.compactMap { e in e.entry.map { ($0.id, e.kind) } })
                try TestSuite.assertEqual(kinds[done.id], .markedMoved)
                try TestSuite.assertEqual(kinds[notDone.id], .droppedSourceStillPresent)
                try TestSuite.assertEqual(kinds[lost.id], .droppedBothMissing)

                let entries = try M3.readManifestEntries(sessionDir: sessionDir)
                try TestSuite.assertEqual(entries.map(\.id), [done.id])
                try TestSuite.assertEqual(entries.map(\.status), [.moved])
                try TestSuite.assertTrue(M3.exists(notDonePath + "/payload.bin"), "a never-moved source was touched")
                try TestSuite.assertFalse(M3.exists(sessionDir + "/" + notDone.id.uuidString), "empty entry folder left behind")

                // The reconciled entry is a normal quarantined item: it restores.
                let restored = try await ctx.quarantine.restore(entryID: done.id)
                try TestSuite.assertEqual(restored.restoredPath, donePath)
                try TestSuite.assertTrue(M3.exists(donePath + "/payload.bin"))
                // A second reconcile has nothing to do.
                try TestSuite.assertEqual(try await ctx.quarantine.reconcile().count, 0)
            }
        }

        await TestSuite.run("Quarantine: pending entries are never purged") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let session = try await ctx.quarantine.beginSession()
                let sessionDir = ctx.quarantineRoot + "/" + session.uuidString
                let path = try M3.cacheItem(ctx.env, "StillPending")
                let target = M3.target(ctx.env, rule: rule, path: path)
                let id = UUID()
                let now = M3.wholeSeconds(ctx.env.clock.now)
                let entry = QuarantineEntry(id: id, sessionID: session, originalPath: path,
                                            quarantinedName: id.uuidString + "/StillPending", identity: target.identity!,
                                            allocatedBytes: 1, reclaimableBytes: 1, ruleID: rule.id, tier: .green,
                                            quarantinedAt: now, expiresAt: now, status: .pending)
                try FileManager.default.createDirectory(atPath: sessionDir + "/" + id.uuidString, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                try TestSuite.assertEqual(Darwin.rename(path, sessionDir + "/" + entry.quarantinedName), 0)
                try M3.writeManifest(sessionDir: sessionDir, sessionID: session, createdAt: now, entries: [entry])
                ctx.env.clock.advance(days: 30)
                try TestSuite.assertEqual(await ctx.quarantine.purgeAll().count, 0)
                try TestSuite.assertTrue(M3.exists(sessionDir + "/" + entry.quarantinedName + "/payload.bin"))
            }
        }

        await TestSuite.run("Quarantine: a symlinked Quarantine root is refused; nothing is written through it") {
            try await M3.withContext { ctx in
                let elsewhere = try ctx.fixture.dir("elsewhere", base: .root)
                try ctx.fixture.symlink("Library/Application Support/iMop/Quarantine", to: elsewhere)
                do {
                    _ = try await ctx.quarantine.beginSession()
                    throw TestError("beginSession accepted a symlinked root")
                } catch let error as QuarantineError {
                    guard case .safetyRejected(.symlinkInPath) = error else { throw TestError("unexpected \(error)") }
                }
                try TestSuite.assertEqual(M3.children(elsewhere), [], "something was written through the link")
                let path = try M3.cacheItem(ctx.env, "NotMoved")
                let rule = M1.rule(id: "test.caches")
                do {
                    _ = try await ctx.quarantine.quarantine(target: M3.target(ctx.env, rule: rule, path: path), rule: rule,
                                                            tier: .green, sessionID: UUID())
                    throw TestError("quarantined through a symlinked root")
                } catch is QuarantineError {}
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
                try TestSuite.assertEqual(M3.children(elsewhere), [])
                try TestSuite.assertEqual(await ctx.quarantine.purgeAll().count, 0)
            }
        }

        await TestSuite.run("Quarantine: an item on another volume (fake st_dev) is refused and never copied") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches")
                let path = try M3.cacheItem(ctx.env, "OtherVolume")
                let target = M3.target(ctx.env, rule: rule, path: path)
                let session = try await ctx.quarantine.beginSession()
                ctx.env.fileSystem.overrideStat(path, device: 4_242)
                try await expectError(.crossVolume) {
                    _ = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                }
                try TestSuite.assertTrue(M3.exists(path + "/payload.bin"))
                let sessionDir = ctx.quarantineRoot + "/" + session.uuidString
                try TestSuite.assertEqual(M3.children(sessionDir), ["manifest.json"], "something was copied or left behind")
                try TestSuite.assertEqual(try M3.readManifestEntries(sessionDir: sessionDir), [])
            }
        }

        await TestSuite.run("Quarantine: an item whose inode changed or that is a symlink is refused right before the move") {
            try await M3.withContext { ctx in
                let rule = M1.rule(id: "test.caches", allowSymlinkTarget: true)
                let path = try M3.cacheItem(ctx.env, "Changed")
                let target = M3.target(ctx.env, rule: rule, path: path)
                let session = try await ctx.quarantine.beginSession()
                try FileManager.default.moveItem(atPath: path, toPath: path + "-old")
                try ctx.fixture.dir("Library/Caches/Changed")
                try await expectError(.safetyRejected(.changedSinceScan)) {
                    _ = try await ctx.quarantine.quarantine(target: target, rule: rule, tier: .green, sessionID: session)
                }
                let link = try ctx.fixture.symlink("Library/Caches/Link", to: ctx.fixture.path("Library/Caches/Changed-old"))
                let linkTarget = M3.target(ctx.env, rule: rule, path: link)
                do {
                    _ = try await ctx.quarantine.quarantine(target: linkTarget, rule: rule, tier: .green, sessionID: session)
                    throw TestError("quarantined a symlink")
                } catch let error as QuarantineError {
                    guard case .safetyRejected(.symlinkInPath) = error else { throw TestError("unexpected \(error)") }
                }
                try TestSuite.assertTrue(M3.exists(link) && M3.exists(path + "-old/payload.bin"))
            }
        }

        await TestSuite.run("Quarantine: the default (compiled-in, dry-run) policy refuses every mutation") {
            try TestSuite.assertFalse(MutationPolicy.compiledIn.isEnabled, "debug/test builds must be compiled without IMOP_ALLOW_MUTATION")
            try await M3.withContext { ctx in
                // Put one real item in Quarantine with the fixture policy first.
                let (entry, path) = try await quarantineOne(ctx, "DryRun")
                let dry = Quarantine(environment: ctx.env.environment, gate: ctx.gate)
                let fresh = try M3.cacheItem(ctx.env, "DryRunFresh")
                let rule = M1.rule(id: "test.caches")
                let before = M3.children(ctx.quarantineRoot)

                try await expectError(.mutationDisabled) { _ = try await dry.beginSession() }
                try await expectError(.mutationDisabled) {
                    _ = try await dry.quarantine(target: M3.target(ctx.env, rule: rule, path: fresh), rule: rule, tier: .green,
                                                 sessionID: entry.sessionID)
                }
                try await expectError(.mutationDisabled) { _ = try await dry.restore(entryID: entry.id) }
                let restoreAll = await dry.restoreSession(entry.sessionID)
                try TestSuite.assertEqual(restoreAll.count, 1)
                guard case .failure(.mutationDisabled) = restoreAll[0] else { throw TestError("restoreSession: \(restoreAll[0])") }
                let purged = await dry.purgeAll()
                try TestSuite.assertEqual(purged.map(\.status), [.failed(.mutationDisabled)])

                try TestSuite.assertEqual(M3.children(ctx.quarantineRoot), before)
                try TestSuite.assertTrue(M3.exists(quarantinedPath(ctx, entry) + "/payload.bin"))
                try TestSuite.assertTrue(M3.exists(fresh + "/payload.bin"))
                try TestSuite.assertFalse(M3.exists(path))
                try TestSuite.assertEqual(QuarantineError.mutationDisabled.message, "mutation disabled in this build")
                try TestSuite.assertEqual(QuarantineError.mutationDisabled.errorCategory, .mutationDisabled)
            }
            // A dry-run Quarantine on a fresh home creates nothing at all.
            try await M1.withEnv { env in
                let dry = Quarantine(environment: env.environment, gate: env.makeGate())
                do { _ = try await dry.beginSession(); throw TestError("dry run began a session") } catch let error as QuarantineError {
                    try TestSuite.assertEqual(error, .mutationDisabled)
                }
                try TestSuite.assertFalse(M3.exists(env.fixture.path("Library/Application Support/iMop")))
            }
        }
    }
}
