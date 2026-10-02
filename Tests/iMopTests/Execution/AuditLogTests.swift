import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §5.5: the JSONL audit log (metadata only, never file contents).
struct AuditLogTests {
    static func date(_ iso: String) throws -> Date {
        guard let date = ISO8601DateFormatter().date(from: iso) else { throw TestError("bad date \(iso)") }
        return date
    }

    static func event(_ action: String, at timestamp: Date, detail: String? = nil) -> AuditEvent {
        AuditEvent(timestamp: timestamp, sessionID: UUID(), ruleID: "test.rule", path: "/some/path", action: action,
                   bytes: 42, verdict: "allowed", rejectionReason: nil, commandExitCode: nil, detail: detail)
    }

    @MainActor
    static func runAll() async {
        print("\n📜 Running Audit Log Tests (spec §5.5)...")

        await TestSuite.run("AuditLog: one JSON object per line, decodable, UTC monthly file name, dir 0700 / file 0600") {
            try await M3.withContext { ctx in
                // 23:30 UTC on 31 March is already April in UTC+1 and later; the file must still be March.
                ctx.env.clock.now = try date("2026-03-31T23:30:00Z")
                let first = event("test.one", at: try date("2026-03-31T23:30:00Z"))
                let second = AuditEvent(timestamp: try date("2026-03-31T23:31:00Z"), action: "test.two", verdict: "rejected",
                                        rejectionReason: "line\nbreak \"quoted\"", commandExitCode: 7, detail: "multi\nline")
                await ctx.audit.record(first)
                await ctx.audit.record(second)
                try TestSuite.assertEqual(M3.children(ctx.logDirectory), ["audit-2026-03.jsonl"])
                try TestSuite.assertEqual(M3.permissions(ctx.logDirectory), 0o700)
                try TestSuite.assertEqual(M3.permissions(ctx.logDirectory + "/audit-2026-03.jsonl"), 0o600)
                let text = try String(contentsOfFile: ctx.logDirectory + "/audit-2026-03.jsonl", encoding: .utf8)
                try TestSuite.assertEqual(text.split(separator: "\n").count, 2, "embedded newlines must be escaped")
                try TestSuite.assertTrue(text.contains("\"timestamp\":\"2026-03-31T23:30:00Z\""), "ISO-8601 dates expected: \(text)")
                try TestSuite.assertEqual(try M3.auditEvents(ctx), [first, second])

                ctx.env.clock.now = try date("2026-04-01T00:30:00Z")
                let third = event("test.three", at: ctx.env.clock.now)
                await ctx.audit.record(third)
                try TestSuite.assertEqual(M3.children(ctx.logDirectory), ["audit-2026-03.jsonl", "audit-2026-04.jsonl"])
                try TestSuite.assertEqual(await ctx.audit.logFiles().map(\.lastPathComponent),
                                          ["audit-2026-03.jsonl", "audit-2026-04.jsonl"])
                try TestSuite.assertEqual(try M3.auditEvents(ctx), [first, second, third])
                try TestSuite.assertEqual(await ctx.audit.failedWrites, 0)
            }
        }

        await TestSuite.run("AuditLog: a real cleanup run never logs file contents") {
            try await M3.withContext { ctx in
                let marker = "TOP-SECRET-CONTENT-7f3a9c"
                let rule = M1.rule(id: "test.caches")
                let path = try M3.cacheItem(ctx.env, "Private", contents: Data(String(repeating: marker + "\n", count: 50).utf8))
                let confirmed = try await M3.confirmedPlan(ctx, [(rule, [M3.target(ctx.env, rule: rule, path: path)])])
                let run = try await M3.run(ctx.executor(), confirmed)
                guard case .quarantined = run.report.outcomes[0].status else { throw TestError("\(run.report.outcomes)") }
                let text = M3.auditText(ctx)
                try TestSuite.assertTrue(text.contains(path), "the path is logged")
                try TestSuite.assertFalse(text.contains(marker), "file contents leaked into the audit log")
            }
        }

        await TestSuite.run("AuditLog: detail is truncated to 64 KB (on a character boundary)") {
            try await M3.withContext { ctx in
                ctx.env.clock.now = try date("2026-05-10T10:00:00Z")
                let huge = String(repeating: "é", count: 100_000) // 200 000 UTF-8 bytes
                let e = event("test.big", at: ctx.env.clock.now, detail: huge)
                let detail = e.detail ?? ""
                try TestSuite.assertTrue(detail.utf8.count <= 64 * 1024, "\(detail.utf8.count) bytes")
                try TestSuite.assertTrue(detail.utf8.count > 60 * 1024, "truncated far too much")
                try TestSuite.assertTrue(detail.hasSuffix("[truncated]"))
                try TestSuite.assertTrue(detail.dropLast("\n… [truncated]".count).allSatisfy { $0 == "é" }, "split a character")
                try TestSuite.assertEqual(event("test.small", at: ctx.env.clock.now, detail: "short").detail, "short")
                await ctx.audit.record(e)
                let events = try M3.auditEvents(ctx)
                try TestSuite.assertEqual(events, [e])
                let fileSize = M3.lstatInfo(ctx.logDirectory + "/audit-2026-05.jsonl").map { Int($0.st_size) } ?? 0
                try TestSuite.assertTrue(fileSize < 64 * 1024 + 1_024, "line is \(fileSize) bytes")
            }
        }

        await TestSuite.run("AuditLog: export concatenates every monthly file into a new file, never overwrites") {
            try await M3.withContext { ctx in
                ctx.env.clock.now = try date("2026-01-15T12:00:00Z")
                await ctx.audit.record(event("jan", at: ctx.env.clock.now))
                ctx.env.clock.now = try date("2026-02-15T12:00:00Z")
                await ctx.audit.record(event("feb.1", at: ctx.env.clock.now))
                await ctx.audit.record(event("feb.2", at: ctx.env.clock.now))
                let exports = try ctx.fixture.dir("exports", base: .root)
                let destination = URL(fileURLWithPath: exports + "/audit-export.jsonl")
                try await ctx.audit.export(to: destination)
                let jan = try String(contentsOfFile: ctx.logDirectory + "/audit-2026-01.jsonl", encoding: .utf8)
                let feb = try String(contentsOfFile: ctx.logDirectory + "/audit-2026-02.jsonl", encoding: .utf8)
                let exported = try String(contentsOf: destination, encoding: .utf8)
                try TestSuite.assertEqual(exported, jan + feb)
                try TestSuite.assertEqual(exported.split(separator: "\n").count, 3)
                do {
                    try await ctx.audit.export(to: destination)
                    throw TestError("export overwrote an existing file")
                } catch let error as AuditLogError {
                    try TestSuite.assertEqual(error, .destinationExists)
                }
                try TestSuite.assertEqual(try String(contentsOf: destination, encoding: .utf8), jan + feb)
            }
        }

        await TestSuite.run("AuditLog: export refuses the Quarantine, iMop's log folder and deny-listed destinations") {
            try await M3.withContext { ctx in
                await ctx.audit.record(event("one", at: ctx.env.clock.now))
                try ctx.fixture.dir("Library/Application Support/iMop/Quarantine")
                try ctx.fixture.dir("Library/Keychains")
                try ctx.fixture.dir("Documents")
                let refused = [
                    ctx.quarantineRoot + "/export.jsonl",
                    ctx.logDirectory + "/export.jsonl",
                    ctx.fixture.path("Library/Keychains/export.jsonl"),
                    ctx.fixture.path("Documents/export.jsonl"),
                ]
                for path in refused {
                    do {
                        try await ctx.audit.export(to: URL(fileURLWithPath: path))
                        throw TestError("export to \(path) was accepted")
                    } catch let error as AuditLogError {
                        guard case .destinationRefused = error else { throw TestError("\(path): \(error)") }
                    }
                    try TestSuite.assertFalse(M3.exists(path), "\(path) was written")
                }
                // Without the fixture waiver, the fixture itself (/private/var/folders) is deny-listed.
                let strict = AuditLog(environment: ctx.env.environment)
                let outside = ctx.fixture.path("export.jsonl", base: .root)
                do {
                    try await strict.export(to: URL(fileURLWithPath: outside))
                    throw TestError("export into /private/var/folders accepted")
                } catch let error as AuditLogError {
                    guard case .destinationRefused = error else { throw TestError("\(error)") }
                }
                try TestSuite.assertFalse(M3.exists(outside))
                // Through a symlinked folder into the Quarantine: refused on the resolved path.
                try ctx.fixture.symlink("exports-link", to: ctx.quarantineRoot, base: .root)
                let viaLink = ctx.fixture.path("exports-link/export.jsonl", base: .root)
                do {
                    try await ctx.audit.export(to: URL(fileURLWithPath: viaLink))
                    throw TestError("export through a link into the Quarantine accepted")
                } catch is AuditLogError {}
                try TestSuite.assertEqual(M3.children(ctx.quarantineRoot), [])
            }
        }

        await TestSuite.run("AuditLog: a symlinked log folder (or Logs folder) is refused — counted, never written through") {
            try await M3.withContext { ctx in
                let elsewhere = try ctx.fixture.dir("elsewhere", base: .root)
                try ctx.fixture.symlink("Library/Logs/iMop", to: elsewhere)
                await ctx.audit.record(event("one", at: ctx.env.clock.now))
                try TestSuite.assertEqual(await ctx.audit.failedWrites, 1)
                try TestSuite.assertEqual(M3.children(elsewhere), [])
                try TestSuite.assertEqual(await ctx.audit.logFiles(), [])
            }
            try await M3.withContext { ctx in
                let elsewhere = try ctx.fixture.dir("elsewhere", base: .root)
                try ctx.fixture.dir("Library")
                try ctx.fixture.symlink("Library/Logs", to: elsewhere)
                await ctx.audit.record(event("one", at: ctx.env.clock.now))
                await ctx.audit.record(event("two", at: ctx.env.clock.now))
                try TestSuite.assertEqual(await ctx.audit.failedWrites, 2)
                try TestSuite.assertEqual(M3.children(elsewhere), [])
            }
        }

        await TestSuite.run("AuditLog: a log file planted as a symlink or hard link is never appended to") {
            try await M3.withContext { ctx in
                ctx.env.clock.now = try date("2026-06-01T08:00:00Z")
                let victim = try ctx.fixture.file("victim.txt", contents: Data("original".utf8), base: .root)
                try ctx.fixture.dir("Library/Logs/iMop")
                try ctx.fixture.symlink("Library/Logs/iMop/audit-2026-06.jsonl", to: victim)
                await ctx.audit.record(event("one", at: ctx.env.clock.now))
                try TestSuite.assertEqual(await ctx.audit.failedWrites, 1)
                try FileManager.default.removeItem(atPath: ctx.logDirectory + "/audit-2026-06.jsonl")
                try TestSuite.assertEqual(Darwin.link(victim, ctx.logDirectory + "/audit-2026-06.jsonl"), 0)
                await ctx.audit.record(event("two", at: ctx.env.clock.now))
                try TestSuite.assertEqual(await ctx.audit.failedWrites, 2)
                try TestSuite.assertEqual(try String(contentsOfFile: victim, encoding: .utf8), "original")
            }
        }
    }
}
