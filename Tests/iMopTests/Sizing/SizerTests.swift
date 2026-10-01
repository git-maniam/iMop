import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Spec §7.1: allocated vs reclaimable sizing with getattrlistbulk (hard links, clones, symlinks).
struct SizerTests {
    @MainActor
    static func runAll() async {
        print("\n📏 Running SizeCalculator Tests (spec §7.1)...")

        await TestSuite.run("Sizer: nested files — allocated equals on-disk blocks, item count includes files and folders") {
            try await M1.withEnv { env in
                let f = env.fixture
                let root = try f.dir("Library/Caches/pip")
                try f.file("Library/Caches/pip/http/a/one.bin", bytes: 10_000)
                try f.file("Library/Caches/pip/http/a/two.bin", bytes: 20_000)
                try f.file("Library/Caches/pip/http/b/c/d/three.bin", bytes: 300_000)
                try f.file("Library/Caches/pip/selfcheck.json", bytes: 1)
                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: root))
                try TestSuite.assertEqual(estimate.allocatedBytes, M2.treeBlocksBytes(root))
                try TestSuite.assertTrue(estimate.allocatedBytes >= 330_001, "\(estimate)")
                try TestSuite.assertEqual(estimate.reclaimableBytes, estimate.allocatedBytes, "no clones or links: all of it is freed")
                // http, a, b, c, d (5 dirs) + 4 files.
                try TestSuite.assertEqual(estimate.itemCount, 9)
                try TestSuite.assertTrue(estimate.complete)
                try TestSuite.assertEqual(estimate.hardLinkedBytesExcluded, 0)
                try TestSuite.assertEqual(estimate.crossedMountPointsSkipped, 0)
                try TestSuite.assertTrue(estimate.newestModification != nil)
            }
        }

        await TestSuite.run("Sizer: allocated size is reported, not logical size") {
            try await M1.withEnv { env in
                let f = env.fixture
                let root = try f.dir("tree")
                try f.file("tree/small.txt", bytes: 5)
                try f.file("tree/odd.bin", bytes: 4_097)
                // A sparse file: logical 64 MiB, (almost) nothing allocated.
                let sparse = f.path("tree/sparse.img")
                let fd = Darwin.open(sparse, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
                guard fd >= 0 else { throw TestError("open sparse failed") }
                defer { Darwin.close(fd) }
                guard ftruncate(fd, 64 << 20) == 0 else { throw TestError("ftruncate failed") }

                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: root))
                try TestSuite.assertEqual(estimate.allocatedBytes, M2.treeBlocksBytes(root))
                try TestSuite.assertTrue(estimate.allocatedBytes < 1 << 20, "sparse file must not count its logical size: \(estimate)")
                try TestSuite.assertTrue(M2.blocksBytes(f.path("tree/odd.bin")) >= 8_192)
            }
        }

        await TestSuite.run("Sizer: a hard link with both links inside the tree is counted once and is reclaimable") {
            try await M1.withEnv { env in
                let f = env.fixture
                let root = try f.dir("tree")
                let original = try f.file("tree/a/original.bin", bytes: 200_000)
                try f.dir("tree/b")
                guard Darwin.link(original, f.path("tree/b/link.bin")) == 0 else { throw TestError("link failed: \(errno)") }
                let single = M2.blocksBytes(original)

                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: root))
                try TestSuite.assertEqual(estimate.allocatedBytes, single, "inode counted once")
                try TestSuite.assertEqual(estimate.reclaimableBytes, single)
                try TestSuite.assertEqual(estimate.hardLinkedBytesExcluded, 0)
                try TestSuite.assertEqual(estimate.itemCount, 4, "a, b, original, link")
                try TestSuite.assertTrue(estimate.complete)
            }
        }

        await TestSuite.run("Sizer: a hard link with a link outside the tree is not reclaimable") {
            try await M1.withEnv { env in
                let f = env.fixture
                let root = try f.dir("tree")
                let inside = try f.file("tree/shared.bin", bytes: 150_000)
                try f.file("tree/own.bin", bytes: 50_000)
                guard Darwin.link(inside, f.path("elsewhere.bin", base: .root)) == 0 else { throw TestError("link failed: \(errno)") }
                let sharedBytes = M2.blocksBytes(inside)
                let ownBytes = M2.blocksBytes(f.path("tree/own.bin"))

                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: root))
                try TestSuite.assertEqual(estimate.allocatedBytes, sharedBytes + ownBytes)
                try TestSuite.assertEqual(estimate.reclaimableBytes, ownBytes)
                try TestSuite.assertEqual(estimate.hardLinkedBytesExcluded, sharedBytes)
            }
        }

        await TestSuite.run("Sizer: an APFS clone (clonefile) is mostly not reclaimable") {
            try await M1.withEnv { env in
                let f = env.fixture
                let source = try f.file("source.bin", bytes: 4 << 20, base: .root)
                let root = try f.dir("tree")
                let clone = f.path("tree/clone.bin")
                guard clonefile(source, clone, 0) == 0 else { throw TestError("clonefile failed: errno \(errno) (fixture not on APFS?)") }

                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: root))
                try TestSuite.assertTrue(estimate.allocatedBytes >= 4 << 20, "\(estimate)")
                try TestSuite.assertTrue(estimate.reclaimableBytes * 10 < estimate.allocatedBytes,
                                         "clone shares its blocks with the source: \(estimate)")
                try TestSuite.assertEqual(estimate.itemCount, 1)
            }
        }

        await TestSuite.run("Sizer: symlinks are not followed and count as one item with 0 bytes") {
            try await M1.withEnv { env in
                let f = env.fixture
                let big = try f.file("big.bin", bytes: 8 << 20, base: .root)
                try f.dir("bigdir/sub", base: .root)
                try f.file("bigdir/sub/more.bin", bytes: 2 << 20, base: .root)
                let root = try f.dir("tree")
                try f.file("tree/real.bin", bytes: 1_000)
                try f.symlink("tree/link-to-file", to: big)
                try f.symlink("tree/link-to-dir", to: f.path("bigdir", base: .root))
                let sizer = SizeCalculator(environment: env.environment)

                let estimate = try unwrap(sizer.measure(path: root))
                try TestSuite.assertEqual(estimate.allocatedBytes, M2.blocksBytes(f.path("tree/real.bin")))
                try TestSuite.assertEqual(estimate.itemCount, 3)
                try TestSuite.assertTrue(estimate.complete)

                // A symlink as the root itself.
                let linkRoot = try unwrap(sizer.measure(path: f.path("tree/link-to-dir")))
                try TestSuite.assertEqual(linkRoot.allocatedBytes, 0)
                try TestSuite.assertEqual(linkRoot.reclaimableBytes, 0)
                try TestSuite.assertEqual(linkRoot.itemCount, 1)
            }
        }

        await TestSuite.run("Sizer: a plain file root gives a single-file estimate") {
            try await M1.withEnv { env in
                let file = try env.fixture.file("Library/iTunes/iPhone Software Updates/iPhone_17.ipsw", bytes: 123_456)
                try env.fixture.setModificationDate("Library/iTunes/iPhone Software Updates/iPhone_17.ipsw", daysAgo: 3, clock: env.clock)
                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: file))
                try TestSuite.assertEqual(estimate.itemCount, 1)
                try TestSuite.assertEqual(estimate.allocatedBytes, M2.blocksBytes(file))
                try TestSuite.assertEqual(estimate.reclaimableBytes, estimate.allocatedBytes)
                try TestSuite.assertTrue(estimate.complete)
                let expected = env.clock.now.addingTimeInterval(-3 * 86_400)
                try TestSuite.assertTrue(abs((estimate.newestModification ?? .distantPast).timeIntervalSince(expected)) < 2, "\(estimate)")
            }
        }

        await TestSuite.run("Sizer: a nonexistent path gives nil; an empty directory gives zero") {
            try await M1.withEnv { env in
                let sizer = SizeCalculator(environment: env.environment)
                try TestSuite.assertTrue(sizer.measure(path: env.fixture.path("does/not/exist")) == nil)
                let empty = try unwrap(sizer.measure(path: try env.fixture.dir("empty")))
                try TestSuite.assertEqual(empty.itemCount, 0)
                try TestSuite.assertEqual(empty.allocatedBytes, 0)
                try TestSuite.assertTrue(empty.complete)
            }
        }

        await TestSuite.run("Sizer: an unreadable subfolder makes the estimate incomplete, not a failure") {
            try await M1.withEnv { env in
                let f = env.fixture
                let root = try f.dir("tree")
                try f.file("tree/visible.bin", bytes: 10_000)
                let locked = try f.dir("tree/locked")
                try f.file("tree/locked/hidden.bin", bytes: 10_000)
                guard chmod(locked, 0) == 0 else { throw TestError("chmod failed") }
                defer { _ = chmod(locked, 0o755) }
                let estimate = try unwrap(SizeCalculator(environment: env.environment).measure(path: root))
                if geteuid() != 0 {
                    try TestSuite.assertFalse(estimate.complete, "\(estimate)")
                    try TestSuite.assertEqual(estimate.allocatedBytes, M2.blocksBytes(f.path("tree/visible.bin")))
                }
            }
        }

        await TestSuite.run("Sizer: a cancelled measurement is marked incomplete") {
            try await M1.withEnv { env in
                let f = env.fixture
                let root = try f.dir("tree")
                for i in 0..<20 { try f.file("tree/d\(i)/f.bin", bytes: 100) }
                let environment = env.environment
                let task = Task.detached { () -> SizeEstimate? in
                    withUnsafeCurrentTask { $0?.cancel() }
                    return SizeCalculator(environment: environment).measure(path: root)
                }
                let estimate = await task.value
                try TestSuite.assertFalse(estimate?.complete ?? false, "\(String(describing: estimate))")
            }
        }
    }

    static func unwrap<T>(_ value: T?, file: StaticString = #file, line: UInt = #line) throws -> T {
        guard let value else { throw TestError("unexpected nil (\(file):\(line))") }
        return value
    }
}
