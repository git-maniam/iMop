import Darwin
import Foundation
@_spi(FixtureTesting) import iMopCore

/// Milestone 5 (spec §6.5): ProjectScanner — manifest pairing, topmost artifacts only, depth and
/// descent limits, user-selected project roots, `notTrackedByGit` and `projectOlderThan`.
struct ProjectScannerTests {
    static let root = "Projects"
    static let cacheDirTag = "Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n"

    static let projectRuleIDs = ["project.nodeModules", "project.rustTarget", "project.pythonVenv", "project.pods",
                                 "project.nextBuild", "project.gradleBuild", "project.swiftBuild"]

    /// Creates `<rel>` with `files` (regular files, relative to it) and `dirs`.
    @MainActor
    static func project(_ f: FixtureBuilder, _ rel: String, files: [String] = [], dirs: [String] = []) throws {
        try f.dir(rel)
        for file in files {
            if file.hasSuffix("CACHEDIR.TAG") {
                try f.file(rel + "/" + file, contents: Data(cacheDirTag.utf8))
            } else {
                try f.file(rel + "/" + file, bytes: 64)
            }
        }
        for dir in dirs { try f.file(rel + "/" + dir + "/payload.bin", bytes: 2_000) }
    }

    /// Configures `env` with the given project roots (default: `~/Projects`, absolute form).
    @MainActor
    static func useRoots(_ env: FakeEnvironment, _ roots: [String]? = nil) {
        env.scanSettings = ScanSettings(projectRoots: roots ?? [env.fixture.path(root)])
    }

    /// Runs the ProjectScanner for one rule and returns the offered paths.
    @MainActor
    static func discovered(_ env: FakeEnvironment, _ ruleID: String,
                           inspector: ProjectArtifactsInspector = ProjectArtifactsInspector()) async throws -> Set<String> {
        let out = try await M5.discover(inspector, env, ruleID)
        try TestSuite.assertEqual(out.status, .ok, ruleID)
        try TestSuite.assertTrue(out.candidates.allSatisfy { $0.owningBundleID == nil }, ruleID)
        return M5.paths(out, env.fixture)
    }

    @MainActor
    static func runAll() async {
        print("\n📦 Running Milestone 5 ProjectScanner tests (spec §6.5)...")
        await pairingTests()
        await walkTests()
        await rootTests()
        await gitTests()
        await ageTests()
    }

    // MARK: Manifest pairing

    @MainActor
    static func pairingTests() async {
        await TestSuite.run("ProjectScanner: every artifact kind needs its manifest beside it (and its marker inside); generic build/ and target/ only with their pairing") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                let p = root + "/"
                // Matched.
                try project(f, p + "web", files: ["package-lock.json", "package.json"], dirs: ["node_modules"])
                try project(f, p + "web-yarn", files: ["yarn.lock"], dirs: ["node_modules"])
                try project(f, p + "web-pnpm", files: ["pnpm-lock.yaml"], dirs: ["node_modules"])
                try project(f, p + "web-bun", files: ["bun.lockb"], dirs: ["node_modules"])
                try project(f, p + "web-bun2", files: ["bun.lock"], dirs: ["node_modules"])
                try project(f, p + "rust", files: ["Cargo.toml", "target/CACHEDIR.TAG"], dirs: ["target/debug"])
                try project(f, p + "rust2", files: ["Cargo.toml", "target/.rustc_info.json"], dirs: ["target/release"])
                try project(f, p + "py", files: ["pyproject.toml", ".venv/pyvenv.cfg"], dirs: [".venv/lib"])
                try project(f, p + "py2", files: ["requirements-dev.txt", "venv/pyvenv.cfg"], dirs: ["venv/lib"])
                try project(f, p + "py3", files: ["uv.lock", ".venv/pyvenv.cfg"])
                try project(f, p + "py4", files: ["poetry.lock", ".venv/pyvenv.cfg"])
                try project(f, p + "py5", files: ["requirements.txt", "venv/pyvenv.cfg"])
                try project(f, p + "ios", files: ["Podfile", "Podfile.lock"], dirs: ["Pods/Alamofire"])
                try project(f, p + "next", files: ["next.config.mjs", "package.json"], dirs: [".next/cache"])
                try project(f, p + "next2", files: ["next.config.js"], dirs: [".next/server"])
                try project(f, p + "gradle", files: ["build.gradle.kts"], dirs: ["build/classes"])
                try project(f, p + "gradle2", files: ["build.gradle"], dirs: ["build/tmp"])
                try project(f, p + "swift", files: ["Package.swift"], dirs: [".build/debug"])
                // NOT matched: artifact without its manifest / marker, or with a symlinked or directory manifest.
                try project(f, p + "web-nolock", files: ["package.json"], dirs: ["node_modules"])
                try project(f, p + "rust-nomarker", files: ["Cargo.toml"], dirs: ["target/debug"])
                try project(f, p + "rust-badtag", files: ["Cargo.toml"], dirs: ["target/debug"])
                try f.file(p + "rust-badtag/target/CACHEDIR.TAG", contents: Data("not a tag".utf8))
                try project(f, p + "rust-nocargo", files: ["target/CACHEDIR.TAG"], dirs: ["target/debug"])
                try project(f, p + "py-nocfg", files: ["requirements.txt"], dirs: ["venv/lib"])
                try project(f, p + "py-nomanifest", files: [".venv/pyvenv.cfg"])
                try project(f, p + "ios-nolock", files: ["Podfile"], dirs: ["Pods/Alamofire"])
                try project(f, p + "next-noconfig", files: ["package.json"], dirs: [".next/cache"])
                try project(f, p + "generic-build", files: ["Makefile", "CMakeLists.txt"], dirs: ["build/obj"])
                try project(f, p + "generic-build2", files: ["package-lock.json"], dirs: ["build/static"])
                try project(f, p + "generic-target", files: ["pom.xml"], dirs: ["target/classes"])
                try project(f, p + "swift-nomanifest", files: ["Package.resolved"], dirs: [".build/debug"])
                try project(f, p + "web-linklock", dirs: ["node_modules"])
                try f.file("elsewhere/package-lock.json", bytes: 10, base: .root)
                try f.symlink(p + "web-linklock/package-lock.json", to: f.path("elsewhere/package-lock.json", base: .root))
                try project(f, p + "web-dirlock", dirs: ["node_modules", "package-lock.json"])
                try project(f, p + "case", files: ["Package-Lock.json"], dirs: ["Node_Modules"])

                let expected: [String: Set<String>] = [
                    "project.nodeModules": ["web", "web-yarn", "web-pnpm", "web-bun", "web-bun2"].reduce(into: []) { $0.insert(p + $1 + "/node_modules") },
                    "project.rustTarget": [p + "rust/target", p + "rust2/target"],
                    "project.pythonVenv": [p + "py/.venv", p + "py2/venv", p + "py3/.venv", p + "py4/.venv", p + "py5/venv"],
                    "project.pods": [p + "ios/Pods"],
                    "project.nextBuild": [p + "next/.next", p + "next2/.next"],
                    "project.gradleBuild": [p + "gradle/build", p + "gradle2/build"],
                    "project.swiftBuild": [p + "swift/.build"],
                ]
                for id in projectRuleIDs {
                    try TestSuite.assertEqual(try await discovered(env, id), expected[id] ?? [], id)
                }

                // Through the Scanner (matcher wiring, allow-roots = the project roots): the same targets.
                let results = try await M5.scan(env, Set(projectRuleIDs))
                for id in projectRuleIDs {
                    try TestSuite.assertEqual(results[id]?.status, .ok, id)
                    try TestSuite.assertEqual(M5.paths(results[id], f), expected[id] ?? [], id)
                    try TestSuite.assertEqual(results[id]?.rule.tier, .yellow, id)
                }
            }
        }

        await TestSuite.run("ProjectScanner: only the TOPMOST node_modules is offered; nothing inside any artifact-named folder is ever matched") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                let p = root + "/"
                try project(f, p + "app", files: ["package-lock.json"], dirs: ["node_modules/left-pad"])
                // A nested project with its own lock file and node_modules INSIDE node_modules.
                try project(f, p + "app/node_modules/inner", files: ["package-lock.json"], dirs: ["node_modules/x"])
                try project(f, p + "app/node_modules/left-pad", files: ["yarn.lock"], dirs: ["node_modules"])
                // An unmatched node_modules (no lock file) is not descended either.
                try project(f, p + "nolock", files: ["package.json"], dirs: ["node_modules"])
                try project(f, p + "nolock/node_modules/sub", files: ["package-lock.json"], dirs: ["node_modules"])
                // A project inside another kind's artifact (Pods / build) is never reached.
                try project(f, p + "ios", files: ["Podfile.lock"], dirs: ["Pods"])
                try project(f, p + "ios/Pods/tooling", files: ["package-lock.json"], dirs: ["node_modules"])
                try project(f, p + "gen", files: ["Makefile"], dirs: ["build"])
                try project(f, p + "gen/build/web", files: ["package-lock.json"], dirs: ["node_modules"])

                try TestSuite.assertEqual(try await discovered(env, "project.nodeModules"), [p + "app/node_modules"])
                try TestSuite.assertEqual(try await discovered(env, "project.pods"), [p + "ios/Pods"])

                // The matcher (SafetyGate's last shape check) refuses nested shapes too.
                let rule = try M5.rule(env, "project.nodeModules")
                let home = CanonicalPath(validatedPath: f.home)
                let matcher = RuleTargetMatcher(homeForms: [home])
                func path(_ rel: String) -> CanonicalPath {
                    rel.split(separator: "/").reduce(home) { $0.appending(String($1)) }
                }
                try TestSuite.assertNil(matcher.mismatch(path(p + "app/node_modules"), rule: rule, owningBundleID: nil))
                for nested in [p + "app/node_modules/inner/node_modules", p + "ios/Pods/tooling/node_modules",
                               p + "gen/build/web/node_modules", p + ".hidden/app/node_modules", p + "Tool.app/x/node_modules"] {
                    try TestSuite.assertTrue(matcher.mismatch(path(nested), rule: rule, owningBundleID: nil) != nil, nested)
                }
                // A target of another kind's name never matches this rule.
                try TestSuite.assertTrue(matcher.mismatch(path(p + "app/build"), rule: rule, owningBundleID: nil) != nil)
            }
        }
    }

    // MARK: Walk limits

    @MainActor
    static func walkTests() async {
        await TestSuite.run("ProjectScanner: depth limit 8 below the project root") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                let seven = (1...7).map { "d\($0)" }.joined(separator: "/")
                let eight = (1...8).map { "e\($0)" }.joined(separator: "/")
                try project(f, root + "/" + seven, files: ["package-lock.json"], dirs: ["node_modules"])
                try project(f, root + "/" + eight, files: ["package-lock.json"], dirs: ["node_modules"])
                try TestSuite.assertEqual(ProjectArtifactsInspector.maxDepth, 8)
                try TestSuite.assertEqual(try await discovered(env, "project.nodeModules"), [root + "/" + seven + "/node_modules"],
                                          "an artifact 8 levels below the root is found; 9 levels is not")
            }
        }

        await TestSuite.run("ProjectScanner: hidden folders, .app bundles, packages, symlinks and other volumes are never descended") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                let p = root + "/"
                let pair = (files: ["package-lock.json"], dirs: ["node_modules"])
                try project(f, p + "ok/app", files: pair.files, dirs: pair.dirs)
                try project(f, p + ".hidden/app", files: pair.files, dirs: pair.dirs)
                try project(f, p + ".cache/app", files: pair.files, dirs: pair.dirs)
                try project(f, p + "Tool.app/Contents/app", files: pair.files, dirs: pair.dirs)
                try project(f, p + "Old.photoslibrary/app", files: pair.files, dirs: pair.dirs)
                try project(f, p + "My.xcodeproj/app", files: pair.files, dirs: pair.dirs)
                try project(f, "ext/app", files: pair.files, dirs: pair.dirs)
                try f.symlink(p + "linked", to: f.path("ext"))
                try project(f, p + "vol/app", files: pair.files, dirs: pair.dirs)
                env.fileSystem.overrideStat(f.path(p + "vol"), device: 4_242)
                // A symlinked artifact itself is never offered.
                try project(f, p + "linkart", files: pair.files)
                try f.symlink(p + "linkart/node_modules", to: f.path("ext/app/node_modules"))

                try TestSuite.assertEqual(try await discovered(env, "project.nodeModules"), [p + "ok/app/node_modules"])
                let walked = env.fileSystem.recordedCalls.filter { $0.0 == .contentsOfDirectory }.map { M5.relative($0.1, f) }
                for forbidden in [".hidden", ".cache", "Tool.app", "Old.photoslibrary", "My.xcodeproj", "linked", "vol"] {
                    try TestSuite.assertFalse(walked.contains { $0.hasPrefix(p + forbidden + "/") || $0 == p + forbidden }, "listed \(forbidden)")
                }
            }
        }

        await TestSuite.run("ProjectScanner: the entry budget truncates with a note; cancellation yields nothing") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                try project(f, root + "/a", files: ["package-lock.json"], dirs: ["node_modules"])
                for letter in "bcdefghijklmnopqrstuvwxyz" { try f.file(root + "/\(letter)/file.txt", bytes: 1) }
                // Root listing 26 + a/ 2 + b/ c/ 1 each = 30; d/ goes over.
                let small = try await M5.discover(ProjectArtifactsInspector(maxEntriesVisited: 30), env, "project.nodeModules")
                try TestSuite.assertEqual(small.status, .ok)
                try TestSuite.assertEqual(M5.paths(small, f), [root + "/a/node_modules"])
                try TestSuite.assertTrue(small.candidates.allSatisfy { $0.notes.contains { $0.contains("stopped after 30 entries") } })
                let tiny = try await M5.discover(ProjectArtifactsInspector(maxEntriesVisited: 5), env, "project.nodeModules")
                guard case .unavailable(let message) = tiny.status else { throw TestError("expected unavailable, got \(tiny.status)") }
                try TestSuite.assertTrue(message.contains("stopped after 5 entries"), message)
                try TestSuite.assertTrue(tiny.candidates.isEmpty)
                let full = try await M5.discover(ProjectArtifactsInspector(), env, "project.nodeModules")
                try TestSuite.assertTrue(full.candidates.allSatisfy { !$0.notes.contains { $0.contains("stopped after") } })

                let rule = try M5.rule(env, "project.nodeModules")
                let environment = env.environment
                let cancelled = await M5.cancelled { await ProjectArtifactsInspector().discover(rule: rule, environment: environment) }
                try TestSuite.assertTrue(cancelled.candidates.isEmpty)
                try TestSuite.assertEqual(cancelled.status, .failed("Scan cancelled"))
            }
        }
    }

    // MARK: Project roots

    @MainActor
    static func rootTests() async {
        await TestSuite.run("ProjectScanner: no project roots → every project rule is unavailable and nothing is walked") {
            try await M1.withEnv { env in
                let f = env.fixture
                try project(f, root + "/app", files: ["package-lock.json"], dirs: ["node_modules"])
                try project(f, "Developer/app", files: ["package-lock.json"], dirs: ["node_modules"])
                try TestSuite.assertEqual(env.scanSettings.projectRoots, [], "no roots by default (suggestions are only offered)")
                try TestSuite.assertTrue(ScanSettings.suggestedProjectRoots.contains("~/Developer"))
                let results = try await M5.scan(env, Set(projectRuleIDs))
                for id in projectRuleIDs {
                    guard case .unavailable = results[id]?.status else { throw TestError("\(id): \(String(describing: results[id]?.status))") }
                    try TestSuite.assertEqual(results[id]?.targets.count, 0, id)
                }
                let direct = try await M5.discover(ProjectArtifactsInspector(), env, "project.nodeModules")
                guard case .unavailable = direct.status else { throw TestError("\(direct.status)") }
                try TestSuite.assertFalse(env.fileSystem.recordedCalls.contains { $0.0 == .contentsOfDirectory && $0.1.contains("/app") })
            }
        }

        await TestSuite.run("ProjectScanner: a root outside HOME, HOME itself, deny-listed, cloud-synced, symlinked, relative or with '..' is rejected") {
            try await M1.withEnv { env in
                let f = env.fixture
                let pair = (files: ["package-lock.json"], dirs: ["node_modules"])
                try project(f, root + "/app", files: pair.files, dirs: pair.dirs)
                try project(f, "outside/app", files: pair.files, dirs: pair.dirs)
                try project(f, "Documents/code/app", files: pair.files, dirs: pair.dirs)
                try project(f, "Library/CloudStorage/Dropbox/code/app", files: pair.files, dirs: pair.dirs)
                try project(f, "Library/Mobile Documents/com~apple~CloudDocs/code/app", files: pair.files, dirs: pair.dirs)
                try f.dir("rootOutside/app", base: .root)
                try f.file("rootOutside/app/package-lock.json", bytes: 1, base: .root)
                try f.file("rootOutside/app/node_modules/x", bytes: 1, base: .root)
                try f.symlink("LinkedProjects", to: f.path(root))
                let bad = [f.home, f.home + "/", f.path("rootOutside", base: .root), f.path("Documents/code"),
                           f.path("Library/CloudStorage/Dropbox/code"), f.path("Library/Mobile Documents/com~apple~CloudDocs/code"),
                           f.path("LinkedProjects"), "Projects", f.path("outside/../Projects"), f.path("missing"),
                           " " + f.path(root), f.path(root + "/app/node_modules")]
                for raw in bad {
                    useRoots(env, [raw])
                    try TestSuite.assertEqual(ProjectRoots.resolve(environment: env.environment, waivedSystemRoots: [f.root]), [], raw)
                    let out = try await M5.discover(ProjectArtifactsInspector(), env, "project.nodeModules")
                    try TestSuite.assertTrue(out.candidates.isEmpty, raw)
                    guard case .unavailable = out.status else { throw TestError("\(raw): \(out.status)") }
                    let results = try await M5.scan(env, ["project.nodeModules"])
                    try TestSuite.assertEqual(results["project.nodeModules"]?.targets.count, 0, raw)
                }
                // Mixed: only the valid roots are used; "~/" spelling is accepted.
                useRoots(env, bad + ["~/" + root, f.path("outside")])
                try TestSuite.assertEqual(try await discovered(env, "project.nodeModules"), [root + "/app/node_modules", "outside/app/node_modules"])
                // A root nested inside another selected root is not walked twice.
                useRoots(env, [f.path(root), f.path(root + "/app")])
                try TestSuite.assertEqual(try await discovered(env, "project.nodeModules"), [root + "/app/node_modules"])

                // SafetyGate rejects a project target outside the configured roots at plan time.
                useRoots(env)
                let rule = try M5.rule(env, "project.nodeModules")
                let foreign = env.scanTarget(ruleID: rule.id, path: "outside/app/node_modules")
                let verdict = await env.makeGate().validate(target: foreign, rule: rule, phase: .plan)
                guard case .rejected = verdict else { throw TestError("expected rejection, got \(verdict)") }
                useRoots(env, [])
                let none = await env.makeGate().validate(target: env.scanTarget(ruleID: rule.id, path: root + "/app/node_modules"),
                                                         rule: rule, phase: .plan)
                guard case .rejected = none else { throw TestError("no roots must reject, got \(none)") }
            }
        }
    }

    // MARK: git

    @MainActor
    static func gitTests() async {
        await TestSuite.run("ProjectScanner: notTrackedByGit — only a clean 'pathspec did not match' passes; exit 0, timeout, other errors, unresolvable or non-system git → tracked") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                try project(f, root + "/repo", files: ["package-lock.json", ".git/HEAD", ".git/index"], dirs: ["node_modules", ".git/objects"])
                let rule = try M5.rule(env, "project.nodeModules")
                let artifact = f.path(root + "/repo/node_modules")
                let args = CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(root + "/repo"), artifactName: "node_modules")
                @MainActor func check(_ result: CommandResult?, git: String? = "/usr/bin/git") async throws -> PreconditionResult {
                    env.commands.executables = [:]
                    env.commands.responses = [:]
                    try M5.useGit(env, git: git)
                    if let result { env.commands.setResponse(result, for: args) }
                    return await M5.evaluate(env, .notTrackedByGit, path: artifact, rule: rule)
                }
                let untracked = CommandResult(exitCode: 1, stdout: "", stderr: M5.gitUntrackedStderr)
                try TestSuite.assertTrue(try await check(untracked).passed)
                let invocation = try M5.unwrap(env.commands.invocations.last)
                try TestSuite.assertEqual(invocation.executable, M5.gitPath)
                try TestSuite.assertEqual(invocation.arguments, args)
                try TestSuite.assertEqual(invocation.purpose, .readOnly)
                try TestSuite.assertEqual(Array(args.prefix(5)), ["--no-optional-locks", "--icase-pathspecs", "-c", "core.fsmonitor=false", "-C"])

                let tracked: [(String, CommandResult?, String?)] = [
                    ("exit 0 (tracked)", CommandResult(exitCode: 0, stdout: "node_modules/x\n", stderr: ""), M5.gitPath),
                    ("timeout", CommandResult(exitCode: 1, stdout: "", stderr: M5.gitUntrackedStderr, timedOut: true), M5.gitPath),
                    ("not a repository", CommandResult(exitCode: 128, stdout: "", stderr: "fatal: not a git repository"), M5.gitPath),
                    ("exit 1 other error", CommandResult(exitCode: 1, stdout: "", stderr: "error: something else"), M5.gitPath),
                    ("exit 2 with pathspec text", CommandResult(exitCode: 2, stdout: "", stderr: M5.gitUntrackedStderr), M5.gitPath),
                    ("no fake response (runner failure)", nil, M5.gitPath),
                    ("git does not resolve", untracked, nil),
                    ("non-system git", untracked, "/opt/homebrew/bin/git"),
                ]
                for (label, result, git) in tracked {
                    let outcome = try await check(result, git: git)
                    try TestSuite.assertFalse(outcome.passed, label)
                }

                // No .git anywhere up to HOME → passes without running git.
                try project(f, root + "/plain", files: ["package-lock.json"], dirs: ["node_modules"])
                let before = env.commands.invocations.count
                let plain = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/plain/node_modules"), rule: rule)
                try TestSuite.assertTrue(plain.passed, plain.detail)
                try TestSuite.assertEqual(env.commands.invocations.count, before, "git is not run without a repository")

                // Monorepo: .git above the project → treated as tracked WITHOUT asking git (review M5:
                // git's cwd prefix would be matched case-sensitively), even when git would say untracked.
                try project(f, root + "/mono", files: [".git/HEAD"])
                try project(f, root + "/mono/pkg", files: ["package-lock.json"], dirs: ["node_modules"])
                let monoArgs = CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(root + "/mono/pkg"), artifactName: "node_modules")
                try M5.useGit(env)
                env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: M5.gitUntrackedStderr), for: monoArgs)
                let beforeMono = env.commands.invocations.count
                let mono = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/mono/pkg/node_modules"), rule: rule)
                try TestSuite.assertFalse(mono.passed)
                try TestSuite.assertEqual(env.commands.invocations.count, beforeMono, "git is not run for a monorepo member")
                // …and the scanner does not even propose an artifact whose own project is not the repository.
                let offered = try await discovered(env, "project.nodeModules")
                try TestSuite.assertFalse(offered.contains(root + "/mono/pkg/node_modules"))
                try TestSuite.assertTrue(offered.contains(root + "/repo/node_modules"))

                // Every command the scan + evaluation issued was read-only.
                try TestSuite.assertTrue(env.commands.purposes.allSatisfy { $0 == .readOnly })
            }
        }

        await TestSuite.run("ProjectScanner: the git probe's {PATH} must be clean, absolute and inside a configured project root; {NAME} a reviewed artifact name") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                try project(f, root + "/repo", files: ["package-lock.json", ".git/HEAD"], dirs: ["node_modules"])
                try project(f, "Other/repo", files: ["package-lock.json", ".git/HEAD"], dirs: ["node_modules"])
                let roots = ProjectRoots.resolve(environment: env.environment, waivedSystemRoots: [f.root])
                try TestSuite.assertEqual(roots.map(\.path), [f.path(root)])
                func allowed(_ path: String, _ name: String = "node_modules") -> Bool {
                    CommandAllowList.gitProbeAllowed(arguments: CommandAllowList.gitTrackedProbeArguments(projectDirectory: path, artifactName: name),
                                                     projectRoots: roots)
                }
                try TestSuite.assertTrue(allowed(f.path(root + "/repo")))
                try TestSuite.assertTrue(allowed(f.path(root)))
                try TestSuite.assertFalse(allowed(f.path("Other/repo")), "outside the project roots")
                try TestSuite.assertFalse(allowed(f.home), "home itself")
                try TestSuite.assertFalse(allowed(f.path(root + "/repo/../../Other/repo")), "..")
                try TestSuite.assertFalse(allowed(f.path(root + "/repo") + "/"), "trailing slash")
                try TestSuite.assertFalse(allowed("Projects/repo"), "relative")
                try TestSuite.assertFalse(allowed("--exec=/bin/sh"), "option")
                try TestSuite.assertFalse(allowed(f.path(root + "/repo"), "src"), "unreviewed name")
                try TestSuite.assertFalse(allowed(f.path(root + "/repo"), "../x"), "path as name")
                try TestSuite.assertFalse(allowed(f.path(root + "/repo"), "-x"), "option as name")
                try TestSuite.assertFalse(CommandAllowList.gitProbeAllowed(
                    arguments: CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(root + "/repo"), artifactName: "node_modules"),
                    projectRoots: []), "no roots configured")
                // Never as an action, never other git subcommands, never another -c setting.
                let args = CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(root + "/repo"), artifactName: "node_modules")
                try TestSuite.assertFalse(CommandAllowList.matches(tool: "git", arguments: args, purpose: .action))
                var hooked = args; hooked[3] = "core.fsmonitor=/tmp/evil"
                try TestSuite.assertFalse(CommandAllowList.matches(tool: "git", arguments: hooked, purpose: .readOnly))
                try TestSuite.assertFalse(CommandAllowList.matches(tool: "git", arguments: ["-C", f.path(root + "/repo"), "clean", "-fdx"], purpose: .readOnly))
                try TestSuite.assertFalse(CommandAllowList.matches(tool: "git", arguments: ["-C", f.path(root + "/repo"), "ls-files", "--error-unmatch", "--", "node_modules"], purpose: .readOnly))

                // The evaluator never runs git for an artifact outside the roots.
                env.commands.executables = ["git": M5.gitPath]
                env.commands.responses = [:]
                let rule = try M5.rule(env, "project.nodeModules")
                let outside = await M5.evaluate(env, .notTrackedByGit, path: f.path("Other/repo/node_modules"), rule: rule)
                try TestSuite.assertFalse(outside.passed)
                try TestSuite.assertTrue(env.commands.invocations.isEmpty, "\(env.commands.invocations)")
                // Nor through a symlinked project folder.
                try f.symlink(root + "/alias", to: f.path("Other/repo"))
                let alias = await M5.evaluate(env, .notTrackedByGit, path: f.path(root + "/alias/node_modules"), rule: rule)
                try TestSuite.assertFalse(alias.passed)
                try TestSuite.assertTrue(env.commands.invocations.isEmpty)
            }
        }
    }

    // MARK: projectOlderThan

    @MainActor
    static func ageTests() async {
        await TestSuite.run("ProjectScanner: projectOlderThan uses manifest / .git mtimes — a recent project is blocked at plan time even when the artifact is old") {
            try await M1.withEnv { env in
                let f = env.fixture
                useRoots(env)
                let p = root + "/"
                for name in ["old", "recentLock", "recentIndex", "recentHead", "recentToml", "noManifest", "gitFile"] {
                    try project(f, p + name, files: ["package-lock.json"], dirs: ["node_modules/pkg"])
                }
                for name in ["recentIndex", "recentHead"] {
                    try f.file(p + name + "/.git/HEAD", bytes: 10)
                    try f.file(p + name + "/.git/index", bytes: 10)
                    try f.dir(p + name + "/.git/objects")
                }
                try f.file(p + "recentToml/Cargo.toml", bytes: 10)
                try f.file(p + "gitFile/.git", bytes: 10) // a worktree/submodule .git FILE
                // Everything 200 days old …
                for name in ["old", "recentLock", "recentIndex", "recentHead", "recentToml", "noManifest", "gitFile"] {
                    for rel in ["", "/package-lock.json", "/node_modules", "/node_modules/pkg", "/.git", "/.git/HEAD", "/.git/index",
                                "/.git/objects", "/Cargo.toml"] where FileManager.default.fileExists(atPath: f.path(p + name + rel)) {
                        try f.setModificationDate(p + name + rel, daysAgo: 200, clock: env.clock)
                    }
                }
                // … except one input per project.
                try f.setModificationDate(p + "recentLock/package-lock.json", daysAgo: 5, clock: env.clock)
                try f.setModificationDate(p + "recentIndex/.git/index", daysAgo: 3, clock: env.clock)
                try f.setModificationDate(p + "recentHead/.git/HEAD", daysAgo: 1, clock: env.clock)
                try f.setModificationDate(p + "recentToml/Cargo.toml", daysAgo: 10, clock: env.clock)

                let rule = try M5.rule(env, "project.nodeModules")
                @MainActor func older(_ name: String) async -> PreconditionResult {
                    await M5.evaluate(env, .projectOlderThan(days: 90), path: f.path(p + name + "/node_modules"), rule: rule)
                }
                try TestSuite.assertTrue(await older("old").passed)
                for name in ["recentLock", "recentIndex", "recentHead", "recentToml", "gitFile"] {
                    try TestSuite.assertFalse(await older(name).passed, name)
                }
                // No manifest and no .git readable → false.
                try FileManager.default.removeItem(atPath: f.path(p + "noManifest/package-lock.json"))
                try TestSuite.assertFalse(await older("noManifest").passed)
                // A user override can only RAISE the threshold.
                env.scanSettings = ScanSettings(projectRoots: [f.path(root)], ageThresholdOverrides: ["project.nodeModules": 365])
                try TestSuite.assertFalse(await older("old").passed, "raised to 365 days")
                env.scanSettings = ScanSettings(projectRoots: [f.path(root)], ageThresholdOverrides: ["project.nodeModules": 1])
                try TestSuite.assertTrue(await older("old").passed, "an override can never lower 90")
                env.scanSettings = ScanSettings(projectRoots: [f.path(root)], ageThresholdOverrides: ["project.nodeModules": 1])

                // Plan time: git untracked everywhere; only the old project is actionable, and it is never preselected.
                try M5.useGit(env)
                for name in ["recentIndex", "recentHead"] {
                    env.commands.setResponse(CommandResult(exitCode: 1, stdout: "", stderr: M5.gitUntrackedStderr),
                                             for: CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(p + name), artifactName: "node_modules"))
                }
                let results = try await M5.scan(env, ["project.nodeModules"])
                let plan = await M5.plan(env, Array(results.values))
                let old = try M5.item(plan, p + "old/node_modules", f)
                try TestSuite.assertTrue(old.isActionable, "\(old.preconditions.filter { !$0.passed })")
                try TestSuite.assertFalse(old.selectedByDefault)
                for name in ["recentLock", "recentIndex", "recentHead", "recentToml"] {
                    let item = try M5.item(plan, p + name + "/node_modules", f)
                    try TestSuite.assertFalse(item.isActionable, name)
                    try TestSuite.assertEqual(M5.failedPrecondition(item), "projectOlderThan", name)
                }
                try TestSuite.assertTrue(plan.items.allSatisfy { !$0.selectedByDefault })

                // A running tool (node) blocks every project item.
                env.processes.names = ["launchd", "node"]
                let blocked = await M5.plan(env, Array(try await M5.scan(env, ["project.nodeModules"]).values))
                try TestSuite.assertFalse(try M5.item(blocked, p + "old/node_modules", f).isActionable)
                // Git says tracked → blocked.
                env.processes.names = ["launchd"]
                try f.file(p + "old/.git/HEAD", bytes: 1)
                try f.setModificationDate(p + "old/.git/HEAD", daysAgo: 200, clock: env.clock)
                try f.setModificationDate(p + "old/.git", daysAgo: 200, clock: env.clock)
                try f.setModificationDate(p + "old", daysAgo: 200, clock: env.clock)
                env.commands.setResponse(CommandResult(exitCode: 0, stdout: "node_modules/pkg/x\n", stderr: ""),
                                         for: CommandAllowList.gitTrackedProbeArguments(projectDirectory: f.path(p + "old"), artifactName: "node_modules"))
                let trackedPlan = await M5.plan(env, Array(try await M5.scan(env, ["project.nodeModules"]).values))
                let trackedItem = try M5.item(trackedPlan, p + "old/node_modules", f)
                try TestSuite.assertFalse(trackedItem.isActionable)
                try TestSuite.assertEqual(M5.failedPrecondition(trackedItem), "notTrackedByGit")
            }
        }
    }
}
