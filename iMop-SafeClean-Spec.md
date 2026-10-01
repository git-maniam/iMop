# iMop — "SafeClean" Junk Reclaim Feature
## Engineering Specification & Code-Generation Prompt (Claude Code)

> **Read this entire document before writing any code.**
> The #1 requirement of this feature is **SAFETY**: iMop must never break macOS, never break an installed application, and never destroy user data. Reclaiming space is the secondary goal. When safety and reclaimed bytes conflict, **safety wins, every time**. When in doubt, **skip the item and log why**.

---

## 0. Instructions to Claude Code

1. You are building the **SafeClean** feature of **iMop**, a macOS storage-reclaim utility for **macOS 26 Tahoe and later**.
2. Work **milestone by milestone** (Section 13). Do **not** start a milestone until the previous one's acceptance criteria pass.
3. **Write the Safety layer and its tests FIRST (Milestone 1).** No code that mutates the filesystem may be written until the `SafetyGate` test suite passes.
4. **Tests must never touch the real user's files.** All filesystem access goes through an injectable `Environment` (home directory, volume root, process list, clock). Tests run against a temporary fixture tree.
5. **Debug builds are dry-run only by default.** A compile-time flag `IMOP_ALLOW_MUTATION` must be explicitly set for any build that can delete/move files. Without it, the `Executor` must refuse every mutation and log `"mutation disabled in this build"`.
6. Never run any shell command through `/bin/sh -c`. Never use `sudo`. Never request root.
7. If any requirement here is ambiguous, choose the **more conservative** interpretation and leave a `// SAFETY-DECISION:` comment explaining the choice.
8. Do not add features not described here (no "RAM cleaning", no language-file stripping, no binary thinning, no "speed boost").

---

## 1. Product Summary

SafeClean finds recognizable, well-understood junk (caches, build artifacts, stale developer tooling, leftover installer files, orphaned app data), shows the user **exactly** what it is, **where** it is, **how big** it is (accurately), **what they lose** by removing it, and **how it regenerates** — then removes only what the user approves, in a recoverable way.

**Trust promises (must be true in code):**
- iMop never touches `/System`, the Signed System Volume, or any SIP-protected path.
- iMop never deletes anything inside iCloud Drive or any cloud-sync folder.
- iMop never modifies files *inside* an application bundle.
- iMop never runs as root and never escalates privileges (v1).
- iMop makes **no network connections** (v1). No telemetry.
- Every removal is logged; most removals are restorable for a retention period.

---

## 2. Technical Baseline

| Item | Requirement |
|---|---|
| Language | Swift 6 (strict concurrency enabled) |
| UI | SwiftUI, standard system controls (inherit Tahoe's Liquid Glass look automatically; no custom chrome) |
| Deployment target | macOS 26.0 |
| Architectures | arm64 + x86_64 (Tahoe still supports some Intel Macs) |
| Distribution | Developer ID, Hardened Runtime, Notarized. **Not sandboxed** (App Store sandbox cannot access the required paths). |
| Entitlements | Hardened Runtime only. No network client/server entitlement. No `get-task-allow` in release. |
| Permissions | Full Disk Access (required for Containers, Mail, Safari caches). App Management (only needed for trashing other `.app` bundles, e.g. old Xcode / macOS installers). |
| Dependencies | **None** beyond Apple SDKs. No third-party packages. |
| Structure | Swift Package `iMopCore` (all logic, fully unit-testable, no UI) + app target `iMop` (SwiftUI). |

### 2.1 Module Layout

```
iMopCore/
  Environment/        Environment.swift (injectable: home, clock, fs, processes, volumes)
  Safety/             SafetyGate.swift, DenyList.swift, PathCanonicalizer.swift, Preconditions.swift
  Rules/              Rule.swift, RuleCatalog.swift, Rules.json (bundled resource)
  Discovery/          Scanner.swift, ProjectScanner.swift, OrphanDetector.swift,
                      XcodeInspector.swift, SimctlClient.swift, DockerClient.swift, ...
  Sizing/             SizeCalculator.swift (allocated + APFS private size)
  Planning/           CleanupPlan.swift, PlanBuilder.swift
  Execution/          Executor.swift, Quarantine.swift, CommandRunner.swift
  Audit/              AuditLog.swift (JSONL)
  Permissions/        FullDiskAccessProbe.swift, AppManagementProbe.swift
Tests/
  iMopCoreTests/      SafetyGateTests, CanonicalizerTests, PreconditionTests, ScannerTests,
                      ExecutorTests, QuarantineTests, RuleCatalogTests, FixtureBuilder.swift
iMop/ (app)
  Views/              ScanView, CategoryListView, ItemDetailView, ReviewSheet,
                      ProgressView, ResultsView, QuarantineView, SettingsView, PermissionsView
```

---

## 3. Safety Architecture (the heart of this feature)

### 3.1 The Pipeline — Read-Only Until the Very Last Step

```
Scan (read-only) → Classify (Rule match) → Size → Precondition check
  → Build CleanupPlan (immutable) → User Review & Confirm
  → Executor: re-validate EVERY item through SafetyGate → act → Audit log
```

- **Scanner, Sizer, PlanBuilder are strictly read-only.** They must not import or call any mutation API. Enforce with a code review rule + a test that greps the `Discovery/`, `Sizing/`, `Planning/` sources for `removeItem`, `trashItem`, `moveItem`, `unlink`, `rmdir`, `removefile`, `rename` and fails if found.
- **The Executor's only public entry point is `execute(_ plan: ConfirmedPlan)`.** There is **no** `delete(path:)` API anywhere in the codebase.
- `ConfirmedPlan` can only be constructed from a `CleanupPlan` + explicit user confirmation (UI action). It carries a SHA-256 hash of the plan contents; the Executor verifies the hash before starting.

### 3.2 Safety Tiers

Every rule has exactly one tier. Tier controls default selection, action type, and confirmation level.

| Tier | Meaning | Default selected? | Action | Confirmation |
|---|---|---|---|---|
| **Green** | Pure caches; regenerate automatically; only cost is slower first launch | Yes | Quarantine (24 h retention) | Single review sheet |
| **Yellow** | Rebuildable/re-downloadable but costs time, bandwidth, or convenience | **No** | Quarantine (7-day retention) **or** vendor command | Review sheet + per-category checkbox + "what you lose" text shown |
| **Red** | User-owned data or hard-to-recover items | **No, never** | Move to Finder Trash, one item at a time | Per-item confirmation dialog naming the item |
| **Advisory** | iMop explains and guides but does **not** act (root needed, app-managed, or too risky) | N/A | "Reveal in Finder" / "Open App" / show instructions | N/A |

### 3.3 The SafetyGate — Hard Invariants

`SafetyGate.validate(target: Target, rule: Rule, env: Environment) -> SafetyVerdict` is called **twice per item**: once at plan time and again **immediately before** acting (to defeat TOCTOU races). Any failure → item is skipped with a reason; execution continues with the next item.

All checks are mandatory and executed in this order:

1. **Process identity**: refuse to run if `geteuid() == 0`.
2. **Canonicalize** the path (Section 3.4). If canonicalization fails → reject.
3. **Absolute deny-list** (Section 3.5) — prefix match on canonical path. Deny-list **always wins** over any rule, user setting, or allow-root.
4. **Allow-root containment**: canonical path must be *strictly inside* one of the rule's declared `allowRoots` (after canonicalizing the roots too). Equality with an allow-root is **rejected** (never delete `~/Library/Caches` itself — only its children).
5. **Minimum depth**: canonical path must have at least `rule.minDepthBelowRoot` (default 1) components below the allow-root.
6. **No symlink at any level**: `lstat` each component from the allow-root down to the target. If the target or any intermediate component is a symlink → reject. (The target symlink itself may be removed only if rule says `allowSymlinkTarget: true`; default false.)
7. **Same volume**: `st_dev` of target must equal `st_dev` of its allow-root. Reject mount-point crossings (protects external drives, network shares, disk images, FUSE mounts).
8. **Ownership**: `st_uid` of target must equal `getuid()`. (We never remove files owned by root or other users.)
9. **Identity pinning**: `(st_dev, st_ino)` captured at scan time must match at execution time. If not → reject (`"item changed since scan"`).
10. **Cloud-sync guard**: reject if the path is inside any cloud root (Section 3.5) **or** `URLResourceValues.isUbiquitousItem == true` **or** the item carries File Provider extended attributes (`com.apple.fileprovider.*`, `com.apple.file-provider-domain-id`).
11. **Bundle guard**: reject if any ancestor component ends with `.app`, `.framework`, `.bundle`, `.plugin`, `.kext`, `.systemextension`, `.appex` — **unless** the rule's action is "trash entire app bundle" and the target *is* the bundle root (Section 6.6).
12. **Preconditions** (Section 3.6) declared by the rule all pass.
13. **Sanity limits**: if a single target exceeds `rule.maxExpectedBytes` (default 200 GB) or `rule.maxExpectedItems` (default 2,000,000 files), downgrade to **Red** for manual review instead of acting. Unexpectedly huge matches often mean a mis-match.
14. **User exclusions**: reject if the path is inside any user-configured exclusion.

`SafetyVerdict` = `.allowed` | `.rejected(reason: SafetyRejection)`. Every rejection is written to the audit log.

### 3.4 Path Canonicalization Rules

- Expand `~` / `{HOME}` from `Environment.homeDirectory` (never from `$HOME` directly in production code paths that tests can't control).
- Standardize (`..`, `.`, duplicate slashes). **Reject any input path containing a `..` component before standardizing** (rules and plan items must never contain them).
- Resolve with `URLResourceKey.canonicalPathKey` and `realpath(3)`; they must agree, else reject.
- Map firmlinks: if the canonical path begins with `/System/Volumes/Data/`, strip that prefix to obtain the logical path, then apply deny/allow checks to the **logical** path; any other path beginning with `/System/` is denied.
- `/var`, `/tmp`, `/etc` → their `/private/...` forms before checks.
- Comparisons are **case-insensitive and Unicode-normalization-insensitive** (APFS default). Compare using `precomposedStringWithCanonicalMapping` + `lowercased()` on both sides, component-wise (never raw string `hasPrefix` — `/Users/a/Lib` must not match `/Users/a/Library`).

### 3.5 Absolute Deny-List (hard-coded in Swift, NOT in Rules.json)

System:
```
/System            (all, including /System/Volumes/* except via firmlink mapping above)
/bin  /sbin  /usr  /opt   (Homebrew under /opt/homebrew is handled ONLY via `brew` commands)
/private/etc  /private/var/db  /private/var/vm  /private/var/folders  /private/var/root
/private/var/log  /private/var/run  /private/tmp (v1)
/Library           (v1: everything — root-owned; Advisory only)
/Applications/Utilities
/Volumes           (v1: no external volumes)
/cores             (except rule `system.coreDumps` with ownership check)
/.Spotlight-V100  /.fseventsd  /.DocumentRevisions-V100  /.MobileBackups  /.vol
```
User (relative to home):
```
~/Library/Keychains
~/Library/Mobile Documents            (iCloud Drive — deletion propagates to the cloud!)
~/Library/CloudStorage                (Dropbox/OneDrive/Google Drive/Box — same)
~/Library/Mail
~/Library/Messages
~/Library/Photos
~/Library/Accounts
~/Library/Cookies
~/Library/HTTPStorages
~/Library/Safari
~/Library/Calendars  ~/Library/Reminders  ~/Library/Contacts (Application Support/AddressBook)
~/Library/Application Support/AddressBook
~/Library/Application Support/MobileSync     (iOS backups — Advisory/Reveal only)
~/Library/Application Support/com.apple.TCC
~/Library/Application Support/iMop            (except via Quarantine module itself)
~/Library/Group Containers/group.com.apple.*  (Notes, etc.)
~/Library/Containers/com.apple.*              (except explicit Apple cache rules, e.g. Mail Downloads)
~/Library/Preferences/com.apple.*
~/Library/LaunchAgents/com.apple.*
~/.ssh  ~/.gnupg  ~/.aws  ~/.kube  ~/.docker/config.json  ~/.config/gh  ~/.netrc
~/Documents ~/Desktop ~/Pictures ~/Movies ~/Music      (v1: only Red "reveal" flows may reference these)
Any path with extension: .photoslibrary .musiclibrary .tvlibrary .lrcat .fcpbundle .logicx .band .sparsebundle .keychain-db
Any git repository's .git directory
```
Write a dedicated test for **every** entry in this list, including symlink-to-denied-path and case-variant attacks.

### 3.6 Preconditions (named, reusable predicates)

| Predicate | Semantics |
|---|---|
| `appNotRunning([bundleID])` | None of the bundle IDs appear in `NSWorkspace.shared.runningApplications`. Supports trailing wildcard (`com.adobe.*`). |
| `processNotRunning([name])` | No process with that executable name (use `libproc` `proc_listallpids` + `proc_name`). E.g. `node`, `npm`, `gradle`, `xcodebuild`, `brew`. |
| `notOpenByAnyProcess` | No process holds an open file under the target (`proc_listpidspath` on the target path). Treat errors as "open" (fail closed). |
| `olderThan(days)` | `lastUsed` older than N days. `lastUsed = max(mtime(target), mtime(each immediate child))`. Never rely on atime. |
| `manifestPresent([filenames])` | For project artifacts: at least one rebuild manifest exists beside the artifact (e.g. `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`, `bun.lock`, `Cargo.lock`, `Podfile.lock`, `pyproject.toml`, `requirements.txt`, `uv.lock`, `poetry.lock`). |
| `notInsideCloudRoot` | See 3.3 #10. |
| `ownedByUser` | See 3.3 #8. |
| `simulatorIdle` | `xcrun simctl list devices -j` reports no device in state `Booted`, and `com.apple.iphonesimulator` not running. |
| `dockerDaemonReachable` | `docker info` exits 0 within 5 s. If not, Docker rules are skipped (never start Docker automatically). |
| `notMounted` | For `.dmg`/`.iso`: not present in `hdiutil info -plist` image-path list. |
| `appleSigned` | `SecStaticCodeCheckValidity` passes with requirement `anchor apple` (for macOS installers / Xcode bundles). |
| `notSelectedXcode` | Bundle is not the developer dir returned by `xcode-select -p`. |
| `uploadedToCloud` | (iCloud eviction only) `isUbiquitousItem && isUploaded && !hasUnresolvedConflicts && downloadingStatus == .current`. |

If a predicate **cannot be evaluated** (error, timeout), it evaluates to **false** (fail closed).

---

## 4. Rule Model (data-driven)

Rules live in `Rules.json` bundled inside the signed app (immutable at runtime; never downloaded). Rules can only **narrow** what is allowed; the Swift deny-list and SafetyGate always apply on top.

```swift
struct Rule: Codable, Sendable, Identifiable {
    let id: String                     // "xcode.derivedData.orphaned"
    let version: Int
    let category: Category             // .developer, .browsers, .apps, .system, .media, .ai, .downloads, .leftovers
    let tier: Tier                     // .green, .yellow, .red, .advisory
    let title: String                  // "Orphaned Xcode DerivedData"
    let explanation: String            // What it is
    let whatYouLose: String            // Shown verbatim in UI
    let howItRegenerates: String       // Shown verbatim in UI
    let discovery: Discovery           // .glob(pattern) | .command(CommandSpec) | .inspector(InspectorID)
    let allowRoots: [String]           // templated with {HOME}; must be ⊂ allowed root universe
    let minDepthBelowRoot: Int         // default 1
    let preconditions: [Precondition]
    let action: Action                 // .quarantine | .trash | .command(CommandSpec) | .advisory(AdvisoryKind)
    let retentionHours: Int?           // quarantine retention override
    let maxExpectedBytes: Int64?
    let maxExpectedItems: Int?
    let allowSymlinkTarget: Bool       // default false
}
```

**Glob grammar** (keep it deliberately tiny): `{HOME}` token, literal segments, and `*` matching exactly one path segment. **No `**`**, no regex, no brace expansion. Recursive discovery is only permitted inside dedicated Inspectors (ProjectScanner) with explicit depth limits.

**RuleCatalog validation at launch (and in tests):** every rule's `allowRoots` must be under `{HOME}` (v1), must not intersect the deny-list, `id`s unique, Green rules must not use `.trash` or `.command` that isn't marked `idempotentSafe`, and Red rules must use `.trash` or `.advisory` only. Any invalid rule → rule disabled + logged; app continues.

---

## 5. Execution, Quarantine & Commands

### 5.1 Quarantine (default action for Green & Yellow filesystem items)

- Location: `{HOME}/Library/Application Support/iMop/Quarantine/<session-UUID>/` — same APFS volume as home, so moving is an atomic `rename(2)` (instant, no copy).
- Use `renamex_np(src, dst, RENAME_EXCL)` — never overwrite. If the item is **not** on the same volume → skip (v1 never copies).
- Write `manifest.json` per session: original canonical path, `(dev, ino)`, size, rule id, timestamp, tier.
- Create `.metadata_never_index` in the Quarantine root (keep Spotlight out).
- **Restore**: moves back with `RENAME_EXCL`. If original path now exists, restore to `<name> (restored <date>)` beside it — never overwrite.
- **Purge**: items past retention are permanently removed on app launch / daily timer, and on explicit "Empty Quarantine Now". Purge uses `removefile(3)` with `REMOVEFILE_RECURSIVE` (does not follow symlinks) and runs every item through `SafetyGate` with `allowRoots = [QuarantineRoot]`.
- UI must clearly state: *"Space from quarantined items is freed when quarantine is emptied. Empty now to reclaim immediately."*

### 5.2 Trash (Red tier, app bundles)

- `FileManager.trashItem(at:resultingItemURL:)` only. Never empty the Trash automatically.

### 5.3 Vendor Commands (`CommandRunner`)

Prefer the owning tool's own cleanup command whenever one exists — it keeps the tool's internal databases consistent.

- `Process` with **absolute executable path** and **argument array** — never a shell string.
- Executable resolution: only from a fixed list of trusted locations (`/usr/bin/xcrun`, `/opt/homebrew/bin/*`, `/usr/local/bin/*`, `{HOME}/.cargo/bin/*`, `{HOME}/go/bin`, `{HOME}/.bun/bin`, `{HOME}/.local/bin`). Verify the file is executable, owned by the user or root, and not world-writable.
- Sanitized environment: `PATH` set to trusted dirs only; inherit `HOME`, `USER`, `LANG`; nothing else.
- Hard timeout per command (default 10 min; `simctl runtime delete` 30 min). On timeout: terminate, log, mark failed.
- Capture stdout/stderr to the audit log (truncate at 64 KB).
- Every `CommandSpec` has an optional `dryRun` variant used during Scan to estimate size (e.g. `brew cleanup --prune=all -n`, `docker system df`).
- Command actions are **not restorable**: UI must display "This cannot be undone. <tool> will re-download what it needs."

### 5.4 Executor Behavior

- Single executor at a time (actor). Items processed sequentially.
- Cancellation honored **between** items, never mid-item.
- For each item: `SafetyGate.validate` (again) → act → verify outcome → audit.
- After the run, measure `volumeAvailableCapacityForImportantUsage` before/after and show **both** estimated and measured reclaim; explain discrepancies (Section 7.3).

### 5.5 Audit Log

`{HOME}/Library/Logs/iMop/audit-YYYY-MM.jsonl` — one JSON object per event: timestamp, session, rule id, path, action, bytes, verdict, rejection reason, command exit code. Exportable from the UI. Never contains file *contents*.

---

## 6. Rule Catalog (v1)

> Paths use `{HOME}`. "Q" = Quarantine, "T" = Trash, "CMD" = vendor command, "ADV" = Advisory.
> All rules implicitly include `ownedByUser`, `notInsideCloudRoot`, and full SafetyGate checks.

### 6.1 Developer — Xcode & Simulators

| ID | Tier | Discovery / Target | Preconditions | Action |
|---|---|---|---|---|
| `xcode.derivedData.orphaned` | Green | `{HOME}/Library/Developer/Xcode/DerivedData/*` where `info.plist → WorkspacePath` **no longer exists** (XcodeInspector) | `appNotRunning(com.apple.dt.Xcode)`, `processNotRunning(xcodebuild)` | Q |
| `xcode.derivedData.active` | Yellow | Same folder, WorkspacePath exists | same + `olderThan(14)` | Q |
| `xcode.previews` | Green | `{HOME}/Library/Developer/Xcode/UserData/Previews/*` | Xcode not running | Q |
| `xcode.docCache` | Green | `{HOME}/Library/Developer/Xcode/DocumentationCache/*` | Xcode not running | Q |
| `xcode.archives.old` | Yellow | `{HOME}/Library/Developer/Xcode/Archives/*/*.xcarchive` — parse `Info.plist` (`ApplicationProperties.CFBundleIdentifier`, `CreationDate`); **keep newest 3 per bundle ID** (user-configurable) | Xcode not running | Q (7 d). `whatYouLose`: "dSYMs needed to symbolicate crash reports for these builds." |
| `xcode.deviceSupport` | Yellow | `{HOME}/Library/Developer/Xcode/{iOS,watchOS,tvOS,visionOS} DeviceSupport/*` — parse OS version from folder name; never preselect; highlight versions older than newest-2 | Xcode not running, `olderThan(30)` | Q |
| `simulator.unavailable` | Green | dry run: `xcrun simctl list devices unavailable -j` | `simulatorIdle` | CMD `xcrun simctl delete unavailable` |
| `simulator.caches` | Green | `{HOME}/Library/Developer/CoreSimulator/Caches/*` | `simulatorIdle` | Q |
| `simulator.devices.stale` | Yellow | `xcrun simctl list devices -j`; devices whose data dir mtime `olderThan(90)` | `simulatorIdle` | CMD `xcrun simctl delete <UDID>` (per device). `whatYouLose`: "Apps & data installed in that simulator." |
| `simulator.runtimes` | Yellow | `xcrun simctl runtime list -j` (show platform, version, size) — never preselect | `simulatorIdle` | CMD `xcrun simctl runtime delete <identifier>`. **Never** touch `/Library/Developer/CoreSimulator` files directly. |
| `xcode.extraInstalls` | Red | `.app` bundles with `CFBundleIdentifier == com.apple.dt.Xcode` found via Spotlight in `/Applications` and `{HOME}/Applications` | `appleSigned`, `notSelectedXcode`, app not running, App Management granted | T |
| `xcode.xipDownloads` | Yellow | `{HOME}/Downloads/*.xip` | `olderThan(7)`, `notOpenByAnyProcess` | Q |

### 6.2 Developer — Package Managers & Toolchains

| ID | Tier | Target | Preconditions | Action |
|---|---|---|---|---|
| `spm.cache` | Green | `{HOME}/Library/Caches/org.swift.swiftpm/*` | Xcode not running, `processNotRunning(swift-build, swift-package)` | Q |
| `carthage.cache` | Green | `{HOME}/Library/Caches/org.carthage.CarthageKit/*` | `processNotRunning(carthage)` | Q |
| `cocoapods.cache` | Green | if `pod` found: CMD `pod cache clean --all`; else `{HOME}/Library/Caches/CocoaPods/*` | `processNotRunning(pod)` | CMD / Q |
| `homebrew.cleanup` | Green | dry run `brew cleanup --prune=all -n` | `processNotRunning(brew)` | CMD `brew cleanup --prune=all`. **Do not** run `brew autoremove` (can remove things users rely on). |
| `npm.cache` | Green | size of `{HOME}/.npm/_cacache` | `processNotRunning(npm, node)` | CMD `npm cache clean --force` |
| `yarn.cache` | Green | `yarn cache dir` (global cache only). **Never** touch a project's `.yarn/cache` (may be a committed zero-install cache). | `processNotRunning(yarn)` | CMD `yarn cache clean` |
| `pnpm.store` | Green | `pnpm store path` | `processNotRunning(pnpm)` | CMD `pnpm store prune` (removes only unreferenced packages) |
| `bun.cache` | Green | `{HOME}/.bun/install/cache` | `processNotRunning(bun)` | CMD `bun pm cache rm` |
| `pip.cache` | Green | `{HOME}/Library/Caches/pip/*` | `processNotRunning(pip, pip3)` | Q |
| `uv.cache.prune` | Green | `uv cache dir` | `processNotRunning(uv)` | CMD `uv cache prune` |
| `uv.cache.clean` | Yellow | same | same | CMD `uv cache clean` |
| `poetry.cache` | Green | `{HOME}/Library/Caches/pypoetry/{cache,artifacts}/*` — **exclude** `virtualenvs` | `processNotRunning(poetry)` | Q |
| `poetry.virtualenvs` | Yellow | `{HOME}/Library/Caches/pypoetry/virtualenvs/*` | same + `olderThan(60)` | Q |
| `go.buildCache` | Green | `go env GOCACHE` | `processNotRunning(go)` | CMD `go clean -cache` |
| `go.modCache` | Yellow | `go env GOMODCACHE` (files are read-only; **must** use the go command) | same | CMD `go clean -modcache` |
| `cargo.registrySrc` | Green | `{HOME}/.cargo/registry/src/*` | `processNotRunning(cargo, rustc)` | Q |
| `cargo.registryCache` | Yellow | `{HOME}/.cargo/registry/cache/*` | same | Q |
| `gradle.caches` | Yellow | `{HOME}/.gradle/caches/*` | `processNotRunning(java)` matching GradleDaemon, or run `gradle --stop` is **not** allowed — just skip if daemon running | Q |
| `maven.repo` | Yellow | `{HOME}/.m2/repository/*` | `processNotRunning(mvn, java)` | Q |
| `flutter.pubCache` | Yellow | `{HOME}/.pub-cache` | `processNotRunning(dart, flutter)` | CMD `flutter pub cache clean -f` |
| `playwright.browsers` | Yellow | `{HOME}/Library/Caches/ms-playwright/*` | `processNotRunning(node)` | Q |
| `puppeteer.browsers` | Yellow | `{HOME}/.cache/puppeteer/*` | same | Q |
| `android.avd` | Yellow | `{HOME}/.android/avd/*.avd` | `processNotRunning(emulator, qemu-system-aarch64)` | CMD `avdmanager delete avd -n <name>` if available, else ADV |
| `android.systemImages` | Yellow | `{HOME}/Library/Android/sdk/system-images/*/*/*` | Android Studio not running (`com.google.android.studio`) | Q |

### 6.3 Developer — Editors & IDEs

| ID | Tier | Target | Preconditions | Action |
|---|---|---|---|---|
| `vscode.caches` | Green | `{HOME}/Library/Application Support/Code/{Cache,CachedData,CachedExtensionVSIXs,Code Cache,GPUCache,logs}` — **only these exact names**. Never `User/`, `Backups/`, `workspaceStorage/`. | `appNotRunning(com.microsoft.VSCode)` | Q |
| `cursor.caches` | Green | Same structure under `Application Support/Cursor` | `appNotRunning(com.todesktop.230313mzl4w4u92)` | Q |
| `vscode.oldExtensions` | Yellow | `{HOME}/.vscode/extensions/<publisher.name>-<version>` where a **newer version of the same extension** exists and the old one is not referenced in `extensions.json` | VS Code not running | Q |
| `jetbrains.caches.orphanedVersion` | Green | `{HOME}/Library/Caches/JetBrains/<Product><Version>` where no installed JetBrains app of that product+version exists | all `com.jetbrains.*` not running | Q |
| `jetbrains.caches.current` | Yellow | same, version installed | same | Q |
| `jetbrains.logs` | Green | `{HOME}/Library/Logs/JetBrains/*` | same, `olderThan(7)` | Q |
| `jetbrains.config.orphanedVersion` | Red | `{HOME}/Library/Application Support/JetBrains/<Product><Version>` for uninstalled versions (contains settings!) | same | T |

### 6.4 Developer — Docker & Containers

| ID | Tier | Target | Preconditions | Action |
|---|---|---|---|---|
| `docker.danglingImages` | Green | dry run `docker system df` | `dockerDaemonReachable` | CMD `docker image prune -f` (dangling only) |
| `docker.buildCache` | Green | same | same | CMD `docker builder prune -f` |
| `docker.unusedImages` | Yellow | `docker image ls` | same | CMD `docker image prune -a -f` |
| `docker.stoppedContainers` | Yellow | `docker ps -a --filter status=exited` (may contain data in writable layer) | same | CMD `docker container prune -f` |
| `docker.volumes` | Red | `docker volume ls -f dangling=true` — **databases live here** | same | CMD `docker volume rm <name>` one at a time, per-item confirmation. **Never** use `--volumes` on `system prune`. |
| `docker.diskImage` | Advisory | `Docker.raw` under `{HOME}/Library/Containers/com.docker.docker/Data/vms/0/data/` | — | ADV: explain the disk image doesn't shrink automatically; guide to Docker Desktop's own settings. **Never** touch the file. Detect OrbStack/Colima and show equivalent guidance. |

### 6.5 Developer — Project Build Artifacts (ProjectScanner)

- Scan **only user-selected project roots** (Settings). Defaults offered (not pre-enabled): `~/Developer`, `~/Projects`, `~/code`, `~/src`, `~/dev`.
- Max depth 8. Do not descend into: hidden dirs (except to detect `.git`), `.app`/package bundles, cloud roots, matched artifacts themselves, symlinks.

| ID | Tier | Artifact | Required manifest beside it | Action |
|---|---|---|---|---|
| `project.nodeModules` | Yellow | `node_modules` (topmost only; never nested) | npm/yarn/pnpm/bun lockfile | Q |
| `project.rustTarget` | Yellow | `target/` | `Cargo.toml` + `target/CACHEDIR.TAG` or `target/.rustc_info.json` | Q |
| `project.pythonVenv` | Yellow | `.venv/`, `venv/` with `pyvenv.cfg` | `pyproject.toml` / `requirements*.txt` / `uv.lock` / `poetry.lock` | Q |
| `project.pods` | Yellow | `Pods/` | `Podfile.lock` | Q |
| `project.nextBuild` | Yellow | `.next/` | `next.config.*` | Q |
| `project.gradleBuild` | Yellow | `build/` | `build.gradle(.kts)` beside it | Q |
| `project.swiftBuild` | Yellow | `.build/` | `Package.swift` | Q |

Conditions for all: `olderThan(90)` measured on the **project** (max mtime of manifest, `.git/index`, `.git/HEAD`), `processNotRunning` relevant tool, artifact not tracked by git (if `.git` exists, run `git -C <project> ls-files --error-unmatch <artifact>` → must fail; treat git errors as "tracked" = skip). Generic names like `build/` and `dist/` are only matched with their manifest pairing — never alone.

### 6.6 Apps, Browsers & General Caches

| ID | Tier | Target | Preconditions | Action |
|---|---|---|---|---|
| `apps.userCaches` | Green | `{HOME}/Library/Caches/<bundleID>` where `bundleID` resolves (LaunchServices `NSWorkspace.urlForApplication(withBundleIdentifier:)`) to an installed **non-Apple** app | `appNotRunning(bundleID)`, `notOpenByAnyProcess` | Q |
| `apps.userCaches.unknownOwner` | Yellow | Folders in `{HOME}/Library/Caches` not resolvable to an app, not in deny-list, not `com.apple.*` | `notOpenByAnyProcess`, `olderThan(30)` | Q |
| `apps.containerCaches` | Green | `{HOME}/Library/Containers/<id>/Data/Library/Caches/*` for installed non-Apple apps (expect Tahoe app-data-protection prompts — handle denial gracefully) | `appNotRunning(id)` | Q |
| `apps.sparkleUpdates` | Green | `{HOME}/Library/Caches/<id>/org.sparkle-project.Sparkle` | `appNotRunning(id)` | Q |
| `apps.squirrelShipIt` | Green | `{HOME}/Library/Caches/*.ShipIt` | owning app not running | Q |
| `apps.electronCaches` | Green | For a known allow-list of Electron apps (Slack `com.tinyspeck.slackmacgap`, Discord `com.hnc.Discord`, Notion `notion.id`, Figma `com.figma.Desktop`, Spotify `com.spotify.client` …): **only** subfolders named `Cache`, `Code Cache`, `GPUCache`, `DawnCache`, `DawnGraphiteCache`, `DawnWebGPUCache` under their `Application Support/<App>/` dir. Never `Local Storage`, `IndexedDB`, `Session Storage`, `Cookies`, `databases`, `Service Worker/Database`. | app not running | Q |
| `apps.savedState` | Green | `{HOME}/Library/Saved Application State/*.savedState` | owning app not running | Q |
| `browser.chromium.cache` | Green | Chrome/Edge/Brave/Arc/Vivaldi profiles: `Cache`, `Code Cache`, `GPUCache` (and `{HOME}/Library/Caches/<Vendor>/<Browser>/*/Cache`) | browser not running (bundle IDs: `com.google.Chrome`, `com.microsoft.edgemac`, `com.brave.Browser`, `company.thebrowser.Browser`, `com.vivaldi.Vivaldi`) | Q |
| `browser.chromium.serviceWorkerCache` | Yellow | `Service Worker/CacheStorage` (may hold offline web-app data) | same | Q |
| `browser.firefox.cache` | Green | `{HOME}/Library/Caches/Firefox/Profiles/*/cache2` | `appNotRunning(org.mozilla.firefox)` | Q |
| `browser.safari.cache` | Green | `{HOME}/Library/Caches/com.apple.Safari/*` (explicit Apple exception) | `appNotRunning(com.apple.Safari)` | Q |
| `mail.downloads` | Green | `{HOME}/Library/Containers/com.apple.mail/Data/Library/Mail Downloads/*` (explicit Apple exception; these are temp copies of opened attachments) | `appNotRunning(com.apple.mail)`, `olderThan(7)` | Q |
| `logs.user` | Green | `{HOME}/Library/Logs/*` (excluding `iMop`) | `olderThan(7)`, `notOpenByAnyProcess` | Q |
| `logs.diagnosticReports` | Green | `{HOME}/Library/Logs/DiagnosticReports/*` | `olderThan(30)` | Q |
| `system.coreDumps` | Green | `/cores/core.*` | `ownedByUser`, `olderThan(1)` | Q not possible (different root) → permanent delete with explicit confirmation; downgrade to Yellow |
| `ios.firmware` | Green | `{HOME}/Library/iTunes/*Software Updates/*.ipsw` | `olderThan(1)`, `notOpenByAnyProcess` | Q |
| `installers.macOS` | Yellow | `/Applications/Install macOS *.app` | `appleSigned`, not running, App Management granted | T |
| `downloads.diskImages` | Yellow | `{HOME}/Downloads/*.{dmg,pkg,mpkg}` | `olderThan(30)`, `notMounted`, `notOpenByAnyProcess` | T |
| `downloads.archives` | Red | `{HOME}/Downloads/*.{zip,iso,tar.gz}` | `olderThan(30)` | T (per item) |
| `trash.empty` | Yellow | `{HOME}/.Trash` (show size + item count) | — | Explicit "Empty Trash" confirmation; permanent |

### 6.7 Creative & Media

| ID | Tier | Target | Preconditions | Action |
|---|---|---|---|---|
| `adobe.mediaCache` | Yellow | `{HOME}/Library/Application Support/Adobe/Common/{Media Cache Files,Media Cache}/*` | `appNotRunning(com.adobe.*)` | Q |
| `lightroom.previews` | Yellow | `*Previews.lrdata` beside a `.lrcat` found via Spotlight (never `Smart Previews.lrdata`, never the `.lrcat`) | `appNotRunning(com.adobe.LightroomClassicCC7)` | Q |
| `finalcut.generated` | Advisory | `.fcpbundle` libraries | — | ADV: guide to *File → Delete Generated Library Files*. Never touch bundle contents. |
| `audio.soundLibraries` | Advisory | `/Library/Application Support/{GarageBand,Logic}`, `/Library/Audio/Apple Loops` | — | ADV: guide to app's Sound Library manager (root-owned). |

### 6.8 Local AI Models

| ID | Tier | Target | Preconditions | Action |
|---|---|---|---|---|
| `ai.ollama` | Yellow | `ollama list` (name, size, modified) — **never** delete blobs manually (layers are shared) | `processNotRunning(ollama)` serving? → if server running use API-free CLI only | CMD `ollama rm <model>` per model |
| `ai.huggingface` | Yellow | `{HOME}/.cache/huggingface/hub/models--*` and `datasets--*` (each repo folder is self-contained) | `notOpenByAnyProcess`, `processNotRunning(python, python3)` | Q |
| `ai.lmstudio` | Yellow | `{HOME}/.lmstudio/models/*/*` | `appNotRunning(ai.elementlabs.lmstudio)` | Q |

Show model name, size, last used. Never preselect. Offer "Delete immediately (skip quarantine)" only behind an extra confirmation because models are huge.

### 6.9 Leftovers from Deleted Apps (OrphanDetector) — Red

Candidates: `{HOME}/Library/{Application Support,Preferences,Containers,Group Containers,Caches,HTTPStorages,WebKit,LaunchAgents}/<identifier>`.

An identifier is **orphaned only if ALL are true** (otherwise skip):
1. Not `com.apple.*`, not in deny-list.
2. No app registered with LaunchServices for that bundle ID (`NSWorkspace.urlsForApplications(withBundleIdentifier:)` empty) **and** Spotlight (`kMDItemCFBundleIdentifier == id`) finds nothing on **any** mounted volume.
3. No running process whose bundle ID / executable path relates to it.
4. Not referenced by a package receipt (`pkgutil --pkgs`, `pkgutil --pkg-info`).
5. For Group Containers: no installed app declares that group in its `com.apple.security.application-groups` entitlement (read via `SecCodeCopySigningInformation`), and the Team-ID prefix doesn't match any installed app's Team ID.
6. Not a known CLI/tool directory (allow-list: `Homebrew`, `pip`, `node-gyp`, `typescript`, `Jupyter`, etc.).
7. `olderThan(30)`.
8. App not in a known "app store / subscription" location (Setapp `/Applications/Setapp`), and no external volume is disconnected that previously held apps (if `/Volumes` lists fewer drives than last scan, warn the user).

Action: per-item Trash with confirmation. For **orphaned LaunchAgents** (`{HOME}/Library/LaunchAgents/*.plist` whose `Program`/`ProgramArguments[0]` no longer exists): show label + missing binary; action = `launchctl bootout gui/<uid> <plist>` then Trash the plist. Never touch `/Library/LaunchAgents` or `/Library/LaunchDaemons` (root) — Advisory only.

### 6.10 Advisory-Only Items (explain, never act, v1)

- **Time Machine local snapshots** — run read-only `tmutil listlocalsnapshots /`; explain they are purgeable and macOS removes them automatically when space is needed; explain that space from deleted files may not return until snapshots expire.
- **"Purgeable" space** — show `volumeAvailableCapacityForImportantUsage` vs `volumeAvailableCapacity`, and explain the difference honestly.
- **iPhone/iPad backups** (`MobileSync/Backup`) — read `Info.plist` per backup (device name, date, size) **read-only**; offer "Manage in Finder" only.
- **Messages attachments, Photos, Music, Podcasts, TV downloads** — open System Settings → General → Storage.
- **Apple Intelligence / Siri / dictation assets**, `/System/Library/AssetsV2` — system-managed; explain only.
- **iCloud Drive local copies** — v1 Advisory: explain "Optimize Mac Storage". (v1.1 spike: evaluate `FileManager.evictUbiquitousItem(at:)` with `uploadedToCloud` predicate; ship only if verified safe.)
- **Root-owned locations** (`/Library/Caches`, `/Library/Logs`, `/Library/Developer/CoreSimulator`) — explain; no privileged helper in v1.

---

## 7. Sizing (accuracy is part of honesty)

### 7.1 What to report
- Use `getattrlistbulk(2)` for fast enumeration. Report **allocated size** (`ATTR_FILE_ALLOCSIZE`), **not** logical size.
- Use **private size** (`ATTR_CMNEXT_PRIVATESIZE`) to report bytes that would actually be freed — APFS clones share blocks, so deleting one clone frees little or nothing.
- Hard links: if `st_nlink > 1`, count the file's bytes as **not reclaimable** unless all links are inside the same target.
- Display: "**Estimated reclaimable**: X GB (Y GB on disk)". Never display logical sizes as reclaimable.

### 7.2 Performance
- Enumerate with bounded concurrency (TaskGroup, max 4 concurrent rule scans). Respect `Task.isCancelled`.
- Do not follow symlinks, do not descend into packages unless the rule targets their contents, do not cross volumes.
- Cache scan results per session only (never persist file lists across launches except the Quarantine manifest).

### 7.3 Post-clean reporting
Show measured free-space delta. If it's lower than estimated, show the honest explanations: items still in Quarantine; Time Machine local snapshots retaining blocks; APFS clones; purgeable space accounting.

---

## 8. Permissions UX

- **Full Disk Access probe**: attempt a read-only `open()` on a known TCC-protected path (e.g. `{HOME}/Library/Containers/com.apple.Safari` listing or `{HOME}/Library/Safari`). Never write to probe.
- If missing: explain *why* (which categories need it), deep-link: `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`. Rules requiring FDA show as "Locked — needs Full Disk Access", never silently fail.
- **App Management**: only requested when the user selects a rule that trashes an app bundle.
- If the system shows an app-data-protection prompt and the user declines, treat the affected rules as unavailable for the session (no repeated prompting).

---

## 9. UI Requirements (SwiftUI)

1. **Scan screen** — "Scan" button, live progress by category, cancel. Scan is always read-only (say so in the UI).
2. **Category list** — grouped (Developer, Browsers, Apps, Media, AI Models, Downloads, Leftovers, Advisory). Each row: tier badge (Green/Yellow/Red/Info), title, estimated reclaimable size, item count, checkbox (default per tier).
3. **Item detail** — full path (selectable text), "Reveal in Finder", size (on disk + reclaimable), last used, owning app, **What it is**, **What you lose**, **How it comes back**, preconditions status (e.g. "Xcode is running — quit to clean"), and any skip reason.
4. **Review sheet** — summary grouped by action type (Quarantine / Vendor command / Trash), totals, explicit list of non-undoable actions with warning styling, "Clean" button disabled for 2 seconds after appearing (prevents accidental double-click confirmation).
5. **Red items** — per-item confirmation dialog naming the item and its size.
6. **Progress** — per item status; skipped items show reason.
7. **Results** — estimated vs measured reclaim, skipped list with reasons, "Open Quarantine", "Export Log".
8. **Quarantine browser** — sessions, items, restore (per item / per session), purge now, retention countdown.
9. **Settings** — project roots, exclusions (add via folder picker), retention days, age thresholds, archives-to-keep count, "Always quarantine (never permanently delete in one step)" default ON.
10. Accessibility: full VoiceOver labels, keyboard navigation, Dynamic Type friendly layouts. Tier must never be conveyed by color alone (badge text + icon).

---

## 10. Explicitly Forbidden (fail code review if present)

- Any deletion path that bypasses `SafetyGate` or `Executor`.
- Shell invocation (`/bin/sh`, `/bin/zsh`, `system()`, `popen()`), `sudo`, `AuthorizationExecuteWithPrivileges`, privileged helpers (v1).
- Stripping `.lproj` localizations, `lipo`/binary thinning, modifying any file inside an app bundle.
- Deleting `~/Library/Caches` (or any allow-root) itself, or wholesale `com.apple.*` caches.
- Touching `/private/var/folders`, swap, sleepimage, Spotlight index, font databases, unified logs.
- Deleting inside iCloud Drive / CloudStorage.
- `docker system prune --volumes`, `brew autoremove`, `rm -rf` equivalents via commands.
- Network calls, analytics, remote rule updates.
- Recursive glob `**` in Rules.json.
- Auto-running cleanup on a schedule without the user reviewing a plan (v1 has no background auto-clean).

---

## 11. Error Handling

- Every failure is per-item and non-fatal; the run continues.
- Errors are categorized: `permissionDenied`, `inUse`, `changedSinceScan`, `preconditionFailed(name)`, `safetyRejected(reason)`, `commandFailed(exitCode)`, `timeout`, `crossVolume`.
- Partial failures inside a directory move: because Quarantine is an atomic rename, there are no partial states. For vendor commands, report exit code and stderr; don't retry automatically.
- Crash safety: write the Quarantine manifest entry **before** the rename (status `pending`), update to `moved` after. On launch, reconcile `pending` entries (if source gone and destination present → `moved`; if source present → drop entry).

---

## 12. Testing Requirements

All tests use `FixtureBuilder` to create a fake home under `FileManager.default.temporaryDirectory/iMopTests-<UUID>/` and an injected `Environment`. **A test-suite guard must abort the run if any code path resolves to the real `NSHomeDirectory()`.**

### 12.1 SafetyGate adversarial tests (must all pass before Milestone 2)
- Path equal to an allow-root → rejected.
- `..` traversal (`{HOME}/Library/Caches/../Keychains`) → rejected.
- Symlink target pointing to `/System`, to `~/Documents`, to a deny-listed path → rejected.
- Intermediate directory is a symlink → rejected.
- Case variants (`~/library/KEYCHAINS`) and NFD/NFC Unicode variants → rejected.
- Prefix confusion (`~/Library/CachesEvil/x` vs root `~/Library/Caches`) → correct component-wise handling.
- Firmlink form `/System/Volumes/Data/Users/<u>/Library/Keychains` → rejected.
- Different `st_dev` (simulate via injected FS stat) → rejected.
- Different owner uid → rejected.
- Inode changed between plan and execute → rejected.
- Item inside `.app` bundle → rejected.
- Item with File Provider xattr → rejected.
- Sanity limit exceeded → downgraded to Red, not executed.
- Running as root (injected euid 0) → refuses.
- One test per deny-list entry.

### 12.2 Other suites
- RuleCatalog validation (every rule in Rules.json passes; malformed rules disabled).
- Precondition evaluators (with fake process lists; error → false).
- XcodeInspector: DerivedData `info.plist` parsing, Archives keep-N logic.
- ProjectScanner: manifest pairing, git-tracked detection, depth limits, no nested `node_modules`.
- OrphanDetector: each of the 8 conditions individually blocks orphan status.
- Quarantine: move, restore (with and without conflict), purge after retention, crash reconciliation.
- CommandRunner: rejects untrusted executable locations, sanitized env, timeout enforcement (use a fake executable script in fixtures).
- Sizer: clones and hard links accounted correctly (create real APFS clones in fixtures with `clonefile(2)`).
- Static test: read-only modules contain no mutation APIs (Section 3.1).

Target: ≥ 90% line coverage for `Safety/`, `Execution/`, `Planning/`.

---

## 13. Milestones & Acceptance Criteria

| # | Milestone | Acceptance criteria |
|---|---|---|
| **M1** | Package skeleton, `Environment`, `PathCanonicalizer`, `DenyList`, `SafetyGate`, `Preconditions`, full test suite 12.1 | All SafetyGate tests pass. No mutation code exists anywhere yet. |
| **M2** | Rule model, `Rules.json` with Green rules only, `RuleCatalog` validation, read-only `Scanner` + `SizeCalculator` | Scanning a fixture home produces correct items & sizes. Static read-only test passes. |
| **M3** | `CleanupPlan`, `ConfirmedPlan` (hash), `Quarantine`, `Executor`, `AuditLog`; `IMOP_ALLOW_MUTATION` flag | Executor refuses without flag; with flag, fixture items are quarantined, restorable, purged; double validation proven by tests that mutate fixtures between plan and execute. |
| **M4** | `CommandRunner` + vendor command rules (simctl, brew, npm, pnpm, yarn, bun, uv, go, docker, pod, ollama) | Untrusted path rejection tests pass; dry-run estimates displayed; all commands run without shell. |
| **M5** | Yellow rules, `XcodeInspector`, `ProjectScanner`, AI model rules | Manifest/git/age conditions enforced; nothing Yellow preselected. |
| **M6** | `OrphanDetector` (Red), Trash flows, LaunchAgent handling | All 8 orphan conditions tested; per-item confirmation enforced. |
| **M7** | SwiftUI app: all screens in Section 9, permissions UX, Advisory content | Manual QA checklist (13.1) passes on a clean macOS 26 VM. |
| **M8** | Hardening: performance on 1M-file home, accessibility audit, notarization build | Scan of a 500 GB fixture completes without UI hangs; no main-thread FS work. |

### 13.1 Manual QA Checklist (on a disposable macOS 26 VM — never on a dev's daily machine)
- [ ] Clean everything Green + Yellow → reboot → Xcode builds a project, Simulator boots, Safari/Chrome/Slack/VS Code launch and stay logged in.
- [ ] Restore an entire quarantine session → apps behave identically to before.
- [ ] With Xcode running, Xcode rules show "Quit Xcode to clean" and are skipped.
- [ ] Symlink `~/Library/Caches/evil → /System` → never touched; audit log shows rejection.
- [ ] Revoke Full Disk Access mid-session → affected rules lock; no crashes.
- [ ] iCloud Drive, Dropbox folders untouched after full clean (checksum before/after).
- [ ] Docker volumes untouched unless explicitly confirmed per item.
- [ ] Time Machine local snapshot present → results screen explains reclaim discrepancy.

---

## 14. Definition of Done

- All milestones' acceptance criteria met; all tests green; coverage targets met.
- No item in Section 10 present in the codebase.
- Every rule in `Rules.json` has non-empty `explanation`, `whatYouLose`, `howItRegenerates`.
- Release build is notarized, Hardened Runtime, no network entitlements.
- A `SAFETY.md` is generated in the repo summarizing the deny-list, tiers, and invariants for future contributors.

> **Final reminder to Claude Code:** if you are ever unsure whether an operation is safe, **don't perform it**: skip, log the reason, and surface it to the user as "Skipped for safety". A cleaner that frees 2 GB less is acceptable. A cleaner that breaks one Mac is not.
