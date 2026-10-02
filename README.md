# iMop for macOS

<p align="center">
  <strong>A native macOS storage cleaner that puts safety first.</strong><br>
  Version 1.1 "SafeClean" &bull; Swift 6 &amp; SwiftUI &bull; macOS 14 (Sonoma) or later &bull; Freeware
</p>

---

## Contents

- [Overview](#overview)
- [Trust promises](#trust-promises)
- [What is new in v1.1](#what-is-new-in-v11)
- [Using iMop](#using-imop)
  - [Scan](#scan)
  - [Safety tiers](#safety-tiers)
  - [Categories](#categories)
  - [Review and clean](#review-and-clean)
  - [Quarantine, Restore and Empty](#quarantine-restore-and-empty)
  - [Results and the audit log](#results-and-the-audit-log)
  - [Settings](#settings)
  - [Permissions](#permissions)
- [Build, run and test](#build-run-and-test)
  - [Prerequisites](#prerequisites)
  - [The IMOP_ALLOW_MUTATION flag](#the-imop_allow_mutation-flag)
  - [Commands](#commands)
  - [Packaging iMop.app](#packaging-imopapp)
- [Developer guide](#developer-guide)
  - [Package layout](#package-layout)
  - [The pipeline](#the-pipeline)
  - [How to add a rule safely](#how-to-add-a-rule-safely)
  - [Test suite](#test-suite)
- [License](#license)

---

## Overview

iMop finds clutter it recognises: caches, build artifacts, old developer tooling, leftover
installer files and data left behind by deleted apps. For every item it shows **what** it is,
**where** it is, **how big** it really is on disk, **what you lose** by removing it and **how it comes
back**. It removes only what you approve, and wherever it can, it does so in a way you can undo.

Reclaiming space comes second. When safety and freed bytes conflict, iMop chooses safety. When in
doubt it skips the item, says so ("Skipped for safety: ...") and writes the reason to the audit log.

The full safety model (deny-list, tiers, SafetyGate invariants, preconditions, command allow-list,
every `SAFETY-DECISION` in the code) is in **[SAFETY.md](SAFETY.md)**.

## Trust promises

These are enforced in code, not just stated:

- iMop never touches `/System`, the Signed System Volume or any SIP-protected path.
- iMop never deletes anything inside iCloud Drive or any cloud-sync folder (Dropbox, OneDrive,
  Google Drive, Box, File Provider items).
- iMop never changes files *inside* an application bundle.
- iMop never runs as root and never asks for more privileges.
- iMop itself makes **no network connections**. No telemetry, no analytics, no remote rule updates.
  Some vendor tools whose own cleanup command iMop runs may contact their own services; iMop passes
  their documented analytics / auto-update opt-outs and never starts the Ollama app (see
  [SAFETY.md](SAFETY.md#spec-deviations)).
- **Scanning is read-only.** Nothing changes until you review a plan and confirm it.
- Every removal is logged, and most removals can be restored during a retention period.
- iMop never cleans in the background. There is no schedule and no auto-clean.

## What is new in v1.1

v1.1 replaces the v1.0 scanner and deletion code with **SafeClean**:

- **Rule-based discovery.** 93 reviewed rules in a bundled, read-only `Rules.json` (never
  downloaded). The hard-coded Swift deny-list and the SafetyGate always apply on top of them.
- **Safety tiers** (Safe / Review / Caution / Info) control what is preselected, how an item is
  removed and how you confirm it.
- **Quarantine instead of permanent deletion.** Green and Yellow items are moved (instantly, on the
  same volume) into iMop's Quarantine and can be restored for 24 hours (Green) or 7 days (Yellow).
  Red items go to the Finder Trash, one at a time, after you confirm each one — except Docker volumes,
  which are removed with `docker volume rm` and cannot be undone.
- **Two validations per item.** Every item goes through the SafetyGate when the plan is built and
  again immediately before it is acted on.
- **Vendor cleanup commands.** For tools such as npm, Docker or the iOS Simulator, iMop runs the
  tool's own cleanup command (exact, allow-listed argument arrays, never a shell). Tools in a folder
  that other accounts can change (by its permissions or by an access-control list) are not run. A default Homebrew install is such a folder
  (`/opt/homebrew/bin` and its other folders can be changed by every account in the `admin` group), so
  by default Homebrew and Homebrew-installed tools (brew, npm, yarn, pnpm, go, uv, pod, flutter, ...)
  are reported as unavailable, with the reason. You can allow them with Settings › **Trust Homebrew
  tools** (off by default; see [Settings](#settings) and
  [SAFETY.md › Vendor commands](SAFETY.md#vendor-commands-allow-list-and-runner)).
- **Honest sizes.** Sizes are allocated bytes on disk. "Estimated reclaimable" counts only blocks that
  would really be freed (APFS clones and hard links are taken into account). After a clean, iMop
  compares the estimate with the measured free-space change and explains any difference.
- **Advisory items.** Things iMop explains but never touches (Time Machine local snapshots,
  purgeable space, iPhone backups, system storage, root-owned caches, ...).
- **Audit log.** Every decision is written to `~/Library/Logs/iMop/audit-YYYY-MM.jsonl` and can be
  exported.
- **Removed from v1.0:** the "Permanent Delete" and "Dry Run Mode" toggles and the old deletion
  service. Dry-run is now a property of the build (see
  [The IMOP_ALLOW_MUTATION flag](#the-imop_allow_mutation-flag)), and the Settings option **"Always
  quarantine (never permanently delete in one step)"** is ON by default.

## Using iMop

### Scan

Open iMop and click the large **Scan** button (or press <kbd>Cmd</kbd>+<kbd>R</kbd>). The scan screen
shows live progress for each category and the path being examined. You can cancel at any time.

> Scanning is read-only — nothing is changed until you review and confirm.

### Safety tiers

Every rule has exactly one tier. The badge always shows the tier as **text and an icon**, never by
colour alone.

| Tier | Badge | What it means | Preselected? | How it is removed | How you confirm |
|---|---|---|---|---|---|
| Green | **Safe** (checkmark shield) | Pure caches that rebuild automatically; the only cost is a slower first launch | Yes | Quarantine, 24 h | The review sheet |
| Yellow | **Review** (warning triangle) | Rebuildable or re-downloadable, but costs time, bandwidth or convenience | No | Quarantine, 7 days; the tool's own cleanup command; the Finder Trash (old disk images, macOS installers); or, only when "Always quarantine" is off, permanent deletion (Empty Trash, crash core dumps) | The review sheet, which shows "What you lose" for each item and asks you to tick "I understand what I lose in <category>"; Empty Trash also has its own confirmation |
| Red | **Caution** (raised hand) | Your own data or hard-to-recover items | Never | Moved to the Finder Trash, one item at a time; Docker volumes are removed with `docker volume rm` (cannot be undone) | A confirmation dialog for each item, naming it and its size |
| Advisory | **Info** (info circle) | iMop explains and guides but does not act | Not selectable | Reveal in Finder / Open App / Open Storage Settings | — |

"Select all" in a category never selects Red items (each must be confirmed on its own) and never a
permanent deletion. The items in the Trash form one **Empty Trash** choice: selecting any of them asks
for a confirmation that names the number of items and their size, then selects all of them together.

### Categories

The sidebar groups rules in this order; each row shows the reclaimable size and the item count.

| Category | Examples |
|---|---|
| Developer | Xcode DerivedData, archives and device support, Simulator devices and runtimes, SwiftPM, CocoaPods, Carthage, Homebrew, npm, Yarn, pnpm, Bun, pip, Poetry, uv, Go, Cargo, Gradle, Maven, Flutter, Android, VS Code, Cursor, JetBrains, Docker, Playwright, Puppeteer, project build folders (`node_modules`, `target`, `.venv`, `Pods`, `.next`, `build`, `.build`) in the project folders you choose |
| Browsers | Chrome, Edge, Brave, Arc, Vivaldi, Firefox and Safari web caches |
| Apps | Caches of installed apps, sandboxed app caches, downloaded app updates, Electron app caches, saved window state, Mail attachment copies, macOS installer apps |
| System & Logs | Old app logs, crash and diagnostic reports, downloaded iPhone/iPad software, the Trash, crash memory dumps |
| Media | Adobe media cache, Lightroom Classic previews |
| AI Models | Ollama, Hugging Face and LM Studio models |
| Downloads | Old disk images, installer packages and archives in Downloads |
| Leftovers | Data and broken login items (LaunchAgents) of apps you have deleted |

Then come **Advisory**, **Quarantine**, **Permissions** and **Results**. Rules that need Full Disk
Access show as "Locked — needs Full Disk Access" instead of silently finding nothing. Rules that could
not be checked in a scan (a tool that is not installed or not running, access that was declined, no
project folders chosen, ...) are listed with the reason in their category and under **Permissions ›
Unavailable this session**.

Click an item to see its details: the full path (selectable), on-disk and reclaimable size, when it
was last used, the owning app, **What it is**, **What you lose**, **How it comes back**, the status of
every precondition (for example "Xcode is running — quit to clean") and any reason it was skipped.
Right-click an item to **Reveal in Finder** or **Exclude from future scans**.

### Review and clean

1. Select items. Green items are preselected; Yellow items you tick yourself; each Red item asks for
   its own confirmation.
2. Click **Review & Clean...** in the bottom bar ("X items selected (Y reclaimable)").
3. The review sheet groups everything by what will happen: **Quarantine**, **Vendor command**,
   **Trash** and **Permanent delete**, with totals. Anything that cannot be undone is listed
   separately with a warning. For commands it says: "This cannot be undone. <tool> will re-download
   what it needs." If the plan contains anything irreversible, you must tick an acknowledgement.
   Every selected Yellow (Review) or Red (Caution) item shows its "What you lose" text, and each
   category with Yellow items needs its own "I understand what I lose in <category>" tick.
4. The **Clean** button stays disabled for 2 seconds after the sheet appears, so a double-click can
   never confirm by accident.
5. While cleaning, each item shows its status. Items are processed one at a time; **Cancel** stops
   before the next item (never in the middle of one).

Every item is checked by the SafetyGate again right before it is acted on. Anything that changed
since the scan (moved, replaced, now in use, now inside an excluded folder, ...) is skipped with a
reason.

### Quarantine, Restore and Empty

- **Where:** `~/Library/Application Support/iMop/Quarantine/<session>/`, on the same volume as your
  home folder, so moving an item there is an instant rename (no copying) and never overwrites
  anything. Spotlight is kept out of it.
- **Restore:** in the Quarantine screen, restore a single item or a whole cleaning session. If
  something new now exists at the original location, the item comes back next to it as
  `<name> (restored <date>)`; nothing is ever overwritten.
- **Retention:** Green items stay 24 hours, Yellow items 7 days (Settings can only make this longer).
  The Quarantine screen shows how long each item has left. Expired items are removed when iMop
  starts and once a day while it is running.
- **Empty Quarantine Now:** removes everything in Quarantine immediately, after a confirmation.

> Space from quarantined items is freed when quarantine is emptied. Empty now to reclaim immediately.

If iMop is interrupted (crash, power loss) while moving or restoring, the next launch reconciles the
Quarantine from its manifest, so an item is never lost or forgotten.

### Results and the audit log

The results screen shows the **estimated** reclaim next to the **measured** change in free space, and
explains honestly why they can differ: items still in Quarantine, Time Machine local snapshots that
keep deleted blocks, APFS clones, and purgeable-space accounting. It lists every skipped item with its
reason, links to the Quarantine, and offers **Export Log...**.

The audit log lives in `~/Library/Logs/iMop/audit-YYYY-MM.jsonl` (one JSON object per event; never file
contents). Export writes a new file (default folder: Downloads). It refuses to overwrite an existing
file and refuses protected destinations such as Desktop or Documents; pick another name or folder if
that happens.

### Settings

Open Settings with <kbd>Cmd</kbd>+<kbd>,</kbd>. Every safety-related change applies to the **next**
scan; a plan built with different settings must be rebuilt before it can be confirmed.

- **Project folders:** the only places scanned for project build folders. Nothing is scanned until
  you add one. Common folders (`~/Developer`, `~/Projects`, `~/code`, `~/src`, `~/dev`) are offered
  but never enabled for you.
- **Exclusions:** folders iMop must never touch (added with a folder picker, or from an item's context
  menu). An exclusion added while a cleanup is running also applies to it: items inside it that have
  not been processed yet are skipped.
- **Quarantine retention:** can only be made longer than a rule's own retention.
- **Age thresholds:** can only be raised ("older than N days" can never be shortened).
- **Archives to keep:** how many of the newest Xcode archives per app are always kept (default 3).
- **Always quarantine (never permanently delete in one step):** ON by default. While it is on, iMop
  never offers a one-step permanent deletion (for example emptying the Trash or removing crash memory
  dumps); those items show as blocked with this reason. Turning it off asks for confirmation.
- **Trust Homebrew tools in /opt/homebrew** (`/usr/local` on Intel): OFF by default. Homebrew makes
  its folders changeable by every account in the `admin` group, so iMop does not run Homebrew tools
  until you turn this on; their rules show "… a folder other accounts can change. Turn on “Trust
  Homebrew tools” in Settings to allow it." When you turn it on, iMop first lists the other accounts
  that could change those tools (members of the `admin` group, not counting you and root) and asks you
  to confirm with **Trust Homebrew Tools** (Cancel is the default). If the `admin` group includes
  other groups (common on Macs managed by an organisation) or iMop cannot read it completely, the
  dialog says the accounts could not be determined and warns more strongly. Even when on, iMop
  accepts only Homebrew's own folders, owned by you, with group `admin`, and never a folder everyone
  can write to; the tools themselves and every other check stay as strict as before. Turning it off is
  immediate, also for a scan or cleanup that is already running: its remaining Homebrew commands are
  refused. Each change is recorded in the audit log.
- **Forget remembered drives:** iMop remembers which external drives it has seen. While a remembered
  drive is disconnected, Leftovers detection pauses (apps on that drive would look deleted).

Settings are stored in the `com.imop.cleaner` defaults domain. If stored settings cannot be read
completely, iMop keeps every part it can read (one damaged value never erases your exclusions), uses
the safe default for the rest, keeps the original data as a backup, and pauses cleaning until you
have checked Settings and confirmed them.

### Permissions

- **Full Disk Access** is needed for app containers, Mail and Safari caches and a few other places.
  iMop checks it with a read-only probe (it never writes to find out). Without it, the affected rules
  show as locked. The Permissions screen and the sidebar card explain why and open
  *System Settings > Privacy & Security > Full Disk Access*. When you run iMop with `swift run`, the
  permission belongs to your terminal app.
- **App Management** is only needed to move other apps to the Trash (extra Xcode copies, macOS
  installer apps). iMop cannot check it without trying, so it explains the permission and links to
  *System Settings > Privacy & Security > App Management*. If macOS refuses, the item is reported with
  that reason.
- If macOS declines access to a rule's location (for example after you decline a data-protection
  prompt), that rule is not scanned again until you quit and reopen iMop, and it shows as
  "Unavailable this session". (For sandboxed app caches this is per rule: when only some app
  containers are refused, the refused ones are skipped in each scan.)
- Vendor tools that iMop does not trust are listed under **Unavailable this session** with the reason,
  for example a Homebrew tool while **Trust Homebrew tools** is off (see [Settings](#settings)).

### About

*iMop > About iMop* shows:

```
Created by Ravi Subramaniam, Bangalore (India)
License :This is a Freeware
version 1.1 (Last updated 1/Oct)
```

---

## Build, run and test

### Prerequisites

- macOS 14 (Sonoma) or later.
- A Swift 6 toolchain (Xcode or the Command Line Tools). Package: `swift-tools-version: 6.0`, strict
  concurrency, no third-party dependencies.

```bash
git clone https://github.com/git-maniam/iMop.git
cd iMop
```

`scripts/swiftc-wrapper.sh` works around a PackageDescription symbol mismatch in some standalone
Command Line Tools installs. Pass it as `SWIFT_EXEC` as shown below (it is harmless otherwise).

### The IMOP_ALLOW_MUTATION flag

Whether iMop can change the file system at all is decided **when it is compiled**:

| Build | Flag | Behaviour |
|---|---|---|
| `swift build` / `swift run iMop` (debug), VS Code launch configs | not set | **Dry-run only.** Scanning, planning and review work; every move, trash, purge or cleanup command is refused and logged as "mutation disabled in this build". The app shows a "Dry-run build — cleaning disabled" banner. |
| `./scripts/package_app.sh` | `-Xswiftc -DIMOP_ALLOW_MUTATION` | **Cleaning enabled.** Builds `build/iMop.app`. |
| Test runner (`iMopTests`) | not set | Mutation only through a fixture policy that is confined to `iMopTests-*` folders in the temporary directory. |

Never add the define to `Package.swift` or to any debug configuration.

### Commands

```bash
# Build everything (debug, dry-run)
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift build

# Run the test suite
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift run iMopTests

# Launch the app from the terminal (debug build: dry-run only, nothing is ever changed)
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift run iMop
```

`--scratch-path <dir>` can be added to any of them to keep several builds apart.

### Packaging iMop.app

```bash
./scripts/package_app.sh
open build/iMop.app
```

The script builds a release binary **with** `IMOP_ALLOW_MUTATION` (in its own scratch folder,
`.build/package-release`), assembles `build/iMop.app` (version 1.1.0, build 2, minimum macOS 14.0),
copies the SwiftPM resource bundles (the `iMop_iMopCore.bundle` holding `Rules.json` is required; the
script fails if it or `Rules.json` is missing) and writes `Info.plist`.

Caveats: the app is **not** Developer ID signed, has no Hardened Runtime and is **not notarized** yet
(Milestone 8), so Gatekeeper will warn the first time you open it. The resource bundles are also copied
to the root of the `.app` for the SwiftPM `Bundle.module` accessor, which `codesign` does not accept;
the notarized build will have to drop that copy. Until the manual QA checklist in
[SAFETY.md](SAFETY.md#manual-qa-checklist) has passed, try cleaning builds on a disposable macOS VM.

---

## Developer guide

### Package layout

```text
Package.swift
 ├── iMopCore   (library)     all logic, UI-free and unit-testable
 ├── iMop       (executable)  the SwiftUI app
 └── iMopTests  (executable)  the custom test runner
```

`Sources/iMopCore/`

| Folder | Contents |
|---|---|
| `Environment/` | `SafeCleanEnvironment`: everything injectable (home folder, clock, file-system probe, processes, running apps, volumes, Spotlight, code-signing, command runner, settings). `LiveEnvironment.make()` builds the real one. |
| `Settings/` | `ScanSettings` (project roots, exclusions, retention and age overrides, archives to keep, `alwaysQuarantine`, remembered volumes, `trustHomebrewAdminWritableDirectories`) and `SettingsStore` (JSON in the `com.imop.cleaner` defaults domain; unreadable data falls back to safe defaults). |
| `Safety/` | `PathCanonicalizer`, `DenyList`, `SafetyGate`, `SafetyRejection`, `Preconditions`. The heart of the app; read [SAFETY.md](SAFETY.md) first. |
| `Rules/` | `Rule` model, strict `RuleCoding`, `Glob` (the tiny glob grammar), `RuleCatalog` (load + validation + Swift-pinned rule shapes), `RuleTargetMatcher` (what each rule may target), `CommandAllowList`, and the bundled `Rules.json`. |
| `Discovery/` | `SafeCleanScanner` (read-only scan, at most 4 rules at a time, progress events) and the inspectors: Xcode, Simulator (`SimctlClient`), Docker, Ollama, package managers, ProjectScanner, app caches, JetBrains, VS Code extensions, media, Trash flows, `OrphanDetector`, LaunchAgents, Advisory. |
| `Sizing/` | `SizeCalculator`: allocated and private (APFS) size via `getattrlistbulk`, hard-link handling, protected-descendant detection. |
| `Planning/` | `PlanBuilder`, `CleanupPlan`, `PlanItem`, `ConfirmedPlan` (SHA-256 sealed, built only from a plan plus `UserConfirmation`). |
| `Execution/` | `Executor` (actor; only entry point `execute(_ ConfirmedPlan)`), `Quarantine`, `Trash`, `CommandRunner` (with `CommandTrustPolicy` / `AdminGroupMembers` for the opt-in "Trust Homebrew tools"), `MutationPolicy`, `SecureFS`. The only code that may change the file system. |
| `Audit/` | `AuditLog` (JSONL, export). |
| `Permissions/` | `FullDiskAccessProbe`, `AppManagementProbe` and their System Settings deep links. |
| `ViewModels/` | `AppState`: the `@MainActor @Observable` state the UI binds to (scan, selection, review, execution, quarantine, settings, permissions). All file-system work runs off the main thread. |
| `Models/`, `Utils/` | `DiskUsage`, `ScanTarget`, `ByteFormatter`, `LocalState`. |

`Sources/iMop/` holds the SwiftUI app: `App/iMopApp.swift` (window, Settings scene, About window,
menu commands: Start Scan <kbd>Cmd</kbd>+<kbd>R</kbd>, Open Quarantine, Export Audit Log..., Full Disk
Access Settings...) and `Views/` (MainView, SidebarView, ScanView, CategoryListView, ItemDetailView,
ReviewSheet, RedItemConfirmation, ExecutionProgressView, ResultsView, QuarantineView, SettingsView, PermissionsView,
AdvisoryView, AboutView and shared components such as the storage gauge and tier badge). Views never
touch the file system; they call `AppState`.

### The pipeline

```
Scan (read-only) -> Classify (rule match) -> Size -> Preconditions
  -> PlanBuilder: CleanupPlan (immutable; SafetyGate pass 1)
  -> Review sheet -> ConfirmedPlan.confirm (selection + confirmations + hash)
  -> Executor: SafetyGate pass 2 for EVERY item -> act -> verify -> audit
```

- `Discovery/`, `Sizing/`, `Planning/`, `Rules/` and `Permissions/` are read-only; a static test
  fails if mutation APIs (`removeItem`, `trashItem`, `moveItem`, `unlink`, `rmdir`, `removefile`,
  `rename`, ...) appear in them, checks that file actions appear only in `Execution/`, and that shells,
  `system()`, `popen()`, `sudo` and `Process` outside `CommandRunner` appear nowhere.
- There is no `delete(path:)` anywhere. The Executor only accepts a `ConfirmedPlan`.
- No filesystem work on the main thread: `AppState` runs scans, planning, quarantine and disk usage in
  background tasks and only assigns results on the main actor.

### How to add a rule safely

Rules can only **narrow** what is allowed; they can never widen the deny-list or the SafetyGate.
A rule that fails validation is disabled at launch (and the tests fail).

1. **Check the spec and the deny-list.** The target must not be in, or contain, anything listed in
   [SAFETY.md](SAFETY.md#absolute-deny-list). If it is user data, it is Red at best. If you are unsure,
   it is not a rule.
2. **Add the rule to `Sources/iMopCore/Rules/Rules.json`** with a unique `id`, `category`, `tier`,
   non-empty `title`, `explanation`, `whatYouLose` and `howItRegenerates` (shown verbatim in the UI),
   `discovery`, `allowRoots` under `{HOME}`, `preconditions` and `action`. Example:

   ```json
   {
     "id": "pip.cache",
     "category": "developer",
     "tier": "green",
     "title": "pip download cache",
     "explanation": "Python packages and web responses that pip has downloaded ...",
     "whatYouLose": "Nothing you created; ...",
     "howItRegenerates": "pip fills the cache again as you install packages.",
     "discovery": { "glob": ["{HOME}/Library/Caches/pip/*"] },
     "allowRoots": ["{HOME}/Library/Caches/pip"],
     "preconditions": [ { "processNotRunning": ["pip", "pip3"] } ],
     "action": "quarantine"
   }
   ```

   Glob grammar: `{HOME}`, literal segments and `*` within **one** segment. No `**`, no regex, no
   braces. Decoding is strict: unknown keys or cases disable the rule.
3. **Respect the tier/action matrix.** Green: quarantine, or a command marked `idempotentSafe`. Yellow:
   quarantine, trash or command (`permanentDelete` only for the allow-listed rules). Red: trash or
   advisory (commands and `bootoutAndTrash` only for the pinned rules). Advisory: advisory only.
4. **Pin it in Swift where the code requires it.**
   - Glob rules are matched against their own patterns by `RuleTargetMatcher`. If the new folder lives
     directly in `~/Library/Caches`, add its name to `RuleTargetMatcher.unknownOwnerReservedCacheNames`
     so the Yellow "Caches of unknown apps" rule can never swallow it.
   - Inspector rules need a pinned spec in `RuleCatalog` (`inspectorRuleSpecs`, `projectArtifactSpecs`,
     `nonHomeRuleSpecs`, `advisoryRuleSpecs`, ...) **and** a shape predicate in `RuleTargetMatcher`
     (an inspector without a predicate matches nothing). Inspectors whose answer depends on what is on
     disk also need a SafetyGate check 11d identity re-check.
   - Vendor-command rules need an exact entry in `CommandAllowList` (tool + argument array, minimum tier,
     `{ITEM}` validator) and a pinned shape in `RuleTargetMatcher.commandRuleShapes` (inspector, tier,
     exact command, required preconditions).
5. **Add tests** (`Tests/iMopTests/`): update the expected rule lists in `Rules/M2Support.swift` /
   `M5Support.swift` / `M6Support.swift`, make sure `RuleCatalogTests` loads the bundled catalog with no
   disabled rules, and add fixture tests that show the rule finds what it should, rejects look-alikes
   (symlinks, other volumes, protected children, excluded names) and that SafetyGate rejects it when a
   precondition fails.
6. **Explain conservative choices** with a `// SAFETY-DECISION:` comment.

### Test suite

The tests are a standalone executable (`Tests/iMopTests/main.swift`, harness in `TestHarness.swift`)
so they run with only the Command Line Tools. They never touch real user files:

- `Support/FixtureBuilder` creates a fake home under `$TMPDIR/iMopTests-<UUID>/`, and
  `Support/FakeEnvironment` injects it (plus fake processes, apps, volumes, Spotlight, commands).
- A real-home tripwire is installed before any test runs: any code path that resolves the real
  `NSHomeDirectory()` aborts the run. At the end, a leak check fails if any fixture folder was left
  behind.
- Mutation in tests is possible only through the fixture `MutationPolicy`, confined to the fixture root.

| Area | Suites |
|---|---|
| Safety (M1) | Canonicalizer, DenyList (one test per entry, symlink and case variants), SafetyGate adversarial tests (spec §12.1), Preconditions, review regressions, permission probes |
| Rules, sizing, scanning (M2) | RuleCatalog (bundled Rules.json valid; malformed rules disabled), Glob, Sizer (clones, hard links), SafeCleanScanner, static read-only test |
| Plan & execution (M3) | Plan / confirmation hash, Quarantine (move, restore with and without conflict, purge, crash reconciliation), Executor (refuses without the flag, double validation), AuditLog |
| Commands (M4) | CommandRunner (untrusted locations, sanitized environment, timeouts), command clients and inspectors |
| Yellow rules (M5) | XcodeInspector, ProjectScanner, other Yellow inspectors, Yellow policy (nothing preselected) |
| Red & advisory (M6) | OrphanDetector (each of the 8 conditions), LaunchAgents, Trash flows, Advisory, retention overrides |
| App state (M7) | AppState / SettingsStore behaviour against a fake environment; static About text / v1.1 badge / no v1.0 toggles or types |

---

## License

iMop is Freeware.

Created by Ravi Subramaniam, Bangalore (India).
