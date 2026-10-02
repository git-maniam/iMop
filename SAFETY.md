# iMop SafeClean: safety model

This document is for contributors. It summarises, **from the code**, what iMop v1.1 ("SafeClean") may
and may not do, and why. The rule is simple: iMop must never break macOS, never break an installed
app and never destroy user data. Reclaiming space comes second. **If you are unsure whether an
operation is safe, don't do it.** Skip the item, log why, and show it to the user as "Skipped for
safety".

The code is the authority. If this file and the code disagree, the code wins and this file is out of
date. Sources: `Sources/iMopCore/Safety/{DenyList,PathCanonicalizer,SafetyGate,SafetyRejection,Preconditions}.swift`,
`Sources/iMopCore/Rules/{RuleCatalog,CommandAllowList,RuleTargetMatcher}.swift`,
`Sources/iMopCore/Execution/*.swift`, `iMop-SafeClean-Spec.md`.

## Contents

1. [Trust promises and where they are enforced](#trust-promises-and-where-they-are-enforced)
2. [The pipeline](#the-pipeline)
3. [Safety tiers](#safety-tiers)
4. [Path canonicalization](#path-canonicalization)
5. [Absolute deny-list](#absolute-deny-list)
6. [SafetyGate invariants (in order)](#safetygate-invariants-in-order)
7. [Preconditions (fail closed)](#preconditions-fail-closed)
8. [Rule catalog validation](#rule-catalog-validation)
9. [Execution: mutation flag, confirmation, Executor](#execution-mutation-flag-confirmation-executor)
10. [Quarantine and crash safety](#quarantine-and-crash-safety)
11. [Vendor commands: allow-list and runner](#vendor-commands-allow-list-and-runner)
12. [App layer (AppState and views)](#app-layer-appstate-and-views)
13. [Settings can only narrow](#settings-can-only-narrow)
14. [Explicitly forbidden (spec §10)](#explicitly-forbidden-spec-10)
15. [Spec deviations](#spec-deviations)
16. [Manual QA checklist](#manual-qa-checklist)
17. [Remaining Milestone 8 work](#remaining-milestone-8-work)
18. [Appendix: every SAFETY-DECISION in the code](#appendix-every-safety-decision-in-the-code)

---

## Trust promises and where they are enforced

| Promise | Enforced by |
|---|---|
| Never touch `/System`, the Signed System Volume or SIP-protected paths | Deny-list system entries (`/System` can never be waived, not even in tests); canonicalizer maps `/System/Volumes/Data/...` firmlinks to their logical path and denies every other `/System/...` path |
| Never delete inside iCloud Drive or a cloud-sync folder | Deny-list (`~/Library/Mobile Documents`, `~/Library/CloudStorage`), SafetyGate check 10 (`isUbiquitousItem`, File Provider xattrs, on the target and every ancestor), `notInsideCloudRoot` precondition added implicitly to every file-system item; `uploadedToCloud` is always false in v1 |
| Never modify files inside an app bundle | SafetyGate check 11 (bundle guard); the only exception is trashing a WHOLE Apple-signed `.app` for two pinned rules |
| Never run as root, never escalate | SafetyGate check 1 refuses effective OR real uid 0; `sudo`, `su`, `doas` and shells are forbidden tools and arguments; no privileged helper exists |
| iMop itself makes no network connections | No networking code in iMop; no remote rules. Vendor commands are exact allow-listed argument arrays, but a vendor tool may still contact its own services (usage analytics, update checks): iMop passes the tools' documented opt-outs (`CommandRunner.networkOptOutVariables`: `FLUTTER_SUPPRESS_ANALYTICS`, `HOMEBREW_NO_ANALYTICS`, `HOMEBREW_NO_AUTO_UPDATE`, `DO_NOT_TRACK`) and runs `ollama list` only while Ollama is already running (the CLI would otherwise start Ollama.app). `ollama rm` itself talks to the local Ollama server |
| Every removal is logged; most are restorable | `AuditLog` (JSONL) for every verdict and outcome, also in dry-run builds; Quarantine (24 h / 7 d) for Green and Yellow file items, Finder Trash for Red items |
| Scan is read-only | Static test: `Discovery/`, `Sizing/`, `Planning/`, `Rules/`, `Permissions/` contain no mutation API; file actions appear only in `Execution/`; only the Executor asks for command purpose `.action` |
| No background auto-clean | The Executor's only entry point is `execute(_ ConfirmedPlan)`, and a `ConfirmedPlan` can only be built from a reviewed plan plus a user confirmation; the only timer purges *expired Quarantine* items |

## The pipeline

```
Scan (read-only) -> Classify (rule match) -> Size -> Preconditions
  -> PlanBuilder: CleanupPlan (immutable; SafetyGate pass 1, phase .plan)
  -> Review sheet -> ConfirmedPlan.confirm(...)  (selection, confirmations, SHA-256 hash)
  -> Executor (actor, one item at a time):
       verify hash -> SafetyGate pass 2 (phase .execute) -> act -> verify outcome -> audit
```

- Both SafetyGate passes run exactly the same checks; nothing is skipped at execute time because it
  passed at plan time.
- There is no `delete(path:)`-style API anywhere (a static test checks this).
- Every per-item failure is non-fatal: the item is skipped with a reason and the run continues.

## Safety tiers

`Tier` in `Rules/Rule.swift`. The UI always shows the badge **text and SF Symbol**, never colour alone.

| Tier | Badge text | Symbol | Preselected | Allowed actions (RuleCatalog matrix) | Retention | Confirmation |
|---|---|---|---|---|---|---|
| Green | Safe | `checkmark.shield` | Yes (actionable items only) | Quarantine, or a vendor command marked `idempotentSafe` | 24 h | Review sheet |
| Yellow | Review | `exclamationmark.triangle` | No | Quarantine, Trash, vendor command; `permanentDelete` only for `trash.empty` and `system.coreDumps` | 7 days | Review sheet; "What you lose" shown |
| Red | Caution | `hand.raised` | Never | Trash or advisory; vendor command only for `docker.volumes`; `bootoutAndTrash` only for `leftovers.launchAgents` | n/a (Trash) | Per-item dialog naming the item and its size |
| Advisory | Info | `info.circle` | Not selectable | Advisory only (Reveal in Finder, Open App, Open Storage Settings, instructions) | n/a | n/a |

Further tier rules from the code:

- A one-step permanent deletion is never preselected, even for a Green rule.
- Bulk selection ("select all in category") never selects Red items and never non-actionable items.
- The Executor accepts an effective tier only if it is *stricter* than the rule's tier, and a planned
  action only if it is not more destructive than the rule's action.
- Non-restorable actions (vendor commands, `permanentDelete`, `bootoutAndTrash`) require an explicit
  irreversible-action acknowledgement on the review sheet.
- Sanity limits (check 13) downgrade an item to Red for manual review; a downgraded item is never acted
  on, neither at plan nor at execute time.

## Path canonicalization

`Safety/PathCanonicalizer.swift`, spec §3.4:

- `~` and `{HOME}` expand only from the injected `Environment.homeDirectory`; `~otheruser` is rejected.
  A home that is relative, contains `..` or NUL, or is `/` is unusable, and then every path expanding
  from it is rejected (and the deny-list denies everything).
- Any input with a `..` component is rejected before standardizing.
- Resolution with `URLResourceKey.canonicalPathKey` **and** `realpath(3)`; they must agree. Resolver
  output goes through the same text rules; relative output, `..` or a mapping into `/System` is rejected.
- `/System/Volumes/Data/...` is mapped to the logical path; every other `/System/...` is denied.
  `/var`, `/tmp`, `/etc` are mapped to `/private/...`.
- Comparisons are component-wise, case-insensitive and Unicode-normalization-insensitive
  (`precomposedStringWithCanonicalMapping` + `lowercased()`, NFC re-applied after lowercasing). Never raw
  `hasPrefix`: `/Users/a/Lib` does not match `/Users/a/Library`.
- `CanonicalPath(validatedPath:)` traps on malformed input (also in release builds) rather than
  producing a path whose containment checks could be fooled.

## Absolute deny-list

`Safety/DenyList.swift`. Hard-coded in Swift, never in `Rules.json`. **The deny-list always wins**
over any rule, setting or allow-root.

**System entries** (component-wise prefix on the logical canonical path):

```
/System  /bin  /sbin  /usr  /opt
/private/etc  /private/var/db  /private/var/vm  /private/var/folders  /private/var/root
/private/var/log  /private/var/run  /private/tmp
/Library  /Applications/Utilities  /Volumes  /cores
/.Spotlight-V100  /.fseventsd  /.DocumentRevisions-V100  /.MobileBackups  /.vol
```

**Home-relative entries** (`~/` = the injected home; a trailing `*` = "component starts with", a
leading and trailing `*` = "component contains"):

```
~/Library/Keychains                ~/Library/Mobile Documents         ~/Library/CloudStorage
~/Library/Mail                     ~/Library/Messages                 ~/Library/Photos
~/Library/Accounts                 ~/Library/Cookies                  ~/Library/HTTPStorages
~/Library/Safari                   ~/Library/Calendars                ~/Library/Reminders
~/Library/Contacts                 ~/Library/Application Support/AddressBook
~/Library/Application Support/MobileSync
~/Library/Application Support/com.apple.TCC
~/Library/Application Support/iMop          (Quarantine module only, see below)
~/Library/Logs/iMop                          (iMop's audit log)
~/Library/Group Containers/group.com.apple.*
~/Library/Group Containers/*com.apple.*      (e.g. <TeamID>.groups.com.apple.podcasts)
~/Library/Containers/com.apple.*             (one exception, see below)
~/Library/Preferences/com.apple.*
~/Library/Preferences/ByHost/com.apple.*
~/Library/LaunchAgents/com.apple.*
~/.ssh  ~/.gnupg  ~/.aws  ~/.kube  ~/.docker/config.json  ~/.config/gh  ~/.netrc
~/Documents  ~/Desktop  ~/Pictures  ~/Movies  ~/Music
```

**Any component** named `.git`, or with one of these extensions:
`.photoslibrary .musiclibrary .tvlibrary .lrcat .fcpbundle .logicx .band .sparsebundle .keychain-db`.

**Cloud roots** (also used by check 10 and `notInsideCloudRoot`): `~/Library/Mobile Documents`,
`~/Library/CloudStorage`.

How it is applied:

- **Containment is denied too.** A path that *contains* a protected location (the home folder itself,
  `~/Library`, `~/.docker`, `/Applications`, `/`) is denied: acting on it would act on the protected
  content beneath it.
- **Protected descendants** (check 11c): a directory target that contains a `.git` or a protected
  extension anywhere below it is rejected; the tree is walked again at every validation, and a walk
  that cannot read the whole tree rejects (fail closed).
- **Both spellings of home.** The deny-list is built for the configured home and, when different, the
  resolved home. Every existing home-relative entry is also resolved with `realpath(3)`; if it is (or is
  reached through) a symlink, its real location is protected under the same label (a link to a
  protected folder is never a bypass).
- **Defence in depth:** the lexical text rules are re-applied to every path before matching, in case
  it was built from a non-logical form (`/tmp`, `/var`, firmlink).
- **The only exceptions:**
  - `/cores/core.<something>` (direct children only) for rule `system.coreDumps`.
  - Direct children of `~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads` for rule
    `mail.downloads` only. Every other entry still applies.
  - `~/Library/Application Support/iMop/Quarantine/**` for the Quarantine module (purpose
    `.quarantine`) only; the Quarantine folder itself stays denied.
  - Test fixtures: `/private/var/folders` and `/private/tmp` may be waived only for roots strictly
    inside the temporary directory whose first component starts with `iMopTests-`. `/System` is never
    waivable. Home-relative entries, extensions and `.git` still apply inside waived roots.

## SafetyGate invariants (in order)

`Safety/SafetyGate.swift`, `validate(target:rule:phase:)`. Called at plan time and again immediately
before acting. The first failing check decides; every rejection is audited.

| # | Check | Rejects when |
|---|---|---|
| 1 | Process identity | `geteuid() == 0` **or** `getuid() == 0` |
| pre | Target/rule coherence | `target.ruleID != rule.id`; the target, rule tier or rule action is Advisory; a command item for a non-command action; a command item that is not for a Swift-pinned vendor-command rule or whose `{ITEM}` fails that command's validator |
| 2 | Canonicalize | The raw path is not already in clean lexical form (trailing `/`, `.`, `~`); `/`; canonicalization fails or `canonicalPathKey` and `realpath` disagree; resolution differs from the lexical path (a symlink was traversed); the target is a symlink and the rule does not set `allowSymlinkTarget`; an allowed link whose destination is protected or unresolvable; a link name whose spelling does not match exactly one directory entry of the parent (APFS case folding) |
| 3 | Absolute deny-list | Any entry matches (see above), on every home spelling and alias |
| 4 | Allow-root containment | Not strictly inside one of the rule's canonicalized allow-roots, or **equal** to any of them (even if inside another); roots that resolve through a symlink or are `/` are unusable; `{PROJECT_ROOTS}` expands to the validated project roots, re-resolved each time |
| 5 | Minimum depth | Fewer than `minDepthBelowRoot` (default 1, minimum 1) components below the innermost allow-root |
| 6 | No symlink at any level | `lstat` of any component from the outermost allow-root down to the target shows a symlink |
| 7 | Same volume | Any component between the allow-root and the target is on another `st_dev` (mount point crossing) |
| 8 | Ownership | `st_uid` of the target is not the current user |
| 9 | Identity pinning | `(st_dev, st_ino)` captured at scan time is missing or differs ("item changed since scan") |
| 10 | Cloud-sync guard | Target or any ancestor up to the allow-root is inside a cloud root, `isUbiquitousItem` is true **or cannot be determined**, or carries a File Provider xattr (`com.apple.fileprovider.*`, `com.apple.file-provider*`) **or xattrs cannot be read**; cloud roots not computable |
| 11 | Bundle guard | An ancestor is a bundle (`.app .framework .bundle .plugin .kext .systemextension .appex`), or the target is one; the only exception is a whole `.app` directory for `xcode.extraInstalls` / `installers.macOS` when the rule passes catalog validation. Reverse-DNS folder names (`com.example.app`) count as bundles only if they have bundle structure, are not directories, or cannot be listed |
| 11b | Rule shape (review M2) | The canonical target does not match one of the rule's glob patterns (with `excludedNames`), or the Swift-coded shape of its inspector (`RuleTargetMatcher`); an inspector without a predicate matches nothing |
| 11d | Inspector identity (review M5/M6) | Re-proves on disk what the inspector checked: project artifact manifest/marker/depth/VCS layout; Lightroom `<name>.lrcat` beside `<name> Previews.lrdata`; unknown-owner cache holds no `com.apple.*` entry and can be listed; whole-app rules re-read `Contents/Info.plist` and require exactly the recorded `CFBundleIdentifier` and that it is Xcode (`com.apple.dt.Xcode`) or an Apple installer (`com.apple.InstallAssistant.*`); orphaned LaunchAgent still declares exactly the confirmed Label, no other plist declares it, and its program is still proven missing |
| 11c | Protected descendants (review M2) | A directory target contains `.git` or a protected extension anywhere, or its contents cannot be fully inspected |
| 12 | Preconditions | Any declared precondition (plus implicit `ownedByUser`, `notInsideCloudRoot` for file items) fails |
| 13 | Sanity limits | `allocatedBytes > maxExpectedBytes` (default 200 GB) or `itemCount > maxExpectedItems` (default 2,000,000), or either is negative: **downgraded to Red**, never acted on |
| 14 | User exclusions | Target (canonical or lexical) is inside an exclusion, or *contains* one; an exclusion that cannot be interpreted rejects; exclusions that are symlinks are also added in their resolved form. Evaluated even when 13 tripped, so an excluded item is rejected outright rather than offered as Red |

Notes:

- The code runs 11b, then 11d, then 11c (cheapest first; all three always run before 12).
- **Command items** (vendor commands with an informational path, UDID or model name) get check 1, the
  coherence pre-check, 12 and 14 (14 only if the value looks like a path; a path-like value that fails
  the text rules is rejected). Their safety comes from the pinned command table, not from paths.
- The exclusions stored in the environment's settings are always merged in, so a caller cannot drop one.
- Rejection reasons are in `SafetyRejection.reason` and map to the spec §11 error categories.

## Preconditions (fail closed)

`Safety/Preconditions.swift`. **Every predicate fails closed:** if it cannot be evaluated (error,
timeout, malformed or unexpected output, missing data), it is **false** and the item is skipped.

| Predicate | Passes only when |
|---|---|
| `appNotRunning([bundleID])` | None of the IDs is running (trailing `*` wildcard; case-insensitive). Empty list, malformed pattern or unavailable app list fail |
| `owningAppNotRunning` | The item's recorded owner is a reverse-DNS ID and is not running (matched exactly; `*` is not a wildcard). Unknown owner fails |
| `processNotRunning([name])` | No process with that name (libproc; case-insensitive; a 15+ char running name that prefixes the requested one counts as running). Empty name or failed listing fail |
| `notOpenByAnyProcess` | No process holds a file under the target (`proc_listpidspath`); errors count as "open", except processes that are gone, zombies, or other users' processes refused with EPERM |
| `olderThan(days)` | `max(mtime(target), mtime(each immediate child))` via `lstat` is strictly older than N days (never atime). Unreadable listing, vanished child, future mtime or negative N fail. User overrides may only raise N |
| `manifestPresent([names])` | A matching regular file (not a symlink, not a directory) exists beside the artifact. Patterns with `/` or more than one `*` never match |
| `projectOlderThan(days)` | Max mtime of every known manifest beside the artifact, `.git/index` and `.git/HEAD` is older than N. Symlinked or unreadable files, a non-directory `.git`, or none present fail |
| `notTrackedByGit` | Only the system `/usr/bin/git` (and only if the active developer dir provides git, so no install dialog appears), read-only, in a validated project root, with the artifact folder being the repo top level, reports "did not match". Any other VCS marker (`.hg`, `.svn`, `.jj`, ...) from the project up to home, any unlistable folder, or any other git outcome counts as tracked |
| `notInsideCloudRoot` | Lexical and resolved forms are outside the cloud roots and the item is not ubiquitous/File Provider (unknown counts as cloud) |
| `ownedByUser` | `st_uid` equals the current user |
| `simulatorIdle` | Every device in `simctl list devices -j` is `Shutdown` (Booted, Booting, Shutting Down, Creating or unknown fail) and the Simulator app is not running |
| `dockerDaemonReachable` | `docker info` exits 0 within the timeout. iMop never starts Docker |
| `notMounted` | Neither the item nor anything inside it is listed by `hdiutil info -plist`; a missing `images` key or an uninterpretable image path fails |
| `appleSigned` | `SecStaticCodeCheckValidity` with `anchor apple` passes (full validation incl. sealed resources) |
| `notSelectedXcode` | The bundle is neither inside nor containing `xcode-select -p` (both spellings) |
| `stillOrphaned` | The OrphanDetector's evaluator re-confirms at execute time that the owner is still orphaned (LaunchServices, Spotlight, running apps/processes, receipts, drives, Setapp, app groups / Team IDs) |
| `uploadedToCloud` | **Always false in v1.1.** iCloud eviction stays Advisory |

## Rule catalog validation

`Rules/RuleCatalog.swift`, `Rules/RuleCoding.swift`. `Rules.json` is bundled and read-only (never
downloaded). Decoding is **strict** (unknown keys, unknown cases, wrong types are errors; unknown
top-level keys or file version invalidate the whole file). Any invalid rule is **disabled and logged**,
and the app continues. A missing `Rules.json` gives an empty catalog (the SwiftPM `Bundle.module`
accessor, which would `fatalError`, is never used).

Each rule must have: a valid unique `id` (an id used twice disables every copy); version >= 1;
non-empty `title`, `explanation`, `whatYouLose`, `howItRegenerates`; `minDepthBelowRoot >= 1`; positive
limits and retention; allow-roots under `{HOME}` that do not intersect the deny-list (Swift-pinned
exceptions: `/cores`, `/Applications`, `{HOME}` itself for `lightroom.previews`, `{PROJECT_ROOTS}` for
ProjectScanner rules, Mail Downloads); glob patterns in the tiny grammar (`{HOME}`, literal segments, `*`
within one segment; no `**`) whose sample match is not deny-listed; the tier/action matrix above; vendor
commands only from the exact `CommandAllowList` (never any `system prune`); timeouts within 10 min
(30 min for `simctl runtime delete`); the spec §6 preconditions pinned for command and inspector rules;
and, for every Swift-pinned rule (inspector rules, ProjectScanner rules, non-home rules, advisory rules,
the LaunchAgent rule), exactly the pinned tier, action, discovery, allow-roots and preconditions.

## Execution: mutation flag, confirmation, Executor

**`IMOP_ALLOW_MUTATION`** (`Execution/MutationPolicy.swift`). Without this compile-time flag every
mutation (quarantine, restore, purge, trash, permanent delete, `.action` command) is refused with
"mutation disabled in this build" and audited. Only `scripts/package_app.sh` sets it. `isEnabled` is
computed, never settable. While the test-suite guard is installed, even a flag-enabled build refuses;
tests mutate only through `MutationPolicy.fixtureOnly(root:)`, which requires the path and home to be
strictly inside an `iMopTests-*` root in the temporary directory, without symlinks. Every policy refuses
relative paths, `..`, NUL, placeholders and `/System`.

**`ConfirmedPlan.confirm`** (`Planning/CleanupPlan.swift`) throws unless: the selection is non-empty and
every ID is a known, actionable, unambiguous plan item; every selected Red item has its per-item
confirmation; irreversible items are acknowledged; no permanent deletion while "Always quarantine" is ON
(plan setting and caller setting must BOTH be off); and at least **2 seconds** passed between the review
sheet appearing and the confirmation (written as `!(elapsed >= 2)` so a NaN or negative interval is
refused). The result is sealed with a SHA-256 hash of the plan contents.

**`Executor`** (actor, `Execution/Executor.swift`):

- One confirmation allows **one** execution. The hash is re-verified before starting.
- Items run sequentially; cancellation is honoured between items only; if the consumer of the event
  stream goes away, the run stops at the next item boundary.
- Per item: SafetyGate pass 2 → act → verify (the moved/trashed object must be the pinned item) → audit.
- The effective tier may only be stricter, the action never more destructive than the rule's.
- Quarantine retention must equal what the CURRENT settings give the rule (overrides may only lengthen);
  a plan built under other settings is refused.
- "Always quarantine" is re-read from the persisted settings right before acting; ON blocks every
  permanent deletion.
- Vendor commands: the exact invocation must be an action entry of the `CommandAllowList` that the rule
  and tier may use, with the `{ITEM}` value accepted by the entry's validator; empty, `-`-prefixed or
  control-character arguments are refused; whole-rule commands never take an item.
- `bootoutAndTrash` (`leftovers.launchAgents` only): the plist is re-read (it must still name a missing
  program); only `/bin/launchctl bootout gui/<own uid> <~/Library/LaunchAgents/x.plist>` is run; the
  plist goes to the Trash only after a successful bootout or launchd's "not loaded" answer.
- Trash (`Execution/Trash.swift`): `FileManager.trashItem` only, never `/`, top-level folders, the home
  folder or its ancestors; the trashed object must be the pinned item. The Trash is never emptied
  automatically, and in test runs the real Trash is never touched.
- After the run, free space (`volumeAvailableCapacityForImportantUsage`) is measured before/after and
  reported with the estimate plus the honest explanations of spec §7.3.

**Audit log** (`Audit/AuditLog.swift`): `~/Library/Logs/iMop/audit-YYYY-MM.jsonl`, one JSON object per
event (timestamp, session, rule id, path, action, bytes, verdict, rejection reason, exit code, details
truncated at 64 KB), never file contents. Written even in dry-run builds. Appends only to a regular,
single-link file owned by the user (`O_NONBLOCK` against FIFOs). Export creates a NEW file only
(`O_CREAT|O_EXCL|O_NOFOLLOW`) and refuses the Quarantine, iMop's own folders and any deny-listed
destination (e.g. `~/Desktop`, `~/Documents`).

## Quarantine and crash safety

`Execution/Quarantine.swift`, spec §5.1 and §11.

```
~/Library/Application Support/iMop/Quarantine/      0700, real directory owned by the user
  .metadata_never_index                             keeps Spotlight out
  <session-UUID>/                                   0700
    manifest.json                                   atomic write (O_EXCL temp file + rename)
    <entry-UUID>/<original name>                    moved with renamex_np(RENAME_EXCL), never copied
```

- `quarantine(...)` is SPI-only (the Executor is the only production caller) and re-runs SafetyGate
  (phase `.execute`) itself. Moves are made relative to verified directory descriptors (no symlink
  following); the pinned identity is checked with `fstatat` immediately before `renameatx_np`; if the
  wrong object was moved, it is moved straight back. Items on another volume are skipped (never copied).
  Symlinks are never quarantined. Only rules whose action already removes the item may quarantine it.
  Retention must be positive. The home folder, its ancestors and the Quarantine itself are never moved.
- **Write-ahead manifest:** every state change is written BEFORE it happens: `pending` (move),
  `restoring` (restore, with the chosen destination), `purging` (purge). `reconcile()` at launch:
  - `pending`: pinned item in Quarantine → `moved`; something else there → `needsReview`; nothing there
    → entry dropped.
  - `restoring`: item at the destination → `restored`; still in Quarantine → `moved`; else `needsReview`.
  - `moved` but missing from Quarantine: back at its origin → `restored`; else `needsReview`.
  - `purging` and gone → `purged` (otherwise the next purge retries it).
  - An entry is dropped only when nothing is in its Quarantine folder, so an item physically in
    Quarantine is never forgotten. `needsReview` is never purged; it can be restored on explicit request.
  - Identity across launches = inode + persistent volume UUID (not `st_dev`).
- **Restore** uses `RENAME_EXCL`; if the original path exists, the item is restored as
  `<name> (restored <date>)` beside it. The original parent must still be a real directory reached
  without symlinks. Nothing is ever overwritten.
- **Purge** (expired items at launch and on a daily timer; everything on "Empty Quarantine Now" after
  a confirmation): `removefile(3)` with `REMOVEFILE_RECURSIVE` (does not follow symlinks), every item
  through SafetyGate with `allowRoots = [Quarantine root]` and purpose `.quarantine`. A session whose
  manifest cannot be read is never purged; a session still in use by the running Executor is not removed.
- UI text (verbatim): "Space from quarantined items is freed when quarantine is emptied. Empty now to
  reclaim immediately."

## Vendor commands: allow-list and runner

`Rules/CommandAllowList.swift` is the single Swift-coded table of commands iMop may ever run. Both
`RuleCatalog` (validation) and `CommandRunner` (at run time) enforce it; `Rules.json` can only pick from
it. `{ITEM}` is one whole argument checked against a strict ASCII shape.

**Action commands** (minimum tier in brackets):

| Tool | Arguments |
|---|---|
| `brew` | `cleanup --prune=all` [Green] |
| `npm` | `cache clean --force` [Green] |
| `yarn` | `cache clean` [Green] |
| `pnpm` | `store prune` [Green] |
| `bun` | `pm cache rm` [Green] |
| `uv` | `cache prune` [Green]; `cache clean` [Yellow] |
| `go` | `clean -cache` [Green]; `clean -modcache` [Yellow] |
| `pod` | `cache clean --all` [Green] |
| `flutter` | `pub cache clean -f` [Yellow] |
| `docker` | `image prune -f`, `builder prune -f` [Green]; `image prune -a -f`, `container prune -f` [Yellow]; `volume rm {ITEM}` [Red, `docker.volumes` only, volume-name shape] |
| `xcrun` | `simctl delete unavailable` [Green]; `simctl delete {ITEM}` [Yellow, upper-case UDID]; `simctl runtime delete {ITEM}` [Yellow, runtime id or UDID, 30 min timeout] |
| `ollama` | `rm {ITEM}` [Yellow, model-name shape, no empty/`.`/`..` namespace segment] |
| `avdmanager` | `delete avd -n {ITEM}` [Yellow, AVD-name shape] |
| `launchctl` | `bootout gui/{UID} {PLIST}` [Red, `leftovers.launchAgents`, no rule may name it; own uid and own `~/Library/LaunchAgents/<non-Apple>.plist` only; `/bin/launchctl` only] |

**Read-only commands** (scan estimates, discovery, precondition probes): `xcrun simctl list devices -j`,
`... list devices unavailable -j`, `simctl runtime list -j`; `brew cleanup --prune=all -n`;
`npm config get cache`; `yarn cache dir`; `pnpm store path`; `uv cache dir`; `bun pm cache`;
`go env GOCACHE` / `GOMODCACHE`; `pod cache list`; `avdmanager list avd`; `ollama list`; `docker info`,
`docker system df` (`-v`, `--format {{json .}}`), `docker image ls`, `docker ps -a --filter status=exited`,
`docker volume ls -f dangling=true` (each optionally with `--format {{json .}}`). Internal probes no rule
may name: `xcode-select -p`, `hdiutil info -plist`, `/usr/sbin/pkgutil --pkgs`,
`/usr/bin/tmutil listlocalsnapshots /`, and the git probe
`git --no-optional-locks --icase-pathspecs -c core.fsmonitor=false -C {PATH} ls-files --error-unmatch -- {NAME}`
(`{PATH}` inside a validated project root, `{NAME}` one of `node_modules target .venv venv Pods .next build .build`).

**Always forbidden**, whatever the table says:

- Tools: `sh bash zsh csh tcsh ksh dash fish sudo su doas env xargs osascript perl ruby python python3 rm
  srm find dd diskutil chmod chown mv cp nohup arch caffeinate nice time timeout exec command open
  launchctl rmdir unlink` (`launchctl` only for the exact bootout shape above). Rules may name only
  `xcrun brew npm yarn pnpm bun uv go docker pod flutter avdmanager ollama`.
- Arguments (whole, case-insensitive): `--volumes autoremove sudo doas -c sh bash zsh csh tcsh ksh dash
  fish -rf -fr -r --recursive --no-preserve-root`; any `system` + `prune` combination; control
  characters. For actions, `/` may appear only inside an `{ITEM}` kind that allows it (Ollama
  namespaces) or the bootout slots.

**`CommandRunner`** (`Execution/CommandRunner.swift`, spec §5.3):

- `Process` with an absolute, fully resolved executable path and an argument array. Never a shell.
- Search order: `/usr/bin` (only `xcrun xcode-select hdiutil tmutil pkgutil launchctl git`),
  `/opt/homebrew/bin`, `/usr/local/bin`, `~/.cargo/bin`, `~/go/bin`, `~/.bun/bin`, `~/.local/bin`.
  `pkgutil`, `tmutil` and `launchctl` only from their exact SIP-protected paths.
- Trust: every directory on the way (each ancestor up to `/`, each symlink hop) is owned by the user or
  root and **not group/world-writable**; every symlink is owned by the user or root; the file is a
  regular executable owned by the user or root, not group/world-writable; its real path is inside a
  trusted root (`/usr/bin`, `/opt/homebrew`, `/usr/local`, `~/.cargo/bin`, `~/go/bin`, `~/.bun/bin`,
  `~/.local/bin`); `#!` interpreters pass the same checks (`#!/usr/bin/env NAME` with exactly one bare
  name, resolved like `env` would). The first match decides: an untrusted match is refused, not skipped.
  The path is re-resolved right before launch and must still be the same inode.
- **Command trust: "Trust Homebrew tools" (opt-in, OFF by default).** A standard Homebrew install makes
  its folders (`/opt/homebrew/bin`, `Cellar`, `lib`, `opt`, …) `drwxrwxr-x`, owned by the installing user
  with group `admin`, so with the rule above every Homebrew-installed tool (`brew`, `npm`, `yarn`, `pnpm`,
  `go`, `uv`, `pod`, `flutter`, `node` for `#!` scripts, …) is refused. When the user turns the setting
  on (`ScanSettings.trustHomebrewAdminWritableDirectories` → `CommandTrustPolicy`), a **directory** —
  never a file, never a symlink — on the resolution path, a symlink hop, a `#!` interpreter's path or a
  PATH search directory may be group-writable only if **all** of these hold
  (`CommandRunner.isTrustedHomebrewDirectory`):
  1. its physical path (built component by component, symlinks followed) is inside or equal to a
     Homebrew prefix, compared component-wise and case-sensitively. Exact list: Apple silicon
     `/opt/homebrew`; Intel `/usr/local/Homebrew`, `/usr/local/Cellar`, `/usr/local/opt`,
     `/usr/local/lib`, `/usr/local/bin`, `/usr/local/share`, `/usr/local/Caskroom` (never `/usr/local`
     itself); only the list for the architecture iMop runs on is used;
  2. its owner is **the current user** (not root, not anyone else; owner decision "option B");
  3. its group is exactly the `admin` group's gid, looked up with `getgrnam_r("admin")` — if the lookup
     fails, the relaxation is disabled;
  4. it is **not world-writable** (`S_IWOTH` is never accepted; the sticky bit changes nothing).

  Files must still be regular, executable, owned by the user or root and not group/world-writable;
  symlinks must still be owned by the user or root. Everything else — trusted roots, the allow-listed
  (tool, arguments) pairs, `{ITEM}` validators, purpose enforcement, the device/inode re-check right
  before launch, the sanitized environment — is unchanged. OFF behaves exactly as before this setting
  existed. The residual risk when ON: every account in the `admin` group can replace these tools, and
  iMop would then run what they put there as the user. That is why turning it on first shows those
  accounts (`AdminGroupMembers.current()`: explicit members of `admin` plus accounts whose primary group
  is `admin`, without the user and root; "could not be determined" is shown with a stronger warning) and
  needs an explicit "Trust Homebrew Tools" click (Cancel is the default action). Turning it off needs no
  confirmation. Every change is recorded in the audit log (`settings.trustHomebrewTools`, enabled /
  disabled, with the disclosed account list).
- Honest reasons: when a tool exists and would pass every check but is refused only because a Homebrew
  folder is admin-writable and the setting is OFF, `CommandRunner.unavailableReason(for:)` says so ("npm
  is in /opt/homebrew/bin, a folder other accounts can change. Turn on “Trust Homebrew tools” in Settings
  to allow it."). Inspectors, the cocoapods exclusive pair and the Executor report that reason instead
  of "not installed in a trusted location"; it appears in Permissions › "Unavailable this session" and in
  each category's "Not offered in this scan".
- Environment: only `PATH` (trusted directories that pass the checks now, then `/usr/bin`, `/bin`),
  `HOME`, `USER`, `LANG`. stdin `/dev/null`, cwd = home.
- Output captured and truncated at 64 KB per stream. Timeout default 10 min, max 30 min; on timeout the
  whole process group gets SIGTERM, then SIGKILL. A cancelled read-only probe is stopped the same way;
  an `.action` command is never interrupted half-way.
- No automatic retries. Exit code and stderr are reported and audited.

## App layer (AppState and views)

`Sources/iMopCore/ViewModels/AppState.swift` and `Sources/iMop/Views/` add no new way to change the file
system; they only drive the core pipeline. Their safety rules:

- `AppState` has no mutation-policy knob: the Executor always uses the compile-time policy. When it is
  disabled the UI shows a "Dry-run build — cleaning disabled" banner.
- No file-system work on the main thread: scanning, planning, sizing, Quarantine and disk usage run in
  background tasks; only state assignment happens on the main actor. No cleanup ever starts without the
  review sheet; the only timer is the daily purge of *expired* Quarantine items (never while a cleanup
  is running).
- A Red item can only be selected by confirming the dialog currently presented for it
  (`pendingRedConfirmation`); bulk selection never selects Red or non-actionable items. In that dialog,
  Cancel is both the default (Return) and the cancel (Esc) action.
- A review is valid only for the exact selection it showed. Settings that affect safety (exclusions,
  project roots, overrides, "Always quarantine") apply to the next scan; a plan built under different
  settings is refused at confirm time and the user is asked to scan again (never silently re-planned).
  Adding an exclusion immediately deselects everything inside or containing it.
- Review sheet: Clean is disabled for 2 seconds after presentation, while an irreversible item is not
  acknowledged, while a permanent deletion is selected with "Always quarantine" ON, and when the plan is
  outdated; Clean is not bound to Return.
- Full Disk Access rules unlock only on a positively confirmed grant (`unknown` keeps them locked).
- "Empty Quarantine Now" and turning "Always quarantine" OFF ask for confirmation, with the safe choice
  as the default action; turning protections ON is immediate. Turning "Trust Homebrew tools" ON (a
  relaxation) asks first and lists the other admin accounts; Cancel is the default action; turning it
  OFF is immediate. Retention and age overrides are only
  written when they lengthen / raise the rule's value.

## Settings can only narrow

`Settings/ScanSettings.swift` (persisted by `SettingsStore`, JSON in the `com.imop.cleaner` defaults
domain; unreadable data falls back to the defaults, `alwaysQuarantine = true`):

- `projectRoots`: empty by default; suggested roots are only offered. Roots must be canonical, strictly
  inside home, not deny-listed, not cloud-synced, not inside an artifact folder or bundle.
- `userExclusions`: always applied (check 14, PlanBuilder, Scanner).
- `ageThresholdOverrides`: may only raise a threshold. `quarantineRetentionOverrideHours`: may only
  lengthen retention. `archivesToKeep`: clamped to 1...50 (default 3).
- `alwaysQuarantine`: default ON; a missing value decodes to ON.
- `trustHomebrewAdminWritableDirectories` ("Trust Homebrew tools"): the one setting that widens what is
  trusted, so it is opt-in: default OFF; a missing or unreadable value decodes to OFF (an unreadable one
  is also reported, which pauses cleaning until Settings are checked); turning it on needs the
  disclosure + confirmation above and is audited. It takes part in the "plan built under other
  settings" check, and the environment's command runner always follows it
  (`SafeCleanEnvironment.with(scanSettings:)` applies `CommandTrustPolicy(settings:)`).
- `lastSeenVolumes`: `nil` (never recorded) or a remembered drive that is not connected pauses orphan
  detection entirely; volumes are identified by UUID.
- Safety-relevant changes apply to the next scan/plan; a plan built under other settings is refused at
  execute time.

## Explicitly forbidden (spec §10)

None of these may appear in the codebase (enforced by code review and the static tests in
`Tests/iMopTests/Discovery/StaticReadOnlyTests.swift`):

- Any deletion path that bypasses `SafetyGate` or `Executor`.
- Shell invocation (`/bin/sh`, `/bin/zsh`, `system()`, `popen()`), `sudo`,
  `AuthorizationExecuteWithPrivileges`, privileged helpers.
- Stripping `.lproj` localizations, `lipo` / binary thinning, modifying any file inside an app bundle.
- Deleting `~/Library/Caches` (or any allow-root) itself, or wholesale `com.apple.*` caches.
- Touching `/private/var/folders`, swap, sleepimage, the Spotlight index, font databases, unified logs.
- Deleting inside iCloud Drive / CloudStorage.
- `docker system prune --volumes`, `brew autoremove`, `rm -rf` equivalents via commands.
- Network calls, analytics, remote rule updates.
- Recursive glob `**` in `Rules.json`.
- Auto-running cleanup on a schedule without the user reviewing a plan.

## Spec deviations

| Spec | Implementation | Why / status |
|---|---|---|
| §2 deployment target macOS 26, Liquid Glass | **macOS 14.0** (`Package.swift` `.macOS(.v14)`, `LSMinimumSystemVersion 14.0`); standard SwiftUI controls and materials, no Liquid Glass | Owner decision. Only APIs available on macOS 14 are used. The QA checklist runs on a macOS 14+ VM (also test the newest macOS available). |
| §5.3 trusted locations include `/opt/homebrew/bin/*`, `/usr/local/bin/*` | By default `CommandRunner` refuses any directory on the way that is **group- or world-writable**, so Homebrew's default `/opt/homebrew/bin` (0775, group `admin`) is refused and Homebrew-installed tools report a specific reason ("… a folder other accounts can change. Turn on “Trust Homebrew tools” in Settings …"). **Implemented owner decision (option B, opt-in):** Settings › "Trust Homebrew tools" — **OFF by default** — accepts admin-group-writable directories only inside the exact Homebrew prefixes, owned by the user, group exactly `admin`, never world-writable (files never relaxed). Turning it on first lists the other `admin` accounts (or warns that they could not be determined), needs an explicit confirmation and is audited. Tools whose symlink resolves outside the trusted roots (e.g. a `/usr/local/bin/docker` link into `/Applications/Docker.app`, Ollama.app's CLI) stay refused. | The spec only forbids world-writable folders; the default stays stricter because on a Mac with several administrators every one of them could swap a Homebrew tool. Opt-in so the user decides with the account list in front of them. `cocoapods.cache` falls back to its Quarantine rule when `pod` is not available. |
| §2 arm64 + x86_64 | `package_app.sh` builds for the host architecture only | Milestone 8 |
| §2 Developer ID, Hardened Runtime, notarized | Ad-hoc linker signature only; resource bundles are also copied to the `.app` root for SwiftPM's `Bundle.module` (rejected by `codesign`) | Milestone 8 |
| §9.2 badge "Green/Yellow/Red/Info" | Badge text "Safe / Review / Caution / Info" (`Tier.displayName`) plus an SF Symbol | Plain-language labels; still text + icon, never colour alone |
| §6.8 "Delete immediately (skip quarantine)" for AI models | Not offered. `permanentDelete` is allowed only for `trash.empty` and `system.coreDumps` (Yellow) | Conservative |
| §6.6 `system.coreDumps`, `trash.empty` (permanent) | Yellow `permanentDelete`, **blocked while "Always quarantine" is ON** (default), shown as blocked with that reason; never preselected and never selected by "Select All"; needs the irreversible acknowledgement. The Trash items are ONE "Empty Trash" choice (`AppState.requestToggle` → `pendingEmptyTrashConfirmation` → `confirmEmptyTrash`): all of them are selected or deselected together, only through a dialog naming the count and size; `confirmAndClean` refuses a partial or unconfirmed Trash selection | Conservative reading of §9.9 ("never permanently delete in one step") and §6.6 |
| §3.2 Yellow "per-category checkbox + what you lose" | The review sheet shows every selected Yellow/Red item's `whatYouLose` verbatim and one "I understand what I lose in <Category>" checkbox per category with Yellow items; `AppState.confirmAndClean(acknowledgedIrreversible:acknowledgedCategories:)` throws `categoryNotAcknowledged` for a missing one. Enforced in AppState, not in `ConfirmedPlan.confirm` (its hash/confirmation format is unchanged) | Review M7 |
| §5.3 sanitized environment (PATH, HOME, USER, LANG) | Also the fixed opt-outs `FLUTTER_SUPPRESS_ANALYTICS=true`, `HOMEBREW_NO_ANALYTICS=1`, `HOMEBREW_NO_AUTO_UPDATE=1`, `DO_NOT_TRACK=1` | Review M7: they can only make a tool do less (no analytics upload / self-update); nothing secret or inherited is passed |
| §6.8 `ai.ollama` discovery | `ollama list` runs only while a process named `ollama` / `Ollama` is running; otherwise (or when processes cannot be listed) the rule is unavailable ("Ollama is not running …") | Review M7: on macOS the CLI launches Ollama.app when its server is down; a scan must never start an app (§3.6). `ollama rm` at execute time has no such check (the app was running at scan time) |
| §8 "declined prompt → unavailable for the session" | Per **rule**: a rule whose discovery reported "Access was declined" is not scanned again by the same AppState (status "Unavailable this session (access was declined) …"); reopening iMop resets this. For `apps.containerCaches`, individual refused containers inside an otherwise readable `~/Library/Containers` are skipped in each scan (not remembered) | Review M7; iMop never retries a refused listing with other APIs |
| §8 / §11 never fail silently | Every rule with status `.unavailable` / `.failed` (except a cancelled scan) is listed with its reason verbatim in its category and under Permissions › "Unavailable this session"; the sidebar marks the category | Review M7 |
| §9.9 settings persistence (not specified) | Stored settings are decoded field by field; an unreadable field uses its safe default, unreadable entries in a path list are dropped, partly unreadable remembered drives become "never recorded". Whenever anything could not be read, the original bytes are kept under `safeclean.scanSettings.v1.unreadableBackup` (never overwritten automatically) and Review & Clean is refused until the user confirms in Settings ("I Have Checked My Settings") | Review M7: losing an exclusion would silently widen what iMop may touch |
| Exclusions vs. a running cleanup (not specified) | An exclusion added while the Executor runs is passed to its execute-time SafetyGate (`LiveExclusions`, add-only), so items inside it that were not processed yet are skipped with the exclusion reason; the confirmed run's list on screen is not edited | Review M7 |
| §6.10 iCloud eviction spike for v1.1 | Not shipped; `uploadedToCloud` is always false, iCloud Drive stays Advisory | Not verified safe |
| §3.3 checks 1-14 | Additional checks: target/rule coherence pre-check, 11b (rule shape), 11c (protected descendants), 11d (inspector identity); order 11b, 11d, 11c | Review findings M2/M5/M6; only add rejections |
| §3.5 deny-list | Additional entries: `~/Library/Logs/iMop`, `~/Library/Group Containers/*com.apple.*`, `~/Library/Preferences/ByHost/com.apple.*`, `~/Library/Contacts`; "contains a protected location" is denied; resolved symlink destinations of entries are protected | Conservative |
| §6.9 condition 8 | Orphan detection is paused until the first scan has recorded the connected drives, and while any remembered drive is missing | Conservative |
| §2.1 layout / §12 | Tests are a custom executable harness in `Tests/iMopTests` (no XCTest, runs with Command Line Tools only); `SafeCleanScanner.swift` instead of `Scanner.swift`; app state in `ViewModels/AppState.swift` | Toolchain constraints; coverage (≥ 90 % for Safety/Execution/Planning) is not measured by tooling yet |
| v1.0 | v1.0 `DeletionService`, scanner, "Permanent Delete" and "Dry Run Mode" toggles are removed; dry-run is the build-level `IMOP_ALLOW_MUTATION` flag | Owner decision: SafeClean replaces all v1.0 deletion paths |

## Manual QA checklist

Spec §13.1. **Run only on a disposable macOS VM (macOS 14 or later; never on a developer's daily
machine)**, with the cleaning-enabled build from `./scripts/package_app.sh`. Take a VM snapshot first.

- [ ] Clean everything Green + Yellow → reboot → Xcode builds a project, Simulator boots,
      Safari/Chrome/Slack/VS Code launch and stay logged in.
- [ ] Restore an entire quarantine session → apps behave identically to before.
- [ ] With Xcode running, Xcode rules show "Quit Xcode to clean" and are skipped.
- [ ] Symlink `~/Library/Caches/evil → /System` → never touched; audit log shows rejection.
- [ ] Revoke Full Disk Access mid-session → affected rules lock; no crashes.
- [ ] iCloud Drive, Dropbox folders untouched after full clean (checksum before/after).
- [ ] Docker volumes untouched unless explicitly confirmed per item.
- [ ] Time Machine local snapshot present → results screen explains reclaim discrepancy.

Additional checks for this build:

- [ ] `swift run iMop` shows the "Dry-run build — cleaning disabled" banner and changes nothing.
- [ ] The review sheet's Clean button is disabled for 2 seconds; irreversible items require the
      acknowledgement; each Red item asks for its own confirmation naming the item and its size.
- [ ] Select a Leftovers (Red) item: the dialog appears; click "Select “<name>”" → the item IS checked
      and appears in the review under Trash. Press Esc on the dialog instead → it stays unchecked.
- [ ] Select a Yellow item (e.g. Developer › DerivedData): the review shows its "What you lose" text and
      "I understand what I lose in Developer"; Clean stays disabled until it is ticked.
- [ ] With "Always quarantine" off and files in the Trash: "Select All" in System & Logs leaves the
      Trash items unchecked; ticking one asks "Empty the Trash (N items, X)?" and then checks all of them.
- [ ] During a cleanup, add an exclusion for a pending item in Settings → that item is reported as
      skipped (excluded), and the progress list still shows it until it is processed.
- [ ] Quarantine, Advisory, Permissions and a long item detail can be scrolled fully above the
      floating "Review & Clean…" bar.
- [ ] After a cleanup, category lists show "Results from before the cleanup" and their checkboxes are
      disabled; the sidebar shows no sizes until the next scan.
- [ ] "Always quarantine" is ON in a fresh install; Trash emptying / core dumps show as blocked.
- [ ] Kill iMop during a large clean, relaunch → Quarantine reconciles, nothing lost, nothing duplicated.
- [ ] Export Log to `~/Desktop` or onto an existing file is refused with a clear message; to `~/Downloads` works.
- [ ] VoiceOver reads every control and row including the tier text; the app is usable with the keyboard only.
- [ ] *iMop > About iMop* shows exactly the three lines from README.md.
- [ ] "Trust Homebrew tools": fresh install → OFF; Homebrew rules (e.g. Homebrew cleanup, npm cache)
      show "… a folder other accounts can change. Turn on “Trust Homebrew tools” …" in Permissions ›
      Unavailable this session. Turn it on → the dialog lists the other admin accounts (create a second
      admin account on the VM to see it listed; the current user and root are never listed), Cancel is the
      default and leaves it OFF; confirm → an outdated-plan notice until the next scan, then the Homebrew
      rules are offered. `chmod o+w /opt/homebrew/bin` (VM only) → refused again even with the setting
      ON; restore with `chmod o-w`. The audit log has one `settings.trustHomebrewTools` entry per change.

## Remaining Milestone 8 work

- Developer ID signing, Hardened Runtime, notarization; entitlements without network client/server and
  without `get-task-allow`; stop copying resource bundles to the `.app` root (drop `Bundle.module` use in
  the app target).
- Universal (arm64 + x86_64) release build.
- Performance: scan a 1M-file home / 500 GB fixture without UI hangs; audit that no file-system work runs
  on the main thread.
- Accessibility audit (VoiceOver, keyboard navigation, Dynamic Type).
- Line-coverage measurement for `Safety/`, `Execution/`, `Planning/` (target ≥ 90 %).

## Appendix: every SAFETY-DECISION in the code

Generated from `grep -rn "SAFETY-DECISION" Sources Tests scripts`. Each entry is the first sentence of
the comment (shortened); open the file and search for `SAFETY-DECISION` for the full reasoning. Every
`// SAFETY-DECISION:` comment marks a place where the spec was ambiguous or silent and the more
conservative behaviour was chosen.

<!-- BEGIN GENERATED SAFETY-DECISION INDEX -->

537 SAFETY-DECISION comments in 50 files.

### `Sources/iMopCore/Environment/Environment.swift` (8)

- a locator that cannot answer vendor-domain queries answers "could not evaluate", so nothing is classified as orphaned through it.
- an inspector that cannot read volume identities reports every volume WITHOUT a UUID, which the OrphanDetector treats as "cannot tell which drive this is" (nothing is orphaned while such a volume is mounted).
- the purpose-less call is always a READ-ONLY request; only an explicit `.action` may ever run a cleanup command.
- there is deliberately NO default for the purpose-taking `run`.
- a verifier that does not implement `signingInfo` can never read anything ("could not evaluate"), so Group Containers are never classified as orphaned through it.
- the default verifier answers `nil` ("cannot evaluate") for every path, so an environment built without an explicit verifier makes `appleSigned` fail closed.
- the defaults configure NO project roots and an unavailable Spotlight, so an environment built without them discovers nothing through those features.
- the runner always follows the settings' command trust policy, so the opt-in Homebrew relaxation is ON only while the settings say so (default OFF).

### `Sources/iMopCore/Environment/LiveEnvironment.swift` (22)

- `readFile` refuses files larger than this (default 32 MiB) rather than loading arbitrarily large data; callers treat `nil` as "could not evaluate".
- any ubiquity-only attribute being present means iCloud manages the item, even if `isUbiquitousItem` itself was not reported.
- Foundation reports no value (rather than `false`) for ordinary local files.
- never read through a symlinked final component.
- only absolute, NUL-free paths without a ".." component ever reach the file system; anything else answers `nil` ("cannot evaluate").
- also report the untruncated executable file name when readable, so a long name (e.g. "com.apple.dt.SKAgent…") matches exactly.
- our own process is always running, so an empty list means the query failed.
- a completely filled buffer may be truncated → cannot evaluate.
- processes this user may not inspect (other users / root, EPERM) and processes that exit mid-walk (ESRCH) are skipped, exactly like an unprivileged `lsof +D`. iMop never runs as root, the target must be owned by the user (SafetyGate check 8), and step 1 still covers the target itself.
- a libproc failure is only ignored when the process is gone (ESRCH, or no longer listed), is a zombie (no open files), or is owned by another user and refused with EPERM — exactly like an unprivileged `lsof +D`.
- still possibly truncated after retries → assume it holds the target open.
- a logged-in session always has running applications (Finder, Dock, …); an empty list means the snapshot is unavailable, so report "cannot evaluate".
- only plain reverse-DNS identifiers are queried, so the identifier can never alter the Spotlight query syntax.
- every MDQuery call (create, execute, read, release) happens on ONE serial queue inside one work item; the caller never touches the query.
- only a plain two-label domain (`com.vendor`) is queried, so it can never alter the query syntax or match more than that developer's identifiers.
- bundle identifiers are case-insensitive (LaunchServices matches them that way), so the comparison uses Spotlight's `c` (case-insensitive) modifier.
- a query never yields more than this many paths (bounded memory); a query that would yield more is answered with the first `maximumSpotlightResults`.
- only absolute paths without ".." or NUL are passed to Spotlight as scopes; anything else makes the whole query unanswerable (nil).
- the extension can never alter the query syntax (no quotes, wildcards, backslashes or spaces reach the query).
- volumes are identified by `volumeUUIDStringKey`, never by mount path alone (two different drives can both mount as `/Volumes/Untitled`); a UUID that cannot be read is reported as `nil` (the OrphanDetector then treats the drive as unidentifiable).
- default flags perform full validation including sealed resources, so a tampered Apple bundle fails.
- anything unexpected (non-absolute path, Security framework error, an entitlements value of the wrong type, entitlements present only as raw data) is `nil`, which the OrphanDetector treats as "cannot evaluate" (no Group Container is orphaned).

### `Sources/iMopCore/Settings/ScanSettings.swift` (11)

- nothing is scanned for project artifacts until the user picks roots; `suggestedProjectRoots` are only OFFERED in the UI, never enabled automatically.
- an override may only RAISE a rule's `olderThan` / `projectOlderThan` threshold, never lower it (enforced by `PreconditionEvaluator`).
- may only LENGTHEN a rule's quarantine retention; see `effectiveRetentionHours(for:)`.
- when a volume listed here is not mounted now (or the mounted volumes cannot be listed or identified), the OrphanDetector offers NOTHING — apps on a disconnected drive are invisible to LaunchServices and Spotlight, so their data would look orphaned.
- `nil` means "never recorded" (first scan, settings reset, older settings file), which is NOT the same as "no external drives": while it is `nil` the OrphanDetector offers nothing and asks the user to connect their app drives and scan again.
- an override shorter than the rule's own retention (or non-positive) is ignored.
- a volume that was seen before but is not connected now is REMEMBERED (it may hold apps), so orphan detection stays paused until it is reconnected; a listing that failed (`nil`) changes nothing.
- a missing value decodes to the safe default (ON).
- a missing key decodes to `nil` ("never recorded").
- a missing or unreadable "Trust Homebrew tools" value means OFF.
- a missing value decodes to OFF; an unreadable one also means OFF.

### `Sources/iMopCore/Settings/SettingsStore.swift` (4)

- every field is read on its own, so one unreadable field can never erase the others (in particular the user's exclusions).
- an unreadable value keeps the safe default (ON).
- explicit null, absence, or any unreadable entry → `nil` ("never recorded"), which pauses orphan detection until a scan records the connected drives again.
- "Trust Homebrew tools" is ON only for a readable `true`; absence → OFF, anything unreadable → OFF (and reported, which pauses cleaning until Settings are checked).

### `Sources/iMopCore/Safety/DenyList.swift` (10)

- the spec lists "~/Library/Contacts (Application Support/AddressBook)"; both the literal ~/Library/Contacts and the AddressBook store are denied.
- iMop's own audit log folder (spec §5.5, {HOME}/Library/Logs/iMop/audit-YYYY-MM.jsonl).
- beyond the spec's literal "group.com.apple.\*", any Group Container whose name contains "com.apple." is Apple-managed too ("&lt;TeamID&gt;.groups.com.apple.podcasts", "&lt;TeamID&gt;.com.apple.…").
- per-host Apple preferences live one level deeper and are just as Apple-owned.
- an unusable home directory makes the deny-list deny everything.
- defense in depth — re-apply the lexical text rules to the path in case it was built with `CanonicalPath(validatedPath:)` from a non-logical form (/tmp, /var, firmlink).
- the only Apple-container exception is a DIRECT child of Mail Downloads ("Mail Downloads/\*"), for rule "mail.downloads" only — exactly like /cores/core.\*.
- a path that CONTAINS a protected location (e.g. ~/Library, the home directory itself, ~/.docker, /Applications, /) is denied too: acting on it would act on the protected content beneath it.
- the fixture waiver exists only so test fixtures under `FileManager.temporaryDirectory` can be validated.
- "/System" can never be waived, even in tests; neither can any entry other than the temporary-directory holders.

### `Sources/iMopCore/Safety/PathCanonicalizer.swift` (6)

- re-apply NFC after lowercasing.
- this initializer cannot fail, so malformed input is a programmer error and traps (also in release builds) rather than producing a path whose containment checks could be fooled (e.g. "/a/b/.." would otherwise look "inside" /a/b).
- a component that could change the meaning of the path (traversal, separators, NUL) is a programmer error and traps instead of being silently accepted.
- resolver outputs are run through the same text rules (but never get "~" or "{HOME}" expansion); a resolver output that is relative, contains "..", or maps into /System is rejected rather than trusted.
- "~otheruser" forms are never expanded; they are rejected.
- a home directory that is relative, contains "..", NUL, or is "/" itself is unusable; anything that would expand from it is rejected.

### `Sources/iMopCore/Safety/Preconditions.swift` (32)

- the git probe only ever runs the SIP-protected system git.
- both override sources may only RAISE a threshold, so merging keeps the larger.
- always false in v1. iCloud eviction stays Advisory (Finder's "Remove Download"); iMop never acts on ubiquitous items.
- an empty list is a malformed rule; it cannot prove anything → fail closed.
- a malformed pattern cannot be evaluated → treat as running.
- the owning bundle ID is data, not a pattern — matched exactly (case-insensitive); a "\*" in it is never treated as a wildcard.
- an empty name cannot be checked → fail closed.
- names are compared case-insensitively (matches more → fails more). proc\_name truncates long names, so a running name of 15+ characters that is a prefix of the requested name counts as the requested process.
- a negative day count is a malformed rule → fail closed.
- a user override may only RAISE the rule's threshold, never lower it.
- an unreadable directory listing, or a child that vanished between listing and lstat, means "last used" is unknown → nil (fail closed).
- `projectOlderThan` considers ALL of these that are present beside the artifact (plus the rule's own `manifestPresent` names), not only the artifact's own manifest: more files can only make the project look more recently used.
- (fail closed → nil): an unreadable project listing; a listed manifest or git file that cannot be lstat'ed; a manifest or git file that is a symlink; a `.git` that is not a plain directory (worktree / submodule `.git` files point elsewhere, so the real activity cannot be measured); or none of the files present at all.
- the artifact name must be exactly one of the reviewed ProjectScanner names (it becomes a git pathspec argument).
- the project directory must be canonical (no symlink on the way) and inside (or equal to) one of the user's validated project roots before git is ever pointed at it.
- a repository can live in the project folder or in any folder above it (monorepos, a dotfiles repository in the home folder): every directory from the project up to and including the home folder is checked for `.git`.
- git is not the only version-control system.
- git is only asked when the artifact's OWN folder is the repository's top level (like ProjectScanner's `mayPropose`).
- only the SIP-protected system git is ever run, read-only, through the allow-listed probe; every outcome except a clean "did not match" counts as tracked.
- `/usr/bin/git` is the xcode-select shim.
- fails closed — no owner, an owner that is not an orphan-candidate identifier (`RuleTargetMatcher.isOrphanCandidateIdentifier`), or any lookup that errs / times out / answers ambiguously means "not orphaned".
- the manifest must be a regular file (not a directory, not a symlink that could point anywhere).
- patterns containing "/" or more than one "\*" are malformed → never match.
- check both the lexical and the resolved form (when resolvable) of the target.
- any attribute in the com.apple.fileprovider / com.apple.file-provider namespaces counts (a superset of the two forms named in the spec).
- only "Shutdown" counts as idle.
- a device entry without a readable state makes the whole answer unknown.
- iMop never starts Docker; if it is not already reachable the rule is skipped.
- an image path that cannot be interpreted might be this item → fail closed.
- also fails when a mounted image lies INSIDE the target (a folder holding it).
- a missing "images" key is treated as malformed output, not "nothing mounted".
- fails if the developer dir is inside-or-equal the target (the target is the selected Xcode) and also if the target lies inside the developer dir.

### `Sources/iMopCore/Safety/SafetyGate.swift` (35)

- the exclusions in the environment's settings always apply too, so a caller that forgets to pass them cannot drop one.
- both phases run exactly the same checks; nothing is skipped at execute time because it passed at plan time.
- a path-like value that fails the text rules is suspicious → reject.
- check 14 is still evaluated when check 13 tripped: an item the user excluded must be rejected outright, never offered as a Red item for manual review.
- a real uid of 0 is refused as well as an effective uid of 0; otherwise the ownership check (8) would accept root-owned files.
- rule-specific exceptions (deny-list, bundle guard) are keyed by `rule.id`, so a target must only ever be validated against the rule that discovered it.
- an Advisory rule or action is never actionable, whatever the target kind.
- command items get only checks 1, 12 and 14, so they are valid only for command actions; a file-system action on a command item would bypass the path checks.
- a command item is only acceptable for one of the Swift-pinned vendor-command rules (exact tool, arguments, tier and inspector), and its per-item argument must pass that command's `{ITEM}` validator.
- `ScanTarget.path` is documented as already canonical, and the Executor can only act on that exact string.
- "/" can never be a target.
- a target that is itself a symlink is refused right here, with a specific reason, for every rule that does not opt in.
- a link whose destination is protected is refused even though only the link would be removed.
- the link's own name is never resolved by realpath, so its spelling is taken from the parent's directory listing instead of the caller.
- the configured home string is always used (an unusable one makes that deny-list deny everything); the resolved home is added when it differs, so both spellings of every home-relative entry are protected.
- (§3.5: a symlink to a protected folder must not be a bypass): every existing home-relative entry is resolved with realpath(3); when the destination differs from the entry's own location it is protected under the same label (with the same "contains" rule).
- `{PROJECT_ROOTS}` expands to the validated project roots of the environment's settings, re-resolved at every validation (a root the user removed, or that became a symlink, no longer contains anything).
- an allow-root that resolves through a symlink, or is "/", is unusable.
- equality with ANY declared root rejects, even if the path is strictly inside another declared root.
- every component between the allow-root and the target must be on the allow-root's device, not just the target (rejects any mount point on the way).
- if the cloud roots cannot be computed, nothing can be proven outside them.
- "could not determine" is treated as ubiquitous.
- unreadable extended attributes are treated as File Provider managed.
- anything that is not a regular file (directory, symlink, other) carrying a bundle extension is treated as a bundle.
- the whole-app exception is keyed by rule id, so it is granted only to a rule that passes catalog validation, i.e. has exactly the Swift-pinned shape for that id (tier, action, discovery, appleSigned, …).
- an allow-root plus a minimum depth is wider than what a rule means.
- for the Milestone 5 inspectors whose offer depends on what is on disk around the target, the pure shape of check 11b is not enough.
- the deny-list "always wins" (spec §3.5) for a `.git` directory or a protected extension anywhere, so a directory target that CONTAINS one (a `.git` inside a cache, a `.photoslibrary` under Logs) is rejected: acting on it would move the protected item with it.
- the spec's bundle guard is name based ("ends with .app, .framework, …"), and a name-only match is kept for every ordinary name ("Foo.app", "X.framework").
- negative sizes/counts mean sizing went wrong → treated like exceeding the limit.
- exclusions the user adds while this gate is in use (Settings stays usable during a cleanup) are read live, so an item excluded mid-run is skipped at its execute-time check.
- an exclusion that cannot be interpreted might cover this item → reject.
- `canonicalize` fails for an exclusion that is itself a symlink (canonicalPathKey does not follow the final link, realpath does), so the location the user actually excluded is added from realpath(3), which follows every link.
- also rejects a target that CONTAINS an excluded path — acting on it would act on the excluded content.
- there is deliberately no `remove`: a gate in use never loses an exclusion.

### `Sources/iMopCore/Rules/CommandAllowList.swift` (20)

- every per-item argument is checked against a strict, ASCII-only shape before a command can run, so an item name can never inject an option ("-…", "--all"), a path or a keyword such as `all` / `unavailable` (e.g. `simctl delete all` would delete every simulator).
- a namespace separator never forms an empty, "." or ".." segment, so a model name can never look like a relative path.
- kept separate from `CommandItemKind` so a rule's `{ITEM}` can never be a path: named slots exist only on internal, read-only, `usableByRules == false` entries (the git probe of `Precondition.notTrackedByGit`) and are refused for `.action` (see `CommandAllowList.entry`).
- exact, case-sensitive membership; never a pattern, never a path.
- `/…/Library/LaunchAgents/<name>.plist` — clean absolute path, the file name is printable ASCII (no "/", not hidden), ends in `.plist` with a non-empty base that is not Apple's (`com.apple*`, case-insensitive), and nothing else may follow.
- exact (tool, argument array) pairs only.
- an entry with an {ITEM} slot but no validator never matches.
- a named slot value must pass its validator and can never look like an option.
- for actions, "/" may appear only inside an {ITEM} slot whose kind explicitly allows it (ollama namespaces) or inside a named action slot (M6 launchctl bootout: `gui/<uid>` and the plist path).
- internal probes with named slots are read-only only; never an action — except the M6 bootout entry, whose slots are action kinds and which no rule may name.
- `launchctl` stays a forbidden tool for every rule and every other invocation; the ONLY exception is exactly `launchctl bootout gui/<uid> <…/Library/LaunchAgents/x.plist>` as an action (the Executor's `bootoutAndTrash`, which also checks the uid and the home folder).
- no "system prune" of any form (Docker's can delete volumes and every image).
- the exemption applies only to tool `git`, purpose `.readOnly`, and only when the invocation begins with EXACTLY (case-sensitive) `--no-optional-locks --icase-pathspecs -c core.fsmonitor=false -C`; the lowercase `-c` may then only carry that one fixed setting.
- beyond the agreed `-C <dir> ls-files --error-unmatch -- <name>`: - `--no-optional-locks` stops git from opportunistically rewriting `.git/index` (Discovery and preconditions must not modify the user's repository); - `--icase-pathspecs` (review M5): git compares pathspecs case-SENSITIVELY even with ...
- the static table cannot know the user's settings, so the project-root containment of `{PATH}` is checked here, by the only caller that runs the probe; a path outside every configured root (or with no roots configured) is refused and git is never run.
- launchctl is only ever taken from this exact SIP-protected path.
- the static table cannot know the user's uid or home folder, so they are checked here; anything else (another user's domain, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, a nested path) is refused and launchctl is never run.
- the only Red command (databases live in volumes) is pinned to its rule.
- tools a rule may name at all (review M2), checked before the exact tables.
- executables that are never acceptable (shells, privilege escalation, generic removers and interpreters that could run arbitrary code).

### `Sources/iMopCore/Rules/Glob.swift` (5)

- an absolute pattern must start with one of the Swift-coded non-home roots, spelled with literal segments, and must reach strictly below it.
- a wildcard never matches a name starting with "." unless the pattern segment itself starts with "." (shell semantics) — hidden entries are only ever matched by name.
- the base itself must be a real directory (not a symlink); otherwise the whole pattern yields nothing.
- a final match on another volume (a mount point) is dropped.
- never descend into a package/bundle (`.app`, `.framework`, `.bundle`, …; same test as SafetyGate check 11).

### `Sources/iMopCore/Rules/Rule.swift` (6)

- the spec requires a permanent removal for `trash.empty` (emptying the Trash) and offers "Delete immediately (skip quarantine)" for AI models.
- `bootoutAndTrash` counts as NOT restorable.
- used only by the Executor to hand the CONFIRMED (hashed) retention of a plan item to the Quarantine, which checks the planned value against the rule it is given.
- `{PROJECT_ROOTS}` expands only to roots that pass every check in `ProjectRoots.resolve`; with none configured it expands to nothing (the rule has no usable allow-root, so SafetyGate check 4 rejects every target and the Scanner offers nothing).
- a root is usable only when ALL of these hold; any other root is ignored: - it passes the §3.4 text rules (`~`/`{HOME}` expanded from the environment, no `..`); - it resolves through the file system to exactly its lexical spelling (no symlink anywhere); - it is an existing directory (lstat), not a symlink; - it is ...
- a root at or below a folder named like a project artifact (`~/code/app/node_modules`) or inside a package / bundle would let nested artifacts be proposed; such a root is ignored here too, so SafetyGate never accepts a root the ProjectScanner would refuse to walk.

### `Sources/iMopCore/Rules/RuleCatalog.swift` (37)

- the SwiftPM-generated `Bundle.module` accessor calls `fatalError` when its bundle is missing, so it is never referenced.
- an unknown file format version is never interpreted.
- an id used more than once (even by a rule that failed to decode) is ambiguous; EVERY rule with that id is disabled.
- rules allowed to declare an allow-root outside `{HOME}` (spec §6: `/cores/core.*`, `/Applications/…`) are pinned COMPLETELY here — allow-roots, tier, action, discovery and required preconditions.
- `installers.macOS` is discovered by the `macOSInstallers` inspector (it reads each bundle's Info.plist so only Apple's "Install macOS …" assistants are offered) instead of a bare glob, and must declare `appNotRunning(com.apple.InstallAssistant.*)`.
- allow-roots that CONTAIN deny-listed locations, permitted only for these rules (e.g. `~/Library/Containers` contains `com.apple.*` containers, `~/Library/Logs` contains iMop's own audit log).
- `~/Library/HTTPStorages` is deny-listed as a whole (cookies / web credentials), so it is never an allow-root and never offered; `~/Library/LaunchAgents` belongs to `leftovers.launchAgents`.
- allow-roots that are themselves inside a deny-listed area, mirroring the deny-list's own narrow exception (`DenyList`: direct children of Mail Downloads for `mail.downloads` only).
- `lightroom.previews` finds catalogs anywhere in the home folder (via Spotlight), so it is the only rule whose allow-root may be `{HOME}` itself.
- rule ids allowed to use each Milestone 5 inspector, with the tier and the spec §6 preconditions pinned.
- Red rules move to the Trash one item at a time with per-item confirmation; `leftovers.appData` re-checks at execute that the owner is still not installed / running / referenced by a receipt (`stillOrphaned`).
- the only rule ids that may use `Action.bootoutAndTrash` (spec §6.9: an orphaned LaunchAgent is booted out with launchctl, then its plist is moved to the Trash).
- the Advisory rules, each pinned to its advisory action.
- Red rules may use a vendor command only when listed here (per-item confirmation is mandatory for them).
- commands are not path-gated, so the validator is an ALLOW-list: only these exact (tool, arguments) pairs from spec §6 may be a rule's action.
- the read-only commands a rule may run during Scan (its discovery command or an action's `dryRunArguments`).
- tools a rule may name at all (review M2), checked before the exact tables.
- executables that are never acceptable as a rule's tool (shells, privilege escalation, generic removers and interpreters that could run arbitrary code).
- s above.
- pinned advisory rules have no allow-root at all (see `advisoryRuleSpecs`); anything else is a misconfiguration.
- `{PROJECT_ROOTS}` is accepted only as the SOLE allow-root of a Swift-pinned ProjectScanner rule.
- `{HOME}` itself is accepted only for the rules in `homeRootRuleExceptions`, as their sole allow-root, with the pinned inspector.
- the Swift-coded non-home roots are reviewed exceptions; root-level deny-list checks are not applied to them (e.g. /Applications contains /Applications/Utilities), but every target below them is still deny-list-checked and gated (only /cores/core.\* is ever reachable under /cores).
- a sample match of the pattern (each "\*" replaced by a probe word) must not be deny-listed for this rule; a pattern that names protected data on its face is invalid.
- a bootout is irreversible; only the Red LaunchAgent rule may use it.
- every field the Swift tables pin must match exactly.
- Milestone 5 inspectors only serve their pinned rules.
- pinned Milestone 6 shapes not covered by the tables above. - `bootoutAndTrash` only for `bootoutAndTrashRuleIDs` (any tier). - The `advisory` inspector only for `advisoryRuleSpecs`, as Advisory tier with the pinned kind; a pinned advisory id must use exactly that shape and never needs or may name an allow-root. - ...
- ProjectScanner rules are Yellow quarantine rules over `{PROJECT_ROOTS}` that declare projectOlderThan(&gt;= 90), notTrackedByGit, processNotRunning(⊇ the artifact's tools) and manifestPresent (a non-empty subset of the artifact's manifests).
- `apps.userCaches.unknownOwner` offers folders directly in `~/Library/Caches` (Yellow).
- no rule may run any "system prune" (Docker's `system prune` can delete volumes and every unused image); the spec only needs targeted prune subcommands.
- allow-lists, not deny-lists.
- spec §5.3 hard timeouts — default 10 min, simctl runtime delete 30 min.
- a pinned vendor-command rule must declare the spec §6 preconditions pinned for it (e.g. processNotRunning(npm, node) for npm.cache).
- project predicates are meaningful only for ProjectScanner rules.
- a glob rule without an owner hint can never name its owner; the predicate would always fail.
- unknown top-level keys make the whole file invalid (it is bundled and reviewed; an unexpected shape means it is not the file we think it is).

### `Sources/iMopCore/Rules/RuleCoding.swift` (1)

- decoding is STRICT.

### `Sources/iMopCore/Rules/RuleTargetMatcher.swift` (25)

- the "shape" of what a rule may target, re-checked by SafetyGate (and by the Scanner) on the canonical target path.
- defence in depth on top of catalog validation.
- like `RuleCatalog.validateProjectArtifactRule`, the rule must also declare manifestPresent with a non-empty subset of the reviewed manifests.
- the whole-app Trash inspectors serve only their Swift-pinned non-home rules (`RuleCatalog.nonHomeRuleSpecs`), with exactly the pinned tier, action and preconditions.
- the advisory inspector only ever serves the pinned advisory rules.
- for inspectors whose owner is implied by the location, an owner is optional, but when one is recorded it must be exactly the expected app.
- the inspector's own pure shape check must agree too (it requires the Xcode owner), so matcher and inspector can never drift apart.
- the Green "orphaned version" rule only ever acts on a KNOWN product owned by exactly that product's bundle id (the inspector's own shape).
- never inside a package (e.g. inside another .lrdata).
- both reserved-name tables (matcher and inspector) apply.
- the same descent rule as the ProjectScanner walk — no ancestor below the home folder may be hidden, artifact-like or a package / bundle.
- the inspector's own pure shape check must agree too.
- the owner (the agent's Label, which bootout acts on) is REQUIRED; the Executor re-reads the plist and requires exactly that Label.
- no predicate yet → nothing this inspector proposes can be acted on.
- a whole `.app` is a target only as a DIRECT child of `/Applications` (`xcode.extraInstalls` also `{HOME}/Applications`), never in a subfolder, never hidden, and the recorded owner (required) must be the expected Apple bundle identifier. - `xcodeExtraInstalls`: `<name>.app`, owner exactly `com.apple.dt.Xcode`. - ...
- the owner is REQUIRED for both whole-app rules (the inspectors always record the bundle identifier they read), and SafetyGate check 11d re-reads the bundle's Info.plist and requires the same identifier right before acting.
- `HTTPStorages` is deny-listed as a whole and therefore not listed here.
- only reverse-DNS-looking identifiers are ever considered — at least two dots (three labels), every label 1–63 ASCII letters, digits or "-", not starting or ending with "-", at most 255 characters.
- `com.apple`, `com.apple.*`, `group.com.apple.*` and any identifier that contains the `com.apple` labels anywhere (e.g. `<TEAMID>.com.apple.x`).
- Smart Previews are used for offline editing; they are never offered.
- every ProjectScanner rule is pinned here; a Rules.json rule bound to the projectArtifacts inspector must be one of these ids, and generic names (`build`, `target`) only ever match together with their manifest.
- every vendor-command rule of spec §6 is pinned here (inspector, tier, exact command).
- the spec §6 preconditions are pinned too, so a Rules.json edit that drops one (e.g. `processNotRunning(npm, node)`) makes the rule offer nothing.
- whole-rule commands accept only `argument == nil`; per-item commands accept only a non-nil argument of the slot's shape.
- a per-item command without a reviewed validator accepts nothing.

### `Sources/iMopCore/Discovery/AdvisoryInspector.swift` (7)

- bounded work for explain-only items.
- only advisory rules (advisory tier AND advisory action) are answered, so these explain-only candidates can never be attached to an actionable rule.
- an unknown rule id bound to this inspector gets nothing.
- the disk image is only looked at (lstat + SizeCalculator); a symlink is ignored.
- the non-destructive route comes first; the two Docker Desktop options that recreate the disk image are named only together with the plain statement that they delete every image, container and volume.
- never descend into the library (not even to measure it).
- unexpected output (an error message on stdout) is "unknown", not 0.

### `Sources/iMopCore/Discovery/AppCacheInspector.swift` (17)

- a symlinked or cross-volume intermediate directory ends the walk.
- a failed LaunchServices lookup (`nil`) is treated exactly like "not installed": the folder is not attributed to an installed app, so it is not offered as Green.
- only real directories on the home volume; a symlink, a plain file or a mount point named like a bundle ID is never treated as an app's cache folder.
- a container whose Caches cannot be listed (macOS app-data protection) is skipped, never retried with other APIs.
- explicit allow-list only.
- exact folder names only.
- only for apps that are installed.
- exact names only.
- only for installed browsers (see ElectronCachesInspector).
- one deny-list per spelling of the home directory, like the Scanner.
- plain-named caches of always-installed macOS components (no `com.apple.` prefix, and LaunchServices resolves none of them to an app).
- without a catalog the folders of other rules cannot be known, so nothing is proposed rather than risking a Yellow folder that hides Green targets.
- a folder named like a bundle (".app", ".bundle", …) is never proposed.
- a folder holding com.apple.\* entries (or that cannot be listed) is treated as an Apple component's cache and never proposed.
- any failed lookup (`nil`) means the owner is unknown, so the folder is not proposed as "unknown owner" (it might belong to an installed app).
- a plain name is still asked about (as an identifier), so that a failing app lookup also withholds plain-named folders instead of offering them while it is unknown which apps are installed.
- only for installed browsers (see ElectronCachesInspector).

### `Sources/iMopCore/Discovery/DockerClient.swift` (7)

- all or nothing — `nil` without the expected header, for an unknown or duplicated row, or for any value that does not parse.
- all or nothing — `nil` when the section or its header is missing, a name is not a valid volume name, a volume is listed twice, or a value does not parse.
- all or nothing — `nil` when the section or its header is missing or any row does not parse.
- all or nothing — a line without a `Name`, a name that is not a valid volume name, or a duplicated name makes the whole listing untrusted (`nil`).
- iMop never starts Docker; an unreachable daemon simply skips the rule.
- volumes hold databases (Red).
- the two listings must agree.

### `Sources/iMopCore/Discovery/JetBrainsInspector.swift` (7)

- only products whose folder name and bundle identifier are certain.
- an unknown rule id bound to this inspector gets nothing.
- folders that are not `<Product><major>.<minor>` (Toolbox, logs, …) are not something this rule understands and are not offered at all.
- no copy of the product found at all cannot be told apart from "installed but not registered with LaunchServices" (a Toolbox install never opened from Finder, an unusual channel): CURRENT, never orphaned.
- a failed lookup or an unreadable app plist means "maybe still installed": CURRENT (Yellow), never orphaned.
- an unknown product is never classified as orphaned.
- a cache folder is orphaned only when no app of ANY channel of the product has that major.minor version.

### `Sources/iMopCore/Discovery/LaunchAgentInspector.swift` (11)

- at most this many plists are examined per scan (bounded work).
- SMAppService-style agents name their program relative to an app bundle; whether it exists cannot be decided here.
- reuses the DerivedData existence proof: an `lstat` failure alone is never proof of absence, a path through a symlink or under a mount area (`/Volumes`, …: a drive that may simply be disconnected) is `unknown`, and a dangling symlink at the end counts as existing.
- a folder that is PROVEN absent is skipped; a folder that cannot be listed (or whose existence cannot be decided, or that is a symlink), more than `maximumAgents` plists, or any plist that cannot be read makes the whole listing `.unreadable` — a duplicate Label or a still-installed job could hide in it.
- a plist that cannot be READ (symlink, not a regular file, too large, permission) may still be loaded by launchd → the listing is unreadable.
- the scan's own parser and existence proof are reused, so execute is never more permissive than discovery: any read / parse problem, another Label, a duplicate Label, a program that exists again, or one whose absence cannot be proven (permission, symlink, `/Volumes/…` drive that may only be disconnected) means the ...
- `launchctl bootout` acts on the Label inside the file; it must be exactly the one the user reviewed.
- an unknown rule id bound to this inspector gets nothing.
- bootout acts on the Label; an agent whose Label any other plist (here or in /Library/LaunchAgents) also declares is never offered, and if those folders cannot all be read nothing is offered.
- any read / parse failure → not offered.
- the Label is pinned as the owner (hashed into the confirmed plan) and must still be exactly this at execute time.

### `Sources/iMopCore/Discovery/MediaInspector.swift` (3)

- Spotlight failing or timing out (nil) is reported, never guessed around with a file-system crawl.
- any name ending in " Smart Previews.lrdata" is rejected, even when it would be the standard previews of a catalog whose own name ends in " Smart" — the two cannot be told apart by name, so neither is proposed.
- "Smart Previews.lrdata" itself (the standard previews of a catalog named "Smart") is refused too — spec §6.7: never "Smart Previews.lrdata".

### `Sources/iMopCore/Discovery/OllamaClient.swift` (2)

- all or nothing for the table itself — `nil` without the exact header, for a row whose ID, size or shape does not parse, or for a name listed twice.
- on macOS the `ollama` CLI starts the Ollama app when its server is not running.

### `Sources/iMopCore/Discovery/OrphanDetector.swift` (26)

- only exactly `<id>.plist` (lowercase extension); lock files, `.plist.lockfile`, backups and anything else are not offered.
- — apps every Mac has, in the system and the data volume.
- — more installed apps than this cannot be evaluated (fail closed).
- without a catalog condition 6 always blocks (the overlap cannot be ruled out).
- more than the agreed 2, 3, 4 is re-checked (Apple prefix, identifier shape, disconnected drives, Setapp, app groups / Team IDs — review M6) because each can only make the result more conservative.
- the location is derived from the target path so the location-specific checks (Group Containers: app groups / Team IDs) run at execute time too; a path whose location cannot be derived is never treated as orphaned.
- any identifier with a label `apple` (case-insensitive) is Apple's: covers `com.apple.*`, `group.com.apple.*` and `<TEAMID>.com.apple.*`.
- , all fail closed: - Spotlight must be indexing (`spotlightSanityBundleIDs` are found), else its empty answers prove nothing; - the `CFBundleIdentifier` of every directly enumerated app bundle (application roots, one folder level down, and `<volume>/Applications` of every mounted volume) is compared too (an app ...
- an app whose Info.plist or `CFBundleIdentifier` cannot be read, or apps that cannot be enumerated completely, mean "cannot evaluate".
- the related-identifier and vendor-domain matches go beyond exact equality — a running sibling app of the same vendor may still read this data.
- fail closed — an unreadable folder or plist blocks every identifier.
- the vendor-domain match is stricter than the spec's "references" (an installer of the same developer may own this data under a different identifier).
- only the SIP-protected system pkgutil, and only the read-only listing.
- a truncated listing may be missing the receipt that matters → unknown.
- every Mac has Apple receipts; an empty listing is not trustworthy.
- a Group Container name that is neither `group.…` nor `<TEAMID>.…` is not understood and is never orphaned.
- if ANY installed app's signing information cannot be read (or the apps cannot be enumerated completely), no Group Container is orphaned.
- an `lstat` failure alone is never proof of absence; the parent is listed and must not contain the name (an unreadable parent, or a name it lists that cannot be `lstat`ed, is unknown).
- plain folder names are never orphan candidates.
- a folder named like a bundle (`com.vendor.app` reads as `*.app`) is never proposed.
- volumes are compared by UUID, never by mount path (another drive can mount under the same name); a mounted volume whose UUID cannot be read blocks; a baseline that was never recorded blocks (the first scan only records it).
- an unknown rule id bound to this inspector gets nothing.
- without a catalog the folders of other rules cannot be excluded.
- with a drive missing that may hold apps (or the drives never recorded), NOTHING is proposed.
- background-job definitions that cannot all be read block every identifier; say so instead of silently offering nothing.
- a deny-listed location (HTTPStorages) is not even listed.

### `Sources/iMopCore/Discovery/PackageManagerInspector.swift` (9)

- `bun pm cache rm` deletes the cache folder bun's own config names (`~/.bunfig.toml`), so the folder is the one `bun pm cache` reports, never a guess.
- the rule must be exactly one of the pinned command rules served here, with the reviewed command; anything else yields nothing.
- never a project's `.yarn/cache` (it may be a committed zero-install cache).
- `pod cache clean --all` deletes `<cache_root>/Pods`, and `cache_root` can be set in `~/.cocoapods/config.yaml`. iMop has no read-only way to ask pod for it, so when that file sets `cache_root` (or cannot be read) the rule is unavailable rather than sizing and checking a folder the command might not touch.
- brew listed items but no total; never guess a number.
- avdmanager identifies a device by the name of its `<name>.ini` file.
- `avdmanager delete avd -n <name>` recursively deletes the folder named by `path=` (or `path.rel`) in `<name>.ini`, not necessarily the `<name>.avd` folder found here.
- every key that is present must resolve to the same real folder as `avdFolder` (not through a symlink), at least one must be present, and a duplicated key or an unreadable/odd file is a mismatch.
- exactly one non-empty line (surrounding whitespace ignored), starting with "/", no control characters, no "." / ".." / empty components; anything else (warnings mixed into stdout, "undefined", "off", relative paths) is refused.

### `Sources/iMopCore/Discovery/ProjectScanner.swift` (12)

- generic names (`build`, `target`) are only ever matched together with their manifest pairing; every kind requires a manifest beside it, and some a marker inside.
- only the Swift-pinned project rules are served; any other rule using this inspector discovers nothing.
- a root that fails any check is ignored, never "repaired".
- start from the SAME validated roots SafetyGate expands `{PROJECT_ROOTS}` to (`ProjectRoots.resolve`: canonical, strictly inside home, not deny-listed, not cloud-synced), so the walk can never cover a folder the gate would not accept.
- a root at or inside a folder named like an artifact (e.g. `~/code/app/node_modules`) would let nested artifacts be proposed; it is ignored.
- an unlistable folder is skipped (nothing below it is proposed).
- a recognised artifact (of ANY kind) is never descended into, so nested artifacts (node\_modules inside node\_modules, …) are never proposed.
- a manifest only counts when it is a regular file (never a symlink).
- `notTrackedByGit` only asks git when the artifact's own parent holds `.git`.
- an artifact in (or below) a checkout of another version-control system (`.hg`, `.svn`, `.jj`, …) may be committed there, and iMop never runs those tools: it is never proposed.
- never hidden folders (`.git` is only detected by name), never a folder named like ANY artifact even when it did not match (an unmatched `node_modules` may hold nested artifacts, which must never be proposed), never a package / bundle / protected library.
- SafetyGate re-proves on the file system, at every validation and independently of the rule's declared preconditions, everything this scanner checked before offering `target` for `ruleID`.

### `Sources/iMopCore/Discovery/SafeCleanScanner.swift` (26)

- `apps.userCaches.unknownOwner` must never offer a folder that another rule of THIS scanner's catalog may target (the overlap rule would let the Yellow folder swallow that rule's targets).
- likewise, the OrphanDetector excludes every folder another rule of THIS scanner's catalog may target.
- see `ScanSettings.lastSeenVolumesAfterScan(mounted:)` — a drive that is not connected now stays remembered (orphan detection stays paused until it is back), and a failed listing changes nothing.
- the quarantine rule and the command rule are never both offered in the same scan.
- the cache keeps each rule's latest result BEFORE overlap resolution and resolves overlaps again over the merged set on every read, so results from different (subset) scans never hold an ancestor and its descendant at the same time.
- a cancelled scan is incomplete for overlap purposes (a more cautious rule that never ran could own an item inside a finished rule's target).
- like SafetyGate, one deny-list per spelling of the home directory (as configured, and resolved when different), so both spellings of every entry are protected.
- a non-Advisory-tier rule with an advisory action is not one of the pinned advisory rules; it never yields targets.
- ProjectScanner rules scan ONLY user-selected project roots.
- an inspector that reports a problem contributes no targets at all, even if it returned some candidates.
- RuleCatalog validation already rejects such rules; a pattern that still fails to parse disables the whole rule for this scan.
- only Swift-pinned command rules (`RuleTargetMatcher.commandRuleShapes`) with inspector discovery are scanned; a rule whose discovery is a raw command is still reported unavailable (the Scanner never runs an arbitrary rule-provided command).
- one target per command invocation (duplicates are dropped).
- only rules in `RuleCatalog.advisoryRuleSpecs` (Advisory tier, the pinned advisory action, the `advisory` inspector) are scanned.
- iMop does not free advisory space itself.
- a command whose own folder is protected (inside iCloud Drive, Documents, a system location, or a folder that contains protected data such as the home folder itself) is never offered, even though the vendor tool would do the work.
- a folder that is deny-listed (on either spelling) or contains a protected item (`.git`, `.photoslibrary`, …) withholds the whole item — the vendor command would remove it.
- an allow-root reached through a symlink (its resolved form differs from its lexical form) is not used: SafetyGate would reject every item below it anyway.
- symlinks are skipped unless the rule explicitly allows a symlink target; even then the link itself (never its destination) is the target.
- a resolved path that differs from the lexical one means an intermediate symlink; such items are skipped (SafetyGate check 6 would reject them).
- the same shape check SafetyGate applies (check 11b): the candidate must match one of the rule's patterns, or its inspector's Swift-coded shape.
- never offer something on another volume than its allow-root.
- mirror SafetyGate check 11 — nothing inside a bundle, and no bundle itself unless the rule trashes whole apps.
- spec §3.5 — a `.git` directory or protected extension anywhere below the candidate makes the whole candidate untouchable (moving it would move the protected item).
- an unreadable listing or child means "last used" is unknown (nil), never guessed from the folder's own mtime.
- an inferred owner that does not look like a reverse-DNS bundle identifier is dropped (nil), so `owningAppNotRunning` fails closed for that item.

### `Sources/iMopCore/Discovery/SimctlClient.swift` (14)

- the runner keeps at most 64 KB of stdout.
- an inspector only emits items for the exact command it was written for.
- all or nothing — `nil` when the shape is unexpected, any device lacks a readable UDID / state / name, or any UDID is not a canonical upper-case UUID.
- a UDID listed twice means the output cannot be trusted.
- all or nothing — `nil` when the shape is unexpected, an entry's identifier is missing, malformed, or differs from its key.
- only an explicit `"deletable": true` counts.
- the folders are always derived from the home directory plus fixed components plus a validated UDID — never from a path printed by simctl — and every step must be a real directory (no symlink) on the home volume.
- a device whose data lives elsewhere (custom device set) is not offered.
- a device simctl explicitly calls available in the "unavailable" listing means iMop does not understand the output → fail closed.
- the command removes every unavailable device at once, so every existing folder is handed to the Scanner, which withholds the whole item if any of them is protected or contains a protected item.
- the rule's own `olderThan` may only raise the 90-day threshold.
- only devices that are fully shut down (never Booted, Booting, Shutting Down, Creating or an unknown state).
- the age is computed exactly like the `olderThan` precondition; an unreadable folder has no known age and is not offered.
- only images simctl itself reports as deletable (bundled / system runtimes report `deletable: false`).

### `Sources/iMopCore/Discovery/TrashFlowInspectors.swift` (12)

- at most this many Xcode bundles are examined; more is not a normal setup.
- an unknown rule id bound to this inspector gets nothing.
- without a definite active developer directory nothing is offered: any copy could be the one in use.
- a bundle is "the selected Xcode" when the developer directory is inside it OR it is inside the developer directory (both spellings of each).
- "extra" means "not the one in use".
- exactly one level below an allowed parent (no nested or external copies).
- no symlink anywhere in the path, a real directory on the parent's volume.
- only Apple's installer apps (their bundle identifiers all start with this).
- an installer whose Info.plist cannot be read, or that is not Apple's installer, is not offered.
- an unknown product is never classified as orphaned.
- same fail-closed rules as the caches inspector — `.unknown` and "no app of the product found at all" are both treated as "maybe still installed".
- symlinks and anything on another volume are left in the Trash (never offered), so a permanent removal can never reach outside the Trash folder.

### `Sources/iMopCore/Discovery/VSCodeExtensionsInspector.swift` (4)

- if any entry cannot be understood we cannot tell which folder it keeps alive, so the whole file counts as unparsable and nothing is offered.
- `~/.vscode/extensions/extensions.json` is only the DEFAULT profile's list; another profile may use (or pin) an older version in the same folder.
- without a readable, fully understood extensions.json nothing is offered.
- "same extension" means same id AND same target platform.

### `Sources/iMopCore/Discovery/XcodeInspector.swift` (8)

- metadata files larger than this are not parsed (the item is skipped).
- an unknown rule id bound to this inspector gets nothing.
- a folder whose project cannot be PROVEN gone is treated as ACTIVE (Yellow, never preselected, age-gated), never as orphaned.
- `lstat` returning nothing is NOT proof of absence (a TCC-protected folder or an I/O error looks the same).
- a listing is only proof of absence when the listed folder is an ordinary folder.
- an archive whose Info.plist is missing, unreadable or lacks a bundle identifier or creation date is KEPT (never offered).
- bundle identifiers are grouped by their exact string (never merged, so a group can only be larger, never smaller, than intended), and every archive whose creation date equals the N-th newest date is kept too (ties keep both).
- a folder whose name carries no recognisable OS version is not something we understand, so it is not offered.

### `Sources/iMopCore/Sizing/SizeCalculator.swift` (10)

- symlinks are never followed at ANY level of `path`: - a path that is not in normal form (trailing "/", "." / ".." / empty components, or "/" itself) is refused, because POSIX resolves a final symlink for "link/" and "link/."; - the root's PARENT directory is opened with `O_NOFOLLOW_ANY`, so a symlink in any ...
- the directory we opened must be the very object getattrlist described; if it was swapped in between we refuse to measure rather than report someone else's tree.
- per-file private size under-reports when two clones of the same blocks are both inside the tree (deleting both would free the shared blocks).
- private size is clamped to [0, allocated] so a file system quirk can never make us promise more than is on disk.
- APFS reports a private size of 0 for decmpfs-compressed files (UF\_COMPRESSED) even when they share no blocks with anything.
- unknown link count → assume it may be hard-linked elsewhere: on disk, but not reclaimable.
- a hard-linked file we cannot identify cannot be proven to have all its links inside the tree → not reclaimable.
- a malformed buffer means we cannot trust anything after it; stop reading this directory and report the estimate as incomplete.
- spec §3.5 protects a .git directory or a protected extension ANYWHERE; a target that contains one must never be acted on.
- O\_NONBLOCK so a FIFO swapped in for a directory can never block the scan.

### `Sources/iMopCore/Planning/CleanupPlan.swift` (5)

- `bootoutAndTrash` is not restorable (see `Action.bootoutAndTrash`), so it needs the explicit irreversible-action acknowledgement as well as the Red per-item confirmation.
- a one-step permanent removal is never preselected, even for a Green rule; the user must opt in to every irreversible deletion that has no undo at all.
- written as `!(elapsed >= 2)` so a NaN or negative interval (clock moved backwards, confirmation dated before the sheet appeared) is also refused.
- an ID shared by several plan items is ambiguous; none of them is acted on.
- the setting recorded in the plan and the caller's value must BOTH be off; the two can never disagree in the permissive direction.

### `Sources/iMopCore/Planning/PlanBuilder.swift` (14)

- a target ID that occurs more than once makes selection ambiguous, so every item carrying a duplicated ID is blocked.
- an Advisory rule or target is always advisory, whatever action the rule declares (SafetyGate rejects such pairs too).
- it may only LENGTHEN the rule's own retention (`ScanSettings.effectiveRetentionHours(for:)` ignores shorter or non-positive values).
- a non-positive retention would make a quarantined item purgeable at once, i.e. an unconfirmed permanent deletion → refuse.
- file-system actions only ever apply to file-system targets.
- RuleCatalog loads `.permanentDelete` only for its allow-listed rules; a rule that reached the builder without the catalog is refused too (defence in depth).
- spec §9.9 "Always quarantine (never permanently delete in one step)", default ON.
- the persisted setting (`environment.scanSettings`, the one source of truth) is honoured too, so a caller that passes `alwaysQuarantine: false` cannot override a setting that is ON (merged like the user exclusions).
- only the Swift-pinned LaunchAgent rule, only file-system targets.
- a per-item command without its item would run with the literal `{ITEM}` token (or act on everything) → refuse.
- an argument that is empty, looks like an option, contains control characters, or contains the token itself could change what the vendor command does.
- an argument the command never consumes means target and rule disagree.
- a target path that cannot be interpreted cannot be shown to be outside every exclusion.
- an exclusion that cannot be interpreted might cover this item.

### `Sources/iMopCore/Execution/CommandRunner.swift` (22)

- the only system tools ever taken from /usr/bin.
- system tools that are resolved ONLY from this exact, SIP-protected path (never from any search directory): `pkgutil --pkgs` (read-only, OrphanDetector condition 4), `tmutil listlocalsnapshots /` (read-only, Time Machine advisory) and `launchctl bootout …` (the Executor's `bootoutAndTrash` only).
- SIP-protected system directories.
- no caller may run a command longer than the longest spec timeout (30 min, `simctl runtime delete`); a non-positive or non-finite timeout means the 10-minute default.
- a symlinked executable is accepted only when its real path is ALSO inside one of these roots (e.g. Homebrew's `bin/brew` → `/opt/homebrew/Library/...`).
- only the exact path; its real path must be that same file.
- resolve the path component by component, checking EVERY directory passed through (all ancestors up to "/", each symlink hop's directory) and every symlink, so nobody but the user or root can swap anything between the check and the launch.
- a `#!` script runs its interpreter, so the interpreter must pass the same checks (inside a trusted root or SIP-protected /bin, /usr/bin).
- a file whose first bytes cannot be read cannot be checked → refused.
- `#!/usr/bin/env NAME` — exactly one bare program name (no `-S`, no options, no assignments), resolved exactly like `env` will: the first directory of the sanitized PATH that has an entry of that name decides, and that entry must pass every check.
- the folder's owner must be the current user — not root, not anyone else (opt-in "Trust Homebrew tools" relaxation; files and symlinks are never relaxed).
- the child's PATH lists only the trusted search directories that pass the directory checks NOW (every directory on the way owned by the user or root, none group/world-writable — e.g. a 0775 `/opt/homebrew/bin` is left out unless "Trust Homebrew tools" is ON and it passes `isTrustedHomebrewDirectory`), followed by the SIP-protected `/usr/bin` and `/bin`.
- spec §5.3 lists only PATH, HOME, USER and LANG.
- the child sees only PATH (trusted directories), HOME, USER, LANG and the fixed `networkOptOutVariables`.
- the purpose-less form is read-only.
- the launchctl bootout must name THIS user's GUI domain and a plist directly in THIS user's ~/Library/LaunchAgents (the static table cannot know either).
- the path is re-resolved and re-verified right before launch; a caller can never run an executable that `resolveExecutable` would not return for that tool now.
- launch the fully resolved, verified file (not the symlink in the search directory), and only if it is still the same inode right before the launch.
- a cancelled task stops a READ-ONLY probe (process group SIGTERM → grace → SIGKILL, result "cancelled").
- the verified file must still be the same inode right before the launch; anything else fails closed.
- signals go to the whole process group of the child (a grandchild that ignores SIGTERM is still killed), even after the direct child has exited — the group id cannot be reused while any member is alive, and nothing is sent once the result is delivered.
- a stopped command's result is delivered only after the SIGKILL went to its process group, or once no member of the group is left.

### `Sources/iMopCore/Execution/CommandTrustPolicy.swift` (3)

- OFF unless the user turned it on (after seeing who else could change the tools).
- the exact Homebrew locations the relaxation may ever apply to — nothing else.
- when the user's own name is unknown nothing else is removed (listing too many accounts is the safe side of a disclosure).

### `Sources/iMopCore/Execution/Executor.swift` (18)

- one user confirmation allows ONE execution.
- if the consumer goes away mid-run, stop at the next item boundary rather than keep acting with nobody watching.
- a plan whose contents no longer match the hash computed at confirmation is not what the user approved.
- a sanity downgrade at execute time is never acted on either.
- a command item's path is informational (it may be a UDID or a model name, not a path).
- the plist is moved to the Trash ONLY after a successful bootout (or launchd's documented "not loaded" answer); any other outcome fails the item and leaves the plist where it is.
- re-read the plist right before acting — it must still name a program that no longer exists (an agent whose binary came back, or that changed, is not touched).
- only the SIP-protected /bin/launchctl is ever run.
- it must equal the retention the CURRENT settings give this rule (`ScanSettings.effectiveRetentionHours`, which may only LENGTHEN the rule's own value) — a plan built with other settings, or a shorter value, is refused.
- the object now in the Trash must be the pinned item; otherwise the item is reported as failed (whatever was trashed stays in the Trash, restorable).
- a per-item command without an argument would pass the literal "{ITEM}" token (or act on everything); an argument that is empty, starts with "-" (option injection) or contains control characters is refused.
- a whole-rule command never takes a per-item argument.
- before anything is resolved or started, the exact invocation must be an action entry of the Swift-coded `CommandAllowList` that this rule and tier may use, with the `{ITEM}` value accepted by that entry's validator (the live `CommandRunner` checks the same table again).
- the effective tier may only be stricter than the rule's tier (a lower tier would skip confirmation steps the rule requires, e.g. Red per-item confirmation).
- the planned action may never be more destructive than the rule's action.
- only the Swift-pinned LaunchAgent rule, with its complete reviewed shape (a hand-built rule with the same id but another shape is refused).
- RuleCatalog only loads `.permanentDelete` for its allow-listed rules; a hand-built rule that skipped the catalog is refused here too (defence in depth).
- "Always quarantine" is read from the persisted settings right before acting, whatever flags the plan was built and confirmed with — a setting that is ON (or was switched ON after confirmation) blocks every permanent deletion.

### `Sources/iMopCore/Execution/MutationPolicy.swift` (6)

- `isEnabled` is read-only (computed).
- with an unknown home the fixture policy always refuses (it can only permit a mutation when the home is proven to be inside the fixture root).
- every policy refuses a path that is relative, contains "..", NUL, a `~`/`{HOME}` placeholder, or maps into /System — mutation targets are always canonical.
- while the test-suite guard is installed (a test run), a build compiled with IMOP\_ALLOW\_MUTATION still refuses; tests may mutate only through `fixtureOnly`.
- lexical containment is not enough — an intermediate symlink could point out of the fixture.
- only a missing component is skipped; any other lstat error denies.

### `Sources/iMopCore/Execution/Quarantine.swift` (16)

- each item gets its own `<entry-UUID>/` directory and keeps its ORIGINAL name (`quarantinedName` = "&lt;entry-UUID&gt;/&lt;original name&gt;") instead of a flat "&lt;uuid&gt;-&lt;name&gt;".
- an unusable (non-canonical) home makes every operation refuse.
- SPI only — the Executor (same module) is the only production caller — and fail-closed on its own: SafetyGate (phase `.execute`, purpose `.standard`) must return `.allowed` first, whatever the caller validated.
- a quarantined item is purged automatically when its retention ends, so only rules whose action already removes the item may quarantine it (a Trash rule may not).
- a non-positive retention would make the item purgeable at once, i.e. an unconfirmed permanent deletion.
- iMop's own Quarantine is never quarantined into itself, and neither the home directory nor any of its ancestors is ever moved.
- whatever was moved is not the pinned item → put it straight back.
- a symlink is never quarantined (whatever the rule's allowSymlinkTarget): purges validate items without the symlink exception, so a quarantined link could never be purged, and moving it gains nothing.
- a `.needsReview` entry could not be proven to hold the pinned item; it is still restored on explicit request, because a restore never overwrites or removes anything (RENAME\_EXCL, "(restored …)" name on conflict) — leaving it stranded is worse.
- the original parent must still exist as a real directory reached without any symlink (realpath spells the same path).
- a failed manifest update is not reported as a failed restore — the item IS back.
- a session whose manifest cannot be read is never purged: only items listed in a valid manifest are ever removed.
- removefileat relative to the entry folder (short relative path, so the long Quarantine prefix does not count against PATH\_MAX).
- the item is gone, so the outcome is `.purged` even if the manifest update fails; the entry then stays `.purging`, which can never restore anything and which the next purge or `reconcile()` marks `.purged`.
- an entry is only ever dropped when nothing is in its Quarantine folder, so an item that is physically in Quarantine is never forgotten.
- a session this instance began is never removed until `endSession(_:)`: the Executor may still be adding items to it (a purge or restore can run between two items).

### `Sources/iMopCore/Execution/Trash.swift` (6)

- "/" and top-level folders ("/Users", "/Applications") are never acted on.
- the real home directory and its ancestors are never acted on, whatever the caller validated.
- always refuses — an item is only ever trashed by pinned identity.
- while the test-suite guard is installed (a test run), the real Trash is never touched: `trashItem` always targets the real user's Trash, which no fixture can redirect.
- the trashed object must be the pinned item; otherwise report failure (the object stays in the Trash, where the user can still put it back).
- always refuses — an item is only ever removed by pinned identity.

### `Sources/iMopCore/Audit/AuditLog.swift` (5)

- the audit log is iMop's own bookkeeping, not a cleanup mutation, so it is written even in builds without IMOP\_ALLOW\_MUTATION (dry runs are auditable).
- O\_NONBLOCK so a FIFO planted at the log name fails (ENXIO) instead of blocking the actor — and with it every Executor run — forever.
- only append to a regular, single-link file owned by the user; a hard link planted at the log name could otherwise make us append to some other file.
- export writes a NEW file only (`O_CREAT|O_EXCL|O_NOFOLLOW`) — an existing file is never overwritten, so the UI must pick a fresh name.
- a log name that is not a regular, single-link file owned by the user (a FIFO, a hard link to some other file, ...) is skipped: its content is never exported.

### `Sources/iMopCore/Permissions/AppManagementProbe.swift` (1)

- no probe ever tries to change an app bundle to find out, so the answer is always `.unknown`; callers must not treat it as granted.

### `Sources/iMopCore/Permissions/FullDiskAccessProbe.swift` (3)

- EVERY existing protected folder is probed.
- only a real directory is probed; a symlink (which could point anywhere) or a missing folder says nothing about the permission.
- any listing failure (not only EPERM) counts as "denied", so rules that need Full Disk Access stay locked rather than failing half-way.

### `Sources/iMopCore/ViewModels/AppState.swift` (19)

- there is deliberately NO mutation-policy knob.
- cleaning is refused until the user has checked Settings and called `acknowledgeSettingsReview()`, because a lost exclusion would silently widen what iMop may touch.
- an exclusion added while a cleanup runs applies to that run too (the Executor's SafetyGate reads `runExclusions` live at every item).
- always the compile-time policy (see AppStateFixtureOptions).
- rules whose access macOS refused earlier in this session are not scanned again (no repeated prompting); they are reported as unavailable.
- only a positively confirmed grant unlocks the rules that need Full Disk Access (`.unknown` keeps them locked).
- only the item currently presented in the dialog (`pendingRedConfirmation`) can be confirmed, so no code path selects a Red item without its dialog having been shown.
- the items in the Trash form ONE "Empty Trash" choice.
- only the request currently presented can be confirmed.
- bulk selection never selects a Red item (each needs its own dialog) and never a non-actionable one; bulk deselection removes everything in the category, Red included.
- a review is valid only for the exact selection it showed.
- Yellow items need the per-category acknowledgement of their "what you lose" text, enforced here and not only in the review sheet.
- Trash items are cleaned only as the whole, separately confirmed "Empty Trash" choice.
- settings that affect safety (exclusions, project roots, overrides, "Always quarantine") apply to the NEXT scan; a plan built under different settings is refused here and the user is asked to scan again (never silently re-planned at confirm time).
- the execute-time gate also reads exclusions added during the run.
- no purge while a cleanup is running (the Executor owns the open session).
- during a cleanup the selection is the confirmed run and is left alone; the new exclusion reaches the running Executor through `runExclusions` (see the `settings` setter), so matching items not processed yet are skipped with the exclusion reason.
- deselect anything inside (or containing) the new exclusion right away; the plan itself is outdated now and must be rebuilt by a new scan before cleaning.
- `nil` means "never recorded", which pauses the OrphanDetector until the next scan records the connected drives again (see `ScanSettings.lastSeenVolumes`).

### `Sources/iMop/Views/CategoryListView.swift` (1)

- bulk selection never selects Red items (enforced in AppState); say so here so the user is not surprised that they stay unchecked.

### `Sources/iMop/Views/MainView.swift` (3)

- however the sheet goes away (Cancel, Esc, programmatic dismissal), the recorded review is discarded, so showing it again always restarts the 2-second wait.
- stored settings could not be read completely; cleaning is paused until the user has checked them in Settings and confirmed.
- a plan built under different safety settings is never cleaned; the Review button is disabled and the user is asked to scan again.

### `Sources/iMop/Views/QuarantineView.swift` (1)

- Cancel is the default (Return) action of this destructive confirmation.

### `Sources/iMop/Views/RedItemConfirmation.swift` (2)

- Cancel is both the cancel (Esc) and the default (Return) action, so only a deliberate click on the named button selects a Caution item.
- Cancel is both the cancel (Esc) and the default (Return) action.

### `Sources/iMop/Views/ReviewSheet.swift` (4)

- a selected permanent deletion while Settings › "Always quarantine" is ON would be refused by `ConfirmedPlan.confirm`; the Clean button is disabled up front and the reason is shown, instead of letting the user press Clean and fail.
- settings changed after this scan (e.g. in the Settings window while the sheet is open) — the plan must be rebuilt by a new scan; Clean stays disabled.
- the 2-second window needs a recorded presentation time; if the sheet was shown without `beginReview()`, record it now (the core measures from it).
- Clean is NOT bound to Return (no `.defaultAction`), so a stray key press can never confirm; it must be clicked (or focused and activated) deliberately.

### `Sources/iMop/Views/SettingsView.swift` (8)

- cleaning stays paused until the user confirms here.
- keeping the safer setting is the default (Return) action.
- keeping the setting OFF is the default (Return) action.
- turning the relaxation ON asks first (showing who else could change the tools); turning it OFF is immediate.
- turning the protection ON is immediate; turning it OFF asks first.
- files may be excluded as well as folders (excluding more is safer).
- never write an override that is not longer than the default.
- an override may only RAISE the threshold.

### `Tests/iMopTests/Execution/ExecutorTests.swift` (1)

- Audited even though nothing may be mutated (the log is bookkeeping).

### `scripts/package_app.sh` (2)

- the cleaning-enabled build gets its own scratch directory, so a binary compiled with IMOP\_ALLOW\_MUTATION never lands in the default .build folder used by `swift build` / `swift run` during development (where it could be mistaken for, or run instead of, a dry-run build).
- without Rules.json the app loads an empty catalog (it never traps, it simply offers nothing), which would ship a cleaner that silently finds nothing.

<!-- END GENERATED SAFETY-DECISION INDEX -->
