# iMop for macOS

**iMop** is a lightweight, native, and blazingly fast macOS storage cleaning utility built with **Swift** and **SwiftUI** (targeting macOS 14.0+ / Sonoma & Sequoia).

It scans system and user directories for safe-to-delete files, detects orphaned remnants of uninstalled applications, provides itemized control over what gets cleaned, and safely purges files using macOS Trash mechanics.

---

## 🌟 Key Features

* **5 Modular Scanning Engines**:
  1. **Application Remnants**: Scans `Application Support`, `Saved Application State`, `Containers`, and `Preferences` for leftovers from deleted apps using intelligent reverse-DNS heuristics and safety allowlists.
  2. **Application & User Caches**: Scans `~/Library/Caches`, automatically excluding active running applications.
  3. **Logs & Diagnostics**: Scans crash reports, diagnostic logs, and spins (`.log`, `.crash`, `.diag`, `.ips`, `.spin`).
  4. **Developer Artifacts**: Reclaims high-volume space from Xcode (`DerivedData`, `Archives`, `iOS DeviceSupport`, `CoreSimulator`), Homebrew cache, CocoaPods, NPM, Yarn, pnpm, Cargo, and Gradle caches.
  5. **Trash & Temporary Files**: Inspects `~/.Trash`, incomplete browser downloads (`.crdownload`, `.download`, `.part`), and temp items.
* **Strict Safety Guardrails**:
  * **macOS Trash by Default**: Files are safely moved to the Trash via `FileManager.default.trashItem` so they can be restored at any time.
  * **Permanent Deletion Mode**: Explicit toggle available in settings for users who want immediate space reclamation.
  * **Dry-Run Simulation**: Test and preview clean operations without deleting or altering any file.
  * **System Blocklist**: Core macOS paths (`/System`, `/usr`, `/bin`, `/sbin`, `/var/db`, `/etc`) are strictly blocked.
  * **Symlink & Cloud Guard**: Symlink boundaries and iCloud sync folders (`com~apple~CloudDocs`) are never traversed or purged.
  * **Running App Protection**: Cross-checks against `NSWorkspace.shared.runningApplications` in real time.
* **Native Modern UI**:
  * Vibrant translucent materials (`.ultraThinMaterial`).
  * Live storage gauge with Macintosh HD metrics.
  * Real-time file path scanning stream.
  * Search, sort (by size, name, modified date), and category filter controls.
  * Context menus ("Reveal in Finder", "Open Item", "Exclude from future scans").
  * Floating clean bar and completion celebration modal.

---

## 🏗️ Architecture

The codebase is structured into modular targets:

```text
iMop/
├── Package.swift               # SPM definition (macOS 14.0+)
├── Sources/
│   ├── iMopCore/               # Core Engine Library
│   │   ├── Models/             # JunkCategory, JunkItem, ScanProgress, DiskUsage
│   │   ├── Services/           # ScannerEngine, AppRegistryService, DeletionService,
│   │   │                       # PermissionService, SystemHealthService
│   │   ├── Utils/              # ByteFormatter, FileSafetyRules, LocalState
│   │   └── ViewModels/         # AppState, DashboardViewModel, CategoryDetailViewModel
│   └── iMop/                   # Native SwiftUI GUI App
│       ├── App/                # iMopApp.swift (@main)
│       └── Views/              # MainView, SidebarView, DashboardView, CategoryDetailView,
│                               # ConfirmationModalView, CompletionModalView, Components/
├── Tests/
│   └── iMopTests/              # Automated Test Suite Runner (Scanner, Registry, Safety)
└── scripts/
    ├── package_app.sh          # Packages release binary into iMop.app bundle
    └── swiftc-wrapper.sh       # Linker manifest alias helper for Swift toolchain
```

---

## 🚀 Building & Running

### Prerequisites
* macOS 14.0 or later.
* Swift 5.10+ / Swift 6 (Apple Command Line Tools or Xcode).

### Run Test Suite
Run all unit and integration tests across scanner engines, safety rules, and sandboxed deletions:

```bash
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift run iMopTests
```

### Launch GUI Application directly via SPM
To build and launch the SwiftUI application in development:

```bash
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift run iMop
```

### Package into a Standalone `iMop.app`
To generate a release build packaged into a native macOS application bundle:

```bash
./scripts/package_app.sh
```

The resulting application will be created at:
```bash
build/iMop.app
```

You can open and test it immediately:
```bash
open build/iMop.app
```

---

## 🔒 Permissions (Full Disk Access)

To allow iMop to scan protected directories such as system logs or containers in `~/Library/Containers`:
1. Open **System Settings** > **Privacy & Security** > **Full Disk Access**.
2. Enable Full Disk Access for **iMop** (or Terminal if running via `swift run`).
3. iMop includes an in-app indicator and a direct button in the sidebar to open the System Settings privacy pane with one click.