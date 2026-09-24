# iMop for macOS

<p align="center">
  <strong>A lightweight, native, and blazingly fast macOS storage cleaning utility built with Swift & SwiftUI.</strong><br>
  Targeting macOS 14.0+ (Sonoma & Sequoia) • Universal Binary (Apple Silicon & Intel)
</p>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [How to Build & Run](#-how-to-build--run)
  - [Prerequisites](#prerequisites)
  - [Run Tests](#1-running-the-automated-test-suite)
  - [Launch the App via CLI](#2-launching-the-swiftui-gui-app)
  - [Package Standalone .app Bundle](#3-packaging-a-standalone-imopapp)
- [User Guide: How to Use iMop](#-user-guide-how-to-use-imop)
  - [Scanning System & Categories](#scanning)
  - [Reviewing & Filtering Junk](#reviewing--filtering-items)
  - [Cleaning & Safety Modes](#cleaning--safety-modes)
  - [Full Disk Access (FDA)](#granting-full-disk-access)
- [Project Architecture & Developer Guide](#-project-architecture--developer-guide)
  - [Target Structure](#target-structure)
  - [File-by-File Breakdown](#file-by-file-breakdown)
  - [How to Modify & Extend iMop](#how-to-modify--extend-imop)
    - [Adding a New Junk Category](#adding-a-new-junk-category)
    - [Adding New Developer / Cache Targets](#adding-new-developer--cache-targets)
    - [Modifying Safety Blocklists & Allowlists](#modifying-safety-blocklists--allowlists)
- [License](#-license)

---

## 🌟 Overview

**iMop** cleans unnecessary clutter from your Mac without risking system integrity. It scans user caches, developer build artifacts, diagnostic logs, and orphaned remnants of uninstalled applications.

Unlike opaque cleaners, **iMop prioritizes user transparency and safety**:
* Files are moved to the **macOS Trash by default** so you can easily restore them anytime.
* An optional **Dry-Run mode** simulates cleaning so you can verify reclaimed space before touching a single byte.
* It enforces **strict safety rules** to protect active running apps, iCloud sync folders, symlinks, and macOS system partitions.

---

## ✨ Key Features

1. **5 Modular Scanning Engines**:
   * **App Remnants**: Leftover support directories, preferences, and container states from uninstalled apps.
   * **Application Caches**: User caches in `~/Library/Caches` (excluding active processes).
   * **Logs & Diagnostics**: System, app, and crash diagnostics (`.log`, `.diag`, `.crash`, `.ips`, `.spin`).
   * **Developer Artifacts**: Reclaims gigabytes from Xcode (`DerivedData`, `Archives`, `iOS DeviceSupport`, `CoreSimulator`), Homebrew, CocoaPods, NPM, Yarn, pnpm, Cargo, and Gradle caches.
   * **Trash & Temporary Files**: Incomplete browser downloads (`.crdownload`, `.download`, `.part`) and Trash contents.
2. **Native macOS Interface**:
   * Modern translucent materials (`.ultraThinMaterial`) and vibrant gradients.
   * Live storage capacity gauge for Macintosh HD.
   * Real-time file path scanning stream.
   * Sortable and searchable item lists (size, modified date, name).
   * Context menus: "Reveal in Finder", "Open Item", and "Exclude from future scans".
   * Floating bottom action bar and celebration completion modal.

---

## 🛠️ How to Build & Run

### Prerequisites

* macOS 14.0 (Sonoma) or later.
* Swift 5.10+ / Swift 6 toolchain (Apple Command Line Tools or Xcode).
* Git.

```bash
git clone https://github.com/git-maniam/iMop.git
cd iMop
```

> [!NOTE]
> For environments running standalone Apple Command Line Tools, a build helper script [`scripts/swiftc-wrapper.sh`](file:///Users/rsubramaniam/Projects/iMop/scripts/swiftc-wrapper.sh) is provided to bridge package manifest symbols automatically.

### 1. Running the Automated Test Suite

iMop includes a standalone test runner covering scanner engines, safety rules, registry indexing, and sandboxed deletions.

To run all automated tests:

```bash
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift run iMopTests
```

Expected output:
```text
🚀 Starting iMop Test Suite Execution...

🔍 Running Scanner Engine Tests...
  ⏳ [RUN] Calculate size of nonexistent directory returns 0... [PASS]
  ⏳ [RUN] Calculate size of nested folder with files... [PASS]
  ⏳ [RUN] Scan mock user caches and log files... [PASS]
  ⏳ [RUN] Scan developer derived data targets... [PASS]

📱 Running App Registry & Safety Tests...
  ⏳ [RUN] Protected vendor and tool names are guarded... [PASS]
  ⏳ [RUN] Uninstalled third-party bundle ID is recognized as candidate... [PASS]
  ⏳ [RUN] AppRegistry indexes active system apps... [PASS]

🛡️ Running Safety Guardrails & Deletion Tests...
  ⏳ [RUN] Blocked system paths cannot be deleted or touched... [PASS]
  ⏳ [RUN] Dry-run mode does not modify or delete files... [PASS]
  ⏳ [RUN] Permanent deletion removes file in test sandbox... [PASS]

=======================================================
✅ ALL 10 TESTS PASSED SUCCESSFULLY!
=======================================================
```

### 2. Launching the SwiftUI GUI App

To launch the native macOS application in development mode directly from terminal:

```bash
SWIFT_EXEC=./scripts/swiftc-wrapper.sh swift run iMop
```

### 3. Packaging a Standalone `iMop.app`

To compile an optimized release binary and assemble a standalone `.app` bundle:

```bash
./scripts/package_app.sh
```

The script builds the binary and outputs:
```bash
build/iMop.app
```

You can open and run it immediately:
```bash
open build/iMop.app
```

---

## 🖥️ User Guide: How to Use iMop

### Scanning
1. Launch **iMop**.
2. Click the pulsing circular **"Scan System"** button on the Overview dashboard (or press <kbd>⌘</kbd>+<kbd>R</kbd>).
3. Watch the real-time path stream as iMop inspects user directories and caches.
4. When complete, the dashboard displays total cleanable space, item counts, and category cards.

### Reviewing & Filtering Items
* Click any category in the sidebar or from the dashboard cards to open its detail view.
* **Search Filter**: Type in the search box to find specific files, folders, or extensions.
* **Sorting**: Sort by size (largest first), date modified, or alphabetical name.
* **Selection**: Check or uncheck individual items, or use **"Select All"** / **"Deselect All"**.
* **Context Menu**: Right-click on any file row to:
  * **Reveal in Finder** — inspect the file directly on disk.
  * **Open Item** — open with its default application.
  * **Exclude from Future Scans** — prevents the item from ever appearing in scans again.

### Cleaning & Safety Modes
* **Move to Trash (Default)**: Items are safely placed in your macOS Trash bin so you can restore them if needed.
* **Dry-Run Mode (Simulation)**: Toggle **"Dry Run Mode"** in the bottom sidebar. When enabled, iMop simulates the entire cleaning process, showing you exact space reclaimed without altering any files.
* **Permanent Deletion**: In the sidebar or menu bar, toggle **"Permanent Delete"** if you want to bypass the Trash and immediately free disk space.
* Click **"Clean with iMop"** on the floating bottom bar and review the confirmation sheet.

### Granting Full Disk Access
macOS requires Full Disk Access to inspect system logs and protected application containers:
1. If Full Disk Access is not yet granted, an alert card appears in the sidebar.
2. Click **"Open Settings"** to jump directly to **System Settings > Privacy & Security > Full Disk Access**.
3. Toggle the switch for **iMop** (or Terminal if running via `swift run`).

---

## 🧩 Project Architecture & Developer Guide

iMop is architected into clean, modular Swift packages:

### Target Structure

```text
Package.swift
 ├── iMopCore (Library)           -> All models, services, safety utils, and viewmodels
 ├── iMop (Executable GUI)        -> SwiftUI App entry point (@main) and interface views
 └── iMopTests (Executable Test)  -> Automated test runner verifying core engines
```

### File-by-File Breakdown

#### `Sources/iMopCore/Models/`
* [`JunkCategory.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Models/JunkCategory.swift): `JunkCategoryType` enum defining the 5 scan modules, SF Symbols, descriptions, and default selection rules (e.g. Caches pre-checked; Developer & Remnants unchecked until reviewed).
* [`JunkItem.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Models/JunkItem.swift): Data model representing an individual file or directory candidate with path, size, date, category, and selection state.
* [`ScanProgress.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Models/ScanProgress.swift): Real-time progress updates (`currentPath`, `category`, `itemsFound`, `bytesFound`).
* [`DiskUsage.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Models/DiskUsage.swift): Boot volume metrics (`totalBytes`, `freeBytes`, `usedBytes`, `recoverableBytes`) and percentage calculations.

#### `Sources/iMopCore/Services/`
* [`ScannerEngine.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/ScannerEngine.swift): Core scanning orchestrator. Computes recursive directory sizes while respecting symlink boundaries, runs scan tasks, and streams progress.
* [`AppRegistryService.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/AppRegistryService.swift): Indexes installed macOS applications (`/Applications`, `/System/Applications`, `/System/Library/CoreServices`, `~/Applications`) and tracks active processes via `NSWorkspace.shared.runningApplications`.
* [`DeletionService.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/DeletionService.swift): Executes safe moves to macOS Trash, handles permanent deletion, enforces safety gates, and manages dry-run simulations.
* [`PermissionService.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/PermissionService.swift): Detects Full Disk Access (FDA) status and deep-links to the System Settings Privacy pane.
* [`SystemHealthService.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/SystemHealthService.swift): Queries `URLResourceValues` for disk capacity and free space.

#### `Sources/iMopCore/Utils/`
* [`ByteFormatter.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Utils/ByteFormatter.swift): Thread-safe formatting of raw byte counts into human-readable strings (GB, MB, KB) and split value/unit pairs.
* [`FileSafetyRules.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Utils/FileSafetyRules.swift): Enforces system blocklists (`/System`, `/usr`, `/bin`, `/sbin`, `/var/db`, `/etc`), detects iCloud sync boundaries, checks running processes, and maintains the safety allowlist for remnant candidates.
* [`LocalState.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Utils/LocalState.swift): Custom `@LocalState` dynamic property wrapper providing reactive local view state and bindings without requiring proprietary Xcode macro plugins.

#### `Sources/iMopCore/ViewModels/`
* [`AppState.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/ViewModels/AppState.swift): Central `@Observable` class driving application lifecycle, scan tasks, selection state, exclusion lists, and cleaning actions.
* [`CategoryDetailViewModel.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/ViewModels/CategoryDetailViewModel.swift): Handles search text query matching and sort ordering for category detail views.
* [`DashboardViewModel.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/ViewModels/DashboardViewModel.swift): Manages pulse animation state for the dashboard scan trigger.

#### `Sources/iMop/App/` & `Sources/iMop/Views/`
* [`iMopApp.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/App/iMopApp.swift): `@main` SwiftUI application scene, window dimensions, and keyboard shortcuts (`⌘R` to scan).
* [`MainView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/MainView.swift): Root `NavigationSplitView` hosting the sidebar and detail view, with the floating clean action bar and modal sheets.
* [`SidebarView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/SidebarView.swift): Branding header, `StorageGaugeView`, FDA status banner, category navigation links, and dry-run/trash toggles.
* [`DashboardView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/DashboardView.swift): Pulsing circular scan trigger, active scanning animation with path stream, and category overview grid.
* [`CategoryDetailView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/CategoryDetailView.swift): Category header, search text field, sort picker, and scrollable file rows.
* [`ConfirmationModalView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/ConfirmationModalView.swift): Item breakdown sheet with permanent vs trash warnings before cleaning.
* [`CompletionModalView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/CompletionModalView.swift): Celebration ring and metrics showing reclaimed disk space.
* [`Components/StorageGaugeView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/Components/StorageGaugeView.swift): Visual multi-segment bar showing used, cleanable, and free disk space.
* [`Components/CategoryCardView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/Components/CategoryCardView.swift): Interactive card showing category metrics and quick check toggles.
* [`Components/FileItemRowView.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMop/Views/Components/FileItemRowView.swift): File row with native file icon, name, path, size, date, and context menus.

---

### How to Modify & Extend iMop

#### Adding a New Junk Category
1. Open [`JunkCategory.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Models/JunkCategory.swift) and add a new case to `JunkCategoryType`:
   ```swift
   public enum JunkCategoryType: String, CaseIterable, Identifiable, Sendable {
       case myNewCategory = "My New Category"
       ...
       public var iconName: String { ... }
       public var subtitle: String { ... }
       public var recommendedByDefault: Bool { ... }
   }
   ```
2. Open [`ScannerEngine.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/ScannerEngine.swift) and add a scan handler for it:
   ```swift
   case .myNewCategory:
       items = await scanMyNewCategory(home: home, onProgress: onProgress)
   ```
3. Implement `scanMyNewCategory(home:onProgress:)` to locate the target paths, calculate sizes with `calculateSize(at:)`, verify safety with `FileSafetyRules.isSafeToDelete(url)`, and return `[JunkItem]`.
4. The UI (`SidebarView`, `DashboardView`, `CategoryDetailView`, and confirmation modals) will automatically adapt because it iterates over `JunkCategoryType.allCases`.

#### Adding New Developer / Cache Targets
Open [`ScannerEngine.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Services/ScannerEngine.swift) and locate `scanDeveloperJunk()`:
```swift
let devTargets: [(name: String, path: URL, desc: String)] = [
    ("Xcode DerivedData", home.appendingPathComponent("Library/Developer/Xcode/DerivedData"), "..."),
    // Add your custom path here:
    ("My Tool Cache", home.appendingPathComponent(".mytool/cache"), "Custom tool cache directory"),
]
```

#### Modifying Safety Blocklists & Allowlists
Open [`FileSafetyRules.swift`](file:///Users/rsubramaniam/Projects/iMop/Sources/iMopCore/Utils/FileSafetyRules.swift):
* **Blocked Paths**: Modify `blockedSystemPrefixes` to protect additional system directories.
* **Remnant Allowlist**: Modify `protectedVendorOrToolNames` to ensure specific developer directories in `~/Library/Application Support` are never marked as dead remnants.

---

## 📄 License

This project is licensed under the MIT License. Contributions, pull requests, and feature suggestions are welcome!