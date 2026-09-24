# Vibe Coding Specification: iMop for macOS

Build **iMop**, a lightweight, native, and blazingly fast macOS storage cleaning utility using Swift and SwiftUI (targeting macOS 14.0+ / Sonoma and Sequoia). 

iMop scans user and system directories for safe-to-delete files, detects orphaned remnants of uninstalled applications, gives users full visibility and itemized control over what gets cleaned, and safely purges files using macOS Trash mechanics.

---

## 1. Project Overview & Target Architecture

* **Product Name:** iMop
* **Platform:** macOS 14.0+ (Universal Binary: Apple Silicon + Intel)
* **Language:** Swift 5.10+ / Swift 6
* **UI Framework:** SwiftUI with AppKit integration (`NSWorkspace`, `NSFilePromiseReceiver`, etc.)
* **Concurrency:** Modern Swift Concurrency (`async/await`, `AsyncStream`, `TaskGroup`, `@Observable`)
* **Entitlements & Permissions:**
  * Disable App Sandbox (`com.apple.security.app-sandbox = false`) in order to scan and clean across `~/Library`, developer paths, and user-level caches.
  * Provide a built-in detection helper for macOS **Full Disk Access (FDA)** with a direct link opening `System Settings > Privacy & Security > Full Disk Access`.

---

## 2. Directory Structure

```text
iMop/
├── Package.swift (or iMop.xcodeproj)
├── Sources/
│   ├── App/
│   │   ├── iMopApp.swift
│   │   └── AppState.swift
│   ├── Models/
│   │   ├── JunkCategory.swift
│   │   ├── JunkItem.swift
│   │   ├── ScanProgress.swift
│   │   └── DiskUsage.swift
│   ├── Services/
│   │   ├── ScannerEngine.swift
│   │   ├── AppRegistryService.swift
│   │   ├── DeletionService.swift
│   │   ├── SystemHealthService.swift
│   │   └── PermissionService.swift
│   ├── ViewModels/
│   │   ├── DashboardViewModel.swift
│   │   └── CategoryDetailViewModel.swift
│   ├── Views/
│   │   ├── MainView.swift
│   │   ├── SidebarView.swift
│   │   ├── DashboardView.swift
│   │   ├── CategoryDetailView.swift
│   │   ├── ConfirmationModalView.swift
│   │   └── Components/
│   │       ├── StorageGaugeView.swift
│   │       ├── FileItemRowView.swift
│   │       └── CategoryCardView.swift
│   └── Utils/
│       ├── ByteFormatter.swift
│       └── FileSafetyRules.swift
└── Tests/
    └── iMopTests/
        ├── ScannerTests.swift
        └── AppRegistryTests.swift
```

---

## 3. Core Scanning Modules & Targets

iMop must categorize files into modular, toggleable scan modules:

### Module 1: Application Remnants (Orphaned App Data)
Detects leftover data from applications that have already been deleted.
* **Scan Algorithm:**
  1. Use `AppRegistryService` to index all active installed application bundle identifiers and display names from:
     * `/Applications`
     * `/System/Applications`
     * `~/Applications`
     * Spotlight / `MDQuery` metadata query fallback.
  2. Inspect targets where application files usually reside:
     * `~/Library/Application Support/`
     * `~/Library/Caches/`
     * `~/Library/Preferences/` (`.plist` files)
     * `~/Library/Saved Application State/`
     * `~/Library/Containers/`
  3. Extract reverse-DNS bundle IDs (`com.vendor.app`) or app folder names.
  4. Cross-reference them with the installed registry. Flag entries with zero matching installed binaries as **Orphaned Remnants**.

### Module 2: System & User Caches
* Target: `~/Library/Caches/*`
* Exclude running apps using `NSWorkspace.shared.runningApplications`.
* Calculate recursive directory sizes.

### Module 3: System & App Logs
* Target: `~/Library/Logs`, `/Library/Logs`, `~/Library/Application Support/CrashReporter`
* Match extensions: `.log`, `.asl`, `.diag`, `.crash`, `.spin`.

### Module 4: Developer Junk (High Reclaim Value)
* **Xcode:**
  * DerivedData: `~/Library/Developer/Xcode/DerivedData`
  * Archives: `~/Library/Developer/Xcode/Archives`
  * iOS DeviceSupport: `~/Library/Developer/Xcode/iOS DeviceSupport`
  * CoreSimulator Caches: `~/Library/Developer/CoreSimulator/Caches`
* **Package Managers & Runtimes:**
  * Homebrew Cache: `~/Library/Caches/Homebrew`
  * CocoaPods: `~/Library/Caches/CocoaPods`
  * Node/NPM/Yarn/pnpm: `~/.npm`, `~/.yarn/cache`, `~/Library/pnpm/store`
  * Rust/Cargo: `~/.cargo/registry/cache`
  * Gradle: `~/.gradle/caches`

### Module 5: Trash & Temporary Files
* User Trash: `~/.Trash`
* Browser partial downloads (`.crdownload`, `.download`, `.part`).
* Temporary directories: `$TMPDIR` items older than 48 hours.

---

## 4. Safety Guardrails & Rules (Strict Priority)

1. **Trash Over Hard Deletion:**
   * By default, deletions must call `FileManager.default.trashItem(at:resultingItemURL:)`.
   * Files go to the macOS Trash so the user can easily undo/restore if needed.
   * Provide an explicit, user-activated toggle for "Permanent Deletion" in Settings.
2. **Absolute Blocklist (Never Touch):**
   * Root partitions & critical macOS system dirs: `/`, `/System`, `/usr`, `/bin`, `/sbin`, `/var`, `/etc`, `/Library/Preferences/SystemConfiguration`.
   * iCloud synced repositories (`com~apple~CloudDocs`).
   * Active application files for processes currently running.
3. **Dry-Run Capability:**
   * The scanner engine must run independently of the deletion engine, allowing complete simulation without modifying any filesystem state.
4. **Symlink Protection:**
   * Never recursively delete across symlink boundaries to prevent accidental deletion outside target folders.

---

## 5. UI/UX Design Directives

* **Design Aesthetic:** Modern, clean, translucent macOS interface using native vibrant materials (`.background(.ultraThinMaterial)`).
* **Navigation:** `NavigationSplitView` with a left-hand navigation sidebar and right-hand content inspector.
* **Views Breakdown:**
  * **Sidebar:**
    * App Branding: Minimalist "iMop" logo and version.
    * Disk Usage Gauge: Overall disk capacity, used space, and potential recoverable space.
    * Category List: Real-time scan progress indicators, total size discovered per category, and toggle checkmarks.
  * **Dashboard / Scan View:**
    * Big circular "Scan System" button with a sleek pulse animation.
    * Real-time path stream showing current file being scanned.
  * **Category Details View:**
    * Sortable file list (Name, Size, Modified Date).
    * Action bar: "Select All", "Deselect All", and search filter bar.
    * Context menu items on file rows: "Reveal in Finder", "Quick Look Preview" (Space bar), and "Exclude from future scans".
  * **Bottom Bar:**
    * Floating cleaning bar showing: `X items selected (Y GB)`.
    * Prominent `Clean with iMop` button.
  * **Summary Modal / Sheet:**
    * Confetti / completion ring animation showing exact disk space reclaimed.

---

## 6. Key Swift Type Definitions

Use these models as foundational contracts:

```swift
import Foundation

public enum JunkCategoryType: String, CaseIterable, Identifiable, Sendable {
    case appRemnants = "App Remnants"
    case userCaches = "Application Caches"
    case systemLogs = "Logs & Diagnostics"
    case developer = "Developer Artifacts"
    case trashAndTemp = "Trash & Temporary Files"

    public var id: String { rawValue }
    
    public var iconName: String {
        switch self {
        case .appRemnants: return "trash.square"
        case .userCaches: return "externaldrive.badge.timemachine"
        case .systemLogs: return "doc.plaintext"
        case .developer: return "hammer"
        case .trashAndTemp: return "trash"
        }
    }
}

public struct JunkItem: Identifiable, Hashable, Sendable {
    public let id: UUID
    public let name: String
    public let path: URL
    public let size: Int64
    public let lastModified: Date
    public let category: JunkCategoryType
    public var isSelected: Bool

    public init(name: String, path: URL, size: Int64, lastModified: Date, category: JunkCategoryType, isSelected: Bool = true) {
        self.id = UUID()
        self.name = name
        self.path = path
        self.size = size
        self.lastModified = lastModified
        self.category = category
        self.isSelected = isSelected
    }
}

public struct ScanProgress: Sendable {
    public let currentPath: String
    public let category: JunkCategoryType
    public let itemsFound: Int
    public let bytesFound: Int64
}
```

---

## 7. Step-by-Step Implementation Instructions

Work sequentially through these phases:

### Phase 1: Foundation & Models
1. Initialize the project with `iMopApp.swift` and configure macOS targets (minimum deployment: macOS 14.0).
2. Set up models (`JunkItem`, `JunkCategoryType`, `ScanProgress`, `DiskUsage`).
3. Add utility helpers: `ByteFormatter` (wrapping `ByteCountFormatter`) and `FileSafetyRules`.

### Phase 2: Services Implementation
1. **AppRegistryService:** Scan `/Applications`, `/System/Applications`, and `~/Applications` for `.app` bundles; store bundle IDs and base names in a fast lookup set.
2. **ScannerEngine:** Implement concurrent scanning tasks using Swift `TaskGroup` to inspect Caches, Logs, Developer, and Application Remnant directories.
3. **DeletionService:** Implement safe deletion calling `FileManager.default.trashItem(at:resultingItemURL:)` and collect results.

### Phase 3: ViewModels & Concurrency
1. Build `AppState` and `DashboardViewModel` with `@Observable`.
2. Connect live `AsyncStream<ScanProgress>` to update the UI during scanning without dropping frames.
3. Expose methods for `startScan()`, `cancelScan()`, `toggleItem(id:)`, and `executeClean()`.

### Phase 4: SwiftUI Interface
1. Build `SidebarView` featuring storage gauges and category statuses.
2. Build `DashboardView` with modern scanning graphics and quick-start controls.
3. Build `CategoryDetailView` with an interactive `Table` or `LazyVStack` containing file checkboxes, sizes, and context menus.
4. Implement the clean confirmation modal and completion screen.

### Phase 5: Verification & Polish
1. Test with mocked junk files in temporary sandbox directories to verify deletion and space recalculation.
2. Ensure empty states, permission warnings (Full Disk Access), and smooth window resizing behaviors.