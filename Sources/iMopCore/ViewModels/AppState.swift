import Foundation
import SwiftUI
import Observation
import AppKit

public enum ScanStatus: Equatable, Sendable {
    case idle
    case scanning
    case scanned
    case cleaning
    case completed
}

@Observable
public final class AppState: @unchecked Sendable {
    // Current application state
    public var scanStatus: ScanStatus = .idle
    public var itemsByCategory: [JunkCategoryType: [JunkItem]] = [:]
    public var selectedCategory: JunkCategoryType? = nil // nil = Dashboard
    public var diskUsage: DiskUsage = DiskUsage()
    public var currentProgress: ScanProgress? = nil

    // Preferences & Safety
    public var hasFullDiskAccess: Bool = false
    public var isPermanentDeleteEnabled: Bool = false
    public var isDryRunEnabled: Bool = false
    public var excludedPaths: Set<String> = []

    // Modals & sheets
    public var showConfirmationModal: Bool = false
    public var showCompletionModal: Bool = false
    public var lastDeletionResult: DeletionResult? = nil

    // Services
    private let scannerEngine: ScannerEngine
    private let deletionService: DeletionService
    private let healthService: SystemHealthService
    private let permissionService: PermissionService
    private let appRegistry: AppRegistryService

    // Active Task tracking
    private var activeScanTask: Task<Void, Never>? = nil
    private var activeCleanTask: Task<Void, Never>? = nil

    @MainActor
    public init(
        scannerEngine: ScannerEngine = ScannerEngine(),
        deletionService: DeletionService = .shared,
        healthService: SystemHealthService = .shared,
        permissionService: PermissionService = .shared,
        appRegistry: AppRegistryService = .shared
    ) {
        self.scannerEngine = scannerEngine
        self.deletionService = deletionService
        self.healthService = healthService
        self.permissionService = permissionService
        self.appRegistry = appRegistry

        // Initialize empty categories
        for cat in JunkCategoryType.allCases {
            itemsByCategory[cat] = []
        }

        refreshPermissions()
        refreshDiskUsage()
    }

    // MARK: - Computed Statistics
    public var totalFoundBytes: Int64 {
        itemsByCategory.values.flatMap { $0 }.reduce(0) { $0 + $1.size }
    }

    public var totalFoundCount: Int {
        itemsByCategory.values.flatMap { $0 }.count
    }

    public var totalSelectedBytes: Int64 {
        itemsByCategory.values.flatMap { $0 }
            .filter { $0.isSelected }
            .reduce(0) { $0 + $1.size }
    }

    public var totalSelectedCount: Int {
        itemsByCategory.values.flatMap { $0 }
            .filter { $0.isSelected }
            .count
    }

    public func items(for category: JunkCategoryType) -> [JunkItem] {
        itemsByCategory[category] ?? []
    }

    public func totalBytes(for category: JunkCategoryType) -> Int64 {
        items(for: category).reduce(0) { $0 + $1.size }
    }

    public func selectedBytes(for category: JunkCategoryType) -> Int64 {
        items(for: category).filter { $0.isSelected }.reduce(0) { $0 + $1.size }
    }

    public func selectedCount(for category: JunkCategoryType) -> Int {
        items(for: category).filter { $0.isSelected }.count
    }

    // MARK: - Permissions & Health
    @MainActor
    public func refreshPermissions() {
        hasFullDiskAccess = permissionService.hasFullDiskAccess()
    }

    @MainActor
    public func openFullDiskAccessSettings() {
        permissionService.openSystemSettingsFullDiskAccess()
    }

    @MainActor
    public func refreshDiskUsage() {
        diskUsage = healthService.getDiskUsage(recoverableBytes: totalSelectedBytes)
    }

    // MARK: - Scanning
    @MainActor
    public func startScan() {
        guard scanStatus != .scanning && scanStatus != .cleaning else { return }

        activeScanTask?.cancel()
        scanStatus = .scanning
        currentProgress = nil

        let runningIDs = appRegistry.getRunningApplicationBundleIDs()
        let runningNames = appRegistry.getRunningApplicationNames()

        activeScanTask = Task { [weak self] in
            guard let self = self else { return }

            let results = await self.scannerEngine.scan(
                runningBundleIDs: runningIDs,
                runningAppNames: runningNames
            ) { progress in
                Task { @MainActor in
                    self.currentProgress = progress
                }
            }

            await MainActor.run {
                // Filter out excluded paths
                var filteredResults: [JunkCategoryType: [JunkItem]] = [:]
                for (cat, list) in results {
                    filteredResults[cat] = list.filter { !self.excludedPaths.contains($0.path.path) }
                }

                self.itemsByCategory = filteredResults
                self.scanStatus = .scanned
                self.currentProgress = nil
                self.refreshDiskUsage()
            }
        }
    }

    @MainActor
    public func cancelScan() {
        activeScanTask?.cancel()
        activeScanTask = nil
        scanStatus = itemsByCategory.values.contains(where: { !$0.isEmpty }) ? .scanned : .idle
        currentProgress = nil
    }

    // MARK: - Selection Management
    @MainActor
    public func toggleItem(id: UUID) {
        for (category, items) in itemsByCategory {
            if let index = items.firstIndex(where: { $0.id == id }) {
                itemsByCategory[category]?[index].isSelected.toggle()
                refreshDiskUsage()
                break
            }
        }
    }

    @MainActor
    public func selectAll(for category: JunkCategoryType) {
        guard var items = itemsByCategory[category] else { return }
        for i in 0..<items.count {
            items[i].isSelected = true
        }
        itemsByCategory[category] = items
        refreshDiskUsage()
    }

    @MainActor
    public func deselectAll(for category: JunkCategoryType) {
        guard var items = itemsByCategory[category] else { return }
        for i in 0..<items.count {
            items[i].isSelected = false
        }
        itemsByCategory[category] = items
        refreshDiskUsage()
    }

    @MainActor
    public func selectAllGlobal() {
        for cat in JunkCategoryType.allCases {
            selectAll(for: cat)
        }
    }

    @MainActor
    public func deselectAllGlobal() {
        for cat in JunkCategoryType.allCases {
            deselectAll(for: cat)
        }
    }

    @MainActor
    public func excludeItem(path: URL) {
        excludedPaths.insert(path.path)
        for cat in JunkCategoryType.allCases {
            itemsByCategory[cat]?.removeAll(where: { $0.path == path })
        }
        refreshDiskUsage()
    }

    // MARK: - Cleaning / Deletion
    @MainActor
    public func requestCleaning() {
        guard totalSelectedCount > 0 else { return }
        showConfirmationModal = true
    }

    @MainActor
    public func confirmAndExecuteCleaning() {
        showConfirmationModal = false
        guard totalSelectedCount > 0 else { return }

        scanStatus = .cleaning

        let selectedItems = itemsByCategory.values.flatMap { $0 }.filter { $0.isSelected }
        let runningIDs = appRegistry.getRunningApplicationBundleIDs()
        let runningNames = appRegistry.getRunningApplicationNames()
        let isPermanent = isPermanentDeleteEnabled
        let isDryRun = isDryRunEnabled

        activeCleanTask?.cancel()
        activeCleanTask = Task { [weak self] in
            guard let self = self else { return }

            let result = await self.deletionService.delete(
                items: selectedItems,
                permanent: isPermanent,
                dryRun: isDryRun,
                runningBundleIDs: runningIDs,
                runningAppNames: runningNames
            )

            await MainActor.run {
                self.lastDeletionResult = result

                // Remove successfully cleaned items from memory
                let cleanedPaths = Set(selectedItems.map { $0.path })
                for cat in JunkCategoryType.allCases {
                    self.itemsByCategory[cat]?.removeAll(where: { cleanedPaths.contains($0.path) })
                }

                self.scanStatus = .completed
                self.showCompletionModal = true
                self.refreshDiskUsage()
            }
        }
    }

    @MainActor
    public func dismissCompletionModal() {
        showCompletionModal = false
        if totalFoundCount == 0 {
            scanStatus = .idle
        } else {
            scanStatus = .scanned
        }
    }
}
