import Foundation
import AppKit

public struct DeletionResult: Sendable {
    public let itemsDeleted: Int
    public let bytesReclaimed: Int64
    public let errors: [String]
    public let isDryRun: Bool

    public init(itemsDeleted: Int, bytesReclaimed: Int64, errors: [String] = [], isDryRun: Bool = false) {
        self.itemsDeleted = itemsDeleted
        self.bytesReclaimed = bytesReclaimed
        self.errors = errors
        self.isDryRun = isDryRun
    }
}

public final class DeletionService: Sendable {
    public static let shared = DeletionService()

    private let fileManager = FileManager.default

    public init() {}

    /// Safely deletes or trashes an array of JunkItems
    public func delete(
        items: [JunkItem],
        permanent: Bool = false,
        dryRun: Bool = false,
        runningBundleIDs: Set<String> = [],
        runningAppNames: Set<String> = [],
        onItemDeleted: (@Sendable (JunkItem) -> Void)? = nil
    ) async -> DeletionResult {
        var itemsDeleted = 0
        var bytesReclaimed: Int64 = 0
        var errors: [String] = []

        for item in items {
            if Task.isCancelled { break }

            // Guard against safety violations
            guard FileSafetyRules.isSafeToDelete(item.path, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) else {
                errors.append("Blocked by safety rules: \(item.path.path)")
                continue
            }

            guard fileManager.fileExists(atPath: item.path.path) else {
                // Already removed
                continue
            }

            if dryRun {
                itemsDeleted += 1
                bytesReclaimed += item.size
                onItemDeleted?(item)
                continue
            }

            do {
                if permanent {
                    try fileManager.removeItem(at: item.path)
                } else {
                    var resultingURL: NSURL?
                    try fileManager.trashItem(at: item.path, resultingItemURL: &resultingURL)
                }

                itemsDeleted += 1
                bytesReclaimed += item.size
                onItemDeleted?(item)
            } catch {
                errors.append("Failed to delete \(item.name): \(error.localizedDescription)")
            }
        }

        return DeletionResult(
            itemsDeleted: itemsDeleted,
            bytesReclaimed: bytesReclaimed,
            errors: errors,
            isDryRun: dryRun
        )
    }
}
