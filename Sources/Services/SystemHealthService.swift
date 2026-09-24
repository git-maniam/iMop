import Foundation

public final class SystemHealthService: Sendable {
    public static let shared = SystemHealthService()

    private init() {}

    /// Retrieves current storage metrics for the main boot volume
    public func getDiskUsage(recoverableBytes: Int64 = 0) -> DiskUsage {
        let rootURL = URL(fileURLWithPath: "/")
        do {
            let values = try rootURL.resourceValues(forKeys: [
                .volumeTotalCapacityKey,
                .volumeAvailableCapacityKey,
                .volumeAvailableCapacityForImportantUsageKey
            ])
            let total = Int64(values.volumeTotalCapacity ?? 0)
            let free = values.volumeAvailableCapacityForImportantUsage ?? Int64(values.volumeAvailableCapacity ?? 0)
            let used = max(0, total - free)

            return DiskUsage(
                totalBytes: total,
                freeBytes: free,
                usedBytes: used,
                recoverableBytes: recoverableBytes
            )
        } catch {
            return DiskUsage()
        }
    }
}
