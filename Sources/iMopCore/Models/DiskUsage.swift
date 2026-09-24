import Foundation

public struct DiskUsage: Sendable, Equatable {
    public let totalBytes: Int64
    public let freeBytes: Int64
    public let usedBytes: Int64
    public var recoverableBytes: Int64

    public init(
        totalBytes: Int64 = 0,
        freeBytes: Int64 = 0,
        usedBytes: Int64 = 0,
        recoverableBytes: Int64 = 0
    ) {
        self.totalBytes = totalBytes
        self.freeBytes = freeBytes
        self.usedBytes = usedBytes
        self.recoverableBytes = recoverableBytes
    }

    public var usedPercentage: Double {
        guard totalBytes > 0 else { return 0 }
        return Double(usedBytes) / Double(totalBytes)
    }

    public var freePercentage: Double {
        guard totalBytes > 0 else { return 0 }
        return Double(freeBytes) / Double(totalBytes)
    }

    public var recoverablePercentage: Double {
        guard totalBytes > 0 else { return 0 }
        return Double(recoverableBytes) / Double(totalBytes)
    }
}
