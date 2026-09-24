import Foundation

public struct ScanProgress: Sendable {
    public let currentPath: String
    public let category: JunkCategoryType
    public let itemsFound: Int
    public let bytesFound: Int64
    public let isComplete: Bool

    public init(
        currentPath: String,
        category: JunkCategoryType,
        itemsFound: Int,
        bytesFound: Int64,
        isComplete: Bool = false
    ) {
        self.currentPath = currentPath
        self.category = category
        self.itemsFound = itemsFound
        self.bytesFound = bytesFound
        self.isComplete = isComplete
    }
}
