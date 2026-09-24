import Foundation

public struct JunkItem: Identifiable, Hashable, Sendable {
    public let id: UUID
    public let name: String
    public let path: URL
    public let size: Int64
    public let lastModified: Date
    public let category: JunkCategoryType
    public var isSelected: Bool
    public var detailHint: String?

    public init(
        id: UUID = UUID(),
        name: String,
        path: URL,
        size: Int64,
        lastModified: Date,
        category: JunkCategoryType,
        isSelected: Bool? = nil,
        detailHint: String? = nil
    ) {
        self.id = id
        self.name = name
        self.path = path
        self.size = size
        self.lastModified = lastModified
        self.category = category
        // If not specified, adopt the category's recommended default
        self.isSelected = isSelected ?? category.recommendedByDefault
        self.detailHint = detailHint
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(path)
    }

    public static func == (lhs: JunkItem, rhs: JunkItem) -> Bool {
        lhs.id == rhs.id && lhs.path == rhs.path && lhs.isSelected == rhs.isSelected
    }
}
