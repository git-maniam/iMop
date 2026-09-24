import Foundation
import SwiftUI
import Observation

public enum SortOption: String, CaseIterable, Identifiable {
    case sizeDescending = "Size (Largest)"
    case sizeAscending = "Size (Smallest)"
    case nameAscending = "Name (A-Z)"
    case dateDescending = "Recently Modified"

    public var id: String { rawValue }
}

@Observable
public final class CategoryDetailViewModel {
    public var searchText: String = ""
    public var sortOption: SortOption = .sizeDescending

    public init() {}

    public func filteredAndSortedItems(from items: [JunkItem]) -> [JunkItem] {
        var result = items

        if !searchText.trimmingCharacters(in: .whitespaces).isEmpty {
            let query = searchText.lowercased()
            result = result.filter {
                $0.name.lowercased().contains(query) ||
                $0.path.path.lowercased().contains(query) ||
                ($0.detailHint?.lowercased().contains(query) ?? false)
            }
        }

        switch sortOption {
        case .sizeDescending:
            result.sort { $0.size > $1.size }
        case .sizeAscending:
            result.sort { $0.size < $1.size }
        case .nameAscending:
            result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .dateDescending:
            result.sort { $0.lastModified > $1.lastModified }
        }

        return result
    }
}
