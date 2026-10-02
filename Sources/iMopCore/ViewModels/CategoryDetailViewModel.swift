import Foundation
import Observation

/// Sort orders of the category list (spec §9.2).
public enum SortOption: String, CaseIterable, Identifiable, Sendable {
    case sizeDescending = "Size (Largest)"
    case sizeAscending = "Size (Smallest)"
    case nameAscending = "Name (A-Z)"
    case dateDescending = "Recently Used"

    public var id: String { rawValue }
}

/// Search and sort state of one category list. Pure presentation: it only filters and orders the
/// `PlanItem`s AppState provides and never changes the plan or the selection.
@MainActor
@Observable
public final class CategoryDetailViewModel {
    public var searchText: String = ""
    public var sortOption: SortOption = .sizeDescending

    public init() {}

    public func filteredAndSortedItems(from items: [PlanItem]) -> [PlanItem] {
        Self.filterAndSort(items, query: searchText, sort: sortOption)
    }

    /// Matches the query (case- and diacritic-insensitive) against the item's name, full path, rule
    /// title, owning app and notes; then sorts. Ties are broken by path so the order is stable.
    public nonisolated static func filterAndSort(_ items: [PlanItem], query: String, sort: SortOption) -> [PlanItem] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        var result = items
        if !trimmed.isEmpty {
            result = result.filter { item in
                let fields = [item.target.displayName, item.target.path, item.rule.title,
                              item.target.owningBundleID ?? ""] + item.target.notes
                return fields.contains { $0.range(of: trimmed, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
            }
        }
        result.sort { lhs, rhs in
            switch sort {
            case .sizeDescending:
                if lhs.target.reclaimableBytes != rhs.target.reclaimableBytes {
                    return lhs.target.reclaimableBytes > rhs.target.reclaimableBytes
                }
            case .sizeAscending:
                if lhs.target.reclaimableBytes != rhs.target.reclaimableBytes {
                    return lhs.target.reclaimableBytes < rhs.target.reclaimableBytes
                }
            case .nameAscending:
                let order = lhs.target.displayName.localizedCaseInsensitiveCompare(rhs.target.displayName)
                if order != .orderedSame { return order == .orderedAscending }
            case .dateDescending:
                // Items with no known last use sort last.
                switch (lhs.target.lastUsed, rhs.target.lastUsed) {
                case let (l?, r?) where l != r: return l > r
                case (.some, .none): return true
                case (.none, .some): return false
                default: break
                }
            }
            return lhs.target.path < rhs.target.path
        }
        return result
    }
}
