import iMopCore
import SwiftUI

public struct CategoryDetailView: View {
    public let category: JunkCategoryType
    @Environment(AppState.self) private var appState
    @LocalState private var viewModel = CategoryDetailViewModel()

    public init(category: JunkCategoryType) {
        self.category = category
    }

    private var categoryColor: Color {
        switch category {
        case .appRemnants: return .orange
        case .userCaches: return .blue
        case .systemLogs: return .indigo
        case .developer: return .cyan
        case .trashAndTemp: return .pink
        }
    }

    public var body: some View {
        let allItems = appState.items(for: category)
        let displayItems = viewModel.filteredAndSortedItems(from: allItems)
        let totalSize = appState.totalBytes(for: category)
        let selectedSize = appState.selectedBytes(for: category)

        VStack(spacing: 0) {
            // Category Header
            VStack(spacing: 14) {
                HStack(alignment: .center, spacing: 14) {
                    Button {
                        appState.selectedCategory = nil
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.left")
                                .font(.system(size: 13, weight: .semibold))
                            Text("Overview")
                                .font(.system(size: 13))
                        }
                    }
                    .buttonStyle(.borderless)

                    Spacer()
                }

                HStack(alignment: .top, spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(categoryColor.opacity(0.18))
                            .frame(width: 48, height: 48)

                        Image(systemName: category.iconName)
                            .font(.system(size: 24, weight: .semibold))
                            .foregroundStyle(categoryColor)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text(category.rawValue)
                            .font(.system(size: 22, weight: .bold))
                            .foregroundStyle(.primary)

                        Text(category.subtitle)
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    VStack(alignment: .trailing, spacing: 4) {
                        Text(ByteFormatter.format(totalSize))
                            .font(.system(size: 22, weight: .bold, design: .rounded))
                            .foregroundStyle(.primary)

                        Text("\(allItems.count) total items (\(ByteFormatter.format(selectedSize)) selected)")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(20)
            .background(.ultraThinMaterial)

            Divider()

            // Filter & Control Bar
            HStack(spacing: 12) {
                // Search Field
                HStack {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)

                    TextField("Search items or paths...", text: $viewModel.searchText)
                        .textFieldStyle(.plain)
                        .font(.system(size: 12))

                    if !viewModel.searchText.isEmpty {
                        Button {
                            viewModel.searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 12))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(Color.primary.opacity(0.05))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                .frame(maxWidth: 260)

                Spacer()

                // Sort Menu
                Picker("Sort", selection: $viewModel.sortOption) {
                    ForEach(SortOption.allCases) { option in
                        Text(option.rawValue).tag(option)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 170)

                // Select / Deselect All
                Button("Select All") {
                    appState.selectAll(for: category)
                }
                .buttonStyle(.borderless)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.blue)

                Text("•")
                    .foregroundStyle(.secondary)

                Button("Deselect All") {
                    appState.deselectAll(for: category)
                }
                .buttonStyle(.borderless)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            .background(Color.primary.opacity(0.02))

            Divider()

            // Item List
            if displayItems.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: allItems.isEmpty ? "sparkles" : "line.3.horizontal.decrease.circle")
                        .font(.system(size: 38))
                        .foregroundStyle(.tertiary)

                    Text(allItems.isEmpty ? "No items found in this category" : "No items match your search")
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(.secondary)

                    if allItems.isEmpty {
                        Text("This category is completely clean.")
                            .font(.system(size: 12))
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 4) {
                        ForEach(displayItems) { item in
                            FileItemRowView(
                                item: item,
                                onToggle: {
                                    appState.toggleItem(id: item.id)
                                },
                                onExclude: {
                                    appState.excludeItem(path: item.path)
                                }
                            )
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                }
            }
        }
    }
}
