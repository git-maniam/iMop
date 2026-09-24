import iMopCore
import SwiftUI

public struct SidebarView: View {
    @Environment(AppState.self) private var appState

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            // Header / App Branding
            HStack(spacing: 10) {
                appIconView

                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text("iMop")
                            .font(.system(size: 17, weight: .bold))
                            .foregroundStyle(.primary)

                        Text("v1.0")
                            .font(.system(size: 10, weight: .semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1.5)
                            .background(Color.blue.opacity(0.12))
                            .clipShape(Capsule())
                            .foregroundStyle(.blue)
                    }

                    Text("Smart macOS Storage Cleaner")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.top, 16)
            .padding(.bottom, 12)

            // Storage Gauge
            StorageGaugeView(usage: appState.diskUsage)
                .padding(.horizontal, 12)
                .padding(.bottom, 12)

            // Full Disk Access Notification Card (if not granted)
            if !appState.hasFullDiskAccess {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "lock.shield")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.orange)
                        Text("Full Disk Access")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.primary)
                    }

                    Text("Grant Full Disk Access to allow iMop to scan system logs and orphaned app containers.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    Button {
                        appState.openFullDiskAccessSettings()
                    } label: {
                        HStack(spacing: 4) {
                            Text("Open Settings")
                                .font(.system(size: 11, weight: .medium))
                            Image(systemName: "arrow.up.right")
                                .font(.system(size: 9))
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .padding(.top, 2)
                }
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.orange.opacity(0.08))
                        .overlay(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .stroke(Color.orange.opacity(0.2), lineWidth: 1)
                        )
                )
                .padding(.horizontal, 12)
                .padding(.bottom, 10)
            }

            Divider()
                .padding(.horizontal, 12)

            // Category Navigation List
            ScrollView {
                VStack(spacing: 4) {
                    // Dashboard Navigation Button
                    sidebarRow(
                        title: "Overview",
                        icon: "gauge.with.needle",
                        accentColor: .blue,
                        count: nil,
                        sizeString: nil,
                        isSelected: appState.selectedCategory == nil
                    ) {
                        appState.selectedCategory = nil
                    }

                    Divider()
                        .padding(.vertical, 4)

                    // Categories
                    ForEach(JunkCategoryType.allCases) { category in
                        let count = appState.items(for: category).count
                        let totalSize = appState.totalBytes(for: category)
                        let sizeString = count > 0 ? ByteFormatter.format(totalSize) : nil

                        sidebarRow(
                            title: category.rawValue,
                            icon: category.iconName,
                            accentColor: color(for: category),
                            count: count > 0 ? count : nil,
                            sizeString: sizeString,
                            isSelected: appState.selectedCategory == category
                        ) {
                            appState.selectedCategory = category
                        }
                    }
                }
                .padding(8)
            }

            Divider()
                .padding(.horizontal, 12)

            // Bottom Settings / Options bar
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Toggle("Dry Run Mode", isOn: Binding(
                        get: { appState.isDryRunEnabled },
                        set: { appState.isDryRunEnabled = $0 }
                    ))
                    .toggleStyle(.switch)
                    .controlSize(.mini)

                    Spacer()

                    if appState.isDryRunEnabled {
                        Text("Simulation")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.purple)
                    }
                }

                HStack {
                    Toggle("Permanent Delete", isOn: Binding(
                        get: { appState.isPermanentDeleteEnabled },
                        set: { appState.isPermanentDeleteEnabled = $0 }
                    ))
                    .toggleStyle(.switch)
                    .controlSize(.mini)

                    Spacer()

                    Text(appState.isPermanentDeleteEnabled ? "Skip Trash" : "Move to Trash")
                        .font(.system(size: 10))
                        .foregroundStyle(appState.isPermanentDeleteEnabled ? .red : .secondary)
                }
            }
            .padding(12)
        }
        .frame(minWidth: 240, idealWidth: 260, maxWidth: 300)
        .background(.ultraThinMaterial)
    }

    private func color(for category: JunkCategoryType) -> Color {
        switch category {
        case .appRemnants: return .orange
        case .userCaches: return .blue
        case .systemLogs: return .indigo
        case .developer: return .cyan
        case .trashAndTemp: return .pink
        }
    }

    @ViewBuilder
    private func sidebarRow(
        title: String,
        icon: String,
        accentColor: Color,
        count: Int?,
        sizeString: String?,
        isSelected: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(isSelected ? .white : accentColor)
                    .frame(width: 20)

                Text(title)
                    .font(.system(size: 13, weight: isSelected ? .semibold : .regular))
                    .foregroundStyle(isSelected ? .white : .primary)

                Spacer()

                if let size = sizeString {
                    Text(size)
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .foregroundStyle(isSelected ? .white.opacity(0.85) : .secondary)
                }

                if let count = count {
                    Text("\(count)")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(isSelected ? Color.white.opacity(0.2) : Color.primary.opacity(0.08))
                        .clipShape(Capsule())
                        .foregroundStyle(isSelected ? .white : .secondary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(isSelected ? Color.blue : Color.clear)
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - App Icon View
    private var appIconView: some View {
        Group {
            if let iconUrl = Bundle.main.url(forResource: "AppIcon_UI", withExtension: "png") ??
                             Bundle.module.url(forResource: "AppIcon_UI", withExtension: "png"),
               let nsImage = NSImage(contentsOf: iconUrl) {
                Image(nsImage: nsImage)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 34, height: 34)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .shadow(color: Color.blue.opacity(0.3), radius: 4, x: 0, y: 2)
            } else {
                ZStack {
                    LinearGradient(
                        colors: [Color.blue, Color.cyan],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                    .frame(width: 34, height: 34)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .shadow(color: Color.blue.opacity(0.3), radius: 4, x: 0, y: 2)

                    Image(systemName: "sparkles")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(.white)
                }
            }
        }
    }
}
