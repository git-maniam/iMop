import iMopCore
import SwiftUI

public struct DashboardView: View {
    @Environment(AppState.self) private var appState
    @LocalState private var isPulsing: Bool = false

    public init() {}

    private let columns = [
        GridItem(.adaptive(minimum: 220, maximum: 300), spacing: 16)
    ]

    public var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header Hero Area
                heroArea

                // Category Grid or Detailed Overview
                if appState.scanStatus == .scanned || appState.scanStatus == .completed {
                    categoryGridSection
                } else if appState.scanStatus == .idle {
                    welcomeFeatureCards
                }
            }
            .padding(24)
        }
    }

    // MARK: - Hero Area
    @ViewBuilder
    private var heroArea: some View {
        VStack(spacing: 18) {
            switch appState.scanStatus {
            case .idle:
                scanTriggerButton(title: "Scan System", subtitle: "Inspect caches, logs, developer junk, and app leftovers")

            case .scanning:
                scanningActiveView

            case .scanned:
                scannedSummaryBanner

            case .cleaning:
                cleaningActiveView

            case .completed:
                completedBanner
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .padding(.horizontal, 20)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                )
        )
    }

    // MARK: - Big Scan Button
    private func scanTriggerButton(title: String, subtitle: String) -> some View {
        VStack(spacing: 16) {
            Button {
                appState.startScan()
            } label: {
                ZStack {
                    // Outer pulse glow
                    Circle()
                        .fill(
                            RadialGradient(
                                colors: [Color.blue.opacity(0.35), Color.blue.opacity(0.0)],
                                center: .center,
                                startRadius: 40,
                                endRadius: 80
                            )
                        )
                        .frame(width: 140, height: 140)
                        .scaleEffect(isPulsing ? 1.15 : 0.95)
                        .opacity(isPulsing ? 0.8 : 0.4)
                        .animation(
                            .easeInOut(duration: 1.8).repeatForever(autoreverses: true),
                            value: isPulsing
                        )

                    // Main circular button
                    Circle()
                        .fill(
                            LinearGradient(
                                colors: [Color.blue, Color.cyan],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 96, height: 96)
                        .shadow(color: Color.blue.opacity(0.4), radius: 10, x: 0, y: 5)

                    VStack(spacing: 4) {
                        Image(systemName: "sparkle.magnifyingglass")
                            .font(.system(size: 30, weight: .bold))
                            .foregroundStyle(.white)
                    }
                }
            }
            .buttonStyle(.plain)
            .onAppear {
                isPulsing = true
            }

            VStack(spacing: 4) {
                Text(title)
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(.primary)

                Text(subtitle)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
    }

    // MARK: - Active Scanning Animation
    private var scanningActiveView: some View {
        VStack(spacing: 16) {
            ZStack {
                Circle()
                    .stroke(Color.primary.opacity(0.1), lineWidth: 6)
                    .frame(width: 90, height: 90)

                Circle()
                    .trim(from: 0, to: 0.7)
                    .stroke(
                        AngularGradient(
                            colors: [Color.blue, Color.cyan, Color.blue],
                            center: .center
                        ),
                        style: StrokeStyle(lineWidth: 6, lineCap: .round)
                    )
                    .frame(width: 90, height: 90)
                    .rotationEffect(.degrees(isPulsing ? 360 : 0))
                    .animation(
                        .linear(duration: 1.2).repeatForever(autoreverses: false),
                        value: isPulsing
                    )

                Image(systemName: "sparkles")
                    .font(.system(size: 26, weight: .semibold))
                    .foregroundStyle(.blue)
            }
            .onAppear { isPulsing = true }

            VStack(spacing: 6) {
                Text("Analyzing Your Mac...")
                    .font(.system(size: 18, weight: .bold))

                if let progress = appState.currentProgress {
                    HStack(spacing: 6) {
                        Image(systemName: progress.category.iconName)
                            .font(.system(size: 12))
                            .foregroundStyle(.blue)
                        Text(progress.category.rawValue)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(.primary)
                    }

                    Text(progress.currentPath)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: 400)
                } else {
                    Text("Scanning user directories and system caches")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                Button("Cancel Scan") {
                    appState.cancelScan()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .padding(.top, 4)
            }
        }
    }

    // MARK: - Scanned Summary
    private var scannedSummaryBanner: some View {
        HStack(spacing: 32) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(.green)
                    Text("Scan Complete")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.secondary)
                }

                let split = ByteFormatter.splitFormat(appState.totalSelectedBytes)
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text(split.value)
                        .font(.system(size: 38, weight: .heavy, design: .rounded))
                        .foregroundStyle(.primary)
                    Text(split.unit)
                        .font(.system(size: 20, weight: .bold, design: .rounded))
                        .foregroundStyle(.secondary)
                    Text("selected to clean")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 4)
                }

                Text("\(appState.totalSelectedCount) of \(appState.totalFoundCount) items selected across 5 categories")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(spacing: 10) {
                Button {
                    appState.requestCleaning()
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "wand.and.stars")
                            .font(.system(size: 14, weight: .bold))
                        Text(appState.isDryRunEnabled ? "Simulate Cleaning" : "Clean Now")
                            .font(.system(size: 14, weight: .semibold))
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(.blue)
                .controlSize(.large)
                .disabled(appState.totalSelectedCount == 0)

                Button("Rescan") {
                    appState.startScan()
                }
                .buttonStyle(.borderless)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Cleaning Active View
    private var cleaningActiveView: some View {
        VStack(spacing: 12) {
            ProgressView()
                .scaleEffect(1.3)
                .padding(.bottom, 6)

            Text(appState.isDryRunEnabled ? "Simulating Cleaning..." : "Cleaning Selected Files...")
                .font(.system(size: 18, weight: .bold))

            Text("Safely moving unneeded files to the macOS Trash")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Completed Banner
    private var completedBanner: some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 38))
                .foregroundStyle(.green)

            if let result = appState.lastDeletionResult {
                Text(result.isDryRun ? "Simulation Finished" : "Cleaning Successful!")
                    .font(.system(size: 20, weight: .bold))

                Text("Safely reclaimed \(ByteFormatter.format(result.bytesReclaimed)) from \(result.itemsDeleted) items.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            Button("Scan Again") {
                appState.startScan()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.regular)
            .padding(.top, 4)
        }
    }

    // MARK: - Category Grid
    private var categoryGridSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Categories")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(.primary)

                Spacer()

                Button("Select All") {
                    appState.selectAllGlobal()
                }
                .buttonStyle(.borderless)
                .font(.system(size: 12))
                .foregroundStyle(.blue)

                Text("•")
                    .foregroundStyle(.secondary)

                Button("Deselect All") {
                    appState.deselectAllGlobal()
                }
                .buttonStyle(.borderless)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            }

            LazyVGrid(columns: columns, spacing: 16) {
                ForEach(JunkCategoryType.allCases) { category in
                    let items = appState.items(for: category)
                    let totalSize = appState.totalBytes(for: category)
                    let selectedSize = appState.selectedBytes(for: category)
                    let isAllSelected = !items.isEmpty && items.allSatisfy { $0.isSelected }

                    CategoryCardView(
                        category: category,
                        itemsCount: items.count,
                        totalBytes: totalSize,
                        selectedBytes: selectedSize,
                        isSelected: isAllSelected,
                        onSelectCategory: {
                            appState.selectedCategory = category
                        },
                        onToggleAll: {
                            if isAllSelected {
                                appState.deselectAll(for: category)
                            } else {
                                appState.selectAll(for: category)
                            }
                        }
                    )
                }
            }
        }
    }

    // MARK: - Welcome Cards (Idle State)
    private var welcomeFeatureCards: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("What iMop Cleans")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(.primary)

            LazyVGrid(columns: columns, spacing: 16) {
                ForEach(JunkCategoryType.allCases) { category in
                    CategoryCardView(
                        category: category,
                        itemsCount: 0,
                        totalBytes: 0,
                        selectedBytes: 0,
                        isSelected: false,
                        onSelectCategory: {
                            appState.selectedCategory = category
                        },
                        onToggleAll: {}
                    )
                }
            }
        }
    }
}
