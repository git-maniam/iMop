import Foundation
import AppKit

public final class ScannerEngine: Sendable {
    private let fileManager = FileManager.default
    private let appRegistry: AppRegistryService

    public init(appRegistry: AppRegistryService = .shared) {
        self.appRegistry = appRegistry
    }

    /// Recursively calculate folder size without crossing symlink boundaries
    public func calculateSize(at url: URL) -> Int64 {
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDir) else {
            return 0
        }

        // If it's a symlink, return 0 to prevent double-counting or escaping
        if FileSafetyRules.isSymlink(url) {
            return 0
        }

        if !isDir.boolValue {
            let values = try? url.resourceValues(forKeys: [.fileSizeKey])
            return Int64(values?.fileSize ?? 0)
        }

        var totalSize: Int64 = 0
        let resourceKeys: Set<URLResourceKey> = [.fileSizeKey, .isDirectoryKey, .isSymbolicLinkKey]

        if let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: Array(resourceKeys),
            options: [.skipsPackageDescendants]
        ) {
            for case let fileURL as URL in enumerator {
                if let values = try? fileURL.resourceValues(forKeys: resourceKeys) {
                    if values.isSymbolicLink == true {
                        continue
                    }
                    if values.isDirectory != true {
                        totalSize += Int64(values.fileSize ?? 0)
                    }
                }
            }
        }

        return totalSize
    }

    /// Performs a full scan across all categories, yielding progress events and returning the results
    public func scan(
        categories: Set<JunkCategoryType> = Set(JunkCategoryType.allCases),
        customHome: URL? = nil,
        runningBundleIDs: Set<String> = [],
        runningAppNames: Set<String> = [],
        onProgress: (@Sendable (ScanProgress) -> Void)? = nil
    ) async -> [JunkCategoryType: [JunkItem]] {
        let home = customHome ?? fileManager.homeDirectoryForCurrentUser

        // Pre-index applications
        appRegistry.indexInstalledApplications()

        var results: [JunkCategoryType: [JunkItem]] = [:]
        for cat in JunkCategoryType.allCases {
            results[cat] = []
        }

        for category in categories {
            if Task.isCancelled { break }

            var items: [JunkItem] = []
            switch category {
            case .appRemnants:
                items = await scanAppRemnants(
                    home: home,
                    runningBundleIDs: runningBundleIDs,
                    runningAppNames: runningAppNames,
                    onProgress: onProgress
                )
            case .userCaches:
                items = await scanUserCaches(
                    home: home,
                    runningBundleIDs: runningBundleIDs,
                    runningAppNames: runningAppNames,
                    onProgress: onProgress
                )
            case .systemLogs:
                items = await scanLogs(
                    home: home,
                    onProgress: onProgress
                )
            case .developer:
                items = await scanDeveloperJunk(
                    home: home,
                    onProgress: onProgress
                )
            case .trashAndTemp:
                items = await scanTrashAndTemp(
                    home: home,
                    onProgress: onProgress
                )
            }

            results[category] = items

            let totalBytes = items.reduce(0) { $0 + $1.size }
            onProgress?(ScanProgress(
                currentPath: "Completed \(category.rawValue)",
                category: category,
                itemsFound: items.count,
                bytesFound: totalBytes,
                isComplete: true
            ))
        }

        return results
    }

    // MARK: - Module 1: App Remnants
    private func scanAppRemnants(
        home: URL,
        runningBundleIDs: Set<String>,
        runningAppNames: Set<String>,
        onProgress: (@Sendable (ScanProgress) -> Void)?
    ) async -> [JunkItem] {
        var items: [JunkItem] = []
        var totalBytes: Int64 = 0

        let candidateDirs: [(URL, Bool)] = [
            (home.appendingPathComponent("Library/Application Support"), false),
            (home.appendingPathComponent("Library/Saved Application State"), false),
            (home.appendingPathComponent("Library/Containers"), false),
            (home.appendingPathComponent("Library/Preferences"), true) // true = file plists
        ]

        for (dir, isPlistDir) in candidateDirs {
            guard fileManager.fileExists(atPath: dir.path) else { continue }
            guard let contents = try? fileManager.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey, .isDirectoryKey], options: [.skipsHiddenFiles]) else {
                continue
            }

            for itemURL in contents {
                if Task.isCancelled { break }
                let itemName = itemURL.lastPathComponent

                // Skip if protected by allowlist / system rules
                if FileSafetyRules.isProtectedRemnantCandidate(name: itemName) {
                    continue
                }

                // If plist directory, strip .plist extension
                let lookupName = isPlistDir ? itemURL.deletingPathExtension().lastPathComponent : itemName

                // Check reverse-DNS pattern (e.g. contains at least one dot or known bundle prefix)
                let isLikelyBundleID = lookupName.contains(".") && !lookupName.hasPrefix(".")
                if !isLikelyBundleID && !isPlistDir && !dir.path.contains("Saved Application State") {
                    // For Application Support, only flag reverse-DNS named items to prevent false positives
                    continue
                }

                // Check running apps
                if FileSafetyRules.isRunningApplication(nameOrBundleID: lookupName, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) {
                    continue
                }

                // Check if the app is still installed
                if appRegistry.isAppInstalled(nameOrBundleID: lookupName) {
                    continue
                }

                // Path is safe to scan
                guard FileSafetyRules.isSafeToDelete(itemURL, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) else {
                    continue
                }

                let size = calculateSize(at: itemURL)
                guard size > 0 else { continue }

                let modDate = (try? itemURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()

                let junkItem = JunkItem(
                    name: itemName,
                    path: itemURL,
                    size: size,
                    lastModified: modDate,
                    category: .appRemnants,
                    isSelected: false, // Default unchecked per safety guidelines
                    detailHint: "Uninstalled application leftover"
                )

                items.append(junkItem)
                totalBytes += size

                onProgress?(ScanProgress(
                    currentPath: itemURL.path,
                    category: .appRemnants,
                    itemsFound: items.count,
                    bytesFound: totalBytes
                ))
            }
        }

        return items
    }

    // MARK: - Module 2: User Caches
    private func scanUserCaches(
        home: URL,
        runningBundleIDs: Set<String>,
        runningAppNames: Set<String>,
        onProgress: (@Sendable (ScanProgress) -> Void)?
    ) async -> [JunkItem] {
        var items: [JunkItem] = []
        var totalBytes: Int64 = 0

        let cacheDirs = [
            home.appendingPathComponent("Library/Caches")
        ]

        for dir in cacheDirs {
            guard fileManager.fileExists(atPath: dir.path) else { continue }
            guard let contents = try? fileManager.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey, .isDirectoryKey], options: [.skipsHiddenFiles]) else {
                continue
            }

            for itemURL in contents {
                if Task.isCancelled { break }
                let itemName = itemURL.lastPathComponent

                // Skip active running applications
                let bundleCheck = itemURL.deletingPathExtension().lastPathComponent
                if FileSafetyRules.isRunningApplication(nameOrBundleID: bundleCheck, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) {
                    continue
                }

                guard FileSafetyRules.isSafeToDelete(itemURL, runningBundleIDs: runningBundleIDs, runningAppNames: runningAppNames) else {
                    continue
                }

                let size = calculateSize(at: itemURL)
                guard size > 1024 else { continue } // Filter negligible items < 1KB

                let modDate = (try? itemURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()

                let junkItem = JunkItem(
                    name: itemName,
                    path: itemURL,
                    size: size,
                    lastModified: modDate,
                    category: .userCaches,
                    isSelected: true,
                    detailHint: "App Cache"
                )

                items.append(junkItem)
                totalBytes += size

                onProgress?(ScanProgress(
                    currentPath: itemURL.path,
                    category: .userCaches,
                    itemsFound: items.count,
                    bytesFound: totalBytes
                ))
            }
        }

        return items
    }

    // MARK: - Module 3: System & App Logs
    private func scanLogs(
        home: URL,
        onProgress: (@Sendable (ScanProgress) -> Void)?
    ) async -> [JunkItem] {
        var items: [JunkItem] = []
        var totalBytes: Int64 = 0

        let logDirs = [
            home.appendingPathComponent("Library/Logs"),
            home.appendingPathComponent("Library/Application Support/CrashReporter"),
            URL(fileURLWithPath: "/Library/Logs")
        ]

        let allowedExtensions: Set<String> = ["log", "asl", "diag", "crash", "spin", "ips", "hang"]

        for dir in logDirs {
            guard fileManager.fileExists(atPath: dir.path) else { continue }
            guard let contents = try? fileManager.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey, .isDirectoryKey], options: [.skipsHiddenFiles]) else {
                continue
            }

            for itemURL in contents {
                if Task.isCancelled { break }
                let ext = itemURL.pathExtension.lowercased()
                let isDir = (try? itemURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? false

                // Match log directory or matching file extensions
                if isDir || allowedExtensions.contains(ext) {
                    guard FileSafetyRules.isSafeToDelete(itemURL) else { continue }
                    let size = calculateSize(at: itemURL)
                    guard size > 0 else { continue }

                    let modDate = (try? itemURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()

                    let junkItem = JunkItem(
                        name: itemURL.lastPathComponent,
                        path: itemURL,
                        size: size,
                        lastModified: modDate,
                        category: .systemLogs,
                        isSelected: true,
                        detailHint: isDir ? "Log Folder" : "\(ext.uppercased()) File"
                    )

                    items.append(junkItem)
                    totalBytes += size

                    onProgress?(ScanProgress(
                        currentPath: itemURL.path,
                        category: .systemLogs,
                        itemsFound: items.count,
                        bytesFound: totalBytes
                    ))
                }
            }
        }

        return items
    }

    // MARK: - Module 4: Developer Junk
    private func scanDeveloperJunk(
        home: URL,
        onProgress: (@Sendable (ScanProgress) -> Void)?
    ) async -> [JunkItem] {
        var items: [JunkItem] = []
        var totalBytes: Int64 = 0

        let devTargets: [(name: String, path: URL, desc: String)] = [
            ("Xcode DerivedData", home.appendingPathComponent("Library/Developer/Xcode/DerivedData"), "Xcode build cache and indexes"),
            ("Xcode Archives", home.appendingPathComponent("Library/Developer/Xcode/Archives"), "Built application archive bundles"),
            ("Xcode iOS DeviceSupport", home.appendingPathComponent("Library/Developer/Xcode/iOS DeviceSupport"), "Debug symbol caches for older iOS versions"),
            ("CoreSimulator Caches", home.appendingPathComponent("Library/Developer/CoreSimulator/Caches"), "iOS simulator temp runtime caches"),
            ("Homebrew Cache", home.appendingPathComponent("Library/Caches/Homebrew"), "Downloaded bottle archives and source tarballs"),
            ("CocoaPods Cache", home.appendingPathComponent("Library/Caches/CocoaPods"), "Cached pod tarballs and git repos"),
            ("NPM Cache", home.appendingPathComponent(".npm"), "Node Package Manager download cache"),
            ("Yarn Cache", home.appendingPathComponent(".yarn/cache"), "Yarn package manager tarball cache"),
            ("pnpm Store", home.appendingPathComponent("Library/pnpm/store"), "pnpm global content-addressable store"),
            ("Cargo Registry Cache", home.appendingPathComponent(".cargo/registry/cache"), "Rust crate download cache"),
            ("Gradle Cache", home.appendingPathComponent(".gradle/caches"), "Gradle build dependencies cache")
        ]

        for target in devTargets {
            if Task.isCancelled { break }
            guard fileManager.fileExists(atPath: target.path.path) else { continue }
            guard FileSafetyRules.isSafeToDelete(target.path) else { continue }

            let size = calculateSize(at: target.path)
            guard size > 0 else { continue }

            let modDate = (try? target.path.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()

            let junkItem = JunkItem(
                name: target.name,
                path: target.path,
                size: size,
                lastModified: modDate,
                category: .developer,
                isSelected: false, // Default unchecked per safe defaults
                detailHint: target.desc
            )

            items.append(junkItem)
            totalBytes += size

            onProgress?(ScanProgress(
                currentPath: target.path.path,
                category: .developer,
                itemsFound: items.count,
                bytesFound: totalBytes
            ))
        }

        return items
    }

    // MARK: - Module 5: Trash & Temp Files
    private func scanTrashAndTemp(
        home: URL,
        onProgress: (@Sendable (ScanProgress) -> Void)?
    ) async -> [JunkItem] {
        var items: [JunkItem] = []
        var totalBytes: Int64 = 0

        // 1. User Trash
        let trashURL = home.appendingPathComponent(".Trash")
        if fileManager.fileExists(atPath: trashURL.path),
           let contents = try? fileManager.contentsOfDirectory(at: trashURL, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles]) {
            for itemURL in contents {
                if Task.isCancelled { break }
                guard FileSafetyRules.isSafeToDelete(itemURL) else { continue }

                let size = calculateSize(at: itemURL)
                guard size > 0 else { continue }

                let modDate = (try? itemURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()

                let junkItem = JunkItem(
                    name: itemURL.lastPathComponent,
                    path: itemURL,
                    size: size,
                    lastModified: modDate,
                    category: .trashAndTemp,
                    isSelected: true,
                    detailHint: "Trash item"
                )

                items.append(junkItem)
                totalBytes += size

                onProgress?(ScanProgress(
                    currentPath: itemURL.path,
                    category: .trashAndTemp,
                    itemsFound: items.count,
                    bytesFound: totalBytes
                ))
            }
        }

        // 2. Partial downloads in ~/Downloads
        let downloadsURL = home.appendingPathComponent("Downloads")
        let partialExts: Set<String> = ["crdownload", "download", "part"]
        if fileManager.fileExists(atPath: downloadsURL.path),
           let contents = try? fileManager.contentsOfDirectory(at: downloadsURL, includingPropertiesForKeys: [.contentModificationDateKey], options: []) {
            for itemURL in contents {
                if Task.isCancelled { break }
                let ext = itemURL.pathExtension.lowercased()
                if partialExts.contains(ext) {
                    guard FileSafetyRules.isSafeToDelete(itemURL) else { continue }
                    let size = calculateSize(at: itemURL)
                    guard size > 0 else { continue }

                    let modDate = (try? itemURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()

                    let junkItem = JunkItem(
                        name: itemURL.lastPathComponent,
                        path: itemURL,
                        size: size,
                        lastModified: modDate,
                        category: .trashAndTemp,
                        isSelected: true,
                        detailHint: "Incomplete download file"
                    )

                    items.append(junkItem)
                    totalBytes += size

                    onProgress?(ScanProgress(
                        currentPath: itemURL.path,
                        category: .trashAndTemp,
                        itemsFound: items.count,
                        bytesFound: totalBytes
                    ))
                }
            }
        }

        return items
    }
}
