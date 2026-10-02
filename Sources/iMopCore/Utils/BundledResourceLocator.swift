import Foundation

/// Finds a file shipped in the app bundle or a SwiftPM resource bundle WITHOUT the SwiftPM-generated
/// `Bundle.module` accessor.
///
/// SAFETY-DECISION: (Milestone 8) `Bundle.module` calls `fatalError` when its bundle is not at
/// `Bundle.main.bundleURL/<name>.bundle` (the .app ROOT). Content at the .app root is unsealed for
/// `codesign`, so the signed, notarized app keeps resource bundles only in Contents/Resources and no
/// code path may use `Bundle.module` (a static test enforces this). Absence is reported as `nil`;
/// callers degrade (placeholder icon, empty catalog) and never crash.
public enum BundledResourceLocator {
    /// Candidate URLs for `name.ext`, most specific first:
    /// 1. the main bundle's own resources (`Contents/Resources/name.ext` in the packaged app),
    /// 2. inside `<resourceBundleName>` in Contents/Resources (packaged app),
    /// 3. inside `<resourceBundleName>` at the main bundle URL / next to the executable (`swift run`
    ///    from the build directory, where SwiftPM puts the resource bundle beside the binary).
    /// Each resource bundle is probed in both the macOS layout (`Contents/Resources/`) and the flat layout.
    public static func candidateURLs(forResource name: String, withExtension ext: String,
                                     resourceBundleName: String, mainBundle: Bundle = .main) -> [URL] {
        let fileName = ext.isEmpty ? name : name + "." + ext
        var urls: [URL] = []
        if let direct = mainBundle.url(forResource: name, withExtension: ext) {
            urls.append(direct)
        }
        if let resources = mainBundle.resourceURL {
            urls.append(resources.appendingPathComponent(fileName))
        }

        var bundleDirs: [URL] = []
        if let resources = mainBundle.resourceURL {
            bundleDirs.append(resources.appendingPathComponent(resourceBundleName, isDirectory: true))
        }
        bundleDirs.append(mainBundle.bundleURL.appendingPathComponent(resourceBundleName, isDirectory: true))
        if let executable = mainBundle.executableURL {
            bundleDirs.append(executable.deletingLastPathComponent()
                .appendingPathComponent(resourceBundleName, isDirectory: true))
        }
        for dir in bundleDirs {
            urls.append(dir.appendingPathComponent("Contents/Resources/" + fileName))
            urls.append(dir.appendingPathComponent(fileName))
        }

        var seen = Set<String>()
        return urls.filter { seen.insert($0.standardizedFileURL.path).inserted }
    }

    /// The first candidate that is a readable regular file, or `nil` (never traps).
    public static func url(forResource name: String, withExtension ext: String,
                           resourceBundleName: String, mainBundle: Bundle = .main) -> URL? {
        let fm = FileManager.default
        for url in candidateURLs(forResource: name, withExtension: ext,
                                 resourceBundleName: resourceBundleName, mainBundle: mainBundle) {
            var isDirectory: ObjCBool = false
            if fm.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue,
               fm.isReadableFile(atPath: url.path) {
                return url
            }
        }
        return nil
    }
}
