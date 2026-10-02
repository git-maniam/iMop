import Foundation
import iMopCore

/// Milestone 8 (distribution): the signed app keeps SwiftPM resource bundles ONLY in
/// Contents/Resources, so nothing may use the SwiftPM-generated `Bundle.module` accessor (it calls
/// `fatalError` when its bundle is not at the .app root). Static check over Sources/ plus behaviour
/// tests for `BundledResourceLocator`, the replacement lookup.
@MainActor
enum BundleResourceTests {
    /// `Bundle.module`, `Bundle . module`, or the shorthand `.module` where a Bundle is expected
    /// (`: Bundle = .module`, `bundle: .module`), and the generated accessor's internal symbols.
    static let forbiddenPatterns: [(String, NSRegularExpression)] = [
        ("Bundle.module", try! NSRegularExpression(pattern: #"\bBundle\s*\.\s*module\b"#)),
        ("Bundle = .module", try! NSRegularExpression(pattern: #"\bBundle\??\s*=\s*\.module\b"#)),
        ("bundle: .module", try! NSRegularExpression(pattern: #"\bbundle\s*:\s*\.module\b"#, options: [.caseInsensitive])),
        ("resource_bundle_accessor", try! NSRegularExpression(pattern: #"resource_bundle_accessor|SWIFTPM_MODULE_BUNDLE"#)),
    ]

    /// `text` with `//` and (nested) `/* */` comments replaced by spaces; string literals are kept
    /// (so a `//` inside a string is not taken for a comment). Newlines are preserved, so line numbers
    /// still match the source.
    static func strippingComments(_ text: String) -> String {
        let chars = Array(text)
        var out: [Character] = []
        out.reserveCapacity(chars.count)
        var i = 0
        var blockDepth = 0
        var inLineComment = false
        var inString = false
        var multilineString = false
        func at(_ k: Int) -> Character? { k < chars.count ? chars[k] : nil }
        while i < chars.count {
            let c = chars[i]
            if inLineComment {
                if c == "\n" { inLineComment = false; out.append(c) } else { out.append(" ") }
                i += 1
            } else if blockDepth > 0 {
                if c == "/" && at(i + 1) == "*" { blockDepth += 1; out.append(contentsOf: "  "); i += 2 }
                else if c == "*" && at(i + 1) == "/" { blockDepth -= 1; out.append(contentsOf: "  "); i += 2 }
                else { out.append(c == "\n" ? "\n" : " "); i += 1 }
            } else if inString {
                if c == "\\" { out.append(c); if let n = at(i + 1) { out.append(n) }; i += 2; continue }
                if multilineString && c == "\"" && at(i + 1) == "\"" && at(i + 2) == "\"" {
                    inString = false; out.append(contentsOf: "\"\"\""); i += 3; continue
                }
                if !multilineString && (c == "\"" || c == "\n") { inString = false }
                out.append(c); i += 1
            } else if c == "/" && at(i + 1) == "/" {
                inLineComment = true; out.append(contentsOf: "  "); i += 2
            } else if c == "/" && at(i + 1) == "*" {
                blockDepth = 1; out.append(contentsOf: "  "); i += 2
            } else if c == "\"" {
                inString = true
                if at(i + 1) == "\"" && at(i + 2) == "\"" { multilineString = true; out.append(contentsOf: "\"\"\""); i += 3 }
                else { multilineString = false; out.append(c); i += 1 }
            } else {
                out.append(c); i += 1
            }
        }
        return String(out)
    }

    /// `"file:line: label"` for every forbidden use in `text` (comments ignored).
    static func violations(in text: String, file: String) -> [String] {
        var result: [String] = []
        for (index, line) in strippingComments(text).components(separatedBy: "\n").enumerated() {
            let range = NSRange(line.startIndex..., in: line)
            for (label, pattern) in forbiddenPatterns where pattern.firstMatch(in: line, range: range) != nil {
                result.append("\(file):\(index + 1): \(label)")
            }
        }
        return result
    }

    static func runAll() async {
        print("\n🧪 Running Bundle Resource Tests...")

        await TestSuite.run("Bundle (M8): no non-comment Bundle.module use anywhere in Sources/ (the signed app has no resource bundle at the .app root)") {
            let sources = M2.repoRoot + "/Sources"
            guard let walker = FileManager.default.enumerator(atPath: sources) else { throw TestError("cannot list \(sources)") }
            var found: [String] = []
            var scanned = 0
            while let rel = walker.nextObject() as? String {
                guard rel.hasSuffix(".swift") else { continue }
                let path = sources + "/" + rel
                guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw TestError("cannot read \(path)") }
                scanned += 1
                found.append(contentsOf: violations(in: text, file: "Sources/" + rel))
            }
            try TestSuite.assertTrue(scanned > 20, "only \(scanned) Swift files found under \(sources)")
            try TestSuite.assertEqual(found, [], "use BundledResourceLocator instead:\n" + found.joined(separator: "\n"))
        }

        await TestSuite.run("Bundle (M8): the static check catches Bundle.module shapes and ignores comments") {
            for sample in ["let u = Bundle.module.url(forResource: \"A\", withExtension: \"png\")",
                           "?? Bundle .module.url(forResource: x)", "let b: Bundle = .module",
                           "NSImage(named: n, bundle: .module)", "let x = 1 /* c */ ; Bundle.module.bundleURL"] {
                try TestSuite.assertTrue(!violations(in: sample, file: "s").isEmpty, "not caught: \(sample)")
            }
            for sample in ["// Bundle.module is never used", "/* Bundle.module\n Bundle.module */ let a = 1",
                           "/* outer /* nested */ Bundle.module */", "let s = \"//\"; /// `Bundle.module` traps",
                           "let moduleName = name.module2", "/// see the `.module` accessor"] {
                try TestSuite.assertEqual(violations(in: sample, file: "s"), [], "false positive: \(sample)")
            }
            // Line numbers survive comment stripping.
            try TestSuite.assertEqual(violations(in: "/* a\n b */\n// c\nBundle.module", file: "f"), ["f:4: Bundle.module"])
        }

        await TestSuite.run("Bundle (M8): BundledResourceLocator finds images in Contents/Resources, inside the nested resource bundle, or returns nil (never traps)") {
            let fixture = try FixtureBuilder()
            defer { fixture.cleanup() }
            let plist = Data("""
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0"><dict>
                <key>CFBundleIdentifier</key><string>test.imop.fixture</string>
                <key>CFBundleExecutable</key><string>Fake</string>
                <key>CFBundlePackageType</key><string>APPL</string>
                </dict></plist>
                """.utf8)

            // Packaged layout: icon directly in Contents/Resources.
            _ = try fixture.file("A.app/Contents/Info.plist", contents: plist, base: .root)
            _ = try fixture.file("A.app/Contents/MacOS/Fake", bytes: 1, base: .root)
            let directIcon = try fixture.file("A.app/Contents/Resources/AppIcon.png", bytes: 8, base: .root)
            guard let a = Bundle(path: fixture.path("A.app", base: .root)) else { throw TestError("fixture bundle A not loadable") }
            let foundA = BundledResourceLocator.url(forResource: "AppIcon", withExtension: "png",
                                                    resourceBundleName: "iMop_iMop.bundle", mainBundle: a)
            try TestSuite.assertEqual(foundA?.resolvingSymlinksInPath().path, URL(fileURLWithPath: directIcon).resolvingSymlinksInPath().path)
            // The first candidates are inside Contents/Resources; none is at the .app root.
            let candidatesA = BundledResourceLocator.candidateURLs(forResource: "AppIcon", withExtension: "png",
                                                                   resourceBundleName: "iMop_iMop.bundle", mainBundle: a)
            try TestSuite.assertTrue(candidatesA.first?.path.contains("/Contents/Resources/") == true, "\(candidatesA)")

            // Only inside the nested SwiftPM bundle (macOS layout) in Contents/Resources.
            _ = try fixture.file("B.app/Contents/Info.plist", contents: plist, base: .root)
            _ = try fixture.file("B.app/Contents/MacOS/Fake", bytes: 1, base: .root)
            let nestedIcon = try fixture.file("B.app/Contents/Resources/iMop_iMop.bundle/Contents/Resources/AppIcon_UI.png",
                                              bytes: 8, base: .root)
            guard let b = Bundle(path: fixture.path("B.app", base: .root)) else { throw TestError("fixture bundle B not loadable") }
            let foundB = BundledResourceLocator.url(forResource: "AppIcon_UI", withExtension: "png",
                                                    resourceBundleName: "iMop_iMop.bundle", mainBundle: b)
            try TestSuite.assertEqual(foundB?.resolvingSymlinksInPath().path, URL(fileURLWithPath: nestedIcon).resolvingSymlinksInPath().path)

            // Absent everywhere -> nil; a directory with the right name is not a file.
            _ = try fixture.dir("B.app/Contents/Resources/Missing.png", base: .root)
            try TestSuite.assertTrue(BundledResourceLocator.url(forResource: "Missing", withExtension: "png",
                                                                resourceBundleName: "iMop_iMop.bundle", mainBundle: b) == nil)
            try TestSuite.assertTrue(BundledResourceLocator.url(forResource: "Nope", withExtension: "png",
                                                                resourceBundleName: "Nope.bundle", mainBundle: a) == nil)
        }

        await TestSuite.run("Bundle (M8): from the build directory (like `swift run`), the app icons resolve through the resource bundle next to the executable") {
            // The test runner is built into the same directory as the iMop executable, so the app
            // target's resource bundle sits next to it; absent (e.g. a filtered build) is acceptable
            // as long as the lookup returns nil instead of trapping.
            let exeDir = Bundle.main.executableURL?.deletingLastPathComponent()
            let bundleDir = exeDir?.appendingPathComponent("iMop_iMop.bundle")
            let found = BundledResourceLocator.url(forResource: "AppIcon_UI", withExtension: "png", resourceBundleName: "iMop_iMop.bundle")
            if let bundleDir, FileManager.default.fileExists(atPath: bundleDir.appendingPathComponent("Contents/Resources/AppIcon_UI.png").path)
                || FileManager.default.fileExists(atPath: bundleDir.appendingPathComponent("AppIcon_UI.png").path) {
                try TestSuite.assertTrue(found != nil, "AppIcon_UI.png exists in \(bundleDir.path) but was not found")
            }
        }
    }
}
