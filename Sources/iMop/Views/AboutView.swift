import iMopCore
import SwiftUI
import AppKit

/// Content of the "About iMop" window (replaces the standard About panel). The three credit lines
/// are fixed by the product owner and must stay EXACTLY as written (spacing and case included), each
/// as a single verbatim `Text`.
public struct AboutView: View {

    public init() {}

    public var body: some View {
        VStack(spacing: 14) {
            AppIconImage(size: 96)
                .accessibilityLabel("iMop app icon")

            Text(verbatim: "iMop")
                .font(.title.weight(.bold))

            VStack(spacing: 6) {
                Text(verbatim: "Created by Ravi Subramaniam, Bangalore (India)")
                Text(verbatim: "License :This is a Freeware")
                Text(verbatim: "version 1.1 (Last updated 1/Oct)")
            }
            .font(.body)
            .multilineTextAlignment(.center)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 36)
        .padding(.vertical, 28)
        .frame(minWidth: 360)
    }
}

/// The app icon from the bundle (v1.0 branding), with a drawn fallback. Loaded once and cached so
/// views never read the bundle repeatedly.
struct AppIconImage: View {
    let size: CGFloat

    @MainActor private static let cachedImage: NSImage? = {
        // Missing image -> nil -> the drawn gradient placeholder below (never `Bundle.module`, which traps).
        if let url = BundledResourceLocator.url(forResource: "AppIcon_UI", withExtension: "png",
                                                resourceBundleName: iMopApp.resourceBundleName),
           let image = NSImage(contentsOf: url) {
            return image
        }
        return NSImage(named: "AppIcon")
    }()

    var body: some View {
        Group {
            if let image = Self.cachedImage {
                Image(nsImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
            } else {
                ZStack {
                    LinearGradient(colors: [Color.blue, Color.cyan], startPoint: .topLeading, endPoint: .bottomTrailing)
                    Image(systemName: "sparkles")
                        .font(.system(size: size * 0.45, weight: .bold))
                        .foregroundStyle(.white)
                }
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous))
        .shadow(color: Color.blue.opacity(0.3), radius: size * 0.12, x: 0, y: size * 0.06)
    }
}
