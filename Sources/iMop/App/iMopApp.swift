import iMopCore
import SwiftUI
import AppKit

@main
public struct iMopApp: App {
    @State private var appState = AppState()

    public init() {
        configureAppIcon()
    }

    /// SwiftPM's resource bundle for this target (holds AppIcon.png / AppIcon_UI.png). The packaged app
    /// keeps it only in Contents/Resources (the icons are also copied there directly).
    static let resourceBundleName = "iMop_iMop.bundle"

    private func configureAppIcon() {
        // Never the SwiftPM `Bundle.module` accessor: it traps when its bundle is not at the .app root,
        // and the signed app has nothing at the root (see BundledResourceLocator).
        if let iconUrl = BundledResourceLocator.url(forResource: "AppIcon", withExtension: "png",
                                                    resourceBundleName: Self.resourceBundleName),
           let img = NSImage(contentsOf: iconUrl) {
            NSApplication.shared.applicationIconImage = img
        } else if let img = NSImage(named: "AppIcon") {
            NSApplication.shared.applicationIconImage = img
        }
    }

    public var body: some Scene {
        WindowGroup {
            MainView()
                .environment(appState)
                .frame(minWidth: 1000, idealWidth: 1100, minHeight: 660, idealHeight: 740)
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified(showsTitle: true))
        .commands {
            SidebarCommands()

            // Replaces the standard About panel with iMop's own About window.
            CommandGroup(replacing: .appInfo) {
                AboutMenuButton()
            }

            CommandGroup(replacing: .newItem) {
                Button("Start Scan") {
                    appState.startScan()
                }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(appState.phase == .scanning || appState.phase == .executing)
            }

            // The v1.0 dry-run and one-step-deletion menu toggles are gone: dry-run is the build-level
            // IMOP_ALLOW_MUTATION flag and "Always quarantine" lives in Settings.
            CommandMenu("Safety") {
                Button("Open Quarantine") {
                    appState.destination = .quarantine
                    appState.refreshQuarantine()
                }

                Button("Export Audit Log…") {
                    MenuAuditLogExport.run(appState: appState)
                }

                Divider()

                Button("Full Disk Access Settings…") {
                    appState.openFullDiskAccessSettings()
                }
            }
        }

        Window("About iMop", id: "about") {
            AboutView()
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)

        Settings {
            SettingsView()
                .environment(appState)
        }
    }
}

/// "About iMop" menu item; a View so it can read `openWindow` from the environment.
private struct AboutMenuButton: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("About iMop") {
            openWindow(id: "about")
        }
    }
}

/// Menu-bar "Export Audit Log…": reuses the Results screen's exporter (NSSavePanel defaulting to
/// ~/Downloads; the core refuses deny-listed destinations and existing files). The outcome — success
/// or the refusal reason — is shown in an alert, because the menu has no screen of its own.
@MainActor
private enum MenuAuditLogExport {
    static func run(appState: AppState) {
        Task { @MainActor in
            guard let result = await AuditLogExporter.run(appState: appState) else { return }
            present(result)
        }
    }

    private static func present(_ result: ExportMessage) {
        let alert = NSAlert()
        alert.alertStyle = result.isError ? .warning : .informational
        alert.messageText = result.isError ? "The audit log was not exported" : "Audit log exported"
        alert.informativeText = result.text
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
