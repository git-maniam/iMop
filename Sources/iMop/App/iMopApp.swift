import iMopCore
import SwiftUI

@main
public struct iMopApp: App {
    private let appState = AppState()

    public init() {
        configureAppIcon()
    }

    private func configureAppIcon() {
        if let iconUrl = Bundle.main.url(forResource: "AppIcon", withExtension: "png") ??
                         Bundle.module.url(forResource: "AppIcon", withExtension: "png"),
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

            CommandGroup(replacing: .newItem) {
                Button("Start Scan") {
                    appState.startScan()
                }
                .keyboardShortcut("r", modifiers: .command)
            }

            CommandMenu("Safety") {
                Toggle("Dry Run Mode", isOn: Binding(
                    get: { appState.isDryRunEnabled },
                    set: { appState.isDryRunEnabled = $0 }
                ))

                Toggle("Permanent Deletion", isOn: Binding(
                    get: { appState.isPermanentDeleteEnabled },
                    set: { appState.isPermanentDeleteEnabled = $0 }
                ))

                Divider()

                Button("Full Disk Access Settings...") {
                    appState.openFullDiskAccessSettings()
                }
            }
        }
    }
}
