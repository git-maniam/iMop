import SwiftUI

@main
public struct iMopApp: App {
    private let appState = AppState()

    public init() {}

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
