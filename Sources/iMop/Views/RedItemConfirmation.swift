import iMopCore
import SwiftUI

// Spec §3.2 / §9.5: a Red (Caution) item is selected only through its own confirmation dialog,
// which names the item and its size. `AppState.requestToggle` sets `pendingRedConfirmation`; this
// modifier presents it and calls `confirmRed` / `cancelRedConfirmation`.

extension View {
    /// Presents the per-item confirmation for `appState.pendingRedConfirmation`.
    func redItemConfirmation(appState: AppState) -> some View {
        modifier(RedItemConfirmationModifier(appState: appState))
    }

    /// Presents the "Empty Trash" confirmation for `appState.pendingEmptyTrashConfirmation`.
    func emptyTrashConfirmation(appState: AppState) -> some View {
        modifier(EmptyTrashConfirmationModifier(appState: appState))
    }
}

private struct RedItemConfirmationModifier: ViewModifier {
    let appState: AppState

    private var isPresented: Binding<Bool> {
        Binding(
            get: { appState.pendingRedConfirmation != nil },
            set: { presented in
                // Review M7: SwiftUI may reset this binding BEFORE it runs the button action, so the
                // cancel is deferred to the next main-actor turn. By then a clicked "Select …" has run
                // `confirmRed` (which clears the pending item), so only a dismissal by another route
                // cancels — and only for the same item that was presented.
                guard !presented, let presentedID = appState.pendingRedConfirmation?.id else { return }
                let state = appState
                Task { @MainActor in
                    if state.pendingRedConfirmation?.id == presentedID {
                        state.cancelRedConfirmation()
                    }
                }
            }
        )
    }

    private func title(_ item: PlanItem) -> String {
        "Select “\(item.target.displayName)” (\(ByteFormatter.format(item.target.reclaimableBytes))) for cleaning?"
    }

    private func message(_ item: PlanItem) -> String {
        var lines: [String] = []
        lines.append("Caution item: \(item.rule.title)")
        lines.append(ActCopy.displayPath(item.target.path))
        lines.append("Estimated reclaimable: \(ByteFormatter.format(item.target.reclaimableBytes)) (\(ByteFormatter.format(item.target.allocatedBytes)) on disk)")
        lines.append("")
        lines.append(ActCopy.actionDescription(item.action))
        if !item.rule.whatYouLose.isEmpty {
            lines.append("What you lose: \(item.rule.whatYouLose)")
        }
        lines.append("")
        lines.append("Nothing is changed yet — you will still review everything before cleaning.")
        return lines.joined(separator: "\n")
    }

    func body(content: Content) -> some View {
        content.alert(
            appState.pendingRedConfirmation.map(title) ?? "",
            isPresented: isPresented,
            presenting: appState.pendingRedConfirmation
        ) { item in
            // SAFETY-DECISION: Cancel is both the cancel (Esc) and the default (Return) action, so
            // only a deliberate click on the named button selects a Caution item.
            Button("Cancel", role: .cancel) {
                appState.cancelRedConfirmation()
            }
            .keyboardShortcut(.defaultAction)

            Button("Select “\(item.target.displayName)”", role: .destructive) {
                appState.confirmRed(item.id)
            }
            .accessibilityLabel("Select \(item.target.displayName), \(ByteFormatter.format(item.target.reclaimableBytes)), for cleaning")
        } message: { item in
            Text(message(item))
        }
    }
}

// MARK: - Empty Trash (spec §6.6)

// The items in the Trash are one "Empty Trash" choice with its own explicit confirmation, which names
// the number of items and their size. `AppState.requestToggle` on any Trash item sets
// `pendingEmptyTrashConfirmation`; confirming selects all of them together.
private struct EmptyTrashConfirmationModifier: ViewModifier {
    let appState: AppState

    private var isPresented: Binding<Bool> {
        Binding(
            get: { appState.pendingEmptyTrashConfirmation != nil },
            set: { presented in
                // Deferred for the same reason as the Caution dialog above.
                guard !presented, let presentedID = appState.pendingEmptyTrashConfirmation?.id else { return }
                let state = appState
                Task { @MainActor in
                    if state.pendingEmptyTrashConfirmation?.id == presentedID {
                        state.cancelEmptyTrashConfirmation()
                    }
                }
            }
        )
    }

    private static func countText(_ count: Int) -> String {
        count == 1 ? "1 item" : "\(count) items"
    }

    private func title(_ request: EmptyTrashRequest) -> String {
        "Empty the Trash (\(Self.countText(request.count)), \(ByteFormatter.format(request.reclaimableBytes)))?"
    }

    private func message(_ request: EmptyTrashRequest) -> String {
        [
            "Selects all \(Self.countText(request.count)) in the Trash as one “Empty Trash” choice — "
                + "estimated reclaimable \(ByteFormatter.format(request.reclaimableBytes)) "
                + "(\(ByteFormatter.format(request.allocatedBytes)) on disk).",
            "",
            "Emptying the Trash is permanent: the items are deleted directly, without Quarantine, and cannot be undone.",
            "",
            "Nothing is changed yet — you will still review everything before cleaning.",
        ].joined(separator: "\n")
    }

    func body(content: Content) -> some View {
        content.alert(
            appState.pendingEmptyTrashConfirmation.map(title) ?? "",
            isPresented: isPresented,
            presenting: appState.pendingEmptyTrashConfirmation
        ) { request in
            // SAFETY-DECISION: Cancel is both the cancel (Esc) and the default (Return) action.
            Button("Cancel", role: .cancel) {
                appState.cancelEmptyTrashConfirmation()
            }
            .keyboardShortcut(.defaultAction)

            Button("Select Empty Trash", role: .destructive) {
                appState.confirmEmptyTrash(request.id)
            }
            .accessibilityLabel("Select Empty Trash, \(Self.countText(request.count)), \(ByteFormatter.format(request.reclaimableBytes)), permanent")
        } message: { request in
            Text(message(request))
        }
    }
}
