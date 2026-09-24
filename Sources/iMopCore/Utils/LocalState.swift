import SwiftUI

/// A standalone SwiftUI dynamic property wrapper providing reactive local view state
/// with full binding support ($value) without dependency on Xcode-specific compiler macro plugins.
@propertyWrapper
public struct LocalState<Value>: DynamicProperty {
    private final class Storage: ObservableObject {
        var value: Value
        init(_ value: Value) { self.value = value }
    }

    @StateObject private var storage: Storage

    public init(wrappedValue: Value) {
        _storage = StateObject(wrappedValue: Storage(wrappedValue))
    }

    @MainActor
    public var wrappedValue: Value {
        get { storage.value }
        nonmutating set {
            storage.objectWillChange.send()
            storage.value = newValue
        }
    }

    @MainActor
    public var projectedValue: Binding<Value> {
        let storage = self.storage
        return Binding(
            get: { storage.value },
            set: { newValue in
                storage.objectWillChange.send()
                storage.value = newValue
            }
        )
    }
}
