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

    public var wrappedValue: Value {
        get { storage.value }
        nonmutating set {
            storage.objectWillChange.send()
            storage.value = newValue
        }
    }

    public var projectedValue: Binding<Value> {
        Binding(
            get: { self.wrappedValue },
            set: { self.wrappedValue = $0 }
        )
    }
}
