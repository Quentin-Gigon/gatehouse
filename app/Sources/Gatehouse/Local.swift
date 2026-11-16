import SwiftUI

/// View-local state, like @State. SwiftUI's @State is a compiler macro whose plugin ships only with
/// Xcode; this builds with the Command Line Tools too.
@propertyWrapper
struct Local<Value>: DynamicProperty {
    final class Storage: ObservableObject {
        @Published var value: Value
        init(_ value: Value) { self.value = value }
    }

    @StateObject private var storage: Storage

    init(wrappedValue: Value) {
        _storage = StateObject(wrappedValue: Storage(wrappedValue))
    }

    var wrappedValue: Value {
        get { storage.value }
        nonmutating set { storage.value = newValue }
    }

    var projectedValue: Binding<Value> {
        let storage = storage
        return Binding(get: { storage.value }, set: { storage.value = $0 })
    }
}
