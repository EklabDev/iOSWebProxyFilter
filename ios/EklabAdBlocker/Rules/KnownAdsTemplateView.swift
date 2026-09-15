import SwiftUI

struct KnownAdsTemplateView: View {
    let existingRules: [Rule]
    let onAdd: ([String]) -> Void
    let onCancel: () -> Void

    @State private var selected: Set<String>

    init(
        existingRules: [Rule],
        onAdd: @escaping ([String]) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.existingRules = existingRules
        self.onAdd = onAdd
        self.onCancel = onCancel
        let already = Self.normalizedHostSuffixes(existingRules)
        _selected = State(initialValue: Set(
            KnownAdDomains.suffixes.filter { !already.contains(KnownAdDomains.normalize($0)) }
        ))
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button("Select all") {
                        selected = Set(KnownAdDomains.suffixes.filter { !isAlreadyAdded($0) })
                    }
                    Button("Deselect all") {
                        selected = []
                    }
                }
                Section("Known ad domains") {
                    ForEach(KnownAdDomains.suffixes, id: \.self) { domain in
                        let added = isAlreadyAdded(domain)
                        Toggle(isOn: binding(for: domain, alreadyAdded: added)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(domain).font(.body)
                                if added {
                                    Text("Already in your rules")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(added)
                    }
                }
            }
            .navigationTitle("Known ads")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add selected") {
                        onAdd(KnownAdDomains.suffixes.filter { selected.contains($0) })
                    }
                    .disabled(selected.isEmpty)
                }
            }
        }
    }

    private func isAlreadyAdded(_ domain: String) -> Bool {
        Self.normalizedHostSuffixes(existingRules).contains(KnownAdDomains.normalize(domain))
    }

    private func binding(for domain: String, alreadyAdded: Bool) -> Binding<Bool> {
        Binding(
            get: { alreadyAdded || selected.contains(domain) },
            set: { on in
                if alreadyAdded { return }
                if on { selected.insert(domain) } else { selected.remove(domain) }
            }
        )
    }

    private static func normalizedHostSuffixes(_ rules: [Rule]) -> Set<String> {
        Set(
            rules
                .filter { $0.selectorType == .hostSuffix }
                .map { KnownAdDomains.normalize($0.selectorValue) }
                .filter { !$0.isEmpty }
        )
    }
}
