import SwiftUI

struct AppsView: View {
    @StateObject private var model = AppsViewModel()

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("iOS packet tunnels cannot map a flow to an app, and there is no public API to list installed apps. APP-type rules are kept for engine parity but never match. Add a bundle ID manually if you want the rule stored for a future OS that exposes identity.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Add per-app rule") {
                    TextField("Bundle ID (e.g. com.example.app)", text: $model.bundleId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Rule name (optional)", text: $model.ruleName)
                    Button("Block this bundle ID") {
                        model.addBundleRule()
                    }
                    .disabled(model.bundleId.trimmingCharacters(in: .whitespaces).isEmpty)
                }

                Section("Existing APP rules") {
                    if model.appRules.isEmpty {
                        Text("No per-app rules yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.appRules) { rule in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(rule.name).font(.headline)
                                Text(rule.selectorValue)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                ActionBadge(action: rule.action)
                            }
                            Spacer()
                            Toggle("", isOn: Binding(
                                get: { rule.enabled },
                                set: { model.setEnabled(id: rule.id, enabled: $0) }
                            ))
                            .labelsHidden()
                        }
                    }
                    .onDelete { indexSet in
                        for i in indexSet {
                            model.delete(model.appRules[i])
                        }
                    }
                }
            }
            .navigationTitle("Apps")
        }
    }
}
