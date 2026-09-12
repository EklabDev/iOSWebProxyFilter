import SwiftUI

struct RulesView: View {
    @StateObject private var model = RulesViewModel()

    var body: some View {
        NavigationStack {
            List {
                if model.rules.isEmpty {
                    Text("No rules yet. Tap + to block or allow traffic.")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.rules) { rule in
                    RuleCard(
                        rule: rule,
                        onToggle: { model.setEnabled(id: rule.id, enabled: $0) },
                        onDelete: { model.pendingDelete = rule }
                    )
                }
                .onMove(perform: model.move)
            }
            .navigationTitle("Rules")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    EditButton()
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        model.showAdd = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Add rule")
                }
            }
            .sheet(isPresented: $model.showAdd) {
                RuleEditView(
                    initial: RuleDraft(),
                    hostSuggestions: model.hostSuggestions,
                    onPreview: model.previewMatchCount,
                    onConfirm: { rule in
                        model.addRule(rule)
                        model.showAdd = false
                    },
                    onCancel: { model.showAdd = false }
                )
            }
            .alert(
                "Delete rule?",
                isPresented: Binding(
                    get: { model.pendingDelete != nil },
                    set: { if !$0 { model.pendingDelete = nil } }
                ),
                presenting: model.pendingDelete
            ) { rule in
                Button("Delete", role: .destructive) { model.delete(rule) }
                Button("Cancel", role: .cancel) { model.pendingDelete = nil }
            } message: { rule in
                Text("\"\(rule.name)\" will be permanently deleted.")
            }
        }
    }
}

private struct RuleCard: View {
    let rule: Rule
    let onToggle: (Bool) -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(rule.name).font(.headline).lineLimit(1)
                Text(selectorSummary(rule))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(spacing: 8) {
                    ActionBadge(action: rule.action)
                    Text("Priority \(rule.priority)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Toggle("", isOn: Binding(
                get: { rule.enabled },
                set: onToggle
            ))
            .labelsHidden()
            Button(role: .destructive, action: onDelete) {
                Image(systemName: "trash")
            }
            .accessibilityLabel("Delete")
        }
        .padding(.vertical, 4)
    }
}

private func selectorSummary(_ rule: Rule) -> String {
    let label: String
    switch rule.selectorType {
    case .app: label = "APP"
    case .host: label = "HOST"
    case .hostSuffix: label = "DOMAIN"
    case .ip: label = "IP"
    case .type: label = "TYPE"
    }
    return "\(label) · \(rule.selectorValue)"
}
