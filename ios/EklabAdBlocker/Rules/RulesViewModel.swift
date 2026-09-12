import Foundation
import Combine

@MainActor
final class RulesViewModel: ObservableObject {
    @Published var rules: [Rule] = []
    @Published var hostSuggestions: [String] = []
    @Published var showAdd = false
    @Published var pendingDelete: Rule?

    private let services = AppServices.shared

    init() {
        refresh()
    }

    func refresh() {
        rules = services.rules.getAll()
        hostSuggestions = services.connections.distinctHosts(since: RetentionPolicy().cutoffMillis())
        services.engine.updateRules(rules)
    }

    func addRule(_ rule: Rule) {
        _ = services.rules.insert(rule)
        refresh()
    }

    func setEnabled(id: Int64, enabled: Bool) {
        services.rules.setEnabled(id: id, enabled: enabled)
        refresh()
    }

    func delete(_ rule: Rule) {
        services.rules.delete(id: rule.id)
        refresh()
    }

    func move(from source: IndexSet, to destination: Int) {
        var ids = rules.map(\.id)
        ids.move(fromOffsets: source, toOffset: destination)
        services.rules.reorder(orderedIds: ids)
        refresh()
    }

    func previewMatchCount(selectorType: SelectorType, selectorValue: String) -> Int {
        services.rules.previewMatchCount(
            selectorType: selectorType,
            selectorValue: selectorValue,
            engine: services.engine,
            logs: services.connections.recentForPreview()
        )
    }
}
