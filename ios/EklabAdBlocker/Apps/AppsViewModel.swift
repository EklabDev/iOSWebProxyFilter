import Foundation
import Combine

@MainActor
final class AppsViewModel: ObservableObject {
    @Published var appRules: [Rule] = []
    @Published var bundleId = ""
    @Published var ruleName = ""

    private let services = AppServices.shared

    init() {
        refresh()
    }

    func refresh() {
        appRules = services.rules.getAll().filter { $0.selectorType == .app }
    }

    func addBundleRule() {
        let value = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }
        let display = ruleName.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = display.isEmpty ? "Block \(value)" : display
        _ = services.rules.insert(Rule(
            name: name,
            enabled: true,
            selectorType: .app,
            selectorValue: value,
            action: .block
        ))
        bundleId = ""
        ruleName = ""
        refresh()
        services.engine.updateRules(services.rules.getAll())
    }

    func setEnabled(id: Int64, enabled: Bool) {
        services.rules.setEnabled(id: id, enabled: enabled)
        refresh()
        services.engine.updateRules(services.rules.getAll())
    }

    func delete(_ rule: Rule) {
        services.rules.delete(id: rule.id)
        refresh()
        services.engine.updateRules(services.rules.getAll())
    }
}
