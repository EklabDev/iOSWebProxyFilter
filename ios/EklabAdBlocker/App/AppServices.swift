import Foundation

final class AppServices {
    static let shared = AppServices()

    let db: Database
    let rules: RulesStore
    let connections: ConnectionsStore
    let settings: SettingsStore
    let engine: RuleEngineImpl

    private init() {
        db = Database()
        rules = RulesStore(db: db)
        connections = ConnectionsStore(db: db)
        settings = SettingsStore()
        engine = RuleEngineImpl()
        engine.updateRules(rules.getAll())
    }
}
