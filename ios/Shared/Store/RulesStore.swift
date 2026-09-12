import Foundation

public final class RulesStore: @unchecked Sendable {
    private let db: Database

    public init(db: Database) {
        self.db = db
    }

    public func getAll() -> [Rule] {
        db.query("SELECT * FROM rules ORDER BY priority ASC, id ASC").compactMap(Self.parse)
    }

    @discardableResult
    public func insert(_ rule: Rule) -> Int64 {
        db.run(
            """
            INSERT INTO rules (name, enabled, priority, selectorType, selectorValue, action, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
        ) { stmt in
            SQLiteBind.text(stmt, 1, rule.name)
            SQLiteBind.int(stmt, 2, rule.enabled ? 1 : 0)
            SQLiteBind.int(stmt, 3, rule.priority)
            SQLiteBind.text(stmt, 4, rule.selectorType.rawValue)
            SQLiteBind.text(stmt, 5, rule.selectorValue)
            SQLiteBind.text(stmt, 6, rule.action.rawValue)
            SQLiteBind.int64(stmt, 7, rule.createdAt)
        }
        bumpVersion()
        return db.lastInsertId()
    }

    public func update(_ rule: Rule) {
        db.run(
            """
            UPDATE rules SET name=?, enabled=?, priority=?, selectorType=?, selectorValue=?, action=?
            WHERE id=?
            """
        ) { stmt in
            SQLiteBind.text(stmt, 1, rule.name)
            SQLiteBind.int(stmt, 2, rule.enabled ? 1 : 0)
            SQLiteBind.int(stmt, 3, rule.priority)
            SQLiteBind.text(stmt, 4, rule.selectorType.rawValue)
            SQLiteBind.text(stmt, 5, rule.selectorValue)
            SQLiteBind.text(stmt, 6, rule.action.rawValue)
            SQLiteBind.int64(stmt, 7, rule.id)
        }
        bumpVersion()
    }

    public func delete(id: Int64) {
        db.run("DELETE FROM rules WHERE id=?") { SQLiteBind.int64($0, 1, id) }
        bumpVersion()
    }

    public func setEnabled(id: Int64, enabled: Bool) {
        db.run("UPDATE rules SET enabled=? WHERE id=?") { stmt in
            SQLiteBind.int(stmt, 1, enabled ? 1 : 0)
            SQLiteBind.int64(stmt, 2, id)
        }
        bumpVersion()
    }

    public func reorder(orderedIds: [Int64]) {
        let current = getAll()
        let listed = Set(orderedIds)
        db.transaction {
            for (index, id) in orderedIds.enumerated() {
                self.db.run("UPDATE rules SET priority=? WHERE id=?") { stmt in
                    SQLiteBind.int(stmt, 1, index)
                    SQLiteBind.int64(stmt, 2, id)
                }
            }
            for (index, rule) in current.filter({ !listed.contains($0.id) }).enumerated() {
                self.db.run("UPDATE rules SET priority=? WHERE id=?") { stmt in
                    SQLiteBind.int(stmt, 1, orderedIds.count + index)
                    SQLiteBind.int64(stmt, 2, rule.id)
                }
            }
        }
        bumpVersion()
    }

    public func rulesVersion() -> Int {
        let rows = db.query("SELECT value FROM meta WHERE key='rules_version'")
        if let v = rows.first?["value"] as? Int64 { return Int(v) }
        return 0
    }

    public func bumpVersion() {
        db.exec("UPDATE meta SET value = value + 1 WHERE key = 'rules_version'")
    }

    public func previewMatchCount(selectorType: SelectorType, selectorValue: String, engine: RuleEngine, logs: [ConnectionLog]) -> Int {
        let probe = Rule(
            id: -1,
            name: "preview",
            enabled: true,
            priority: 0,
            selectorType: selectorType,
            selectorValue: selectorValue,
            action: .block
        )
        return logs.reduce(0) { acc, log in
            acc + (engine.matches(rule: probe, flow: log.toFlowContext()) ? 1 : 0)
        }
    }

    private static func parse(_ row: [String: Any?]) -> Rule? {
        guard
            let id = row["id"] as? Int64,
            let name = row["name"] as? String,
            let selectorTypeRaw = row["selectorType"] as? String,
            let selectorType = SelectorType(rawValue: selectorTypeRaw),
            let selectorValue = row["selectorValue"] as? String,
            let actionRaw = row["action"] as? String,
            let action = RuleAction(rawValue: actionRaw)
        else { return nil }
        let enabled = ((row["enabled"] as? Int64) ?? 1) != 0
        let priority = Int((row["priority"] as? Int64) ?? 100)
        let createdAt = (row["createdAt"] as? Int64) ?? 0
        return Rule(
            id: id,
            name: name,
            enabled: enabled,
            priority: priority,
            selectorType: selectorType,
            selectorValue: selectorValue,
            action: action,
            createdAt: createdAt
        )
    }
}
