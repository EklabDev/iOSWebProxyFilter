import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif

public final class ConnectionsStore: @unchecked Sendable {
    private let db: Database

    public init(db: Database) {
        self.db = db
    }

    public func insertAll(_ logs: [ConnectionLog]) {
        if logs.isEmpty { return }
        db.transaction {
            for log in logs {
                self.db.run(
                    """
                    INSERT INTO connection_log (
                        timestamp, appPackage, appName, uid, "protocol", destIp, destPort,
                        sni, dnsHostname, resolvedHostname, bytesSent, bytesReceived,
                        blocked, matchedRuleId, durationMs
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ) { stmt in
                    SQLiteBind.int64(stmt, 1, log.timestamp)
                    SQLiteBind.text(stmt, 2, log.appPackage)
                    SQLiteBind.text(stmt, 3, log.appName)
                    SQLiteBind.int(stmt, 4, log.uid)
                    SQLiteBind.text(stmt, 5, log.protocolType.rawValue)
                    SQLiteBind.text(stmt, 6, log.destIp)
                    SQLiteBind.int(stmt, 7, log.destPort)
                    SQLiteBind.text(stmt, 8, log.sni)
                    SQLiteBind.text(stmt, 9, log.dnsHostname)
                    SQLiteBind.text(stmt, 10, log.resolvedHostname)
                    SQLiteBind.int64(stmt, 11, log.bytesSent)
                    SQLiteBind.int64(stmt, 12, log.bytesReceived)
                    SQLiteBind.int(stmt, 13, log.blocked ? 1 : 0)
                    if let id = log.matchedRuleId {
                        SQLiteBind.int64(stmt, 14, id)
                    } else {
                        sqlite3_bind_null(stmt, 14)
                    }
                    SQLiteBind.int64(stmt, 15, log.durationMs)
                }
            }
        }
    }

    public func pagedFeed(
        hostQuery: String?,
        blockedOnly: Bool,
        startTime: Int64 = 0,
        endTime: Int64 = Int64.max,
        limit: Int,
        offset: Int
    ) -> [ConnectionLog] {
        var sql = """
            SELECT * FROM connection_log
            WHERE timestamp BETWEEN ? AND ?
            """
        if blockedOnly { sql += " AND blocked = 1" }
        if let q = hostQuery, !q.isEmpty {
            sql += """
                 AND (sni LIKE '%' || ? || '%'
                   OR dnsHostname LIKE '%' || ? || '%'
                   OR resolvedHostname LIKE '%' || ? || '%'
                   OR destIp LIKE '%' || ? || '%')
                """
        }
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        return db.query(sql) { stmt in
            SQLiteBind.int64(stmt, 1, startTime)
            SQLiteBind.int64(stmt, 2, endTime)
            var idx: Int32 = 3
            if let q = hostQuery, !q.isEmpty {
                SQLiteBind.text(stmt, idx, q); idx += 1
                SQLiteBind.text(stmt, idx, q); idx += 1
                SQLiteBind.text(stmt, idx, q); idx += 1
                SQLiteBind.text(stmt, idx, q); idx += 1
            }
            SQLiteBind.int(stmt, idx, limit)
            SQLiteBind.int(stmt, idx + 1, offset)
        }.compactMap(Self.parse)
    }

    public func todayStats(since: Int64) -> TodayStats {
        let count = intValue("SELECT COUNT(*) AS v FROM connection_log WHERE timestamp >= ?", since)
        let blocked = intValue("SELECT COUNT(*) AS v FROM connection_log WHERE timestamp >= ? AND blocked = 1", since)
        let bytes = int64Value("SELECT COALESCE(SUM(bytesSent + bytesReceived), 0) AS v FROM connection_log WHERE timestamp >= ?", since)
        return TodayStats(connectionCount: count, blockedCount: blocked, totalBytes: bytes)
    }

    public func distinctHosts(since: Int64) -> [String] {
        db.query(
            """
            SELECT DISTINCT COALESCE(sni, dnsHostname, resolvedHostname) AS host
            FROM connection_log
            WHERE timestamp >= ?
              AND COALESCE(sni, dnsHostname, resolvedHostname) IS NOT NULL
            ORDER BY host
            """
        ) { SQLiteBind.int64($0, 1, since) }
        .compactMap { $0["host"] as? String }
    }

    public func recentForPreview(limit: Int = 5000) -> [ConnectionLog] {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let cutoff = RetentionPolicy().cutoffMillis(now)
        return db.query(
            """
            SELECT * FROM connection_log
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp DESC
            LIMIT ?
            """
        ) { stmt in
            SQLiteBind.int64(stmt, 1, cutoff)
            SQLiteBind.int64(stmt, 2, now)
            SQLiteBind.int(stmt, 3, limit)
        }.compactMap(Self.parse)
    }

    @discardableResult
    public func prune(cutoff: Int64) -> Int {
        db.run("DELETE FROM connection_log WHERE timestamp < ?") { SQLiteBind.int64($0, 1, cutoff) }
    }

    private func intValue(_ sql: String, _ arg: Int64) -> Int {
        Int(int64Value(sql, arg))
    }

    private func int64Value(_ sql: String, _ arg: Int64) -> Int64 {
        (db.query(sql) { SQLiteBind.int64($0, 1, arg) }.first?["v"] as? Int64) ?? 0
    }

    private static func parse(_ row: [String: Any?]) -> ConnectionLog? {
        guard
            let id = row["id"] as? Int64,
            let timestamp = row["timestamp"] as? Int64,
            let protocolRaw = row["protocol"] as? String,
            let protocolType = ProtocolType(rawValue: protocolRaw),
            let destIp = row["destIp"] as? String
        else { return nil }
        return ConnectionLog(
            id: id,
            timestamp: timestamp,
            appPackage: row["appPackage"] as? String,
            appName: row["appName"] as? String,
            uid: Int((row["uid"] as? Int64) ?? -1),
            protocolType: protocolType,
            destIp: destIp,
            destPort: Int((row["destPort"] as? Int64) ?? 0),
            sni: row["sni"] as? String,
            dnsHostname: row["dnsHostname"] as? String,
            resolvedHostname: row["resolvedHostname"] as? String,
            bytesSent: (row["bytesSent"] as? Int64) ?? 0,
            bytesReceived: (row["bytesReceived"] as? Int64) ?? 0,
            blocked: ((row["blocked"] as? Int64) ?? 0) != 0,
            matchedRuleId: row["matchedRuleId"] as? Int64,
            durationMs: (row["durationMs"] as? Int64) ?? 0
        )
    }
}
