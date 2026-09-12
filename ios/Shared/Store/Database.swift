import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif

/// Zero-dependency sqlite3 wrapper over the App Group database.
public final class Database: @unchecked Sendable {
    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "dev.eklab.adblocker.sqlite")
    private static let queueKey = DispatchSpecificKey<UInt8>()
    private let path: String

    public init(path: String) {
        self.path = path
        queue.setSpecific(key: Self.queueKey, value: 1)
        queue.sync { self.open() }
    }

    public convenience init(url: URL = AppGroup.databaseURL) {
        self.init(path: url.path)
    }

    deinit {
        if db != nil { sqlite3_close(db) }
    }

    public func sync<T>(_ body: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            return try body()
        }
        return try queue.sync(execute: body)
    }

    @discardableResult
    public func exec(_ sql: String) -> Bool {
        sync {
            sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK
        }
    }

    public func query(_ sql: String, bind: ((OpaquePointer) -> Void)? = nil) -> [[String: Any?]] {
        sync {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { return [] }
            defer { sqlite3_finalize(stmt) }
            bind?(stmt)
            var rows: [[String: Any?]] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                rows.append(Self.row(stmt))
            }
            return rows
        }
    }

    @discardableResult
    public func run(_ sql: String, bind: ((OpaquePointer) -> Void)? = nil) -> Int {
        sync {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { return 0 }
            defer { sqlite3_finalize(stmt) }
            bind?(stmt)
            sqlite3_step(stmt)
            return Int(sqlite3_changes(db))
        }
    }

    public func lastInsertId() -> Int64 {
        sync { sqlite3_last_insert_rowid(db) }
    }

    public func transaction(_ body: () -> Void) {
        sync {
            sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil)
            body()
            sqlite3_exec(db, "COMMIT", nil, nil, nil)
        }
    }

    private func open() {
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        if sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) != SQLITE_OK {
            return
        }
        sqlite3_busy_timeout(db, 3000)
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", nil, nil, nil)
        sqlite3_exec(db, "PRAGMA foreign_keys=ON", nil, nil, nil)
        migrate()
    }

    private func migrate() {
        sqlite3_exec(db, """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                selectorType TEXT NOT NULL,
                selectorValue TEXT NOT NULL,
                action TEXT NOT NULL,
                createdAt INTEGER NOT NULL
            );
            """, nil, nil, nil)
        sqlite3_exec(db, """
            CREATE TABLE IF NOT EXISTS connection_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                appPackage TEXT,
                appName TEXT,
                uid INTEGER NOT NULL,
                "protocol" TEXT NOT NULL,
                destIp TEXT NOT NULL,
                destPort INTEGER NOT NULL,
                sni TEXT,
                dnsHostname TEXT,
                resolvedHostname TEXT,
                bytesSent INTEGER NOT NULL DEFAULT 0,
                bytesReceived INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                matchedRuleId INTEGER,
                durationMs INTEGER NOT NULL DEFAULT 0
            );
            """, nil, nil, nil)
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS index_connection_log_timestamp ON connection_log(timestamp)", nil, nil, nil)
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS index_connection_log_appPackage ON connection_log(appPackage)", nil, nil, nil)
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS index_connection_log_blocked ON connection_log(blocked)", nil, nil, nil)
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS index_connection_log_resolvedHostname ON connection_log(resolvedHostname)", nil, nil, nil)
        sqlite3_exec(db, """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            """, nil, nil, nil)
        sqlite3_exec(db, "INSERT OR IGNORE INTO meta (key, value) VALUES ('rules_version', 0)", nil, nil, nil)
        sqlite3_exec(db, "PRAGMA user_version = 1", nil, nil, nil)
    }

    private static func row(_ stmt: OpaquePointer) -> [String: Any?] {
        var dict: [String: Any?] = [:]
        let count = sqlite3_column_count(stmt)
        for i in 0..<count {
            let name = String(cString: sqlite3_column_name(stmt, i))
            switch sqlite3_column_type(stmt, i) {
            case SQLITE_INTEGER:
                dict[name] = sqlite3_column_int64(stmt, i)
            case SQLITE_FLOAT:
                dict[name] = sqlite3_column_double(stmt, i)
            case SQLITE_TEXT:
                if let c = sqlite3_column_text(stmt, i) {
                    dict[name] = String(cString: c)
                } else {
                    dict[name] = nil
                }
            case SQLITE_NULL:
                dict[name] = nil
            default:
                dict[name] = nil
            }
        }
        return dict
    }
}

public enum SQLiteBind {
    public static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    public static func text(_ stmt: OpaquePointer, _ index: Int32, _ value: String?) {
        if let value {
            sqlite3_bind_text(stmt, index, value, -1, transient)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    public static func int64(_ stmt: OpaquePointer, _ index: Int32, _ value: Int64) {
        sqlite3_bind_int64(stmt, index, value)
    }

    public static func int(_ stmt: OpaquePointer, _ index: Int32, _ value: Int) {
        sqlite3_bind_int64(stmt, index, Int64(value))
    }
}
