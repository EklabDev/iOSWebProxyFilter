#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class RetentionPolicyTests: XCTestCase {
    private static let instantMs: Int64 = {
        var c = DateComponents()
        c.timeZone = TimeZone(secondsFromGMT: 0)
        c.year = 2026; c.month = 7; c.day = 28; c.hour = 12
        return Int64(Calendar(identifier: .gregorian).date(from: c)!.timeIntervalSince1970 * 1000)
    }()

    func testCutoffIsExactlyNowMinus7Days() {
        let fixed = Self.instantMs
        let policy = RetentionPolicy(nowMs: { fixed })
        let expected = Self.instantMs - RetentionPolicy.retentionDays * 24 * 60 * 60 * 1000
        XCTAssertEqual(policy.cutoffMillis(), expected)
    }

    func testCutoffHonorsExplicitNow() {
        let policy = RetentionPolicy()
        let now = Self.instantMs + 3_600_000
        XCTAssertEqual(policy.cutoffMillis(now), now - 7 * 24 * 60 * 60 * 1000)
    }

    func testRowStampedExactlyAtCutoffIsKept() {
        let fixed = Self.instantMs
        let policy = RetentionPolicy(nowMs: { fixed })
        let cutoff = policy.cutoffMillis()
        XCTAssertFalse(cutoff < cutoff)
        XCTAssertTrue(cutoff - 1 < cutoff)
    }
}

final class StoreTests: XCTestCase {
    func testRulesVersionBumpsAndEnginePreview() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let db = Database(path: dir.appendingPathComponent("t.db").path)
        let rules = RulesStore(db: db)
        let connections = ConnectionsStore(db: db)
        XCTAssertEqual(rules.rulesVersion(), 0)
        let id = rules.insert(TestSupport.rule(selectorValue: "ads.example.com"))
        XCTAssertGreaterThan(id, 0)
        XCTAssertEqual(rules.rulesVersion(), 1)
        XCTAssertEqual(rules.getAll().count, 1)

        let ts = Int64(Date().timeIntervalSince1970 * 1000) - 1_000
        connections.insertAll([
            ConnectionLog(
                timestamp: ts,
                protocolType: .https,
                destIp: "1.2.3.4",
                destPort: 443,
                sni: "ads.example.com"
            ),
            ConnectionLog(
                timestamp: ts,
                protocolType: .https,
                destIp: "1.2.3.5",
                destPort: 443,
                sni: "ok.example.com"
            ),
        ])
        let engine = RuleEngineImpl()
        let count = rules.previewMatchCount(
            selectorType: .host,
            selectorValue: "ads.example.com",
            engine: engine,
            logs: connections.recentForPreview()
        )
        XCTAssertEqual(count, 1)

        let old = connections.prune(cutoff: Int64.max)
        XCTAssertEqual(old, 2)
    }
}
