#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class ConnectionLogBufferTests: XCTestCase {
    private func log(_ seq: Int64) -> ConnectionLog {
        ConnectionLog(
            timestamp: seq,
            appPackage: "com.a",
            uid: 10001,
            protocolType: .otherTcp,
            destIp: "10.0.0.1",
            destPort: 80
        )
    }

    func testOfferDoesNotFlushUntilBatchSize() {
        var flushed: [[ConnectionLog]] = []
        let buffer = ConnectionLogBuffer(
            batchSize: 3,
            flushIntervalMs: 60_000,
            flushQueue: nil,
            flushSink: { flushed.append($0) }
        )
        buffer.offer(log(1))
        buffer.offer(log(2))
        XCTAssertTrue(flushed.isEmpty)
        XCTAssertEqual(buffer.size, 2)
        buffer.offer(log(3))
        // No auto-flush queue: caller must flush.
        XCTAssertEqual(buffer.size, 3)
        buffer.flush()
        XCTAssertEqual(flushed.count, 1)
        XCTAssertEqual(flushed[0].count, 3)
        XCTAssertEqual(buffer.size, 0)
    }

    func testDueReflectsFlushInterval() {
        let now: Int64 = 10_000
        let buffer = ConnectionLogBuffer(
            batchSize: 100,
            flushIntervalMs: 5_000,
            flushQueue: nil,
            nowMs: { now },
            flushSink: { _ in }
        )
        XCTAssertFalse(buffer.due(now))
        buffer.offer(log(1))
        XCTAssertFalse(buffer.due(now))
        XCTAssertFalse(buffer.due(now + 4_999))
        XCTAssertTrue(buffer.due(now + 5_000))
    }

    func testFlushDrainsAndIsSafeWhenEmpty() {
        var flushed: [[ConnectionLog]] = []
        let buffer = ConnectionLogBuffer(batchSize: 100, flushQueue: nil, flushSink: { flushed.append($0) })
        buffer.flush()
        XCTAssertTrue(flushed.isEmpty)
        buffer.offer(log(1))
        buffer.offer(log(2))
        buffer.flush()
        XCTAssertEqual(flushed.count, 1)
        XCTAssertEqual(flushed[0].map(\.timestamp), [1, 2])
        XCTAssertEqual(buffer.size, 0)
        XCTAssertFalse(buffer.due(Int64.max))
    }

    func testConcurrentOffersAreNotLost() {
        var flushed: [ConnectionLog] = []
        let buffer = ConnectionLogBuffer(batchSize: 10_000, flushQueue: nil, flushSink: { flushed.append(contentsOf: $0) })
        let group = DispatchGroup()
        for t in 1...4 {
            group.enter()
            DispatchQueue.global().async {
                for i in 0..<250 {
                    buffer.offer(self.log(Int64(t * 1000 + i)))
                }
                group.leave()
            }
        }
        group.wait()
        XCTAssertEqual(buffer.size, 1_000)
        buffer.flush()
        XCTAssertEqual(flushed.count, 1_000)
    }
}
