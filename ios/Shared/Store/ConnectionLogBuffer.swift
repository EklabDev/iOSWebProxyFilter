import Foundation

/// Batches connection-log writes so the packet path does not hit SQLite once per flow.
/// Flush every `flushIntervalMs` or at `batchSize` entries.
public final class ConnectionLogBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: [ConnectionLog] = []
    private var firstPendingAtMs: Int64 = -1
    private let batchSize: Int
    private let flushIntervalMs: Int64
    private let flushSink: ([ConnectionLog]) -> Void
    private let nowMs: () -> Int64
    private let flushQueue: DispatchQueue?

    public init(
        batchSize: Int = 200,
        flushIntervalMs: Int64 = 3_000,
        flushQueue: DispatchQueue? = DispatchQueue.global(qos: .utility),
        nowMs: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
        flushSink: @escaping ([ConnectionLog]) -> Void
    ) {
        self.batchSize = batchSize
        self.flushIntervalMs = flushIntervalMs
        self.flushQueue = flushQueue
        self.nowMs = nowMs
        self.flushSink = flushSink
    }

    public var size: Int {
        lock.lock(); defer { lock.unlock() }
        return pending.count
    }

    public func offer(_ log: ConnectionLog) {
        let full: Bool = {
            lock.lock()
            defer { lock.unlock() }
            if pending.isEmpty {
                firstPendingAtMs = nowMs()
            }
            pending.append(log)
            return pending.count >= batchSize
        }()
        if full {
            if let flushQueue {
                flushQueue.async { self.flush() }
            }
        }
    }

    public func due(_ now: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !pending.isEmpty && firstPendingAtMs >= 0 && now - firstPendingAtMs >= flushIntervalMs
    }

    public func flush() {
        let batch: [ConnectionLog] = {
            lock.lock()
            defer { lock.unlock() }
            if pending.isEmpty { return [] }
            let drained = pending
            pending = []
            firstPendingAtMs = -1
            return drained
        }()
        if !batch.isEmpty {
            flushSink(batch)
        }
    }
}
