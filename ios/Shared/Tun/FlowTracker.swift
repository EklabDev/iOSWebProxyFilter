import Foundation

/// Registry of live flows, keyed by 5-tuple. Owns expiry and log emission.
public final class FlowTracker: @unchecked Sendable {
    public static let udpIdleMs: Int64 = 60_000
    public static let tcpIdleMs: Int64 = 60_000
    public static let blockedIdleMs: Int64 = 60_000

    public final class FlowEntry {
        public let base: FlowBase
        public var udp: UdpRelay?
        public var tcp: TcpRelay?

        public init(base: FlowBase, udp: UdpRelay? = nil, tcp: TcpRelay? = nil) {
            self.base = base
            self.udp = udp
            self.tcp = tcp
        }
    }

    private let logBuffer: ConnectionLogBuffer
    private let lock = NSLock()
    private var flows: [FlowKey: FlowEntry] = [:]

    public init(logBuffer: ConnectionLogBuffer) {
        self.logBuffer = logBuffer
    }

    public func get(_ key: FlowKey) -> FlowEntry? {
        lock.lock(); defer { lock.unlock() }
        return flows[key]
    }

    public func put(_ entry: FlowEntry) {
        lock.lock()
        flows[entry.base.key] = entry
        lock.unlock()
    }

    public var size: Int {
        lock.lock(); defer { lock.unlock() }
        return flows.count
    }

    /// Called by a TcpRelay exactly once when it reaches a non-block terminal state.
    public func onTcpClosed(_ relay: TcpRelay) {
        let key = relay.base.key
        lock.lock()
        guard let entry = flows[key], entry.tcp === relay else {
            lock.unlock()
            return
        }
        flows.removeValue(forKey: key)
        lock.unlock()
        emitLog(entry.base)
    }

    /// Keep a tombstone (no relay) so later packets are dropped silently.
    public func tombstone(_ entry: FlowEntry) {
        emitLog(entry.base)
        lock.lock()
        entry.udp = nil
        entry.tcp = nil
        lock.unlock()
    }

    public func emitLog(_ base: FlowBase) {
        guard base.markLogged() else { return }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        logBuffer.offer(base.toLog(nowMs: now))
    }

    public func reap(nowMs: Int64) {
        lock.lock()
        let snapshot = flows
        lock.unlock()
        for (key, entry) in snapshot {
            let idleMs = nowMs - entry.base.lastActivityMs
            let udp = entry.udp
            let tcp = entry.tcp
            if let udp, idleMs > Self.udpIdleMs {
                if remove(key, entry) {
                    udp.close()
                    emitLog(entry.base)
                }
            } else if let tcp, tcp.isTerminated {
                if remove(key, entry) {
                    emitLog(entry.base)
                }
            } else if let tcp, idleMs > Self.tcpIdleMs {
                if remove(key, entry) {
                    tcp.abort()
                    emitLog(entry.base)
                }
            } else if udp == nil && tcp == nil && idleMs > Self.blockedIdleMs {
                _ = remove(key, entry)
            }
        }
    }

    public func closeAll() {
        lock.lock()
        let snapshot = flows
        flows.removeAll()
        lock.unlock()
        for (_, entry) in snapshot {
            entry.udp?.close()
            entry.tcp?.abort()
            emitLog(entry.base)
        }
    }

    private func remove(_ key: FlowKey, _ entry: FlowEntry) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if flows[key] === entry {
            flows.removeValue(forKey: key)
            return true
        }
        return false
    }
}
