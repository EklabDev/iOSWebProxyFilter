import Foundation

/// Identity of one flow as seen on the TUN device: the 5-tuple.
public struct FlowKey: Hashable, Sendable {
    public var protocolNumber: UInt8
    public var srcIp: UInt32
    public var srcPort: Int
    public var dstIp: UInt32
    public var dstPort: Int

    public init(protocolNumber: UInt8, srcIp: UInt32, srcPort: Int, dstIp: UInt32, dstPort: Int) {
        self.protocolNumber = protocolNumber
        self.srcIp = srcIp
        self.srcPort = srcPort
        self.dstIp = dstIp
        self.dstPort = dstPort
    }
}

/// Mutable per-flow metadata and counters.
public final class FlowBase: @unchecked Sendable {
    public static let unknownUid = -1

    public let key: FlowKey
    public let startMs: Int64

    private let lock = NSLock()
    private var _lastActivityMs: Int64
    private var _sni: String?
    private var _dnsHostname: String?
    private var _resolvedHostname: String?
    private var _httpHost: String?
    private var _protocolType: ProtocolType
    private var _blocked = false
    private var _matchedRuleId: Int64?
    private var _logged = false
    private var _bytesSent: Int64 = 0
    private var _bytesReceived: Int64 = 0

    public var uid: Int = FlowBase.unknownUid
    public var appPackage: String?
    public var appName: String?

    public init(key: FlowKey, startMs: Int64) {
        self.key = key
        self.startMs = startMs
        self._lastActivityMs = startMs
        self._protocolType = key.protocolNumber == Packets.protoUDP ? .otherUdp : .otherTcp
    }

    public var lastActivityMs: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _lastActivityMs
    }

    public var sni: String? {
        get { lock.lock(); defer { lock.unlock() }; return _sni }
        set { lock.lock(); _sni = newValue; lock.unlock() }
    }

    public var dnsHostname: String? {
        get { lock.lock(); defer { lock.unlock() }; return _dnsHostname }
        set { lock.lock(); _dnsHostname = newValue; lock.unlock() }
    }

    public var resolvedHostname: String? {
        get { lock.lock(); defer { lock.unlock() }; return _resolvedHostname }
        set { lock.lock(); _resolvedHostname = newValue; lock.unlock() }
    }

    public var httpHost: String? {
        get { lock.lock(); defer { lock.unlock() }; return _httpHost }
        set { lock.lock(); _httpHost = newValue; lock.unlock() }
    }

    public var protocolType: ProtocolType {
        get { lock.lock(); defer { lock.unlock() }; return _protocolType }
        set { lock.lock(); _protocolType = newValue; lock.unlock() }
    }

    public var blocked: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _blocked }
        set { lock.lock(); _blocked = newValue; lock.unlock() }
    }

    public var matchedRuleId: Int64? {
        get { lock.lock(); defer { lock.unlock() }; return _matchedRuleId }
        set { lock.lock(); _matchedRuleId = newValue; lock.unlock() }
    }

    public func markLogged() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if _logged { return false }
        _logged = true
        return true
    }

    public var bytesSent: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _bytesSent
    }

    public var bytesReceived: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _bytesReceived
    }

    public func addBytesSent(_ n: Int64) {
        lock.lock(); _bytesSent += n; lock.unlock()
    }

    public func addBytesReceived(_ n: Int64) {
        lock.lock(); _bytesReceived += n; lock.unlock()
    }

    public func touch(nowMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) {
        lock.lock(); _lastActivityMs = nowMs; lock.unlock()
    }

    public func toLog(nowMs: Int64) -> ConnectionLog {
        lock.lock()
        defer { lock.unlock() }
        return ConnectionLog(
            timestamp: startMs,
            appPackage: appPackage,
            appName: appName,
            uid: uid,
            protocolType: _protocolType,
            destIp: Packets.ipToString(key.dstIp),
            destPort: key.dstPort,
            sni: _sni,
            dnsHostname: _dnsHostname,
            resolvedHostname: _resolvedHostname,
            bytesSent: _bytesSent,
            bytesReceived: _bytesReceived,
            blocked: _blocked,
            matchedRuleId: _matchedRuleId,
            durationMs: max(0, nowMs - startMs)
        )
    }
}
