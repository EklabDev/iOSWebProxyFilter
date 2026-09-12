import Foundation

/// Relays one allowed UDP flow through a provider-created UDP session.
public final class UdpRelay: @unchecked Sendable {
    public static let dnsPort = 53
    public static let maxDatagram = 4096

    public let base: FlowBase
    private let session: OutboundUDPSession
    private let tunWriter: TunWriting
    private let ipHostnameCache: IpHostnameCache
    private let closed = LockedFlag()

    public init(
        base: FlowBase,
        session: OutboundUDPSession,
        tunWriter: TunWriting,
        ipHostnameCache: IpHostnameCache
    ) {
        self.base = base
        self.session = session
        self.tunWriter = tunWriter
        self.ipHostnameCache = ipHostnameCache
        session.setReadHandler { [weak self] data in
            self?.onUpstream(data)
        }
    }

    public func send(_ buf: [UInt8], off: Int, len: Int) {
        if closed.value || len <= 0 { return }
        base.touch()
        base.addBytesSent(Int64(len))
        let slice = buf[off..<(off + len)]
        session.write(Data(slice))
    }

    private func onUpstream(_ data: Data) {
        if closed.value || data.isEmpty { return }
        base.touch()
        base.addBytesReceived(Int64(data.count))
        if base.key.dstPort == Self.dnsPort {
            if let msg = DnsParser.parse(data), msg.isResponse {
                for answer in msg.answers {
                    ipHostnameCache.put(answer.ip, hostname: answer.hostname)
                }
            }
        }
        var reply = [UInt8](repeating: 0, count: Packets.ipv4HeaderLen + Packets.udpHeaderLen + data.count)
        let payload = [UInt8](data)
        let packetLen = Packets.buildUdpPacket(
            &reply,
            srcIp: base.key.dstIp,
            srcPort: base.key.dstPort,
            dstIp: base.key.srcIp,
            dstPort: base.key.srcPort,
            payload: payload,
            payloadOff: 0,
            payloadLen: payload.count
        )
        tunWriter.write(reply, length: packetLen)
    }

    public func close() {
        if closed.set() {
            session.cancel()
        }
    }
}

final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var value: Bool {
        lock.lock(); defer { lock.unlock() }
        return flag
    }
    /// Returns true if this call flipped false → true.
    func set() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if flag { return false }
        flag = true
        return true
    }
}
