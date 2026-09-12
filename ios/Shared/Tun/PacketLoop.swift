import Foundation

/// TUN packet dispatcher: IPv4 TCP/UDP demux into FlowTracker relays.
public final class PacketLoop: @unchecked Sendable {
    public static let maxFlows = TunnelConfig.maxFlows

    private let tunWriter: TunWriting
    private let tracker: FlowTracker
    private let evaluator: VerdictEvaluator
    private let ipHostnameCache: IpHostnameCache
    private let factory: OutboundSessionFactory

    public init(
        tunWriter: TunWriting,
        tracker: FlowTracker,
        evaluator: VerdictEvaluator,
        ipHostnameCache: IpHostnameCache,
        factory: OutboundSessionFactory
    ) {
        self.tunWriter = tunWriter
        self.tracker = tracker
        self.evaluator = evaluator
        self.ipHostnameCache = ipHostnameCache
        self.factory = factory
    }

    public func handlePacket(_ data: Data) {
        handlePacket([UInt8](data))
    }

    public func handlePacket(_ buf: [UInt8]) {
        let n = buf.count
        if n < Packets.ipv4HeaderLen { return }
        if Packets.ipVersion(buf) != 4 { return }
        let ihl = Packets.ihl(buf)
        if ihl < Packets.ipv4HeaderLen || ihl > n { return }
        let totalLen = min(Packets.totalLength(buf), n)
        if totalLen < ihl { return }
        let srcIp = Packets.srcIp(buf)
        let dstIp = Packets.dstIp(buf)
        switch Packets.protocolNumber(buf) {
        case Int(Packets.protoUDP):
            handleUdp(buf, ihl: ihl, totalLen: totalLen, srcIp: srcIp, dstIp: dstIp)
        case Int(Packets.protoTCP):
            handleTcp(buf, ihl: ihl, totalLen: totalLen, srcIp: srcIp, dstIp: dstIp)
        default:
            break
        }
    }

    private func handleUdp(_ buf: [UInt8], ihl: Int, totalLen: Int, srcIp: UInt32, dstIp: UInt32) {
        if totalLen < ihl + Packets.udpHeaderLen { return }
        let srcPort = Packets.srcPort(buf, transportOff: ihl)
        let dstPort = Packets.dstPort(buf, transportOff: ihl)
        let udpLen = min(Packets.u16(buf, ihl + 4), totalLen - ihl)
        let payloadOff = ihl + Packets.udpHeaderLen
        let payloadLen = udpLen - Packets.udpHeaderLen
        if payloadLen < 0 { return }

        let key = FlowKey(protocolNumber: Packets.protoUDP, srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort)
        if let existing = tracker.get(key) {
            existing.base.touch()
            existing.udp?.send(buf, off: payloadOff, len: payloadLen)
            return
        }

        let base = FlowBase(key: key, startMs: nowMs())
        if dstPort == UdpRelay.dnsPort && payloadLen > 0 {
            let payload = Array(buf[payloadOff..<(payloadOff + payloadLen)])
            if let msg = DnsParser.parse(payload), !msg.isResponse {
                base.dnsHostname = msg.questions.first
            }
        }
        let entry = FlowTracker.FlowEntry(base: base)
        tracker.put(entry)

        if evaluator.evaluate(base) {
            base.addBytesSent(Int64(payloadLen))
            tracker.emitLog(base)
            return
        }

        if tracker.size > Self.maxFlows {
            tracker.emitLog(base)
            return
        }

        let remoteIp = (dstIp == TunnelConfig.virtualDNSIP && dstPort == TunnelConfig.dnsPort)
            ? TunnelConfig.upstreamDNSIP
            : dstIp
        let session = factory.makeUDP(host: Packets.ipToString(remoteIp), port: dstPort)
        let relay = UdpRelay(base: base, session: session, tunWriter: tunWriter, ipHostnameCache: ipHostnameCache)
        entry.udp = relay
        relay.send(buf, off: payloadOff, len: payloadLen)
    }

    private func handleTcp(_ buf: [UInt8], ihl: Int, totalLen: Int, srcIp: UInt32, dstIp: UInt32) {
        if totalLen < ihl + Packets.tcpHeaderLen { return }
        let srcPort = Packets.srcPort(buf, transportOff: ihl)
        let dstPort = Packets.dstPort(buf, transportOff: ihl)
        let tcpHeaderLen = Packets.tcpHeaderLen(buf, tcpOff: ihl)
        if tcpHeaderLen < Packets.tcpHeaderLen || ihl + tcpHeaderLen > totalLen { return }
        let flags = Packets.tcpFlags(buf, tcpOff: ihl)
        let seq = Packets.tcpSeq(buf, tcpOff: ihl)
        let payloadOff = ihl + tcpHeaderLen
        let payloadLen = totalLen - payloadOff

        let key = FlowKey(protocolNumber: Packets.protoTCP, srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort)
        if let existing = tracker.get(key) {
            existing.tcp?.onTunPacket(flags: flags, seq: seq, buf: buf, payloadOff: payloadOff, payloadLen: payloadLen)
            return
        }

        if flags & Packets.tcpSYN != 0 && flags & Packets.tcpACK == 0 {
            if tracker.size >= Self.maxFlows {
                sendRstForUnknown(buf, ihl: ihl, srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, seq: seq, flags: flags, payloadLen: payloadLen)
                return
            }
            let base = FlowBase(key: key, startMs: nowMs())
            let relay = TcpRelay(
                base: base,
                tunWriter: tunWriter,
                evaluator: evaluator,
                factory: factory,
                onClosed: { [weak tracker] in tracker?.onTcpClosed($0) },
                onBlocked: { [weak tracker] relay in
                    if let entry = tracker?.get(relay.base.key) {
                        tracker?.tombstone(entry)
                    }
                }
            )
            tracker.put(FlowTracker.FlowEntry(base: base, tcp: relay))
            relay.onSyn(seq: seq)
        } else if flags & Packets.tcpRST == 0 {
            sendRstForUnknown(buf, ihl: ihl, srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, seq: seq, flags: flags, payloadLen: payloadLen)
        }
    }

    private func sendRstForUnknown(
        _ buf: [UInt8],
        ihl: Int,
        srcIp: UInt32,
        srcPort: Int,
        dstIp: UInt32,
        dstPort: Int,
        seq: UInt32,
        flags: Int,
        payloadLen: Int
    ) {
        var out = [UInt8](repeating: 0, count: Packets.ipv4HeaderLen + Packets.tcpHeaderLen)
        let len: Int
        if flags & Packets.tcpACK != 0 {
            len = Packets.buildTcpPacket(
                &out, srcIp: dstIp, srcPort: dstPort, dstIp: srcIp, dstPort: srcPort,
                seq: Packets.tcpAck(buf, tcpOff: ihl), ack: 0, flags: Packets.tcpRST, window: 0
            )
        } else {
            var consumed = payloadLen
            if flags & Packets.tcpSYN != 0 { consumed += 1 }
            if flags & Packets.tcpFIN != 0 { consumed += 1 }
            len = Packets.buildTcpPacket(
                &out, srcIp: dstIp, srcPort: dstPort, dstIp: srcIp, dstPort: srcPort,
                seq: 0, ack: seq &+ UInt32(consumed), flags: Packets.tcpRST | Packets.tcpACK, window: 0
            )
        }
        tunWriter.write(out, length: len)
    }

    private func nowMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}
