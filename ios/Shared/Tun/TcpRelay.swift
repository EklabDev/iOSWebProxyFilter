import Foundation

/// Minimal userspace TCP relay for one flow.
///
/// Handshake is local (SYN → SYN/ACK). TCP/443 waits for SNI; TCP/80 waits for
/// a Host header (or 8 KB buffered). Allowed traffic is relayed through a
/// provider-created TCP connection. Client FIN ACKs and closes upstream
/// (NE flows have no half-close). Blocked flows send RST then become tombstones.
public final class TcpRelay: @unchecked Sendable {
    public static let httpPort = 80
    public static let httpsPort = 443
    public static let connectTimeout: TimeInterval = 10
    public static let window = 65535
    public static let chunk = 1400
    public static let controlPacketMax = 64
    public static let maxPendingHttps = 64 * 1024
    public static let maxPendingHttp = 8 * 1024
    public static let maxHttpScan = 8192

    private enum State { case syn, awaitingMetadata, connecting, established, closed }

    public let base: FlowBase
    private let tunWriter: TunWriting
    private let evaluator: VerdictEvaluator
    private let factory: OutboundSessionFactory
    private let onClosed: (TcpRelay) -> Void
    private let onBlocked: (TcpRelay) -> Void

    private let key: FlowKey
    private let lock = NSLock()
    private var state: State = .syn
    private var clientNext: UInt32 = 0
    private var clientSynSeq: UInt32 = 0
    private let ourIsn: UInt32 = UInt32.random(in: 0...UInt32.max)
    private var ourNext: UInt32
    private var synAckSent = false
    private var clientClosed = false
    private var serverClosed = false
    private var decided = false
    private var pending = Data()
    private var connection: OutboundTCPConnection?
    private var sniParser: TlsSniParser?
    private let closedOnce = LockedFlag()
    private var loopScratch = [UInt8](repeating: 0, count: 64)

    public var isTerminated: Bool {
        lock.lock(); defer { lock.unlock() }
        return state == .closed
    }

    public init(
        base: FlowBase,
        tunWriter: TunWriting,
        evaluator: VerdictEvaluator,
        factory: OutboundSessionFactory,
        onClosed: @escaping (TcpRelay) -> Void,
        onBlocked: @escaping (TcpRelay) -> Void
    ) {
        self.base = base
        self.tunWriter = tunWriter
        self.evaluator = evaluator
        self.factory = factory
        self.onClosed = onClosed
        self.onBlocked = onBlocked
        self.key = base.key
        self.ourNext = ourIsn
        if key.dstPort == Self.httpsPort {
            sniParser = TlsSniParser()
        }
    }

    public func onSyn(seq: UInt32) {
        base.touch()
        clientSynSeq = seq
        clientNext = seq &+ 1
        if key.dstPort == Self.httpsPort || key.dstPort == Self.httpPort {
            state = .awaitingMetadata
            sendSynAck()
        } else if evaluator.evaluate(base) {
            blockAndRst()
        } else {
            state = .connecting
            connectUpstream(sendSynAckAfter: true)
        }
    }

    public func onTunPacket(flags: Int, seq: UInt32, buf: [UInt8], payloadOff: Int, payloadLen: Int) {
        if isTerminated { return }
        base.touch()

        if flags & Packets.tcpRST != 0 {
            clientClosed = true
            connection?.cancel()
            terminate()
            return
        }

        lock.lock()
        let current = state
        lock.unlock()

        switch current {
        case .syn, .closed:
            return
        case .awaitingMetadata, .connecting:
            if flags & Packets.tcpSYN != 0 {
                if seq == clientSynSeq && synAckSent { sendSynAck() }
                return
            }
            if seq != clientNext {
                sendAck()
                return
            }
            var advance = payloadLen
            if payloadLen > 0 {
                pending.append(contentsOf: buf[payloadOff..<(payloadOff + payloadLen)])
                base.addBytesSent(Int64(payloadLen))
                if current == .awaitingMetadata {
                    feedMetadata(buf, off: payloadOff, len: payloadLen)
                    if isTerminated { return }
                    if !decided {
                        let cap = key.dstPort == Self.httpsPort ? Self.maxPendingHttps : Self.maxPendingHttp
                        if pending.count > cap { decide() }
                    }
                }
            }
            if flags & Packets.tcpFIN != 0 {
                advance += 1
                clientClosed = true
            }
            clientNext = clientNext &+ UInt32(advance)
            sendAck()
            if clientClosed {
                // No half-close on NE flows: ACK the FIN and close upstream.
                connection?.cancel()
                terminate()
            }
        case .established:
            if seq != clientNext {
                sendAck()
                return
            }
            var advance = payloadLen
            if payloadLen > 0 {
                let data = Data(buf[payloadOff..<(payloadOff + payloadLen)])
                connection?.write(data) { [weak self] error in
                    if error != nil {
                        self?.sendRst()
                        self?.terminate()
                    }
                }
                base.addBytesSent(Int64(payloadLen))
            }
            if flags & Packets.tcpFIN != 0 {
                advance += 1
                clientClosed = true
            }
            clientNext = clientNext &+ UInt32(advance)
            if payloadLen > 0 || flags & Packets.tcpFIN != 0 {
                sendAck()
            }
            if clientClosed {
                connection?.cancel()
                terminate()
            }
        }
    }

    private func feedMetadata(_ buf: [UInt8], off: Int, len: Int) {
        if decided { return }
        switch key.dstPort {
        case Self.httpsPort:
            guard let parser = sniParser else {
                decide()
                return
            }
            parser.feed(Array(buf[off..<(off + len)]))
            if parser.isFinished || parser.isFailed {
                base.sni = parser.sni
                sniParser = nil
                decide()
            }
        case Self.httpPort:
            if let host = extractHostHeader(pending) {
                base.httpHost = host
                decide()
            } else if pending.count >= Self.maxPendingHttp {
                decide()
            }
        default:
            decide()
        }
    }

    private func extractHostHeader(_ data: Data) -> String? {
        let scan = data.prefix(Self.maxHttpScan)
        guard let text = String(data: scan, encoding: .isoLatin1) else { return nil }
        guard let regex = try? NSRegularExpression(pattern: "(?im)^host:\\s*([^\\r\\n]+)") else { return nil }
        let range = NSRange(location: 0, length: (text as NSString).length)
        guard let match = regex.firstMatch(in: text, range: range), match.numberOfRanges > 1 else { return nil }
        let value = (text as NSString).substring(with: match.range(at: 1))
        let host = value.trimmingCharacters(in: .whitespaces).split(separator: ":").first.map(String.init) ?? ""
        let lowered = host.lowercased()
        return lowered.isEmpty ? nil : lowered
    }

    private func decide() {
        if decided { return }
        decided = true
        if evaluator.evaluate(base) {
            blockAndRst()
        } else {
            lock.lock(); state = .connecting; lock.unlock()
            connectUpstream(sendSynAckAfter: false)
        }
    }

    private func blockAndRst() {
        sendRst()
        if closedOnce.set() {
            lock.lock(); state = .closed; lock.unlock()
            connection?.cancel()
            onBlocked(self)
        }
    }

    private func connectUpstream(sendSynAckAfter: Bool) {
        let host = Packets.ipToString(key.dstIp)
        let conn = factory.makeTCP(host: host, port: key.dstPort)
        conn.connect(timeout: Self.connectTimeout) { [weak self] error in
            guard let self else { return }
            if let error {
                _ = error
                self.sendRst()
                self.terminate()
                return
            }
            self.lock.lock()
            if self.state == .closed {
                self.lock.unlock()
                conn.cancel()
                return
            }
            self.connection = conn
            if sendSynAckAfter { self.sendSynAck() }
            let buffered = self.pending
            self.pending = Data()
            self.lock.unlock()
            if !buffered.isEmpty {
                conn.write(buffered) { [weak self] err in
                    if err != nil {
                        self?.sendRst()
                        self?.terminate()
                    }
                }
            }
            self.lock.lock()
            if self.state == .closed {
                self.lock.unlock()
                return
            }
            self.state = .established
            if self.clientClosed {
                self.lock.unlock()
                conn.cancel()
                self.terminate()
                return
            }
            self.lock.unlock()
            self.readLoop(conn)
        }
    }

    private func readLoop(_ conn: OutboundTCPConnection) {
        conn.read(maximumLength: Self.chunk) { [weak self] data, error in
            guard let self else { return }
            if self.isTerminated { return }
            if let data, !data.isEmpty, error == nil {
                self.base.touch()
                self.base.addBytesReceived(Int64(data.count))
                let seq = self.ourNext
                self.ourNext = self.ourNext &+ UInt32(data.count)
                var packet = [UInt8](repeating: 0, count: Packets.ipv4HeaderLen + Packets.tcpHeaderLen + data.count)
                let payload = [UInt8](data)
                let packetLen = Packets.buildTcpPacket(
                    &packet,
                    srcIp: self.key.dstIp,
                    srcPort: self.key.dstPort,
                    dstIp: self.key.srcIp,
                    dstPort: self.key.srcPort,
                    seq: seq,
                    ack: self.clientNext,
                    flags: Packets.tcpACK | Packets.tcpPSH,
                    window: Self.window,
                    payload: payload,
                    payloadOff: 0,
                    payloadLen: payload.count
                )
                self.tunWriter.write(packet, length: packetLen)
                self.readLoop(conn)
            } else {
                self.serverClosed = true
                let seq = self.ourNext
                self.ourNext = self.ourNext &+ 1
                var packet = [UInt8](repeating: 0, count: Packets.ipv4HeaderLen + Packets.tcpHeaderLen)
                let packetLen = Packets.buildTcpPacket(
                    &packet,
                    srcIp: self.key.dstIp,
                    srcPort: self.key.dstPort,
                    dstIp: self.key.srcIp,
                    dstPort: self.key.srcPort,
                    seq: seq,
                    ack: self.clientNext,
                    flags: Packets.tcpFIN | Packets.tcpACK,
                    window: Self.window
                )
                self.tunWriter.write(packet, length: packetLen)
                if self.clientClosed {
                    self.terminate()
                }
            }
        }
    }

    private func sendSynAck() {
        ourNext = ourIsn &+ 1
        synAckSent = true
        sendControl(seq: ourIsn, ack: clientNext, flags: Packets.tcpSYN | Packets.tcpACK)
    }

    private func sendAck() {
        sendControl(seq: ourNext, ack: clientNext, flags: Packets.tcpACK)
    }

    private func sendRst() {
        sendControl(seq: ourNext, ack: clientNext, flags: Packets.tcpRST | Packets.tcpACK)
    }

    private func sendControl(seq: UInt32, ack: UInt32, flags: Int) {
        let len = Packets.buildTcpPacket(
            &loopScratch,
            srcIp: key.dstIp,
            srcPort: key.dstPort,
            dstIp: key.srcIp,
            dstPort: key.srcPort,
            seq: seq,
            ack: ack,
            flags: flags,
            window: Self.window
        )
        tunWriter.write(loopScratch, length: len)
    }

    public func abort() {
        connection?.cancel()
        terminate()
    }

    private func terminate() {
        if !closedOnce.set() { return }
        lock.lock(); state = .closed; lock.unlock()
        connection?.cancel()
        onClosed(self)
    }
}
