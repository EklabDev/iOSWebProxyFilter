import Foundation

/// Stateful parser extracting the SNI hostname from a TLS ClientHello.
/// Chunks may be split at arbitrary boundaries. Never throws.
public final class TlsSniParser {
    public private(set) var isFinished = false
    public private(set) var isFailed = false
    public private(set) var sni: String?

    private var recordBuf = Data()
    private var handshakeBuf = Data()

    private static let recordHeaderLen = 5
    private static let handshakeHeaderLen = 4
    private static let contentTypeHandshake = 22
    private static let handshakeTypeClientHello = 1
    private static let extServerName = 0
    private static let nameTypeHostName = 0
    private static let maxBufferBytes = 64 * 1024

    public init() {}

    /// Feeds the next bytes of the stream. Returns the SNI hostname once complete.
    @discardableResult
    public func feed(_ data: Data) -> String? {
        if isFinished { return sni }
        if isFailed { return nil }
        recordBuf.append(data)
        if recordBuf.count > Self.maxBufferBytes {
            isFailed = true
            return nil
        }
        do {
            try processRecords()
        } catch {
            isFailed = true
        }
        return sni
    }

    @discardableResult
    public func feed(_ bytes: [UInt8]) -> String? {
        feed(Data(bytes))
    }

    private struct Malformed: Error {}

    private func processRecords() throws {
        while !isFinished {
            let buf = recordBuf
            if buf.count < Self.recordHeaderLen { return }
            let contentType = Int(buf[0])
            let majorVersion = Int(buf[1])
            let recordLen = Self.u16(buf, 3)
            if contentType != Self.contentTypeHandshake || majorVersion != 0x03 {
                throw Malformed()
            }
            if buf.count < Self.recordHeaderLen + recordLen { return }
            handshakeBuf.append(buf[Self.recordHeaderLen..<(Self.recordHeaderLen + recordLen)])
            recordBuf = Data(buf[(Self.recordHeaderLen + recordLen)...])
            if handshakeBuf.count > Self.maxBufferBytes { throw Malformed() }
            try processHandshake()
        }
    }

    private func processHandshake() throws {
        let buf = handshakeBuf
        if buf.count < Self.handshakeHeaderLen { return }
        let hsType = Int(buf[0])
        let hsLen = (Int(buf[1]) << 16) | (Int(buf[2]) << 8) | Int(buf[3])
        if hsType != Self.handshakeTypeClientHello { throw Malformed() }
        if buf.count < Self.handshakeHeaderLen + hsLen { return }
        sni = try parseClientHello(buf, off: Self.handshakeHeaderLen, len: hsLen)
        isFinished = true
    }

    private func parseClientHello(_ buf: Data, off: Int, len: Int) throws -> String? {
        var p = off
        let end = off + len
        if end > buf.count { throw Malformed() }

        p += 2
        p += 32
        p += 1 + (try lengthAt(buf, p: p, end: end, size: 1))
        p += 2 + (try lengthAt(buf, p: p, end: end, size: 2))
        p += 1 + (try lengthAt(buf, p: p, end: end, size: 1))

        if p == end { return nil }
        let extLen = try lengthAt(buf, p: p, end: end, size: 2)
        p += 2
        if p + extLen > end { throw Malformed() }
        let extEnd = p + extLen

        while p + 4 <= extEnd {
            let extType = Self.u16(buf, p)
            let extDataLen = Self.u16(buf, p + 2)
            p += 4
            if p + extDataLen > extEnd { throw Malformed() }
            if extType == Self.extServerName {
                return try parseServerName(buf, off: p, len: extDataLen)
            }
            p += extDataLen
        }
        return nil
    }

    private func parseServerName(_ buf: Data, off: Int, len: Int) throws -> String? {
        let end = off + len
        if len < 2 { throw Malformed() }
        let listLen = Self.u16(buf, off)
        var p = off + 2
        let listEnd = min(p + listLen, end)
        while p + 3 <= listEnd {
            let nameType = Int(buf[p])
            let nameLen = Self.u16(buf, p + 1)
            p += 3
            if p + nameLen > listEnd { throw Malformed() }
            if nameType == Self.nameTypeHostName && nameLen > 0 {
                let slice = buf[p..<(p + nameLen)]
                return String(bytes: slice, encoding: .ascii)?.lowercased()
            }
            p += nameLen
        }
        return nil
    }

    private func lengthAt(_ buf: Data, p: Int, end: Int, size: Int) throws -> Int {
        if p < 0 || p + size > end { throw Malformed() }
        let value = size == 1 ? Int(buf[p]) : Self.u16(buf, p)
        if p + size + value > end { throw Malformed() }
        return value
    }

    private static func u16(_ buf: Data, _ off: Int) -> Int {
        (Int(buf[off]) << 8) | Int(buf[off + 1])
    }
}
