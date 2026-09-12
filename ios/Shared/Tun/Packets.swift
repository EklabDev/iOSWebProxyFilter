import Foundation

/// Low-level IPv4 / TCP / UDP packet helpers: accessors, checksums, builders.
/// IPs are host-order UInt32s (e.g. 10.0.0.2 == 0x0A000002).
public enum Packets {
    public static let protoTCP: UInt8 = 6
    public static let protoUDP: UInt8 = 17

    public static let ipv4HeaderLen = 20
    public static let udpHeaderLen = 8
    public static let tcpHeaderLen = 20

    public static let tcpFIN = 0x01
    public static let tcpSYN = 0x02
    public static let tcpRST = 0x04
    public static let tcpPSH = 0x08
    public static let tcpACK = 0x10

    public static func ipVersion(_ buf: [UInt8], off: Int = 0) -> Int {
        Int(buf[off] >> 4) & 0xF
    }

    public static func ihl(_ buf: [UInt8], off: Int = 0) -> Int {
        Int(buf[off] & 0xF) * 4
    }

    public static func protocolNumber(_ buf: [UInt8], off: Int = 0) -> Int {
        Int(buf[off + 9])
    }

    public static func totalLength(_ buf: [UInt8], off: Int = 0) -> Int {
        u16(buf, off + 2)
    }

    public static func srcIp(_ buf: [UInt8], off: Int = 0) -> UInt32 {
        u32(buf, off + 12)
    }

    public static func dstIp(_ buf: [UInt8], off: Int = 0) -> UInt32 {
        u32(buf, off + 16)
    }

    public static func srcPort(_ buf: [UInt8], transportOff: Int) -> Int {
        u16(buf, transportOff)
    }

    public static func dstPort(_ buf: [UInt8], transportOff: Int) -> Int {
        u16(buf, transportOff + 2)
    }

    public static func tcpSeq(_ buf: [UInt8], tcpOff: Int) -> UInt32 {
        u32(buf, tcpOff + 4)
    }

    public static func tcpAck(_ buf: [UInt8], tcpOff: Int) -> UInt32 {
        u32(buf, tcpOff + 8)
    }

    public static func tcpHeaderLen(_ buf: [UInt8], tcpOff: Int) -> Int {
        (Int(buf[tcpOff + 12]) >> 4) * 4
    }

    public static func tcpFlags(_ buf: [UInt8], tcpOff: Int) -> Int {
        Int(buf[tcpOff + 13])
    }

    public static func u16(_ buf: [UInt8], _ off: Int) -> Int {
        (Int(buf[off]) << 8) | Int(buf[off + 1])
    }

    public static func u32(_ buf: [UInt8], _ off: Int) -> UInt32 {
        (UInt32(buf[off]) << 24) |
            (UInt32(buf[off + 1]) << 16) |
            (UInt32(buf[off + 2]) << 8) |
            UInt32(buf[off + 3])
    }

    public static func putU16(_ buf: inout [UInt8], _ off: Int, _ v: Int) {
        buf[off] = UInt8((v >> 8) & 0xFF)
        buf[off + 1] = UInt8(v & 0xFF)
    }

    public static func putU32(_ buf: inout [UInt8], _ off: Int, _ v: UInt32) {
        buf[off] = UInt8((v >> 24) & 0xFF)
        buf[off + 1] = UInt8((v >> 16) & 0xFF)
        buf[off + 2] = UInt8((v >> 8) & 0xFF)
        buf[off + 3] = UInt8(v & 0xFF)
    }

    public static func ipToString(_ ip: UInt32) -> String {
        "\(ip >> 24).\(ip >> 16 & 0xFF).\(ip >> 8 & 0xFF).\(ip & 0xFF)"
    }

    public static func ipFromString(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard let octet = UInt32(part), octet <= 255 else { return nil }
            result = (result << 8) | octet
        }
        return result
    }

    // MARK: checksums

    /// One's-complement checksum over `len` bytes starting at `off`, seeded with `initial`.
    public static func checksum(_ buf: [UInt8], off: Int, len: Int, initial: UInt64 = 0) -> Int {
        var sum = initial
        var i = off
        let end = off + len
        while i + 1 < end {
            sum += UInt64((Int(buf[i]) << 8) | Int(buf[i + 1]))
            i += 2
        }
        if i < end { sum += UInt64(buf[i]) << 8 }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return Int((~sum) & 0xFFFF)
    }

    public static func ipHeaderChecksum(_ buf: [UInt8], off: Int, headerLen: Int) -> Int {
        checksum(buf, off: off, len: headerLen)
    }

    public static func transportChecksum(
        srcIp: UInt32,
        dstIp: UInt32,
        proto: Int,
        buf: [UInt8],
        off: Int,
        len: Int
    ) -> Int {
        var pseudo: UInt64 = 0
        pseudo += UInt64((srcIp >> 16) & 0xFFFF)
        pseudo += UInt64(srcIp & 0xFFFF)
        pseudo += UInt64((dstIp >> 16) & 0xFFFF)
        pseudo += UInt64(dstIp & 0xFFFF)
        pseudo += UInt64(proto)
        pseudo += UInt64(len)
        return checksum(buf, off: off, len: len, initial: pseudo)
    }

    // MARK: builders

    private static func writeIpHeader(
        _ out: inout [UInt8],
        off: Int,
        proto: Int,
        srcIp: UInt32,
        dstIp: UInt32,
        totalLen: Int
    ) {
        out[off] = 0x45
        out[off + 1] = 0
        putU16(&out, off + 2, totalLen)
        putU16(&out, off + 4, 0)
        putU16(&out, off + 6, 0)
        out[off + 8] = 64
        out[off + 9] = UInt8(proto)
        putU16(&out, off + 10, 0)
        putU32(&out, off + 12, srcIp)
        putU32(&out, off + 16, dstIp)
        putU16(&out, off + 10, ipHeaderChecksum(out, off: off, headerLen: ipv4HeaderLen))
    }

    /// Builds a complete IPv4+UDP packet at the start of `out`. Returns total length.
    @discardableResult
    public static func buildUdpPacket(
        _ out: inout [UInt8],
        srcIp: UInt32,
        srcPort: Int,
        dstIp: UInt32,
        dstPort: Int,
        payload: [UInt8],
        payloadOff: Int,
        payloadLen: Int
    ) -> Int {
        let udpLen = udpHeaderLen + payloadLen
        let total = ipv4HeaderLen + udpLen
        ensureCapacity(&out, total)
        writeIpHeader(&out, off: 0, proto: Int(protoUDP), srcIp: srcIp, dstIp: dstIp, totalLen: total)
        let u = ipv4HeaderLen
        putU16(&out, u, srcPort)
        putU16(&out, u + 2, dstPort)
        putU16(&out, u + 4, udpLen)
        putU16(&out, u + 6, 0)
        if payloadLen > 0 {
            for i in 0..<payloadLen {
                out[u + udpHeaderLen + i] = payload[payloadOff + i]
            }
        }
        var csum = transportChecksum(srcIp: srcIp, dstIp: dstIp, proto: Int(protoUDP), buf: out, off: u, len: udpLen)
        if csum == 0 { csum = 0xFFFF }
        putU16(&out, u + 6, csum)
        return total
    }

    /// Builds a complete IPv4+TCP packet (20-byte header, no options). Returns total length.
    @discardableResult
    public static func buildTcpPacket(
        _ out: inout [UInt8],
        srcIp: UInt32,
        srcPort: Int,
        dstIp: UInt32,
        dstPort: Int,
        seq: UInt32,
        ack: UInt32,
        flags: Int,
        window: Int,
        payload: [UInt8]? = nil,
        payloadOff: Int = 0,
        payloadLen: Int = 0
    ) -> Int {
        let total = ipv4HeaderLen + tcpHeaderLen + payloadLen
        ensureCapacity(&out, total)
        writeIpHeader(&out, off: 0, proto: Int(protoTCP), srcIp: srcIp, dstIp: dstIp, totalLen: total)
        let t = ipv4HeaderLen
        putU16(&out, t, srcPort)
        putU16(&out, t + 2, dstPort)
        putU32(&out, t + 4, seq)
        putU32(&out, t + 8, ack)
        out[t + 12] = UInt8(5 << 4)
        out[t + 13] = UInt8(flags)
        putU16(&out, t + 14, window)
        putU16(&out, t + 16, 0)
        putU16(&out, t + 18, 0)
        if let payload, payloadLen > 0 {
            for i in 0..<payloadLen {
                out[t + tcpHeaderLen + i] = payload[payloadOff + i]
            }
        }
        let csum = transportChecksum(
            srcIp: srcIp, dstIp: dstIp, proto: Int(protoTCP),
            buf: out, off: t, len: tcpHeaderLen + payloadLen
        )
        putU16(&out, t + 16, csum)
        return total
    }

    private static func ensureCapacity(_ out: inout [UInt8], _ total: Int) {
        if out.count < total {
            out.append(contentsOf: repeatElement(0, count: total - out.count))
        }
    }
}
