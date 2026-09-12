import Foundation

/// Parser for DNS wire-format messages (RFC 1035) carried as UDP payloads.
/// Never throws: any truncated or malformed input returns `nil`.
public enum DnsParser {
    public struct DnsAnswer: Equatable, Sendable {
        public let hostname: String
        public let ip: String
        public init(hostname: String, ip: String) {
            self.hostname = hostname
            self.ip = ip
        }
    }

    public struct DnsMessage: Equatable, Sendable {
        public let transactionId: Int
        public let isResponse: Bool
        public let questions: [String]
        public let answers: [DnsAnswer]
    }

    private static let headerLen = 12
    private static let maxPointerJumps = 10
    private static let maxNameLen = 253
    private static let typeA = 1
    private static let typeAAAA = 28

    public static func parse(_ packet: [UInt8], length: Int? = nil) -> DnsMessage? {
        let len = min(length ?? packet.count, packet.count)
        if len < headerLen { return nil }

        let transactionId = u16(packet, 0)
        let flags = u16(packet, 2)
        let qdCount = u16(packet, 4)
        let anCount = u16(packet, 6)

        var pos = headerLen
        var questions: [String] = []
        questions.reserveCapacity(qdCount)
        for _ in 0..<qdCount {
            guard let (name, next) = readName(packet, limit: len, start: pos) else { return nil }
            if next + 4 > len { return nil }
            questions.append(name)
            pos = next + 4
        }

        var answers: [DnsAnswer] = []
        for _ in 0..<anCount {
            guard let (name, next) = readName(packet, limit: len, start: pos) else { return nil }
            if next + 10 > len { return nil }
            let type = u16(packet, next)
            let rdLength = u16(packet, next + 8)
            let rdata = next + 10
            if rdata + rdLength > len { return nil }
            if type == typeA && rdLength == 4 {
                answers.append(DnsAnswer(hostname: name, ip: ipv4ToString(packet, rdata)))
            } else if type == typeAAAA && rdLength == 16 {
                answers.append(DnsAnswer(hostname: name, ip: ipv6ToString(packet, rdata)))
            }
            pos = rdata + rdLength
        }

        return DnsMessage(
            transactionId: transactionId,
            isResponse: (flags & 0x8000) != 0,
            questions: questions,
            answers: answers
        )
    }

    public static func parse(_ data: Data, length: Int? = nil) -> DnsMessage? {
        parse([UInt8](data), length: length)
    }

    private static func u16(_ buf: [UInt8], _ off: Int) -> Int {
        (Int(buf[off]) << 8) | Int(buf[off + 1])
    }

    /// Reads a possibly compressed domain name. Returns lowercase name (no trailing
    /// dot) and the offset just past the name in the original stream.
    private static func readName(_ buf: [UInt8], limit: Int, start: Int) -> (String, Int)? {
        var sb = ""
        var pos = start
        var next = -1
        var jumps = 0
        while true {
            if pos < 0 || pos >= limit { return nil }
            let b = Int(buf[pos])
            if b == 0 {
                pos += 1
                if next == -1 { next = pos }
                return (sb.lowercased(), next)
            } else if b & 0xC0 == 0xC0 {
                if pos + 1 >= limit { return nil }
                let ptr = ((b & 0x3F) << 8) | Int(buf[pos + 1])
                if ptr >= limit { return nil }
                if next == -1 { next = pos + 2 }
                pos = ptr
                jumps += 1
                if jumps > maxPointerJumps { return nil }
            } else if b & 0xC0 != 0 {
                return nil
            } else {
                if pos + 1 + b > limit { return nil }
                if !sb.isEmpty { sb.append(".") }
                let label = Array(buf[(pos + 1)..<(pos + 1 + b)])
                sb.append(String(bytes: label, encoding: .isoLatin1) ?? "")
                if sb.count > maxNameLen { return nil }
                pos += 1 + b
            }
        }
    }

    private static func ipv4ToString(_ buf: [UInt8], _ off: Int) -> String {
        "\(buf[off]).\(buf[off + 1]).\(buf[off + 2]).\(buf[off + 3])"
    }

    /// Formats 16 bytes as a compressed IPv6 string (RFC 5952 style).
    private static func ipv6ToString(_ buf: [UInt8], _ off: Int) -> String {
        var groups = [Int](repeating: 0, count: 8)
        for i in 0..<8 {
            groups[i] = (Int(buf[off + i * 2]) << 8) | Int(buf[off + i * 2 + 1])
        }
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while i < 8 {
            if groups[i] == 0 {
                var j = i
                while j < 8 && groups[j] == 0 { j += 1 }
                if j - i > bestLen {
                    bestStart = i
                    bestLen = j - i
                }
                i = j
            } else {
                i += 1
            }
        }
        if bestLen < 2 {
            bestStart = -1
            bestLen = 0
        }
        var sb = ""
        var idx = 0
        while idx < 8 {
            if idx == bestStart {
                sb.append("::")
                idx += bestLen
                continue
            }
            if !sb.isEmpty && !sb.hasSuffix("::") { sb.append(":") }
            sb.append(String(groups[idx], radix: 16))
            idx += 1
        }
        if sb.isEmpty { sb = "::" }
        return sb
    }
}
