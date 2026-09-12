#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class DnsParserTests: XCTestCase {
    private func u16(_ out: inout [UInt8], _ v: Int) {
        out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8(v & 0xFF))
    }

    private func writeName(_ out: inout [UInt8], _ name: String) {
        var n = name
        if n.hasSuffix(".") { n.removeLast() }
        for label in n.split(separator: ".") {
            let bytes = Array(label.utf8)
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(0)
    }

    private func header(id: Int, flags: Int, qd: Int, an: Int) -> [UInt8] {
        var out: [UInt8] = []
        u16(&out, id)
        u16(&out, flags)
        u16(&out, qd)
        u16(&out, an)
        u16(&out, 0)
        u16(&out, 0)
        return out
    }

    private func question(_ name: String, qtype: Int = 1) -> [UInt8] {
        var out: [UInt8] = []
        writeName(&out, name)
        u16(&out, qtype)
        u16(&out, 1)
        return out
    }

    private func queryPacket(id: Int = 0x1234, name: String = "example.com") -> [UInt8] {
        var out = header(id: id, flags: 0x0100, qd: 1, an: 0)
        out.append(contentsOf: question(name))
        return out
    }

    func testSingleAQuery() {
        let msg = DnsParser.parse(queryPacket())!
        XCTAssertEqual(msg.transactionId, 0x1234)
        XCTAssertFalse(msg.isResponse)
        XCTAssertEqual(msg.questions, ["example.com"])
        XCTAssertTrue(msg.answers.isEmpty)
    }

    func testHostnameIsLowercasedAndTrailingDotStripped() {
        let msg = DnsParser.parse(queryPacket(name: "ExAmPle.COM."))!
        XCTAssertEqual(msg.questions, ["example.com"])
    }

    func testResponseWithCompressedAanswer() {
        var out = header(id: 0xbeef, flags: 0x8180, qd: 1, an: 1)
        out.append(contentsOf: question("example.com"))
        out.append(0xC0)
        out.append(0x0C)
        u16(&out, 1)
        u16(&out, 1)
        out.append(contentsOf: [0, 0, 0x0E, 0x10])
        u16(&out, 4)
        out.append(contentsOf: [93, 184, 216, 34])

        let msg = DnsParser.parse(out)!
        XCTAssertTrue(msg.isResponse)
        XCTAssertEqual(msg.questions, ["example.com"])
        XCTAssertEqual(msg.answers, [DnsParser.DnsAnswer(hostname: "example.com", ip: "93.184.216.34")])
    }

    func testMultipleQuestions() {
        var out = header(id: 1, flags: 0x0100, qd: 2, an: 0)
        out.append(contentsOf: question("example.com"))
        out.append(contentsOf: question("test.org", qtype: 28))
        let msg = DnsParser.parse(out)!
        XCTAssertEqual(msg.questions, ["example.com", "test.org"])
    }

    func testAaaaAnswerIsCompressedIpv6() {
        var out = header(id: 7, flags: 0x8180, qd: 1, an: 1)
        out.append(contentsOf: question("example.com", qtype: 28))
        out.append(0xC0)
        out.append(0x0C)
        u16(&out, 28)
        u16(&out, 1)
        out.append(contentsOf: [0, 0, 0, 60])
        u16(&out, 16)
        out.append(contentsOf: [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ])
        let msg = DnsParser.parse(out)!
        XCTAssertEqual(msg.answers, [DnsParser.DnsAnswer(hostname: "example.com", ip: "2001:db8::1")])
    }

    func testNonAddressAnswersAreSkipped() {
        var out = header(id: 9, flags: 0x8180, qd: 1, an: 2)
        out.append(contentsOf: question("example.com"))
        out.append(0xC0)
        out.append(0x0C)
        u16(&out, 5)
        u16(&out, 1)
        out.append(contentsOf: [0, 0, 0, 30])
        u16(&out, 2)
        out.append(0xC0)
        out.append(0x0C)
        out.append(0xC0)
        out.append(0x0C)
        u16(&out, 1)
        u16(&out, 1)
        out.append(contentsOf: [0, 0, 0, 30])
        u16(&out, 4)
        out.append(contentsOf: [1, 2, 3, 4])

        let msg = DnsParser.parse(out)!
        XCTAssertEqual(msg.answers, [DnsParser.DnsAnswer(hostname: "example.com", ip: "1.2.3.4")])
    }

    func testTruncatedPacketReturnsNull() {
        let full = queryPacket()
        XCTAssertNil(DnsParser.parse(Array(full.prefix(15))))
        XCTAssertNil(DnsParser.parse(Array(full.prefix(5))))
        XCTAssertNil(DnsParser.parse([UInt8]()))
        XCTAssertNil(DnsParser.parse(full, length: 14))
    }

    func testRandomGarbageReturnsNullWithoutCrashing() {
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<20 {
            let n = Int.random(in: 1..<200, using: &rng)
            var garbage = [UInt8](repeating: 0, count: n)
            for i in 0..<n { garbage[i] = UInt8.random(in: 0...255, using: &rng) }
            _ = DnsParser.parse(garbage)
        }
        XCTAssertNil(DnsParser.parse(header(id: 1, flags: 0x8180, qd: 0xFFFF, an: 0xFFFF)))
    }

    func testCompressionPointerLoopReturnsNull() {
        var out = header(id: 1, flags: 0x8180, qd: 0, an: 1)
        out.append(0xC0)
        out.append(0x0C)
        u16(&out, 1)
        u16(&out, 1)
        out.append(contentsOf: [0, 0, 0, 30])
        u16(&out, 4)
        out.append(contentsOf: [1, 2, 3, 4])
        XCTAssertNil(DnsParser.parse(out))
    }
}
