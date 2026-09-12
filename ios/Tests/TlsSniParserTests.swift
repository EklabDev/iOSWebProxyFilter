#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class TlsSniParserTests: XCTestCase {
    private func u16(_ out: inout [UInt8], _ v: Int) {
        out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8(v & 0xFF))
    }

    private func u24(_ out: inout [UInt8], _ v: Int) {
        out.append(UInt8((v >> 16) & 0xFF))
        out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8(v & 0xFF))
    }

    private func sniExtension(_ hostname: String) -> [UInt8] {
        let name = Array(hostname.utf8)
        var data: [UInt8] = []
        u16(&data, 3 + name.count)
        data.append(0)
        u16(&data, name.count)
        data.append(contentsOf: name)
        var ext: [UInt8] = []
        u16(&ext, 0)
        u16(&ext, data.count)
        ext.append(contentsOf: data)
        return ext
    }

    private func supportedVersionsExtension() -> [UInt8] {
        var ext: [UInt8] = []
        u16(&ext, 43)
        u16(&ext, 3)
        ext.append(2)
        u16(&ext, 0x0304)
        return ext
    }

    private func buildClientHello(
        sni: String?,
        recordVersion: Int = 0x0301,
        legacyVersion: Int = 0x0303,
        sessionId: [UInt8] = [],
        withSupportedVersions: Bool = false
    ) -> [UInt8] {
        var exts: [UInt8] = []
        if withSupportedVersions { exts.append(contentsOf: supportedVersionsExtension()) }
        if let sni { exts.append(contentsOf: sniExtension(sni)) }

        var body: [UInt8] = []
        u16(&body, legacyVersion)
        body.append(contentsOf: (0..<32).map { UInt8($0) })
        body.append(UInt8(sessionId.count))
        body.append(contentsOf: sessionId)
        u16(&body, 4)
        u16(&body, 0x1301)
        u16(&body, 0xC02F)
        body.append(1)
        body.append(0)
        u16(&body, exts.count)
        body.append(contentsOf: exts)

        var hs: [UInt8] = []
        hs.append(1)
        u24(&hs, body.count)
        hs.append(contentsOf: body)

        var record: [UInt8] = []
        record.append(22)
        u16(&record, recordVersion)
        u16(&record, hs.count)
        record.append(contentsOf: hs)
        return record
    }

    private func splitIntoRecords(_ hello: [UInt8], chunkSize: Int) -> [UInt8] {
        let hs = Array(hello[5...])
        var out: [UInt8] = []
        var p = 0
        while p < hs.count {
            let n = min(chunkSize, hs.count - p)
            out.append(22)
            u16(&out, 0x0301)
            u16(&out, n)
            out.append(contentsOf: hs[p..<(p + n)])
            p += n
        }
        return out
    }

    func testSniIsExtractedFromTls12ClientHello() {
        let parser = TlsSniParser()
        let result = parser.feed(buildClientHello(sni: "example.com"))
        XCTAssertEqual(result, "example.com")
        XCTAssertEqual(parser.sni, "example.com")
        XCTAssertTrue(parser.isFinished)
        XCTAssertFalse(parser.isFailed)
    }

    func testSniIsLowercased() {
        let parser = TlsSniParser()
        XCTAssertEqual(parser.feed(buildClientHello(sni: "ExAmPle.COM")), "example.com")
    }

    func testFragmentationMidExtensionStillYieldsSni() {
        let hello = buildClientHello(sni: "example.com")
        let needle = Array("example".utf8)
        let splitAt = hello.firstRange(of: needle)!.lowerBound + 3
        let parser = TlsSniParser()
        XCTAssertNil(parser.feed(Array(hello[..<splitAt])))
        XCTAssertFalse(parser.isFinished)
        XCTAssertEqual(parser.feed(Array(hello[splitAt...])), "example.com")
        XCTAssertTrue(parser.isFinished)
    }

    func testRecordSplitAcrossThreeFeedsStillWorks() {
        let hello = buildClientHello(sni: "example.com")
        let parser = TlsSniParser()
        XCTAssertNil(parser.feed(Array(hello[..<2])))
        XCTAssertNil(parser.feed(Array(hello[2..<10])))
        XCTAssertEqual(parser.feed(Array(hello[10...])), "example.com")
    }

    func testClientHelloSpanningTwoRecords() {
        let hello = buildClientHello(sni: "example.com")
        let handshakeLen = hello.count - 5
        let multi = splitIntoRecords(hello, chunkSize: handshakeLen / 2)
        XCTAssertGreaterThan(multi.count, hello.count)
        let parser = TlsSniParser()
        XCTAssertEqual(parser.feed(multi), "example.com")
        XCTAssertTrue(parser.isFinished)
    }

    func testTls13StyleClientHello() {
        let parser = TlsSniParser()
        let hello = buildClientHello(
            sni: "example.com",
            recordVersion: 0x0301,
            legacyVersion: 0x0303,
            sessionId: [UInt8](repeating: 0x11, count: 32),
            withSupportedVersions: true
        )
        XCTAssertEqual(parser.feed(hello), "example.com")
    }

    func testClientHelloWithoutSniFinishesWithNull() {
        let parser = TlsSniParser()
        XCTAssertNil(parser.feed(buildClientHello(sni: nil)))
        XCTAssertTrue(parser.isFinished)
        XCTAssertFalse(parser.isFailed)
        XCTAssertNil(parser.sni)
    }

    func testNonTlsBytesFailWithoutCrashing() {
        let parser = TlsSniParser()
        let http = Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
        XCTAssertNil(parser.feed(http))
        XCTAssertTrue(parser.isFailed)
        XCTAssertFalse(parser.isFinished)
        XCTAssertNil(parser.feed(buildClientHello(sni: "example.com")))
    }

    func testEmptyAndTinyFeedsDoNotCrash() {
        let parser = TlsSniParser()
        XCTAssertNil(parser.feed([UInt8]()))
        XCTAssertNil(parser.feed([22]))
        XCTAssertFalse(parser.isFailed)
        XCTAssertFalse(parser.isFinished)
    }
}
