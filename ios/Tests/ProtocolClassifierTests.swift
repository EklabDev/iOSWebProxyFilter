#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class ProtocolClassifierTests: XCTestCase {
    func testSniWinsOverPortBasedGuesses() {
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: false, destPort: 443, sni: "example.com"), .https)
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: false, destPort: 8443, sni: "example.com"), .https)
        XCTAssertEqual(
            ProtocolClassifier.classify(
                isUdp: false, destPort: 80, sni: "example.com", httpHostHeader: "example.com"
            ),
            .https
        )
    }

    func testUdp443IsQuic() {
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: true, destPort: 443), .quic)
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: false, destPort: 443), .otherTcp)
    }

    func testPort53IsDnsOnBothTransports() {
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: true, destPort: 53), .dns)
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: false, destPort: 53), .dns)
    }

    func testPort80OrHostHeaderIsHttp() {
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: false, destPort: 80), .http)
        XCTAssertEqual(
            ProtocolClassifier.classify(isUdp: false, destPort: 8080, httpHostHeader: "example.com"),
            .http
        )
    }

    func testFallbackToOther() {
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: false, destPort: 5228), .otherTcp)
        XCTAssertEqual(ProtocolClassifier.classify(isUdp: true, destPort: 123), .otherUdp)
    }
}
