#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class PacketsTests: XCTestCase {
    func testIpToStringAndRoundTrip() {
        let ip: UInt32 = 0x0A00_0002
        XCTAssertEqual(Packets.ipToString(ip), "10.0.0.2")
        XCTAssertEqual(Packets.ipFromString("10.0.0.2"), ip)
    }

    func testUdpPacketChecksumsVerify() {
        var out = [UInt8](repeating: 0, count: 64)
        let payload: [UInt8] = [1, 2, 3, 4]
        let total = Packets.buildUdpPacket(
            &out,
            srcIp: 0x0A00_0002,
            srcPort: 12345,
            dstIp: 0x0808_0808,
            dstPort: 53,
            payload: payload,
            payloadOff: 0,
            payloadLen: 4
        )
        XCTAssertEqual(total, Packets.ipv4HeaderLen + Packets.udpHeaderLen + 4)
        XCTAssertEqual(Packets.ipVersion(out), 4)
        XCTAssertEqual(Packets.ihl(out), 20)
        XCTAssertEqual(Packets.protocolNumber(out), Int(Packets.protoUDP))
        XCTAssertEqual(Packets.srcIp(out), 0x0A00_0002)
        XCTAssertEqual(Packets.dstIp(out), 0x0808_0808)

        var header = Array(out[0..<20])
        header[10] = 0
        header[11] = 0
        let ipCsum = Packets.ipHeaderChecksum(header, off: 0, headerLen: 20)
        XCTAssertEqual(Packets.u16(out, 10), ipCsum)

        var transport = Array(out[20..<total])
        transport[6] = 0
        transport[7] = 0
        var csum = Packets.transportChecksum(
            srcIp: 0x0A00_0002, dstIp: 0x0808_0808, proto: Int(Packets.protoUDP),
            buf: transport, off: 0, len: transport.count
        )
        if csum == 0 { csum = 0xFFFF }
        XCTAssertEqual(Packets.u16(out, 26), csum)
    }

    func testTcpPacketChecksumsVerify() {
        var out = [UInt8](repeating: 0, count: 64)
        let total = Packets.buildTcpPacket(
            &out,
            srcIp: 0x0A00_0002,
            srcPort: 443,
            dstIp: 0x0A00_0002,
            dstPort: 55555,
            seq: 1,
            ack: 2,
            flags: Packets.tcpSYN | Packets.tcpACK,
            window: 65535
        )
        XCTAssertEqual(total, Packets.ipv4HeaderLen + Packets.tcpHeaderLen)
        XCTAssertEqual(Packets.tcpFlags(out, tcpOff: 20), Packets.tcpSYN | Packets.tcpACK)
        XCTAssertEqual(Packets.tcpSeq(out, tcpOff: 20), 1)
        XCTAssertEqual(Packets.tcpAck(out, tcpOff: 20), 2)

        var header = Array(out[0..<20])
        header[10] = 0
        header[11] = 0
        XCTAssertEqual(Packets.u16(out, 10), Packets.ipHeaderChecksum(header, off: 0, headerLen: 20))

        var transport = Array(out[20..<total])
        transport[16] = 0
        transport[17] = 0
        let csum = Packets.transportChecksum(
            srcIp: 0x0A00_0002, dstIp: 0x0A00_0002, proto: Int(Packets.protoTCP),
            buf: transport, off: 0, len: transport.count
        )
        XCTAssertEqual(Packets.u16(out, 36), csum)
    }

    func testUdpZeroChecksumTransmittedAsAllOnes() {
        // Empty payload can theoretically checksum to 0; builder must store 0xFFFF.
        var out = [UInt8](repeating: 0, count: 64)
        _ = Packets.buildUdpPacket(
            &out,
            srcIp: 0, srcPort: 0, dstIp: 0, dstPort: 0,
            payload: [], payloadOff: 0, payloadLen: 0
        )
        XCTAssertNotEqual(Packets.u16(out, 26), 0)
    }
}
