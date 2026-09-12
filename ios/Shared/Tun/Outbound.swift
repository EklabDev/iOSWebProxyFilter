import Foundation

/// Outbound sessions created by the packet-tunnel provider. Provider-created
/// flows bypass the tunnel automatically (no `protect()` equivalent needed).
public protocol OutboundTCPConnection: AnyObject {
    func connect(timeout: TimeInterval, completion: @escaping (Error?) -> Void)
    func write(_ data: Data, completion: @escaping (Error?) -> Void)
    func read(maximumLength: Int, completion: @escaping (Data?, Error?) -> Void)
    func cancel()
}

public protocol OutboundUDPSession: AnyObject {
    func write(_ data: Data)
    func setReadHandler(_ handler: @escaping (Data) -> Void)
    func cancel()
}

public protocol OutboundSessionFactory: AnyObject {
    func makeTCP(host: String, port: Int) -> OutboundTCPConnection
    func makeUDP(host: String, port: Int) -> OutboundUDPSession
}

public enum RelayError: Error {
    case connectFailed
    case timeout
}

public enum TunnelConfig {
    public static let tunAddress = "10.0.0.2"
    public static let tunAddressIP: UInt32 = 0x0A00_0002
    public static let virtualDNS = "10.0.0.1"
    public static let virtualDNSIP: UInt32 = 0x0A00_0001
    public static let upstreamDNS = "8.8.8.8"
    public static let upstreamDNSIP: UInt32 = 0x0808_0808
    public static let dnsPort = 53
    public static let mtu = 1500
    public static let maxFlows = 256
    public static let subnetMask = "255.255.255.255"
}
