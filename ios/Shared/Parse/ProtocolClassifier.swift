import Foundation

/// Coarse per-flow protocol classification from transport and parsed metadata.
///
/// Precedence (first match wins):
/// 1. `sni` present → HTTPS
/// 2. UDP/443 → QUIC
/// 3. Port 53 → DNS
/// 4. Port 80, or an HTTP Host header → HTTP
/// 5. Fallback: OTHER_TCP / OTHER_UDP
public enum ProtocolClassifier {
    public static func classify(
        isUdp: Bool,
        destPort: Int,
        sni: String? = nil,
        httpHostHeader: String? = nil
    ) -> ProtocolType {
        if sni != nil { return .https }
        if isUdp && destPort == 443 { return .quic }
        if destPort == 53 { return .dns }
        if destPort == 80 || httpHostHeader != nil { return .http }
        return isUdp ? .otherUdp : .otherTcp
    }
}
