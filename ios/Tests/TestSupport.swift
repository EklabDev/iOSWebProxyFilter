#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import Foundation

enum TestSupport {
    static func rule(
        id: Int64 = 1,
        enabled: Bool = true,
        priority: Int = 100,
        selectorType: SelectorType = .host,
        selectorValue: String = "example.com",
        action: RuleAction = .block
    ) -> Rule {
        Rule(
            id: id,
            name: "rule-\(id)",
            enabled: enabled,
            priority: priority,
            selectorType: selectorType,
            selectorValue: selectorValue,
            action: action
        )
    }

    static func flow(
        appPackage: String? = "com.example.app",
        destIp: String = "1.2.3.4",
        protocolType: ProtocolType = .https,
        sni: String? = nil,
        dnsHostname: String? = nil,
        resolvedHostname: String? = nil
    ) -> FlowContext {
        FlowContext(
            appPackage: appPackage,
            uid: 10123,
            destIp: destIp,
            destPort: 443,
            protocolType: protocolType,
            sni: sni,
            dnsHostname: dnsHostname,
            resolvedHostname: resolvedHostname
        )
    }
}
