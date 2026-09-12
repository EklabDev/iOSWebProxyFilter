import Foundation

/// Single place where a flow's fate is decided. Never throws; any internal error → allow.
public final class VerdictEvaluator: @unchecked Sendable {
    private let ruleEngine: RuleEngine
    private let settings: SettingsStore
    private let ipHostnameCache: IpHostnameCache

    public init(ruleEngine: RuleEngine, settings: SettingsStore, ipHostnameCache: IpHostnameCache) {
        self.ruleEngine = ruleEngine
        self.settings = settings
        self.ipHostnameCache = ipHostnameCache
    }

    /// Returns `true` when the flow must be blocked. Fail-open on any unexpected issue.
    public func evaluate(_ base: FlowBase) -> Bool {
        let key = base.key
        base.uid = FlowBase.unknownUid
        base.appPackage = nil
        base.appName = nil
        if base.resolvedHostname == nil {
            base.resolvedHostname = ipHostnameCache.get(Packets.ipToString(key.dstIp))
        }
        base.protocolType = ProtocolClassifier.classify(
            isUdp: key.protocolNumber == Packets.protoUDP,
            destPort: key.dstPort,
            sni: base.sni,
            httpHostHeader: base.httpHost
        )

        if base.protocolType == .quic && settings.blockQuic {
            base.blocked = true
            base.matchedRuleId = nil
            return true
        }

        let verdict = ruleEngine.evaluate(base.toFlowContext())
        switch verdict {
        case .block(let ruleId):
            base.blocked = true
            base.matchedRuleId = ruleId
            return true
        case .allow(let ruleId):
            base.blocked = false
            base.matchedRuleId = ruleId
        case .defaultAllow:
            base.blocked = false
            base.matchedRuleId = nil
        }
        return false
    }
}

private extension FlowBase {
    func toFlowContext() -> FlowContext {
        FlowContext(
            appPackage: appPackage,
            uid: uid,
            destIp: Packets.ipToString(key.dstIp),
            destPort: key.dstPort,
            protocolType: protocolType,
            sni: sni,
            dnsHostname: dnsHostname,
            resolvedHostname: resolvedHostname
        )
    }
}
