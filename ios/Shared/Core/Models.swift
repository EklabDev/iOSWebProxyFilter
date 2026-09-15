import Foundation

/// Coarse traffic classification used by the rule engine and the connection log.
public enum ProtocolType: String, Codable, CaseIterable, Sendable {
    case https = "HTTPS"
    case http = "HTTP"
    case dns = "DNS"
    case quic = "QUIC"
    case otherTcp = "OTHER_TCP"
    case otherUdp = "OTHER_UDP"
}

public enum SelectorType: String, Codable, CaseIterable, Sendable {
    case app = "APP"
    case host = "HOST"
    case hostSuffix = "HOST_SUFFIX"
    case ip = "IP"
    case type = "TYPE"
}

public enum RuleAction: String, Codable, CaseIterable, Sendable {
    case block = "BLOCK"
    case allow = "ALLOW"
}

/// Everything the rule engine needs to decide a flow's fate.
public struct FlowContext: Sendable {
    public var appPackage: String?
    public var uid: Int
    public var destIp: String
    public var destPort: Int
    public var protocolType: ProtocolType
    public var sni: String?
    public var dnsHostname: String?
    public var resolvedHostname: String?

    public init(
        appPackage: String?,
        uid: Int,
        destIp: String,
        destPort: Int,
        protocolType: ProtocolType,
        sni: String? = nil,
        dnsHostname: String? = nil,
        resolvedHostname: String? = nil
    ) {
        self.appPackage = appPackage
        self.uid = uid
        self.destIp = destIp
        self.destPort = destPort
        self.protocolType = protocolType
        self.sni = sni
        self.dnsHostname = dnsHostname
        self.resolvedHostname = resolvedHostname
    }

    /// Hostname candidates in priority order: SNI -> DNS query -> IP->hostname cache.
    public var hostnameCandidates: [String] {
        [sni, dnsHostname, resolvedHostname].compactMap { $0 }
    }
}

/// Result of a rule evaluation.
public enum Verdict: Equatable, Sendable {
    /// No rule matched; traffic is allowed (documented default).
    case defaultAllow
    case allow(ruleId: Int64)
    case block(ruleId: Int64)
}

public struct Rule: Identifiable, Equatable, Sendable {
    public var id: Int64
    public var name: String
    public var enabled: Bool
    /// Lower value = evaluated first. First match wins.
    public var priority: Int
    public var selectorType: SelectorType
    public var selectorValue: String
    public var action: RuleAction
    public var createdAt: Int64

    public init(
        id: Int64 = 0,
        name: String,
        enabled: Bool = true,
        priority: Int = 100,
        selectorType: SelectorType,
        selectorValue: String,
        action: RuleAction,
        createdAt: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.priority = priority
        self.selectorType = selectorType
        self.selectorValue = selectorValue
        self.action = action
        self.createdAt = createdAt
    }
}

public struct ConnectionLog: Identifiable, Equatable, Hashable, Sendable {
    public var id: Int64
    public var timestamp: Int64
    public var appPackage: String?
    public var appName: String?
    public var uid: Int
    public var protocolType: ProtocolType
    public var destIp: String
    public var destPort: Int
    public var sni: String?
    public var dnsHostname: String?
    public var resolvedHostname: String?
    public var bytesSent: Int64
    public var bytesReceived: Int64
    public var blocked: Bool
    public var matchedRuleId: Int64?
    public var durationMs: Int64

    public init(
        id: Int64 = 0,
        timestamp: Int64,
        appPackage: String? = nil,
        appName: String? = nil,
        uid: Int = -1,
        protocolType: ProtocolType,
        destIp: String,
        destPort: Int,
        sni: String? = nil,
        dnsHostname: String? = nil,
        resolvedHostname: String? = nil,
        bytesSent: Int64 = 0,
        bytesReceived: Int64 = 0,
        blocked: Bool = false,
        matchedRuleId: Int64? = nil,
        durationMs: Int64 = 0
    ) {
        self.id = id
        self.timestamp = timestamp
        self.appPackage = appPackage
        self.appName = appName
        self.uid = uid
        self.protocolType = protocolType
        self.destIp = destIp
        self.destPort = destPort
        self.sni = sni
        self.dnsHostname = dnsHostname
        self.resolvedHostname = resolvedHostname
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.blocked = blocked
        self.matchedRuleId = matchedRuleId
        self.durationMs = durationMs
    }

    public var displayHost: String {
        sni ?? dnsHostname ?? resolvedHostname ?? destIp
    }

    public func toFlowContext() -> FlowContext {
        FlowContext(
            appPackage: appPackage,
            uid: uid,
            destIp: destIp,
            destPort: destPort,
            protocolType: protocolType,
            sni: sni,
            dnsHostname: dnsHostname,
            resolvedHostname: resolvedHostname
        )
    }
}

public struct TodayStats: Equatable, Sendable {
    public var connectionCount: Int
    public var blockedCount: Int
    public var totalBytes: Int64

    public init(connectionCount: Int = 0, blockedCount: Int = 0, totalBytes: Int64 = 0) {
        self.connectionCount = connectionCount
        self.blockedCount = blockedCount
        self.totalBytes = totalBytes
    }
}

public protocol RuleEngine: AnyObject {
    func evaluate(_ flow: FlowContext) -> Verdict
    /// True when this single rule's selector matches the flow, ignoring enabled/action/priority.
    func matches(rule: Rule, flow: FlowContext) -> Bool
    /// Hot-swap the compiled snapshot of enabled rules; takes effect immediately.
    func updateRules(_ rules: [Rule])
}

public enum AppConstants {
    public static let appGroup = "group.dev.eklab.adblocker"
    public static let appBundleId = "dev.eklab.adblocker"
    public static let tunnelBundleId = "dev.eklab.adblocker.PacketTunnel"
    public static let dbName = "traffic_inspector.db"
    public static let settingsSuite = "group.dev.eklab.adblocker"
    public static let blockQuicKey = "block_quic"
    public static let protectionEnabledKey = "protection_enabled"
    public static let protectionWidgetKind = "dev.eklab.adblocker.ProtectionWidget"
    public static let protectionControlKind = "dev.eklab.adblocker.ProtectionControl"
    public static let retentionTaskId = "dev.eklab.adblocker.retention"
}
