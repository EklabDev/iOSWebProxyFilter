import Foundation

/// Compiled, thread-safe rule engine.
///
/// Snapshot model: enabled rules only, sorted by priority ascending.
/// First matching rule wins. No match → `defaultAllow` (fail-open).
public final class RuleEngineImpl: RuleEngine, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: [Rule] = []

    public init() {}

    public func evaluate(_ flow: FlowContext) -> Verdict {
        let rules: [Rule] = {
            lock.lock()
            defer { lock.unlock() }
            return snapshot
        }()
        for rule in rules {
            if matchesSelector(rule, flow) {
                switch rule.action {
                case .block: return .block(ruleId: rule.id)
                case .allow: return .allow(ruleId: rule.id)
                }
            }
        }
        return .defaultAllow
    }

    public func matches(rule: Rule, flow: FlowContext) -> Bool {
        matchesSelector(rule, flow)
    }

    public func updateRules(_ rules: [Rule]) {
        let compiled = rules.filter(\.enabled).sorted { $0.priority < $1.priority }
        lock.lock()
        snapshot = compiled
        lock.unlock()
    }

    private func matchesSelector(_ rule: Rule, _ flow: FlowContext) -> Bool {
        switch rule.selectorType {
        case .app:
            return flow.appPackage == rule.selectorValue
        case .host:
            return flow.hostnameCandidates.contains { normalizeHost($0) == normalizeHost(rule.selectorValue) }
        case .hostSuffix:
            return matchesHostSuffix(rule.selectorValue, flow.hostnameCandidates)
        case .ip:
            return matchesIp(rule.selectorValue, flow.destIp)
        case .type:
            return matchesProtocolType(rule.selectorValue, flow.protocolType)
        }
    }

    /// Lowercases and strips trailing dots (Kotlin `trimEnd('.')`).
    private func normalizeHost(_ host: String) -> String {
        var h = host
        while h.hasSuffix(".") {
            h.removeLast()
        }
        return h.lowercased()
    }

    private func matchesHostSuffix(_ selectorValue: String, _ candidates: [String]) -> Bool {
        var base = normalizeHost(selectorValue)
        if base.hasPrefix(".") {
            base.removeFirst()
        }
        if base.isEmpty { return false }
        return candidates.contains { candidate in
            let host = normalizeHost(candidate)
            return host == base || host.hasSuffix("." + base)
        }
    }

    private func matchesIp(_ selectorValue: String, _ destIp: String) -> Bool {
        let selector = selectorValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let target = destIp.trimmingCharacters(in: .whitespacesAndNewlines)
        if selector.isEmpty || target.isEmpty { return false }

        if selector.contains("/") {
            let parts = selector.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            if parts.count != 2 { return false }
            guard let network = parseIpv4(parts[0]) else { return false }
            guard let prefix = Int(parts[1]), (0...32).contains(prefix) else { return false }
            guard let targetInt = parseIpv4(target) else { return false }
            let mask: UInt32 = prefix == 0 ? 0 : (UInt32.max << (32 - prefix))
            return (network & mask) == (targetInt & mask)
        }

        let selectorV4 = parseIpv4(selector)
        let targetV4 = parseIpv4(target)
        if selectorV4 != nil || targetV4 != nil {
            return selectorV4 != nil && selectorV4 == targetV4
        }
        return normalizeIpv6(selector) == normalizeIpv6(target)
    }

    /// Parses dotted-quad IPv4 into its 32-bit value; nil when malformed.
    private func parseIpv4(_ value: String) -> UInt32? {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count != 4 { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard let octet = Int(part), (0...255).contains(octet) else { return nil }
            result = (result << 8) | UInt32(octet)
        }
        return result
    }

    private func normalizeIpv6(_ value: String) -> String {
        var v = value
        if v.hasPrefix("[") { v.removeFirst() }
        if v.hasSuffix("]") { v.removeLast() }
        return v.lowercased()
    }

    private func matchesProtocolType(_ selectorValue: String, _ protocolType: ProtocolType) -> Bool {
        protocolType.rawValue.caseInsensitiveCompare(selectorValue.trimmingCharacters(in: .whitespacesAndNewlines)) == .orderedSame
    }
}
