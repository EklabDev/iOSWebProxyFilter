import Foundation
import NetworkExtension

/// Packet-tunnel provider: IPv4-only inspector with virtual DNS at 10.0.0.1.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var pipeline: VpnPipeline?
    private var reading = false
    private lazy var database = Database()
    private lazy var rulesStore = RulesStore(db: database)
    private lazy var connectionsStore = ConnectionsStore(db: database)
    private lazy var settings = SettingsStore()
    private let ruleEngine = RuleEngineImpl()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        _ = RetentionPolicy().cutoffMillis()
        connectionsStore.prune(cutoff: RetentionPolicy().cutoffMillis())
        ruleEngine.updateRules(rulesStore.getAll())

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: TunnelConfig.tunAddress)
        settings.mtu = NSNumber(value: TunnelConfig.mtu)
        let ipv4 = NEIPv4Settings(addresses: [TunnelConfig.tunAddress], subnetMasks: [TunnelConfig.subnetMask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: [TunnelConfig.virtualDNS])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                completionHandler(error)
                return
            }
            if let error {
                completionHandler(error)
                return
            }
            let writer = PacketFlowWriter(flow: self.packetFlow)
            let factory = ProviderSessionFactory(provider: self)
            let pipeline = VpnPipeline(
                tunWriter: writer,
                ruleEngine: self.ruleEngine,
                rulesStore: self.rulesStore,
                settings: self.settings,
                connectionsStore: self.connectionsStore,
                factory: factory
            )
            self.pipeline = pipeline
            pipeline.start()
            self.reading = true
            self.readLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        reading = false
        pipeline?.stop()
        pipeline = nil
        completionHandler()
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.reading else { return }
            for packet in packets {
                self.pipeline?.handlePacket(packet)
            }
            if self.reading {
                self.readLoop()
            }
        }
    }
}
