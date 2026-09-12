import Foundation

/// Owns one VPN session: packet loop, relays, rule checks, logging, maintenance.
public final class VpnPipeline: @unchecked Sendable {
    public static let maintenanceInterval: TimeInterval = 1.0

    private let packetLoop: PacketLoop
    private let tracker: FlowTracker
    private let logBuffer: ConnectionLogBuffer
    private let rulesStore: RulesStore
    private let settings: SettingsStore
    private let ruleEngine: RuleEngine
    private var lastRulesVersion: Int = -1
    private var running = false
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "dev.eklab.adblocker.pipeline")

    public init(
        tunWriter: TunWriting,
        ruleEngine: RuleEngine,
        rulesStore: RulesStore,
        settings: SettingsStore,
        connectionsStore: ConnectionsStore,
        factory: OutboundSessionFactory
    ) {
        self.ruleEngine = ruleEngine
        self.rulesStore = rulesStore
        self.settings = settings
        let cache = IpHostnameCache()
        let logBuffer = ConnectionLogBuffer(
            batchSize: 200,
            flushIntervalMs: 3_000,
            flushSink: { logs in connectionsStore.insertAll(logs) }
        )
        self.logBuffer = logBuffer
        let tracker = FlowTracker(logBuffer: logBuffer)
        self.tracker = tracker
        let evaluator = VerdictEvaluator(ruleEngine: ruleEngine, settings: settings, ipHostnameCache: cache)
        self.packetLoop = PacketLoop(
            tunWriter: tunWriter,
            tracker: tracker,
            evaluator: evaluator,
            ipHostnameCache: cache,
            factory: factory
        )
    }

    public func handlePacket(_ data: Data) {
        packetLoop.handlePacket(data)
    }

    public func start() {
        running = true
        reloadRulesIfNeeded(force: true)
        settings.reload()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.maintenanceInterval, repeating: Self.maintenanceInterval)
        timer.setEventHandler { [weak self] in
            self?.tick()
        }
        timer.resume()
        self.timer = timer
    }

    public func stop() {
        running = false
        timer?.cancel()
        timer = nil
        tracker.closeAll()
        logBuffer.flush()
    }

    private func tick() {
        settings.reload()
        reloadRulesIfNeeded(force: false)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        tracker.reap(nowMs: now)
        if logBuffer.due(now) {
            logBuffer.flush()
        }
    }

    private func reloadRulesIfNeeded(force: Bool) {
        let version = rulesStore.rulesVersion()
        if force || version != lastRulesVersion {
            lastRulesVersion = version
            ruleEngine.updateRules(rulesStore.getAll())
        }
    }
}
