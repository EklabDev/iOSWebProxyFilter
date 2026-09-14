import Foundation
import Combine
import NetworkExtension

@MainActor
final class VpnManager: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published var lastError: String?

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    var isRunning: Bool {
        switch status {
        case .connected, .connecting, .reasserting: return true
        default: return false
        }
    }

    init() {
#if targetEnvironment(simulator)
        status = .disconnected
        lastError = "VPN is not available in the iOS Simulator. Run on a physical device to use Traffic Inspector."
#else
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] note in
            Task { @MainActor in
                if let conn = note.object as? NEVPNConnection {
                    self?.status = conn.status
                }
            }
        }
        Task { await reload() }
#endif
    }

    deinit {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func reload() async {
#if targetEnvironment(simulator)
        status = .disconnected
        lastError = "VPN is not available in the iOS Simulator. Run on a physical device to use Traffic Inspector."
#else
        do {
            let managers = try await loadAll()
            let existing = managers.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == AppConstants.tunnelBundleId
            }
            manager = existing
            status = existing?.connection.status ?? .invalid
        } catch {
            lastError = error.localizedDescription
        }
#endif
    }

    func setEnabled(_ enabled: Bool) async {
#if targetEnvironment(simulator)
        status = .disconnected
        lastError = "VPN is not available in the iOS Simulator. Run on a physical device to use Traffic Inspector."
#else
        lastError = nil
        do {
            let mgr = try await ensureManager()
            if enabled {
                mgr.isEnabled = true
                mgr.isOnDemandEnabled = true
                try await save(mgr)
                try await load(mgr)
                if mgr.connection.status != .connected {
                    try mgr.connection.startVPNTunnel()
                }
            } else {
                mgr.isOnDemandEnabled = false
                try await save(mgr)
                mgr.connection.stopVPNTunnel()
            }
            status = mgr.connection.status
        } catch {
            lastError = error.localizedDescription
        }
#endif
    }

#if !targetEnvironment(simulator)
    private func ensureManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }
        await reload()
        if let manager { return manager }

        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConstants.tunnelBundleId
        proto.serverAddress = TunnelConfig.tunAddress
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "Traffic Inspector"
        mgr.isEnabled = true

        let connect = NEOnDemandRuleConnect()
        connect.interfaceTypeMatch = .any
        mgr.onDemandRules = [connect]
        mgr.isOnDemandEnabled = true

        try await save(mgr)
        try await load(mgr)
        manager = mgr
        return mgr
    }

    private func loadAll() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { cont in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func save(_ mgr: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            mgr.saveToPreferences { error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume() }
            }
        }
    }

    private func load(_ mgr: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            mgr.loadFromPreferences { error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume() }
            }
        }
    }
#endif
}
