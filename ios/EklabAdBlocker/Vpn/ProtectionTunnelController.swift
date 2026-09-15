import AppIntents
import Foundation
import NetworkExtension

enum ProtectionTunnelError: Error, LocalizedError, CustomLocalizedStringResourceConvertible {
    case simulator
    case noProfile
    case underlying(String)

    var errorDescription: String? {
        switch self {
        case .simulator:
            return "VPN is not available in the iOS Simulator."
        case .noProfile:
            return "Turn on protection in the app first to create the VPN profile."
        case .underlying(let message):
            return message
        }
    }

    var localizedStringResource: LocalizedStringResource {
        LocalizedStringResource(stringLiteral: errorDescription ?? "Unable to update protection.")
    }
}

/// Starts or stops the existing packet-tunnel profile without creating one.
/// Used by the home-screen widget and Control Center toggle.
enum ProtectionTunnelController {
    static func setEnabled(_ enabled: Bool) async throws {
#if targetEnvironment(simulator)
        throw ProtectionTunnelError.simulator
#else
        let managers = try await loadAll()
        guard let mgr = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == AppConstants.tunnelBundleId
        }) else {
            throw ProtectionTunnelError.noProfile
        }
        do {
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
        } catch {
            throw ProtectionTunnelError.underlying(error.localizedDescription)
        }
        persist(enabled: enabled)
        ProtectionWidgets.reload()
#endif
    }

    static func persist(enabled: Bool) {
        SettingsStore().setProtectionEnabled(enabled)
    }

    static func currentEnabled() -> Bool {
        SettingsStore().protectionEnabled
    }

#if !targetEnvironment(simulator)
    private static func loadAll() async throws -> [NETunnelProviderManager] {
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

    private static func save(_ mgr: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            mgr.saveToPreferences { error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume() }
            }
        }
    }

    private static func load(_ mgr: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            mgr.loadFromPreferences { error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume() }
            }
        }
    }
#endif
}
