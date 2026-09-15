import Foundation

/// User settings backed by the App Group UserDefaults suite.
public final class SettingsStore: @unchecked Sendable {
    private let defaults: UserDefaults
    private let lock = NSLock()
    private var _blockQuic: Bool
    private var _protectionEnabled: Bool

    public init(defaults: UserDefaults = AppGroup.userDefaults) {
        self.defaults = defaults
        self._blockQuic = defaults.bool(forKey: AppConstants.blockQuicKey)
        self._protectionEnabled = defaults.bool(forKey: AppConstants.protectionEnabledKey)
    }

    public var blockQuic: Bool {
        lock.lock(); defer { lock.unlock() }
        return _blockQuic
    }

    public func setBlockQuic(_ enabled: Bool) {
        defaults.set(enabled, forKey: AppConstants.blockQuicKey)
        lock.lock(); _blockQuic = enabled; lock.unlock()
    }

    public var protectionEnabled: Bool {
        lock.lock(); defer { lock.unlock() }
        return _protectionEnabled
    }

    public func setProtectionEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: AppConstants.protectionEnabledKey)
        lock.lock(); _protectionEnabled = enabled; lock.unlock()
    }

    /// Re-read from disk. Called by the extension on its 1s maintenance tick.
    public func reload() {
        let quic = defaults.bool(forKey: AppConstants.blockQuicKey)
        let protection = defaults.bool(forKey: AppConstants.protectionEnabledKey)
        lock.lock()
        _blockQuic = quic
        _protectionEnabled = protection
        lock.unlock()
    }
}
