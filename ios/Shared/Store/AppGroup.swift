import Foundation

/// App Group container helpers shared by the app and the packet-tunnel extension.
public enum AppGroup {
    public static var containerURL: URL {
        #if os(iOS)
        if let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AppConstants.appGroup
        ) {
            return url
        }
        #endif
        let fallback = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = fallback.appendingPathComponent("TrafficInspector", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var databaseURL: URL {
        containerURL.appendingPathComponent(AppConstants.dbName)
    }

    public static var userDefaults: UserDefaults {
        UserDefaults(suiteName: AppConstants.settingsSuite) ?? .standard
    }
}
