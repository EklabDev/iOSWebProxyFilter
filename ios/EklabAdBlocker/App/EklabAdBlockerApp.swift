import SwiftUI

@main
struct EklabAdBlockerApp: App {
    @StateObject private var vpn = VpnManager()

    init() {
        RetentionScheduler.register()
        RetentionScheduler.pruneNow()
        RetentionScheduler.schedule()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vpn)
        }
    }
}
