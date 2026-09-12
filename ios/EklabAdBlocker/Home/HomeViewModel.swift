import Foundation
import Combine

@MainActor
final class HomeViewModel: ObservableObject {
    @Published var stats = TodayStats()
    @Published var blockQuic: Bool

    private let services = AppServices.shared
    private var timer: Timer?

    init() {
        blockQuic = services.settings.blockQuic
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    deinit { timer?.invalidate() }

    func refresh() {
        stats = services.connections.todayStats(since: startOfTodayMillis())
        blockQuic = services.settings.blockQuic
    }

    func setBlockQuic(_ enabled: Bool) {
        services.settings.setBlockQuic(enabled)
        blockQuic = enabled
    }
}
