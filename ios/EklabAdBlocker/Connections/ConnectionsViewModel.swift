import Foundation
import Combine

@MainActor
final class ConnectionsViewModel: ObservableObject {
    @Published var logs: [ConnectionLog] = []
    @Published var search = ""
    @Published var blockedOnly = false
    @Published var hostSuggestions: [String] = []
    @Published var selected: ConnectionLog?
    @Published var ruleDraft: RuleDraft?

    private let services = AppServices.shared
    private let pageSize = 50
    private var loaded = 0
    private var hasMore = true
    private var timer: Timer?
    private var searchTask: Task<Void, Never>?

    init() {
        reload(reset: true)
        hostSuggestions = services.connections.distinctHosts(since: RetentionPolicy().cutoffMillis())
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.reload(reset: false) }
        }
    }

    deinit { timer?.invalidate() }

    func setSearch(_ value: String) {
        search = value
        searchTask?.cancel()
        searchTask = Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            if Task.isCancelled { return }
            await MainActor.run { self.reload(reset: true) }
        }
    }

    func setBlockedOnly(_ enabled: Bool) {
        blockedOnly = enabled
        reload(reset: true)
    }

    func loadMore() {
        guard hasMore else { return }
        let more = services.connections.pagedFeed(
            hostQuery: trimmedQuery,
            blockedOnly: blockedOnly,
            limit: pageSize,
            offset: loaded
        )
        logs.append(contentsOf: more)
        loaded += more.count
        hasMore = more.count == pageSize
    }

    func reload(reset: Bool) {
        if reset {
            loaded = 0
            hasMore = true
            logs = []
        }
        let page = services.connections.pagedFeed(
            hostQuery: trimmedQuery,
            blockedOnly: blockedOnly,
            limit: max(pageSize, loaded == 0 ? pageSize : loaded),
            offset: 0
        )
        logs = page
        loaded = page.count
        hasMore = page.count >= pageSize && (reset ? page.count == pageSize : true)
        hostSuggestions = services.connections.distinctHosts(since: RetentionPolicy().cutoffMillis())
    }

    func addRule(_ rule: Rule) {
        _ = services.rules.insert(rule)
        services.engine.updateRules(services.rules.getAll())
    }

    func previewMatchCount(selectorType: SelectorType, selectorValue: String) -> Int {
        services.rules.previewMatchCount(
            selectorType: selectorType,
            selectorValue: selectorValue,
            engine: services.engine,
            logs: services.connections.recentForPreview()
        )
    }

    private var trimmedQuery: String? {
        let q = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return q.isEmpty ? nil : q
    }
}

struct RuleDraft: Equatable {
    var name: String = ""
    var selectorType: SelectorType = .host
    var selectorValue: String = ""
    var action: RuleAction = .block
    var priority: Int = 100
}
