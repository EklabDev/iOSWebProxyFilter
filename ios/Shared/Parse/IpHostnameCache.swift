import Foundation

/// Thread-safe bounded LRU map from IP address string to hostname.
public final class IpHostnameCache: @unchecked Sendable {
    public static let defaultCapacity = 512

    private let maxCapacity: Int
    private let lock = NSLock()
    private var map: [String: String] = [:]
    private var order: [String] = []

    public init(maxCapacity: Int = IpHostnameCache.defaultCapacity) {
        self.maxCapacity = maxCapacity
    }

    public func put(_ ip: String, hostname: String) {
        if ip.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return }
        if hostname.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return }
        lock.lock()
        defer { lock.unlock() }
        if map[ip] != nil {
            order.removeAll { $0 == ip }
        }
        map[ip] = hostname
        order.append(ip)
        while order.count > maxCapacity {
            let eldest = order.removeFirst()
            map.removeValue(forKey: eldest)
        }
    }

    public func get(_ ip: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard map[ip] != nil else { return nil }
        order.removeAll { $0 == ip }
        order.append(ip)
        return map[ip]
    }

    public var size: Int {
        lock.lock()
        defer { lock.unlock() }
        return map.count
    }

    public func clear() {
        lock.lock()
        map.removeAll()
        order.removeAll()
        lock.unlock()
    }
}
