import Foundation

/// Computes the 7-day retention cutoff.
public struct RetentionPolicy: Sendable {
    public static let retentionDays: Int64 = 7
    private static let millisPerDay: Int64 = 24 * 60 * 60 * 1000

    public var nowMs: @Sendable () -> Int64
    public var retentionDays: Int64

    public init(
        nowMs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
        retentionDays: Int64 = RetentionPolicy.retentionDays
    ) {
        self.nowMs = nowMs
        self.retentionDays = retentionDays
    }

    /// Rows with timestamp strictly older than this value must be pruned.
    public func cutoffMillis(_ now: Int64? = nil) -> Int64 {
        (now ?? nowMs()) - retentionDays * Self.millisPerDay
    }
}
