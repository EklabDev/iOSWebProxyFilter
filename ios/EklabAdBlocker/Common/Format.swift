import Foundation

func formatBytes(_ bytes: Int64) -> String {
    if bytes < 1024 { return "\(bytes) B" }
    let units = ["KB", "MB", "GB", "TB"]
    var value = Double(bytes)
    var unit = -1
    repeat {
        value /= 1024.0
        unit += 1
    } while value >= 1024.0 && unit < units.count - 1
    return String(format: "%.1f %@", value, units[unit])
}

func relativeTime(_ timestamp: Int64, now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> String {
    let seconds = max(0, now - timestamp) / 1000
    let minutes = seconds / 60
    let hours = minutes / 60
    let days = hours / 24
    if seconds < 60 { return "just now" }
    if minutes < 60 { return "\(minutes)m ago" }
    if hours < 24 { return "\(hours)h ago" }
    return "\(days)d ago"
}

func formatTimestamp(_ timestamp: Int64) -> String {
    let date = Date(timeIntervalSince1970: Double(timestamp) / 1000.0)
    let fmt = DateFormatter()
    fmt.dateFormat = "MMM d, yyyy HH:mm:ss"
    return fmt.string(from: date)
}

func startOfTodayMillis() -> Int64 {
    let start = Calendar.current.startOfDay(for: Date())
    return Int64(start.timeIntervalSince1970 * 1000)
}
