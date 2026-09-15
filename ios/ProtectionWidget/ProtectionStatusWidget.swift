import WidgetKit
import SwiftUI
import AppIntents

struct ProtectionEntry: TimelineEntry {
    let date: Date
    let isOn: Bool
}

struct ProtectionProvider: TimelineProvider {
    func placeholder(in context: Context) -> ProtectionEntry {
        ProtectionEntry(date: Date(), isOn: true)
    }

    func getSnapshot(in context: Context, completion: @escaping (ProtectionEntry) -> Void) {
        completion(ProtectionEntry(date: Date(), isOn: ProtectionTunnelController.currentEnabled()))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<ProtectionEntry>) -> Void) {
        let entry = ProtectionEntry(date: Date(), isOn: ProtectionTunnelController.currentEnabled())
        let next = Date().addingTimeInterval(15 * 60)
        completion(Timeline(entries: [entry], policy: .after(next)))
    }
}

struct ProtectionStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: AppConstants.protectionWidgetKind, provider: ProtectionProvider()) { entry in
            ProtectionWidgetView(entry: entry)
        }
        .configurationDisplayName("Protection")
        .description("Turn Traffic Inspector on or off.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct ProtectionWidgetView: View {
    var entry: ProtectionEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Traffic Inspector", systemImage: entry.isOn ? "checkmark.shield.fill" : "shield")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(entry.isOn ? "Protection is on" : "Protection is off")
                .font(.headline)
            Toggle(isOn: entry.isOn, intent: ToggleProtectionIntent())
                .labelsHidden()
            Text(
                entry.isOn
                    ? "Traffic on this device is being inspected locally."
                    : "Turn on to inspect and filter traffic locally."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }
}

#Preview(as: .systemSmall) {
    ProtectionStatusWidget()
} timeline: {
    ProtectionEntry(date: .now, isOn: true)
    ProtectionEntry(date: .now, isOn: false)
}
