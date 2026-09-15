import AppIntents
import SwiftUI
import WidgetKit

struct ProtectionControlWidget: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(
            kind: AppConstants.protectionControlKind,
            provider: ProtectionControlValueProvider()
        ) { isOn in
            ControlWidgetToggle(
                "Protection",
                isOn: isOn,
                action: ToggleProtectionIntent()
            ) { isOn in
                Label(isOn ? "On" : "Off", systemImage: isOn ? "checkmark.shield.fill" : "shield")
            }
        }
        .displayName("Protection")
        .description("Turn Traffic Inspector on or off.")
    }
}

struct ProtectionControlValueProvider: ControlValueProvider {
    var previewValue: Bool { false }

    func currentValue() async throws -> Bool {
        ProtectionTunnelController.currentEnabled()
    }
}
