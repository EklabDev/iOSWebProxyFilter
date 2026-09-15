import WidgetKit

enum ProtectionWidgets {
    static func reload() {
        WidgetCenter.shared.reloadTimelines(ofKind: AppConstants.protectionWidgetKind)
        ControlCenter.shared.reloadControls(ofKind: AppConstants.protectionControlKind)
    }
}
