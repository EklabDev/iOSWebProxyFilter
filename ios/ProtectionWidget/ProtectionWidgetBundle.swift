import WidgetKit
import SwiftUI

@main
struct ProtectionWidgetBundle: WidgetBundle {
    var body: some Widget {
        ProtectionStatusWidget()
        ProtectionControlWidget()
    }
}
