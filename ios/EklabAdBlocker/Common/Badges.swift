import SwiftUI

struct ProtocolBadge: View {
    let protocolType: ProtocolType

    var color: Color {
        switch protocolType {
        case .https: return Color(red: 0.18, green: 0.49, blue: 0.20)
        case .http: return Color(red: 0.08, green: 0.40, blue: 0.75)
        case .dns: return Color(red: 0.42, green: 0.11, blue: 0.60)
        case .quic: return Color(red: 0.94, green: 0.42, blue: 0.00)
        case .otherTcp, .otherUdp: return Color(red: 0.33, green: 0.43, blue: 0.48)
        }
    }

    var body: some View {
        Text(protocolType.rawValue)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
    }
}

struct ActionBadge: View {
    let action: RuleAction

    var color: Color {
        switch action {
        case .block: return Color(red: 0.83, green: 0.18, blue: 0.18)
        case .allow: return Color(red: 0.18, green: 0.49, blue: 0.20)
        }
    }

    var body: some View {
        Text(action.rawValue)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
    }
}
