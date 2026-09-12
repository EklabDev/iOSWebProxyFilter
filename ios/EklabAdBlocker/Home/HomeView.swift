import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var vpn: VpnManager
    @StateObject private var model = HomeViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Traffic Inspector")
                        .font(.largeTitle.bold())

                    Card {
                        VStack(spacing: 12) {
                            Text(vpn.isRunning ? "Protection is on" : "Protection is off")
                                .font(.title2.weight(.semibold))
                                .foregroundStyle(vpn.isRunning ? Color.accentColor : Color.secondary)
                            Toggle("", isOn: Binding(
                                get: { vpn.isRunning },
                                set: { enabled in
                                    Task { await vpn.setEnabled(enabled) }
                                }
                            ))
                            .labelsHidden()
                            Text(
                                vpn.isRunning
                                    ? "Traffic on this device is being inspected locally."
                                    : "Turn on to inspect and filter traffic locally."
                            )
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            if let err = vpn.lastError {
                                Text(err)
                                    .font(.footnote)
                                    .foregroundStyle(.red)
                                    .multilineTextAlignment(.center)
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Today").font(.headline)
                            StatRow(label: "Connections", value: "\(model.stats.connectionCount)")
                            Divider()
                            StatRow(label: "Blocked", value: "\(model.stats.blockedCount)")
                            Divider()
                            StatRow(label: "Data inspected", value: formatBytes(model.stats.totalBytes))
                        }
                    }

                    Card {
                        HStack(alignment: .center) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Block QUIC").font(.headline)
                                Text("Blocks UDP/443, forcing apps back to inspectable HTTPS.")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Toggle("", isOn: Binding(
                                get: { model.blockQuic },
                                set: { model.setBlockQuic($0) }
                            ))
                            .labelsHidden()
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Known limitations").font(.headline)
                            Text("IPv6 traffic bypasses the tunnel and is neither inspected nor logged.")
                            Text("Packet tunnels cannot identify the originating app, so APP rules never match.")
                            Text("DoH/DoT queries are invisible; enable Block QUIC and use SNI rules.")
                            Text("Network Extension flows have no TCP half-close; a client FIN closes the upstream.")
                            Text("The tunnel extension is memory-capped (~50 MB).")
                        }
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    }

                    Text("Connection history is kept for 7 days and processed only on this device.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(24)
            }
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

private struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}

private struct StatRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value)
        }
        .font(.body)
    }
}
