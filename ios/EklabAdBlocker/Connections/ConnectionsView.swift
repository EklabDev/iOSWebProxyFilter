import SwiftUI

struct ConnectionsView: View {
    @StateObject private var model = ConnectionsViewModel()

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle("Blocked only", isOn: Binding(
                        get: { model.blockedOnly },
                        set: { model.setBlockedOnly($0) }
                    ))
                }
                if model.logs.isEmpty {
                    Text("No connections recorded yet.")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.logs) { log in
                    Button {
                        model.selected = log
                    } label: {
                        ConnectionRow(log: log)
                    }
                    .buttonStyle(.plain)
                    .onAppear {
                        if log.id == model.logs.last?.id {
                            model.loadMore()
                        }
                    }
                }
            }
            .navigationTitle("Connections")
            .searchable(text: Binding(
                get: { model.search },
                set: { model.setSearch($0) }
            ), prompt: "Search host or IP")
            .refreshable { model.reload(reset: true) }
            .sheet(item: $model.selected) { log in
                ConnectionDetailSheet(
                    log: log,
                    onDismiss: { model.selected = nil },
                    onCreateRule: {
                        model.selected = nil
                        let host = log.sni ?? log.dnsHostname ?? log.resolvedHostname
                        if let host {
                            model.ruleDraft = RuleDraft(selectorType: .host, selectorValue: host)
                        } else {
                            model.ruleDraft = RuleDraft(selectorType: .ip, selectorValue: log.destIp)
                        }
                    }
                )
            }
            .sheet(isPresented: Binding(
                get: { model.ruleDraft != nil },
                set: { if !$0 { model.ruleDraft = nil } }
            )) {
                if let draft = model.ruleDraft {
                    RuleEditView(
                        initial: draft,
                        hostSuggestions: model.hostSuggestions,
                        onPreview: model.previewMatchCount,
                        onConfirm: { rule in
                            model.addRule(rule)
                            model.ruleDraft = nil
                        },
                        onCancel: { model.ruleDraft = nil }
                    )
                }
            }
        }
    }
}

private struct ConnectionRow: View {
    let log: ConnectionLog

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(log.displayHost)
                    .font(.body)
                    .lineLimit(1)
                Spacer()
                Text(relativeTime(log.timestamp))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text("\(log.destIp):\(log.destPort)")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            HStack(spacing: 8) {
                ProtocolBadge(protocolType: log.protocolType)
                Image(systemName: log.blocked ? "xmark.octagon.fill" : "checkmark.circle.fill")
                    .foregroundStyle(log.blocked ? Color.red : Color.green)
                    .font(.caption)
                Text(formatBytes(log.bytesSent + log.bytesReceived))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct ConnectionDetailSheet: View {
    let log: ConnectionLog
    let onDismiss: () -> Void
    let onCreateRule: () -> Void

    var body: some View {
        NavigationStack {
            List {
                DetailRow(label: "App", value: log.appName ?? "—")
                DetailRow(label: "Package", value: log.appPackage ?? "—")
                DetailRow(label: "UID", value: "\(log.uid)")
                DetailRow(label: "Time", value: formatTimestamp(log.timestamp))
                DetailRow(label: "Protocol", value: log.protocolType.rawValue)
                DetailRow(label: "Destination", value: "\(log.destIp):\(log.destPort)")
                DetailRow(label: "SNI", value: log.sni ?? "—")
                DetailRow(label: "DNS hostname", value: log.dnsHostname ?? "—")
                DetailRow(label: "Resolved hostname", value: log.resolvedHostname ?? "—")
                DetailRow(label: "Bytes sent", value: formatBytes(log.bytesSent))
                DetailRow(label: "Bytes received", value: formatBytes(log.bytesReceived))
                DetailRow(label: "Duration", value: "\(log.durationMs) ms")
                DetailRow(label: "Verdict", value: log.blocked ? "Blocked" : "Allowed")
                DetailRow(label: "Matched rule", value: log.matchedRuleId.map(String.init) ?? "—")
                DetailRow(label: "Log ID", value: "\(log.id)")
            }
            .navigationTitle("Connection details")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: onDismiss)
                }
            }
            .safeAreaInset(edge: .bottom) {
                Button("Create block rule from this connection", action: onCreateRule)
                    .buttonStyle(.borderedProminent)
                    .padding()
                    .frame(maxWidth: .infinity)
            }
        }
        .presentationDetents([.medium, .large])
    }
}

private struct DetailRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary).frame(width: 140, alignment: .leading)
            Text(value)
        }
    }
}
