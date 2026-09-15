import SwiftUI

struct RuleEditView: View {
    let initial: RuleDraft
    let hostSuggestions: [String]
    let onPreview: (SelectorType, String) -> Int
    let onConfirm: (Rule) -> Void
    let onCancel: () -> Void

    @State private var selectorType: SelectorType
    @State private var value: String
    @State private var action: RuleAction
    @State private var priorityText: String
    @State private var name: String
    @State private var nameTouched: Bool
    @State private var previewCount: Int?
    @State private var previewLoading = false
    @State private var previewTask: Task<Void, Never>?

    init(
        initial: RuleDraft,
        hostSuggestions: [String],
        onPreview: @escaping (SelectorType, String) -> Int,
        onConfirm: @escaping (Rule) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.initial = initial
        self.hostSuggestions = hostSuggestions
        self.onPreview = onPreview
        self.onConfirm = onConfirm
        self.onCancel = onCancel
        _selectorType = State(initialValue: initial.selectorType)
        _value = State(initialValue: initial.selectorValue)
        _action = State(initialValue: initial.action)
        _priorityText = State(initialValue: String(initial.priority))
        _name = State(initialValue: initial.name)
        _nameTouched = State(initialValue: !initial.name.isEmpty)
    }

    private let selectorLabels: [(SelectorType, String)] = [
        (.app, "App"),
        (.host, "Exact host"),
        (.hostSuffix, "Domain & subdomains"),
        (.ip, "IP or CIDR"),
        (.type, "Traffic type"),
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section("Match") {
                    Picker("Selector", selection: $selectorType) {
                        ForEach(selectorLabels, id: \.0) { type, label in
                            Text(label).tag(type)
                        }
                    }
                    .onChange(of: selectorType) {
                        if !nameTouched { name = autoName(selectorType, value) }
                        schedulePreview()
                    }

                    TextField(valuePlaceholder, text: $value)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: value) {
                            if !nameTouched { name = autoName(selectorType, value) }
                            schedulePreview()
                        }

                    if !suggestionItems.isEmpty {
                        ForEach(suggestionItems, id: \.0) { suggestion, display in
                            Button(display) {
                                value = suggestion
                                if !nameTouched { name = autoName(selectorType, suggestion) }
                                schedulePreview()
                            }
                        }
                    }

                    if let error = valueError, !value.isEmpty {
                        Text(error).foregroundStyle(.red).font(.footnote)
                    }
                }

                Section("Action") {
                    Picker("Action", selection: $action) {
                        Text("Block").tag(RuleAction.block)
                        Text("Allow").tag(RuleAction.allow)
                    }
                    .pickerStyle(.segmented)
                }

                Section {
                    TextField("Rule name", text: Binding(
                        get: { name },
                        set: { name = $0; nameTouched = true }
                    ))
                    TextField("Priority (lower runs first)", text: $priorityText)
                        .keyboardType(.numberPad)
                }

                Section {
                    Text(previewText)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Add rule")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        guard canConfirm, let priority else { return }
                        onConfirm(Rule(
                            name: name.trimmingCharacters(in: .whitespaces),
                            enabled: true,
                            priority: priority,
                            selectorType: selectorType,
                            selectorValue: trimmedValue,
                            action: action
                        ))
                    }
                    .disabled(!canConfirm)
                }
            }
            .onAppear { schedulePreview() }
        }
    }

    private var trimmedValue: String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var valuePlaceholder: String {
        switch selectorType {
        case .app: return "Bundle ID"
        case .host: return "Host (exact)"
        case .hostSuffix: return "Domain suffix (e.g. .ads.example.com)"
        case .ip: return "IP or CIDR"
        case .type: return "Traffic type"
        }
    }

    private var suggestionItems: [(String, String)] {
        switch selectorType {
        case .host:
            return hostSuggestions.filter { $0.localizedCaseInsensitiveContains(value) }.prefix(8).map { ($0, $0) }
        case .hostSuffix:
            return hostSuggestions.filter { $0.localizedCaseInsensitiveContains(value) }.prefix(8).map { (".\($0)", ".\($0)") }
        case .type:
            return ProtocolType.allCases.map(\.rawValue)
                .filter { value.isEmpty || $0.localizedCaseInsensitiveContains(value) }
                .map { ($0, $0) }
        case .app, .ip:
            return []
        }
    }

    private var valueError: String? {
        if trimmedValue.isEmpty { return "Value is required" }
        if selectorType == .ip && !isValidIpOrCidr(trimmedValue) {
            return "Enter an IPv4 address or CIDR (e.g. 203.0.113.0/24)"
        }
        return nil
    }

    private var priority: Int? { Int(priorityText.trimmingCharacters(in: .whitespaces)) }
    private var nameError: Bool { name.trimmingCharacters(in: .whitespaces).isEmpty }
    private var canConfirm: Bool { valueError == nil && !nameError && priority != nil }

    private var previewText: String {
        if valueError != nil { return " " }
        if previewLoading { return "Checking recent history…" }
        if let previewCount {
            return "This rule would have matched \(previewCount) connections in the last 7 days."
        }
        return "Match preview: —"
    }

    private func autoName(_ type: SelectorType, _ v: String) -> String {
        switch type {
        case .type: return "\(v) traffic"
        default: return v
        }
    }

    private func schedulePreview() {
        previewTask?.cancel()
        previewCount = nil
        guard valueError == nil else { return }
        previewLoading = true
        let type = selectorType
        let val = trimmedValue
        previewTask = Task {
            try? await Task.sleep(nanoseconds: 400_000_000)
            if Task.isCancelled { return }
            let count = onPreview(type, val)
            await MainActor.run {
                previewCount = count
                previewLoading = false
            }
        }
    }
}

private func isValidIpOrCidr(_ value: String) -> Bool {
    let parts = value.split(separator: "/", omittingEmptySubsequences: false)
    if parts.count > 2 { return false }
    let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
    guard octets.count == 4 else { return false }
    for octet in octets {
        guard let n = Int(octet), (0...255).contains(n) else { return false }
    }
    if parts.count == 2 {
        guard let prefix = Int(parts[1]), (0...32).contains(prefix) else { return false }
    }
    return true
}
