import AppIntents

struct ToggleProtectionIntent: SetValueIntent {
    static var title: LocalizedStringResource = "Toggle Protection"
    static var description = IntentDescription("Turn Traffic Inspector protection on or off.")
    static var openAppWhenRun = false

    @Parameter(title: "Protection")
    var value: Bool

    init() {
        self.value = false
    }

    init(value: Bool) {
        self.value = value
    }

    func perform() async throws -> some IntentResult {
        try await ProtectionTunnelController.setEnabled(value)
        return .result()
    }
}
