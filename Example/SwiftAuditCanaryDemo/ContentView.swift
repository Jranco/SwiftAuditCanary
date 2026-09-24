import SwiftUI
import SwiftAuditCanary

struct ContentView: View {
    @StateObject private var model = DemoModel()

    var body: some View {
        NavigationStack {
            Form {
                seedSection
                probesSection
                outputsSection
                networkExclusionsSection
                termsSection
                runSection
                if model.isMonitoring { liveTriggersSection }
                if model.outFile && !model.fileReport.isEmpty { fileSection }
                findingsSection
            }
            .navigationTitle("SwiftAuditCanary")
        }
    }

    // MARK: 1 · Seed

    private var seedSection: some View {
        Section {
            Button("Seed sensitive demo data") { DemoSeeder.seedAll() }
            Text("Plants fake secrets in UserDefaults, Keychain, the clipboard and the sandbox so the probes have something to find.")
                .font(.footnote).foregroundStyle(.secondary)
        } header: { Text("1 · Seed") }
    }

    // MARK: 2 · Probes

    private var probesSection: some View {
        Section {
            Toggle("keychain", isOn: $model.keychain)
            Toggle("pasteboard", isOn: $model.pasteboard)
            Toggle("container", isOn: $model.container)
            Toggle("userDefaults", isOn: $model.userDefaults)
            Toggle("bundleSecrets", isOn: $model.bundleSecrets)
            Toggle("network", isOn: $model.network)
        } header: { Text("2 · Probes") }
    }

    // MARK: 3 · Outputs

    private var outputsSection: some View {
        Section {
            Toggle("console", isOn: $model.outConsole)
            Toggle("onScreen (overlay)", isOn: $model.outOnScreen)
            Toggle("file (silent, to Caches)", isOn: $model.outFile)
            Toggle("server (SSE, all interfaces)", isOn: $model.outServer)
            if model.outServer {
                LabeledContent("port") {
                    TextField("8080", text: $model.serverPort)
                        .keyboardType(.numberPad).multilineTextAlignment(.trailing)
                }
            }
            Toggle("webhook (POST)", isOn: $model.outWebhook)
            if model.outWebhook {
                TextField("https://…", text: $model.webhookURL)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            Text("server needs NSLocalNetworkUsageDescription in Info.plist (included). Point webhook only at a server you control.")
                .font(.footnote).foregroundStyle(.secondary)
        } header: { Text("3 · Outputs") }
    }

    // MARK: Network exclusions

    private var networkExclusionsSection: some View {
        Section {
            TextField("api.mybank.com, auth.mybank.com", text: $model.excludedHosts)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
            Text("Hosts the network probe leaves untouched. Use for mTLS / cert-pinned endpoints whose TLS the interceptor can't reproduce.")
                .font(.footnote).foregroundStyle(.secondary)
        } header: { Text("Network exclusions") }
    }

    // MARK: 4 · Suspicious terms

    private var termsSection: some View {
        Section {
            TextField("comma,separated,terms", text: $model.extraTerms)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
            HStack {
                Button("Add live") { model.addTermsLive() }
                Spacer()
                Button("Reset") { model.resetTerms() }.foregroundStyle(.red)
            }
            Text("Flagged in UserDefaults key names and values, on top of the built-in list.")
                .font(.footnote).foregroundStyle(.secondary)
        } header: { Text("4 · Suspicious terms") }
    }

    // MARK: 5 · Run

    private var runSection: some View {
        Section {
            Button("Run once (sync snapshot)") { model.runOnce() }
            if model.isMonitoring {
                Button("Stop monitoring") { model.stopMonitoring() }
                    .foregroundStyle(.red)
            } else {
                Button("Start monitoring (async)") { model.startMonitoring() }
            }
            Stepper("poll interval: \(Int(model.pollInterval))s",
                    value: $model.pollInterval, in: 2...60, step: 1)
            Text("Sync = one snapshot. Monitoring = baseline snapshot, then keeps watching (keychain/container re-poll at the interval above; userDefaults/pasteboard/network are event-driven).")
                .font(.footnote).foregroundStyle(.secondary)
        } header: { Text("5 · Run") }
    }

    // MARK: Live triggers

    private var liveTriggersSection: some View {
        Section {
            Button("Make outbound request → network") { model.makeSampleRequest() }
            Button("Write a UserDefaults secret → userDefaults") { model.mutateUserDefaults() }
            Button("Change clipboard → pasteboard") { model.mutatePasteboard() }
        } header: { Text("Live triggers") } footer: {
            Text("While monitoring, these produce findings you'll see appear below in real time.")
        }
    }

    // MARK: File report

    private var fileSection: some View {
        Section {
            Text(model.fileReport)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
        } header: { Text("Silent file report (proves quiet capture)") }
    }

    // MARK: Findings

    private var findingsSection: some View {
        Section {
            if model.findings.isEmpty {
                Text("No findings yet — seed data, then Run or Start monitoring.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.findings.reversed()) { logged in
                    FindingRow(logged: logged)
                }
                Button("Clear") { model.clearFindings() }.foregroundStyle(.red)
            }
        } header: {
            HStack {
                Text("Findings (\(model.findings.count))")
                if model.isMonitoring {
                    Spacer()
                    Label("live", systemImage: "dot.radiowaves.left.and.right")
                        .font(.caption).foregroundStyle(.green)
                }
            }
        }
    }
}

private struct FindingRow: View {
    let logged: DemoModel.LoggedFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(logged.finding.severity.rawValue.uppercased())
                    .font(.caption2).bold()
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(color.opacity(0.2))
                    .foregroundStyle(color)
                    .clipShape(Capsule())
                Text(logged.finding.probe).font(.caption).foregroundStyle(.secondary)
                if logged.live {
                    Text("live").font(.caption2).foregroundStyle(.green)
                }
            }
            Text(logged.finding.title).font(.subheadline).bold()
            if !logged.finding.detail.isEmpty {
                Text(logged.finding.detail)
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(4)
            }
        }
        .padding(.vertical, 2)
    }

    private var color: Color {
        switch logged.finding.severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .gray
        }
    }
}

#Preview {
    ContentView()
}
