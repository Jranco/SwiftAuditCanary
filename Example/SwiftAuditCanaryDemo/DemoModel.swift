import Foundation
import Combine
import UIKit
import SwiftAuditCanary

/// Drives the demo: builds an `AuditCanaryConfig` from the UI toggles, runs the
/// package both ways (sync `run` and async `startMonitoring`), and collects
/// findings for display.
final class DemoModel: ObservableObject {

    // MARK: Probe selection
    @Published var keychain = true
    @Published var pasteboard = true
    @Published var container = true
    @Published var userDefaults = true
    @Published var bundleSecrets = true
    @Published var network = true

    // MARK: Output selection
    @Published var outConsole = true
    @Published var outOnScreen = false
    @Published var outFile = false
    @Published var outServer = false
    @Published var serverPort = "8080"
    @Published var outWebhook = false
    @Published var webhookURL = "https://example.com/collect"

    // MARK: Config
    @Published var extraTerms = "stripeCustomerId, deviceSecret"
    @Published var pollInterval: Double = 15
    @Published var excludedHosts = ""   // hosts the network probe must not touch

    // MARK: State
    @Published private(set) var isMonitoring = false
    @Published private(set) var findings: [LoggedFinding] = []
    @Published private(set) var fileReport = ""

    private var cancellable: AnyCancellable?

    struct LoggedFinding: Identifiable {
        let id = UUID()
        let finding: Finding
        let at = Date()
        let live: Bool
    }

    // MARK: Config assembly

    private func selectedProbes() -> AuditCanaryConfig.Probes {
        var p: AuditCanaryConfig.Probes = []
        if keychain      { p.insert(.keychain) }
        if pasteboard    { p.insert(.pasteboard) }
        if container     { p.insert(.container) }
        if userDefaults  { p.insert(.userDefaults) }
        if bundleSecrets { p.insert(.bundleSecrets) }
        if network       { p.insert(.network) }
        return p
    }

    private func selectedOutputs() -> [AuditCanaryConfig.Output] {
        var o: [AuditCanaryConfig.Output] = []
        if outConsole  { o.append(.console) }
        if outOnScreen { o.append(.onScreen) }
        if outFile     { o.append(.file(Self.reportFileURL)) }
        if outServer, let port = UInt16(serverPort) { o.append(.server(port: port)) }
        if outWebhook, let url = URL(string: webhookURL) { o.append(.webhook(url)) }
        return o.isEmpty ? [.console] : o   // always have at least one sink
    }

    private func terms() -> [String] {
        extraTerms
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private func excludedHostList() -> [String] {
        excludedHosts
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private func makeConfig() -> AuditCanaryConfig {
        AuditCanaryConfig(
            outputs: selectedOutputs(),
            probes: selectedProbes(),
            additionalSuspiciousTerms: terms(),
            excludedHosts: excludedHostList()
        )
    }

    static var reportFileURL: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("audit.txt")
    }

    // MARK: Actions

    /// Sync, point-in-time snapshot. Replaces the list with what the probes
    /// can see right now.
    func runOnce() {
        let results = AuditCanary.run(config: makeConfig())
        findings = results.map { LoggedFinding(finding: $0, live: false) }
        refreshFileReport()
    }

    /// Async: same baseline, then keeps watching. New findings arrive on
    /// `findingsPublisher` (delivered on the main queue by the package).
    func startMonitoring() {
        stopMonitoring()
        let baseline = AuditCanary.startMonitoring(config: makeConfig(), pollInterval: pollInterval)
        findings = baseline.map { LoggedFinding(finding: $0, live: false) }
        cancellable = AuditCanary.findingsPublisher.sink { [weak self] finding in
            self?.findings.append(LoggedFinding(finding: finding, live: true))
            self?.refreshFileReport()
        }
        isMonitoring = true
    }

    func stopMonitoring() {
        AuditCanary.stopMonitoring()
        cancellable?.cancel()
        cancellable = nil
        isMonitoring = false
    }

    // Suspicious-term runtime API
    func addTermsLive()  { AuditCanary.addSuspiciousTerms(terms()) }
    func resetTerms()    { AuditCanary.resetSuspiciousTerms() }

    func clearFindings() { findings.removeAll() }

    // MARK: Live triggers (meaningful while monitoring)

    /// Fires an outbound request so the `network` probe emits a live finding.
    func makeSampleRequest() {
        guard let url = URL(string: "https://example.com/api/session?token=demo123") else { return }
        URLSession.shared.dataTask(with: url).resume()
    }

    /// Writes a new UserDefaults secret — triggers the `userDefaults` live probe.
    func mutateUserDefaults() {
        UserDefaults.standard.set(
            "eyJhbGci.\(Int.random(in: 1000...9999)).demo",
            forKey: "authToken_\(Int.random(in: 0...999))")
    }

    /// Changes the clipboard — triggers the `pasteboard` live probe.
    func mutatePasteboard() {
        UIPasteboard.general.string = "otp \(Int.random(in: 100000...999999))"
    }

    private func refreshFileReport() {
        guard outFile else { return }
        fileReport = (try? String(contentsOf: Self.reportFileURL, encoding: .utf8)) ?? "(empty)"
    }
}
