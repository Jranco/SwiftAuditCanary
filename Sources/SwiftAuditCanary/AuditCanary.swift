import Foundation
import Combine

/// A deliberately "malicious" third-party library you add to your OWN app.
///
/// Because iOS provides no isolation between an app and the libraries it links,
/// this package runs with the host app's full sandbox and entitlements — exactly
/// like any SDK you pull in via SPM or CocoaPods. It then reports everything a real
/// rogue dependency could have reached, with no jailbreak and nothing injected at
/// runtime, because *you* embedded it at build time.
///
/// Two ways to run it:
///
///     #if DEBUG
///     AuditCanary.run(config: .init(outputs: [.console, .onScreen]))          // one-shot snapshot
///     AuditCanary.startMonitoring(config: .init(outputs: [.console]))          // snapshot + keeps watching
///     #endif
///
/// `run(config:)` is a synchronous, point-in-time audit: every probe is asked
/// "what can you see right now", once. `startMonitoring(config:)` does that same
/// baseline pass, then keeps every probe that supports continuous observation
/// (see `LiveProbe`) running for the rest of the process, publishing anything
/// newly discovered — a UserDefaults write, a clipboard change, an outbound
/// request, a new keychain item or sandbox file — to `findingsPublisher` and to
/// `config.outputs`, as it happens, not just the next time you call `run()`.
public enum AuditCanary {

    /// Findings discovered by live-monitoring probes, for the life of the
    /// process. `run()`'s return value is a synchronous baseline snapshot;
    /// this is where anything discovered *afterward* — while monitoring is
    /// active — arrives, in real time, as it happens. Always delivered on
    /// the main queue.
    public static let findingsPublisher = PassthroughSubject<Finding, Never>()

    private static var monitors: Set<AnyCancellable> = []
    private static var reporterSink: AnyCancellable?

    @discardableResult
    public static func run(config: AuditCanaryConfig = AuditCanaryConfig()) -> [Finding] {
        let findings = Self.probes(for: config).flatMap { $0.run() }
        Reporter.emit(findings, to: config.outputs)
        return findings
    }

    /// Takes the same baseline snapshot as `run()`, then starts continuous
    /// observation for the rest of the process:
    ///
    /// - `userDefaults` and `pasteboard` react to real system change
    ///   notifications (`UserDefaults.didChangeNotification`,
    ///   `UIPasteboard.changedNotification`) — genuine push signals, no polling.
    /// - `network` streams every intercepted request live, as it happens.
    /// - `keychain` and `container` have no OS-level push signal reachable
    ///   this way, so they poll and diff every `pollInterval` seconds instead.
    /// - `bundleSecrets` is always one-shot only — `Bundle.main` is fixed for
    ///   the process, so there's nothing to watch.
    ///
    /// New findings are published on `findingsPublisher` and routed live to
    /// `config.outputs`, so `.onScreen` / `.webhook` / `.file` / `.console`
    /// all see things as they're discovered instead of only at the next
    /// manual `run()`.
    ///
    /// Call `stopMonitoring()` to tear everything down; calling
    /// `startMonitoring` again restarts cleanly.
    @discardableResult
    public static func startMonitoring(
        config: AuditCanaryConfig = AuditCanaryConfig(),
        pollInterval: TimeInterval = 15
    ) -> [Finding] {
        stopMonitoring()

        let allProbes = Self.probes(for: config, pollInterval: pollInterval)
        let baseline = allProbes.flatMap { $0.run() }
        Reporter.emit(baseline, to: config.outputs)

        for probe in allProbes {
            guard let live = probe as? LiveProbe else { continue }
            live.startObserving { finding in
                DispatchQueue.main.async {
                    findingsPublisher.send(finding)
                }
            }.store(in: &monitors)
        }

        reporterSink = findingsPublisher.sink { finding in
            Reporter.emitLive(finding, to: config.outputs)
        }

        return baseline
    }

    /// Stops all live observation started by `startMonitoring()`. Safe to
    /// call even if monitoring was never started. `run()` is unaffected.
    public static func stopMonitoring() {
        monitors.forEach { $0.cancel() }
        monitors.removeAll()
        reporterSink?.cancel()
        reporterSink = nil
    }

    /// Add term(s) to the `userDefaults` probe's suspicious list at runtime, on top of the
    /// built-in baseline (and anything passed via `additionalSuspiciousTerms` in `run(config:)`).
    /// The terms stick for the rest of the process, so the intended flow is:
    ///
    ///     AuditCanary.run()                                   // baseline pass
    ///     // ...update UserDefaults in your app...
    ///     AuditCanary.addSuspiciousTerms(["newFeatureFlag"])   // now watch for this too
    ///     AuditCanary.run()                                   // re-run, picks up the new term
    ///
    /// Call as many times as you like; terms accumulate rather than replace.
    /// If monitoring is active, terms you add apply the next time a probe is
    /// (re)started — call `startMonitoring` again to pick them up immediately.
    public static func addSuspiciousTerms(_ terms: [String]) {
        UserDefaultsProbe.addSuspiciousTerms(terms)
    }

    /// Clears runtime-added suspicious terms (the built-in baseline is unaffected).
    public static func resetSuspiciousTerms() {
        UserDefaultsProbe.resetSuspiciousTerms()
    }

    private static func probes(for config: AuditCanaryConfig, pollInterval: TimeInterval = 15) -> [Probe] {
        var probes: [Probe] = []
        if config.probes.contains(.keychain)      { probes.append(KeychainProbe(pollInterval: pollInterval)) }
        if config.probes.contains(.pasteboard)    { probes.append(PasteboardProbe()) }
        if config.probes.contains(.container)     { probes.append(ContainerProbe(pollInterval: pollInterval)) }
        if config.probes.contains(.userDefaults) {
            probes.append(UserDefaultsProbe(additionalSuspiciousTerms: config.additionalSuspiciousTerms))
        }
        if config.probes.contains(.bundleSecrets) { probes.append(BundleSecretProbe()) }
        if config.probes.contains(.network)       { probes.append(NetworkProbe()) }
        return probes
    }
}
