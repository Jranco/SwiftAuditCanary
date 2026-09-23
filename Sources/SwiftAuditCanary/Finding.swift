import Foundation
import Combine

/// A single thing a linked third-party library was able to observe or reach
/// while running inside the host app's process, with the host app's sandbox
/// and entitlements.
public struct Finding {
    public enum Severity: String, CaseIterable {
        case info, low, medium, high, critical
    }

    public let probe: String
    public let severity: Severity
    public let title: String
    public let detail: String

    public init(probe: String, severity: Severity, title: String, detail: String) {
        self.probe = probe
        self.severity = severity
        self.title = title
        self.detail = detail
    }
}

/// Anything a probe reaches, a real malicious dependency could exfiltrate silently.
protocol Probe {
    var name: String { get }
    /// A synchronous, point-in-time snapshot — everything this probe can see
    /// right now, in one shot.
    func run() -> [Finding]
}

/// A probe that can keep watching after `run()` returns, for as long as
/// `AuditCanary.startMonitoring()` is active — discovering *new* things over
/// the life of the process instead of only at the moment it's called.
///
/// Not every probe can genuinely do this. Some OS surfaces push a real change
/// notification (`UserDefaults`, the pasteboard), the network probe is
/// inherently event-driven (it observes every request as it's made), but
/// others have no push signal at all — the keychain and the sandbox
/// container — so their `LiveProbe` conformance polls and diffs on an
/// interval instead of reacting to anything. `BundleSecretProbe`
/// deliberately has no `LiveProbe` conformance: `Bundle.main`'s resources
/// are fixed for the life of the process, so there is nothing to observe
/// changing, ever — re-scanning it on any cadence would always return the
/// same answer.
protocol LiveProbe: Probe {
    /// Start watching. Call `emit` for each *new* finding as it's discovered —
    /// implementations should not re-emit something already reported by
    /// `run()` or by a previous call to `emit`. Monitoring stops when the
    /// returned token is cancelled or deallocated.
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable
}
