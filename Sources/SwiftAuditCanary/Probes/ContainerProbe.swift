import Foundation
import Combine

/// Walks the app's sandbox container looking for files a data-hungry SDK would
/// love: databases, Core Data stores, plists, keys, credentials.
struct ContainerProbe: Probe {
    let name = "AppContainer"

    /// How often `startObserving` re-walks the container. There's no
    /// tree-wide change notification reachable this way, so "live" here
    /// means polling and diffing, not a real push signal.
    let pollInterval: TimeInterval

    init(pollInterval: TimeInterval = 15) {
        self.pollInterval = pollInterval
    }

    private static let sensitiveExt: Set<String> = [
        "sqlite", "sqlite3", "db", "realm", "store",
        "plist", "json", "keychain", "pem", "p12", "key", "cer", "crt"
    ]

    func run() -> [Finding] {
        let hits = Self.scan()

        if hits.isEmpty {
            return [Finding(
                probe: name, severity: .info,
                title: "No obviously sensitive files found",
                detail: NSHomeDirectory()
            )]
        }
        return [Finding(
            probe: name, severity: .medium,
            title: "\(hits.count) sensitive file(s) readable in the app container",
            detail: hits.prefix(20).joined(separator: "\n")
        )]
    }

    /// One synchronous walk of the sandbox, capped at 5000 entries scanned so
    /// it stays cheap on large containers (same cap `run()` always used).
    static func scan() -> [String] {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var hits: [String] = []

        if let enumerator = fm.enumerator(atPath: home) {
            var scanned = 0
            for case let path as String in enumerator {
                scanned += 1
                if scanned > 5000 { break }
                let ext = (path as NSString).pathExtension.lowercased()
                if sensitiveExt.contains(ext) { hits.append(path) }
            }
        }
        return hits
    }
}

// MARK: - Live monitoring (polling — no OS push signal for this)

extension ContainerProbe: LiveProbe {
    /// No API notifies an app when a new file appears anywhere in its own
    /// sandbox, so this polls `scan()` every `pollInterval` seconds and
    /// diffs against the last pass, only emitting genuinely new files.
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable {
        var seen = Set(Self.scan())

        return Timer.publish(every: pollInterval, on: .main, in: .common)
            .autoconnect()
            .sink { _ in
                let current = Set(Self.scan())
                let newPaths = current.subtracting(seen)
                seen = current
                guard !newPaths.isEmpty else { return }

                emit(Finding(
                    probe: "AppContainer", severity: .medium,
                    title: "\(newPaths.count) new sensitive file(s) appeared in the app container",
                    detail: newPaths.sorted().prefix(20).joined(separator: "\n")
                ))
            }
    }
}
