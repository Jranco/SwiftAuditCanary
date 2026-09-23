import Foundation
import Combine

/// Dumps UserDefaults keys — a very common (and wrong) place to stash tokens.
struct UserDefaultsProbe: Probe {
    let name = "UserDefaults"

    /// Baseline terms, always active.
    private static let defaultSuspicious = [
        "token", "password", "passwd", "secret", "auth", "session",
        "apikey", "api_key", "key", "credential", "jwt", "bearer", "refresh"
    ]

    /// Terms added at runtime via `addSuspiciousTerms(_:)`. Persists across probe
    /// instances/runs (in-process only — resets on next launch) so you can keep adding
    /// terms as you explore: update UserDefaults, add the new key/value fragment you're
    /// now worried about, and re-run the canary — no need to resupply everything you
    /// already added.
    private static var runtimeSuspicious: Set<String> = []

    /// Baseline + accumulated runtime terms + whatever this particular run was configured with.
    private let suspicious: [String]

    /// A JWT looks like three dot-separated base64url segments — this catches a token
    /// stashed under an innocuous key name, where the *value* is what gives it away.
    private static let jwtPattern = try? NSRegularExpression(
        pattern: #"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"#
    )

    init(additionalSuspiciousTerms: [String] = []) {
        var terms = Set(Self.defaultSuspicious)
        terms.formUnion(Self.runtimeSuspicious)
        terms.formUnion(additionalSuspiciousTerms.map { $0.lowercased() })
        self.suspicious = Array(terms)
    }

    /// Add one or more terms to the running set used by every `UserDefaultsProbe` created
    /// from now on (in this process) — including ones spun up by a later `AuditCanary.run()`
    /// call. Lets you iterate without re-specifying the full list each time: add a term,
    /// re-run, add another, re-run again.
    static func addSuspiciousTerms(_ terms: [String]) {
        runtimeSuspicious.formUnion(terms.map { $0.lowercased() })
    }

    /// Drops runtime-added terms (leaves the built-in baseline untouched). Useful between
    /// unrelated test passes so old terms don't bleed into a fresh investigation.
    static func resetSuspiciousTerms() {
        runtimeSuspicious.removeAll()
    }

    func run() -> [Finding] {
        let dict = UserDefaults.standard.dictionaryRepresentation()
        var findings: [Finding] = [
            Finding(probe: name, severity: .info,
                    title: "\(dict.count) UserDefaults key(s) readable", detail: "")
        ]

        let flaggedKeys = Self.flaggedKeys(in: dict, suspicious: suspicious)
        if !flaggedKeys.isEmpty {
            findings.append(Finding(
                probe: name, severity: .high,
                title: "\(flaggedKeys.count) suspicious key name(s) — possible secrets in plaintext",
                detail: flaggedKeys.joined(separator: ", ")
            ))
        }

        let flaggedValues = Self.flaggedValueKeys(in: dict, suspicious: suspicious)
        if !flaggedValues.isEmpty {
            findings.append(Finding(
                probe: name, severity: .high,
                title: "\(flaggedValues.count) key(s) with suspicious-looking value(s) — possible secrets in plaintext",
                detail: flaggedValues.joined(separator: ", ")
            ))
        }

        return findings
    }

    /// Key *names* that look suspicious, sorted.
    private static func flaggedKeys(in dict: [String: Any], suspicious: [String]) -> [String] {
        dict.keys.filter { key in
            let lk = key.lowercased()
            return suspicious.contains { lk.contains($0) }
        }.sorted()
    }

    /// Keys whose *value's content* looks suspicious, sorted.
    private static func flaggedValueKeys(in dict: [String: Any], suspicious: [String]) -> [String] {
        dict.compactMap { key, value -> String? in
            isSuspiciousValue(value, suspicious: suspicious) ? key : nil
        }.sorted()
    }

    /// Does this value's *content* look like a secret, regardless of what the key is called?
    private static func isSuspiciousValue(_ value: Any, suspicious: [String]) -> Bool {
        guard let text = stringify(value), !text.isEmpty else { return false }

        let lv = text.lowercased()
        if suspicious.contains(where: { lv.contains($0) }) { return true }

        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        if let jwtPattern = jwtPattern, jwtPattern.firstMatch(in: text, range: range) != nil {
            return true
        }

        return false
    }

    /// Best-effort string form of a UserDefaults value so it can be pattern-matched.
    private static func stringify(_ value: Any) -> String? {
        switch value {
        case let s as String:
            return s
        case let n as NSNumber:
            return n.stringValue
        default:
            return nil
        }
    }
}

// MARK: - Live monitoring

extension UserDefaultsProbe: LiveProbe {
    /// Reacts to `UserDefaults.didChangeNotification` — a real system push
    /// signal fired on every write, so this is genuine continuous
    /// observation, not polling. Only *newly* flagged keys/values (not
    /// already surfaced by `run()` or a previous change) are emitted.
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable {
        let initial = UserDefaults.standard.dictionaryRepresentation()
        var seenFlaggedKeys = Set(Self.flaggedKeys(in: initial, suspicious: suspicious))
        var seenFlaggedValueKeys = Set(Self.flaggedValueKeys(in: initial, suspicious: suspicious))

        return NotificationCenter.default
            .publisher(for: UserDefaults.didChangeNotification)
            .sink { [suspicious] _ in
                let dict = UserDefaults.standard.dictionaryRepresentation()

                let flaggedNow = Set(Self.flaggedKeys(in: dict, suspicious: suspicious))
                let newKeys = flaggedNow.subtracting(seenFlaggedKeys)
                seenFlaggedKeys = flaggedNow
                if !newKeys.isEmpty {
                    emit(Finding(
                        probe: "UserDefaults", severity: .high,
                        title: "\(newKeys.count) new suspicious UserDefaults key(s)",
                        detail: newKeys.sorted().joined(separator: ", ")
                    ))
                }

                let flaggedValuesNow = Set(Self.flaggedValueKeys(in: dict, suspicious: suspicious))
                let newValueKeys = flaggedValuesNow.subtracting(seenFlaggedValueKeys)
                seenFlaggedValueKeys = flaggedValuesNow
                if !newValueKeys.isEmpty {
                    emit(Finding(
                        probe: "UserDefaults", severity: .high,
                        title: "\(newValueKeys.count) key(s) with new suspicious-looking value(s)",
                        detail: newValueKeys.sorted().joined(separator: ", ")
                    ))
                }
            }
    }
}
