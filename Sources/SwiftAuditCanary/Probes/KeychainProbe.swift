import Foundation
import Security
import Combine

/// Enumerates keychain items reachable from inside the host app.
/// Note: this lists item *attributes* (account/service) to demonstrate the exposure —
/// it deliberately does not dump secret bytes.
struct KeychainProbe: Probe {
    let name = "Keychain"

    /// How often `startObserving` re-scans the keychain. There is no OS-level
    /// change notification for arbitrary keychain items reachable from an
    /// app's normal API surface, so "live" here means polling and diffing,
    /// not a real push signal.
    let pollInterval: TimeInterval

    init(pollInterval: TimeInterval = 15) {
        self.pollInterval = pollInterval
    }

    private static let classes: [(CFString, String)] = [
        (kSecClassGenericPassword,  "GenericPassword"),
        (kSecClassInternetPassword, "InternetPassword"),
        (kSecClassCertificate,      "Certificate"),
        (kSecClassKey,              "Key"),
        (kSecClassIdentity,         "Identity")
    ]

    /// One keychain item's attributes, plus a stable-enough identity for diffing between scans.
    struct Item: Hashable {
        let label: String
        let account: String?
        let service: String?

        var identifier: String { "\(label)|\(account ?? "—")|\(service ?? "—")" }
    }

    func run() -> [Finding] {
        let items = Self.scan()
        var findings: [Finding] = []

        if items.isEmpty {
            findings.append(Finding(
                probe: name, severity: .info,
                title: "No keychain items readable",
                detail: "Nothing accessible with this app's keychain access groups."
            ))
        } else {
            findings.append(Finding(
                probe: name, severity: .high,
                title: "\(items.count) keychain item(s) readable by a linked SDK",
                detail: "Any embedded dependency can enumerate these with no user prompt."
            ))

            let grouped = Dictionary(grouping: items, by: { $0.label })
            for (_, label) in Self.classes {
                guard let group = grouped[label] else { continue }
                for item in group.prefix(25) {
                    findings.append(Finding(
                        probe: name, severity: .high,
                        title: "\(item.label) readable",
                        detail: "account=\(item.account ?? "—") service=\(item.service ?? "—")"
                    ))
                }
            }
        }
        return findings
    }

    /// One synchronous pass over every keychain class this probe checks.
    static func scan() -> [Item] {
        var items: [Item] = []
        for (cls, label) in classes {
            let query: [String: Any] = [
                kSecClass as String: cls,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll
            ]
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            guard status == errSecSuccess, let raw = result as? [[String: Any]] else { continue }

            for item in raw {
                let account = item[kSecAttrAccount as String] as? String
                let service = (item[kSecAttrService as String] as? String)
                    ?? (item[kSecAttrServer as String] as? String)
                items.append(Item(label: label, account: account, service: service))
            }
        }
        return items
    }
}

// MARK: - Live monitoring (polling — no OS push signal for this)

extension KeychainProbe: LiveProbe {
    /// No API notifies an app when an arbitrary keychain item is added, so
    /// this polls `scan()` every `pollInterval` seconds and diffs against
    /// what's been seen already, only emitting genuinely new items.
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable {
        var seen = Set(Self.scan().map { $0.identifier })

        return Timer.publish(every: pollInterval, on: .main, in: .common)
            .autoconnect()
            .sink { _ in
                let current = Self.scan()
                let currentIDs = Set(current.map { $0.identifier })
                let newIDs = currentIDs.subtracting(seen)
                seen = currentIDs
                guard !newIDs.isEmpty else { return }

                let newItems = current.filter { newIDs.contains($0.identifier) }
                emit(Finding(
                    probe: "Keychain", severity: .high,
                    title: "\(newItems.count) new keychain item(s) appeared",
                    detail: newItems
                        .map { "\($0.label): account=\($0.account ?? "—") service=\($0.service ?? "—")" }
                        .joined(separator: "\n")
                ))
            }
    }
}
