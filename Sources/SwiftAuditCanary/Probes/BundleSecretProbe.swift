import Foundation

/// Scans Info.plist and bundled plist/json resources for baked-in secrets.
/// A shipped binary is readable by anything running inside it (and by anyone
/// who unzips the .ipa), so hardcoded keys are effectively public.
struct BundleSecretProbe: Probe {
    let name = "BundleSecrets"

    private let suspiciousKeys = [
        "apikey", "api_key", "secret", "token", "password",
        "clientsecret", "client_secret", "privatekey", "private_key",
        "accesskey", "access_key", "credential"
    ]

    func run() -> [Finding] {
        var findings: [Finding] = []

        if let info = Bundle.main.infoDictionary {
            for (k, v) in info {
                let lk = k.lowercased()
                if suspiciousKeys.contains(where: { lk.contains($0) }),
                   let sv = v as? String, !sv.isEmpty {
                    findings.append(Finding(
                        probe: name, severity: .high,
                        title: "Secret-looking key in Info.plist",
                        detail: "\(k) = \(redact(sv))"
                    ))
                }
            }
        }

        for ext in ["plist", "json"] {
            let urls = Bundle.main.urls(forResourcesWithExtension: ext, subdirectory: nil) ?? []
            for url in urls {
                guard let data = try? Data(contentsOf: url),
                      let text = String(data: data, encoding: .utf8) else { continue }
                let lower = text.lowercased()
                if let match = suspiciousKeys.first(where: { lower.contains($0) }) {
                    findings.append(Finding(
                        probe: name, severity: .medium,
                        title: "Secret-looking token in \(url.lastPathComponent)",
                        detail: "matched \"\(match)\""
                    ))
                }
            }
        }

        if findings.isEmpty {
            findings.append(Finding(probe: name, severity: .info,
                                    title: "No obvious baked-in secrets found", detail: ""))
        }
        return findings
    }

    private func redact(_ s: String) -> String {
        guard s.count > 6 else { return "***" }
        return String(s.prefix(3)) + "***" + String(s.suffix(2))
    }
}
