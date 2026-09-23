import Foundation
#if canImport(UIKit)
import UIKit
#endif

enum Reporter {

    // MARK: - Batch path (used by `run()` and the baseline pass of `startMonitoring()`)

    static func emit(_ findings: [Finding], to outputs: [AuditCanaryConfig.Output]) {
        let text = render(findings)
        for output in outputs {
            switch output {
            case .console:
                print(text)
            case .file(let url):
                try? text.data(using: .utf8)?.write(to: url)
            case .onScreen:
                presentOnScreen(text)
            case .webhook(let url):
                exfiltrate(text, to: url)
            case .server(let port):
                LocalServer.start(port: port)?.broadcast(text)
            }
        }
    }

    static func render(_ findings: [Finding]) -> String {
        var out = "=== AuditCanary report ===\n"
        out += "A linked third-party library just ran with your app's full permissions.\n"
        out += "Everything below is what it could reach. A real malicious SDK could exfiltrate it silently.\n\n"

        let order: [Finding.Severity] = [.critical, .high, .medium, .low, .info]
        let grouped = Dictionary(grouping: findings, by: { $0.probe })
        for probe in grouped.keys.sorted() {
            out += "## \(probe)\n"
            let sorted = grouped[probe]!.sorted {
                (order.firstIndex(of: $0.severity) ?? 99) < (order.firstIndex(of: $1.severity) ?? 99)
            }
            for f in sorted {
                out += "  [\(f.severity.rawValue.uppercased())] \(f.title)\n"
                for line in f.detail.split(separator: "\n") {
                    out += "        \(line)\n"
                }
            }
            out += "\n"
        }
        return out
    }

    #if canImport(UIKit)
    static func presentOnScreen(_ text: String) {
        DispatchQueue.main.async {
            guard let scene = UIApplication.shared.connectedScenes
                    .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
                  let root = scene.windows.first(where: { $0.isKeyWindow })?.rootViewController else { return }

            let vc = UIViewController()
            vc.view.backgroundColor = .systemBackground

            let textView = UITextView()
            textView.translatesAutoresizingMaskIntoConstraints = false
            textView.isEditable = false
            textView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            textView.text = text

            let close = UIButton(type: .system)
            close.translatesAutoresizingMaskIntoConstraints = false
            close.setTitle("Close", for: .normal)
            close.addAction(UIAction { [weak vc] _ in vc?.dismiss(animated: true) }, for: .touchUpInside)

            vc.view.addSubview(textView)
            vc.view.addSubview(close)
            NSLayoutConstraint.activate([
                close.topAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.topAnchor, constant: 8),
                close.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -16),
                textView.topAnchor.constraint(equalTo: close.bottomAnchor, constant: 8),
                textView.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor, constant: 12),
                textView.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -12),
                textView.bottomAnchor.constraint(equalTo: vc.view.bottomAnchor)
            ])

            (root.presentedViewController ?? root).present(vc, animated: true)
        }
    }
    #else
    static func presentOnScreen(_ text: String) { print(text) }
    #endif

    /// The concrete "capture → send" step a real malicious SDK performs. Fire-and-forget
    /// POST of the report to a caller-supplied endpoint. Opt-in only; point it at a
    /// server you control. A rogue lib would additionally hide this and encrypt the body.
    private static func exfiltrate(_ text: String, to url: URL) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("text/plain; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("AuditCanary", forHTTPHeaderField: "X-Canary")
        request.httpBody = text.data(using: .utf8)
        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                NSLog("[canary] webhook send failed: \(error.localizedDescription)")
            } else if let http = response as? HTTPURLResponse {
                NSLog("[canary] webhook sent report → HTTP \(http.statusCode)")
            }
        }.resume()
    }

    // MARK: - Live path (used by `startMonitoring()` as probes discover new things)

    /// Delivers a single, newly-discovered finding to every configured output,
    /// as it happens — the counterpart to `emit(_:to:)` for continuous
    /// monitoring. `.console`/`.file`/`.webhook`/`.server` each just handle
    /// one line; `.onScreen` appends to the same overlay instead of
    /// re-presenting one per finding.
    static func emitLive(_ finding: Finding, to outputs: [AuditCanaryConfig.Output]) {
        let line = renderLine(finding)
        for output in outputs {
            switch output {
            case .console:
                print(line)
            case .file(let url):
                appendLine(line, to: url)
            case .onScreen:
                #if canImport(UIKit)
                LiveOverlay.shared.append(line)
                #else
                print(line)
                #endif
            case .webhook(let url):
                exfiltrate(line, to: url)
            case .server(let port):
                LocalServer.start(port: port)?.broadcast(line)
            }
        }
    }

    private static func renderLine(_ f: Finding) -> String {
        var line = "[\(f.severity.rawValue.uppercased())] \(f.probe): \(f.title)"
        if !f.detail.isEmpty {
            for detailLine in f.detail.split(separator: "\n") {
                line += "\n        \(detailLine)"
            }
        }
        return line
    }

    private static func appendLine(_ line: String, to url: URL) {
        let data = (line + "\n").data(using: .utf8) ?? Data()
        if FileManager.default.fileExists(atPath: url.path), let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            handle.seekToEndOfFile()
            handle.write(data)
        } else {
            try? data.write(to: url)
        }
    }
}

#if canImport(UIKit)
/// Keeps a single on-screen overlay alive across a live-monitoring session,
/// appending new lines to it instead of presenting a fresh one per finding.
private final class LiveOverlay {
    static let shared = LiveOverlay()

    private weak var textView: UITextView?
    private var buffer = ""

    func append(_ line: String) {
        DispatchQueue.main.async {
            self.buffer += line + "\n"
            if let textView = self.textView {
                textView.text = self.buffer
                textView.scrollRangeToVisible(NSRange(location: (self.buffer as NSString).length, length: 0))
            } else {
                self.present()
            }
        }
    }

    private func present() {
        guard let scene = UIApplication.shared.connectedScenes
                .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
              let root = scene.windows.first(where: { $0.isKeyWindow })?.rootViewController else { return }

        let vc = UIViewController()
        vc.view.backgroundColor = .systemBackground

        let textView = UITextView()
        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.text = buffer

        let close = UIButton(type: .system)
        close.translatesAutoresizingMaskIntoConstraints = false
        close.setTitle("Close", for: .normal)
        close.addAction(UIAction { [weak vc, weak self] _ in
            vc?.dismiss(animated: true)
            self?.textView = nil
        }, for: .touchUpInside)

        vc.view.addSubview(textView)
        vc.view.addSubview(close)
        NSLayoutConstraint.activate([
            close.topAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.topAnchor, constant: 8),
            close.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -16),
            textView.topAnchor.constraint(equalTo: close.bottomAnchor, constant: 8),
            textView.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor, constant: 12),
            textView.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -12),
            textView.bottomAnchor.constraint(equalTo: vc.view.bottomAnchor)
        ])

        (root.presentedViewController ?? root).present(vc, animated: true)
        self.textView = textView
    }
}
#endif
