import Foundation
import Combine
#if canImport(UIKit)
import UIKit
#endif

/// Reads the general pasteboard — the same clipboard other apps copy tokens,
/// passwords, and 2FA codes into.
struct PasteboardProbe: Probe {
    let name = "Pasteboard"

    func run() -> [Finding] {
        #if canImport(UIKit)
        let pb = UIPasteboard.general
        var findings: [Finding] = []

        if let s = pb.string, !s.isEmpty {
            let preview = s.count > 40 ? String(s.prefix(40)) + "…" : s
            findings.append(Finding(
                probe: name, severity: .medium,
                title: "Clipboard text readable",
                detail: "value=\"\(preview)\" (length \(s.count))"
            ))
        }
        if pb.hasURLs {
            findings.append(Finding(probe: name, severity: .low, title: "Clipboard contains URL(s)", detail: ""))
        }
        if pb.hasImages {
            findings.append(Finding(probe: name, severity: .low, title: "Clipboard contains image(s)", detail: ""))
        }
        if findings.isEmpty {
            findings.append(Finding(probe: name, severity: .info, title: "Clipboard empty or unreadable", detail: ""))
        }
        return findings
        #else
        return [Finding(probe: name, severity: .info, title: "Pasteboard unavailable (no UIKit)", detail: "")]
        #endif
    }
}

// MARK: - Live monitoring

#if canImport(UIKit)
extension PasteboardProbe: LiveProbe {
    /// Reacts to `UIPasteboard.changedNotification` — fires whenever the
    /// general pasteboard's contents change while this app has access. This
    /// is exactly how real clipboard-snooping code stays live: subscribe
    /// once, get every subsequent copy for the life of the process, no
    /// polling needed.
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable {
        NotificationCenter.default
            .publisher(for: UIPasteboard.changedNotification, object: UIPasteboard.general)
            .sink { _ in
                let pb = UIPasteboard.general
                if let s = pb.string, !s.isEmpty {
                    let preview = s.count > 40 ? String(s.prefix(40)) + "…" : s
                    emit(Finding(
                        probe: "Pasteboard", severity: .medium,
                        title: "Clipboard changed",
                        detail: "value=\"\(preview)\" (length \(s.count))"
                    ))
                } else if pb.hasImages {
                    emit(Finding(probe: "Pasteboard", severity: .low, title: "Clipboard changed to image content", detail: ""))
                }
            }
    }
}
#else
extension PasteboardProbe: LiveProbe {
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable {
        AnyCancellable {}
    }
}
#endif
