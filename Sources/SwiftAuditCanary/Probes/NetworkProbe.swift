import Foundation
import ObjectiveC.runtime
import Combine

/// Full-coverage network interception from inside the host app.
///
/// A single method swizzle only catches one `dataTask` overload. To observe *all*
/// traffic — `URLSession.shared`, custom sessions, `async/await`, delegate-based,
/// upload and download tasks — this installs a `URLProtocol` two ways:
///   1. `URLProtocol.registerClass` — consulted by `URLSession.shared` and NSURLConnection.
///   2. A class-method swizzle of `URLSessionConfiguration.default` / `.ephemeral`
///      that injects the protocol into every session built from those configs.
///
/// This is the same approach used by traffic debuggers (Wormholy, netfox) and by
/// the real-world "SourMint" ad SDK. It only logs; a malicious lib would forward it out.
final class NetworkProbe: Probe {
    let name = "Network"

    static private(set) var interceptedCount = 0
    static private(set) var lastRequest = ""
    private static var installed = false

    /// Set while `startObserving` is active. Called for every intercepted
    /// request so live monitoring sees each request as it happens, instead
    /// of only an aggregate count on the next manual `run()`.
    private static var liveEmit: ((Finding) -> Void)?

    func run() -> [Finding] {
        NetworkProbe.install()

        var detail = "A URLProtocol was registered and URLSessionConfiguration.default/.ephemeral "
        detail += "were swizzled to inject it. Traffic from URLSession.shared, custom sessions, "
        detail += "async/await, delegate, upload and download tasks all flow through this linked SDK."
        if NetworkProbe.interceptedCount > 0 {
            detail += "\nObserved \(NetworkProbe.interceptedCount) request(s). Last: \(NetworkProbe.lastRequest)"
        }
        return [Finding(
            probe: name, severity: .high,
            title: "All outbound traffic can be intercepted",
            detail: detail
        )]
    }

    static func install() {
        guard !installed else { return }
        installed = true
        URLProtocol.registerClass(CanaryURLProtocol.self)
        URLSessionConfiguration.canary_enableProtocolInjection()
    }

    static func record(_ request: URLRequest) {
        interceptedCount += 1
        let method = request.httpMethod ?? "GET"
        let url = request.url?.absoluteString ?? "—"
        lastRequest = "\(method) \(url)"
        NSLog("[canary] intercepted \(method) \(url)")

        liveEmit?(Finding(
            probe: "Network", severity: .high,
            title: "Outbound request intercepted",
            detail: "\(method) \(url)"
        ))
    }
}

// MARK: - Live monitoring (genuinely event-driven — no polling needed)

extension NetworkProbe: LiveProbe {
    /// The interception itself is already always-on once `install()` runs;
    /// this just hooks `record(_:)` so each intercepted request also reaches
    /// `AuditCanary.findingsPublisher` instead of only `NSLog` and a counter.
    func startObserving(emit: @escaping (Finding) -> Void) -> AnyCancellable {
        NetworkProbe.install()
        NetworkProbe.liveEmit = emit
        return AnyCancellable { NetworkProbe.liveEmit = nil }
    }
}

// MARK: - The interceptor

/// Observes each request, then transparently replays it so the app's traffic is
/// unaffected. Recursion is prevented by a per-request "handled" marker.
final class CanaryURLProtocol: URLProtocol, URLSessionDataDelegate {
    private static let handledKey = "CanaryURLProtocolHandled"
    private var proxySession: URLSession?
    private var proxyTask: URLSessionTask?

    override class func canInit(with request: URLRequest) -> Bool {
        if URLProtocol.property(forKey: handledKey, in: request) != nil { return false }
        guard let scheme = request.url?.scheme?.lowercased() else { return false }
        return scheme == "http" || scheme == "https"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        NetworkProbe.record(request)

        guard let mutable = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        // Mark so our own replay request skips canInit (no infinite loop even though
        // the proxy session below is built from the swizzled .default config).
        URLProtocol.setProperty(true, forKey: Self.handledKey, in: mutable)

        proxySession = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        proxyTask = proxySession?.dataTask(with: mutable as URLRequest)
        proxyTask?.resume()
    }

    override func stopLoading() {
        proxyTask?.cancel()
        proxySession?.invalidateAndCancel()
        proxySession = nil
        proxyTask = nil
    }

    // MARK: URLSession delegate — bridge the replay back to the original caller

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        client?.urlProtocol(self, didLoad: data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didCompleteWithError error: Error?) {
        if let error = error {
            client?.urlProtocol(self, didFailWithError: error)
        } else {
            client?.urlProtocolDidFinishLoading(self)
        }
        proxySession?.finishTasksAndInvalidate()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        client?.urlProtocol(self, wasRedirectedTo: request, redirectResponse: response)
        completionHandler(request)
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.performDefaultHandling, nil)
    }
}

// MARK: - Inject the interceptor into every session configuration

extension URLSessionConfiguration {
    private static var canaryInjected = false

    static func canary_enableProtocolInjection() {
        guard !canaryInjected else { return }
        canaryInjected = true
        swizzleClassMethod(Selector(("defaultSessionConfiguration")),
                           #selector(canary_defaultConfiguration))
        swizzleClassMethod(Selector(("ephemeralSessionConfiguration")),
                           #selector(canary_ephemeralConfiguration))
    }

    private static func swizzleClassMethod(_ original: Selector, _ swizzled: Selector) {
        let cls: AnyClass = URLSessionConfiguration.self
        guard let o = class_getClassMethod(cls, original),
              let s = class_getClassMethod(cls, swizzled) else { return }
        method_exchangeImplementations(o, s)
    }

    // After the swap these names call the ORIGINAL implementations.
    @objc private class func canary_defaultConfiguration() -> URLSessionConfiguration {
        let config = canary_defaultConfiguration()
        config.canary_inject()
        return config
    }

    @objc private class func canary_ephemeralConfiguration() -> URLSessionConfiguration {
        let config = canary_ephemeralConfiguration()
        config.canary_inject()
        return config
    }

    private func canary_inject() {
        var classes = protocolClasses ?? []
        if !classes.contains(where: { $0 == CanaryURLProtocol.self }) {
            classes.insert(CanaryURLProtocol.self, at: 0)
            protocolClasses = classes
        }
    }
}
