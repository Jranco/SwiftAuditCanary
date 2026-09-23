import Foundation

public struct AuditCanaryConfig {

    /// Where the report goes.
    /// - `.console`: print to stdout / Xcode console.
    /// - `.file`: write to disk (use this to prove silent exfiltration is possible).
    /// - `.onScreen`: present a scrollable overlay (loud, good for live demos).
    /// - `.webhook`: POST the report to a URL. This is the full attacker path
    ///   (capture → send) made concrete. It is NEVER on by default — you must
    ///   pass it explicitly, and you should only ever point it at a server YOU
    ///   control, on a build/device you own. Demonstration only.
    /// - `.server`: start an embedded HTTP server on `port`, bound to every
    ///   interface (not just loopback), that streams findings live to any
    ///   client on the same network via Server-Sent Events — `curl -N
    ///   http://<device-ip>:<port>/` or just open that URL in a browser. The
    ///   "capture → serve" step made concrete with *no* external
    ///   infrastructure at all: no webhook endpoint, no server you control,
    ///   just a nearby attacker. Unlike every other output, this one is
    ///   user-visible: the first incoming connection triggers iOS's Local
    ///   Network permission prompt, and the host app needs
    ///   `NSLocalNetworkUsageDescription` in its Info.plist or the OS
    ///   refuses the connection. Demonstration only.
    public enum Output {
        case console
        case file(URL)
        case onScreen
        case webhook(URL)
        case server(port: UInt16)
    }

    /// Which surfaces to probe.
    public struct Probes: OptionSet {
        public let rawValue: Int
        public init(rawValue: Int) { self.rawValue = rawValue }

        public static let keychain      = Probes(rawValue: 1 << 0)
        public static let pasteboard    = Probes(rawValue: 1 << 1)
        public static let container     = Probes(rawValue: 1 << 2)
        public static let userDefaults  = Probes(rawValue: 1 << 3)
        public static let bundleSecrets = Probes(rawValue: 1 << 4)
        public static let network       = Probes(rawValue: 1 << 5)

        public static let all: Probes = [
            .keychain, .pasteboard, .container, .userDefaults, .bundleSecrets, .network
        ]
    }

    public var outputs: [Output]
    public var probes: Probes

    /// Extra terms to flag in UserDefaults key names and values, on top of the
    /// probe's built-in list (e.g. "stripeCustomerId", "deviceSecret"). Handy for
    /// app-specific field names the generic list won't know about.
    public var additionalSuspiciousTerms: [String]

    public init(
        outputs: [Output] = [.console],
        probes: Probes = .all,
        additionalSuspiciousTerms: [String] = []
    ) {
        self.outputs = outputs
        self.probes = probes
        self.additionalSuspiciousTerms = additionalSuspiciousTerms
    }
}
