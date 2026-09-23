import Foundation
import Network

/// The "capture → serve" step made concrete without any external
/// infrastructure at all: a plain listening socket inside the host app,
/// reachable by anyone on the same network — no webhook endpoint, no server
/// you control, just a nearby attacker and a browser.
///
/// Serves `GET /` as a Server-Sent Events stream (`text/event-stream`), so
/// `curl -N http://<device-ip>:<port>/` or opening that URL in any browser
/// shows every finding as it's reported, live. A newly-connected client is
/// first replayed the last ~200 lines already sent, so it isn't starting
/// from nothing.
///
/// Bound to all interfaces (not just loopback) — that's the whole point of
/// the demonstration. iOS surfaces this: the first incoming connection from
/// another device triggers the system's Local Network permission prompt,
/// and the host app needs `NSLocalNetworkUsageDescription` in its
/// Info.plist or the OS silently refuses the connection. Every other probe
/// in this package runs with no user-visible prompt at all — this is
/// deliberately the one exception, because *this* is the step where a real
/// rogue SDK would rather stay quiet (e.g. by preferring `.webhook`
/// instead) to avoid exactly this dialog tipping the user off.
final class LocalServer {
    private static var servers: [UInt16: LocalServer] = [:]

    /// Starts (once per port) a server broadcasting to every connected
    /// client. Calling this again for a port already listening just returns
    /// the existing instance. Returns `nil` if the port couldn't be bound
    /// (already in use, out of range, sandboxed away, etc).
    static func start(port: UInt16) -> LocalServer? {
        if let existing = servers[port] { return existing }
        guard let server = LocalServer(port: port) else { return nil }
        servers[port] = server
        return server
    }

    private let listener: NWListener
    private let queue = DispatchQueue(label: "AuditCanary.LocalServer")
    private var clients: [ObjectIdentifier: NWConnection] = [:]
    private var recent: [String] = []

    private init?(port: UInt16) {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        guard let listener = try? NWListener(using: params, on: nwPort) else { return nil }
        self.listener = listener

        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                NSLog("[canary] local server listening on port \(port) — open http://<device-ip>:\(port)/ from another device on the same network")
            case .failed(let error):
                NSLog("[canary] local server on port \(port) failed: \(error)")
            default:
                break
            }
        }
        listener.start(queue: queue)
    }

    private func accept(_ connection: NWConnection) {
        let id = ObjectIdentifier(connection)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.beginStreaming(to: connection, id: id)
            case .failed, .cancelled:
                self?.clients.removeValue(forKey: id)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// Reads (and ignores) whatever the client sent — the HTTP request line
    /// and headers — then responds with an SSE stream regardless of path or
    /// method. This is a demonstration server, not a router.
    private func beginStreaming(to connection: NWConnection, id: ObjectIdentifier) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] _, _, _, _ in
            guard let self else { return }
            let header = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/event-stream\r\n"
                + "Cache-Control: no-cache\r\n"
                + "Connection: keep-alive\r\n"
                + "Access-Control-Allow-Origin: *\r\n\r\n"
            self.write(header, to: connection)
            self.clients[id] = connection
            for line in self.recent {
                self.write(Self.sseFrame(line), to: connection)
            }
        }
    }

    /// Sends `blob` (batch report text or a single live finding line) to
    /// every connected client, and remembers it so the next client to
    /// connect gets caught up.
    func broadcast(_ blob: String) {
        queue.async {
            self.recent.append(blob)
            if self.recent.count > 200 {
                self.recent.removeFirst(self.recent.count - 200)
            }
            let frame = Self.sseFrame(blob)
            for connection in self.clients.values {
                self.write(frame, to: connection)
            }
        }
    }

    private func write(_ text: String, to connection: NWConnection) {
        connection.send(content: text.data(using: .utf8), completion: .contentProcessed { _ in })
    }

    /// One SSE event: every line of `blob` becomes its own `data:` line, so
    /// a multi-line batch report arrives as a single `event.data` on the
    /// client, newlines intact.
    private static func sseFrame(_ blob: String) -> String {
        blob.split(separator: "\n", omittingEmptySubsequences: false)
            .map { "data: \($0)" }
            .joined(separator: "\n") + "\n\n"
    }
}
