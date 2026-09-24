import Foundation
import UIKit
import Security

/// Plants realistic-looking sensitive data across the surfaces the probes read,
/// so a run actually has something to find. Everything here is fake.
enum DemoSeeder {

    static func seedAll() {
        seedUserDefaults()
        seedKeychain()
        seedPasteboard()
        seedContainer()
    }

    /// Token/secret-looking keys and a JWT-shaped value — caught by the
    /// `userDefaults` probe's built-in heuristics and by `additionalSuspiciousTerms`.
    static func seedUserDefaults() {
        let d = UserDefaults.standard
        d.set("cus_Nx91jHxxxxxxxx", forKey: "stripeCustomerId")
        d.set("super-secret-device-value", forKey: "deviceSecret")
        d.set("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.s1gnatur3",
              forKey: "sessionJWT")
        d.set(true, forKey: "isDemoSeeded")
    }

    /// A generic-password keychain item in the app's default access group —
    /// enumerated (attributes only) by the `keychain` probe.
    static func seedKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.jranco.SwiftAuditCanaryDemo",
            kSecAttrAccount as String: "demoUser"
        ]
        SecItemDelete(query as CFDictionary)

        var add = query
        add[kSecValueData as String] = Data("demo-password".utf8)
        SecItemAdd(add as CFDictionary, nil)
    }

    /// Clipboard contents — read wholesale by the `pasteboard` probe.
    static func seedPasteboard() {
        UIPasteboard.general.string = "card 4242 4242 4242 4242 exp 12/29"
    }

    /// A plausible DB-looking file in the sandbox — found by the `container` probe.
    static func seedContainer() {
        guard let docs = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let db = docs.appendingPathComponent("credentials.sqlite")
        try? Data("-- demo db: tokens, cookies, secrets".utf8).write(to: db)
    }
}
