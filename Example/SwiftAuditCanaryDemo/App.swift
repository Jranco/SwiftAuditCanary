import SwiftUI

/// Demo host app for the SwiftAuditCanary package.
///
/// SwiftAuditCanary is meant to be embedded in DEBUG builds only — this demo
/// exists purely to exercise every probe, output and configuration path in one
/// place so you can see exactly what a linked dependency can reach.
@main
struct SwiftAuditCanaryDemoApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
