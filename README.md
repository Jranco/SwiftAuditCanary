# SwiftAuditCanary

A deliberately "malicious" third-party library you add to **your own** iOS app to
showcase what a rogue dependency could reach — **no jailbreak, nothing injected at
runtime**. It works because iOS gives an app and its linked libraries no isolation:
any SDK you add via SPM/CocoaPods runs with the host app's full sandbox and
entitlements. AuditCanary exercises that same ambient authority and reports back.

> ⚠️ For auditing apps you own or are authorized to test. Ship it in **DEBUG only**.

## Install (SPM)

Add the package and `import SwiftAuditCanary`, then in your `App` init / `AppDelegate`:

```swift
#if DEBUG
import SwiftAuditCanary

AuditCanary.run(config: .init(
    outputs: [.console, .onScreen],   // loud: console + overlay
    probes: .all
))
#endif
```

Add app-specific terms to the `userDefaults` probe (checked against both key names and
stringified values, e.g. `"stripeCustomerId"`, `"deviceSecret"`):

```swift
AuditCanary.run(config: .init(
    outputs: [.console],
    probes: .all,
    additionalSuspiciousTerms: ["stripeCustomerId", "deviceSecret"]
))
```

Re-run after updating UserDefaults and want to check for new terms too, without
resupplying the whole list each time? `AuditCanary.addSuspiciousTerms(_:)` adds to a
running set that every subsequent `run()` picks up automatically:

```swift
AuditCanary.run()                                     // baseline pass

// ...update UserDefaults in your app...

AuditCanary.addSuspiciousTerms(["newFeatureFlag"])    // now watch for this too
AuditCanary.run()                                     // re-run, sees old + new terms

AuditCanary.addSuspiciousTerms(["anotherOne"])        // keep adding as you go
AuditCanary.run()

AuditCanary.resetSuspiciousTerms()                    // drop runtime terms, keep baseline
```

Silent mode (proves quiet exfiltration is possible — writes to a file instead):

```swift
let url = FileManager.default
    .urls(for: .cachesDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("audit.txt")
AuditCanary.run(config: .init(outputs: [.file(url)], probes: .all))
```

## Sync vs. async — both through `run`

**Sync** — `AuditCanary.run(config:)` is a point-in-time snapshot: every probe
reports what it can see right now, once, and you get the results immediately.

**Async** — `AuditCanary.run(config:pollInterval:)` takes that same baseline
snapshot, then keeps watching for the rest of the process and returns a
publisher: subscribe to it to observe findings as they're discovered.
`userDefaults` and `pasteboard` react to real system change notifications,
`network` streams every request as it's made, and `keychain`/`container`
(which have no OS push signal to react to) poll and diff on a configurable
interval. Everything discovered is also routed live to `config.outputs` as it
happens. Call `AuditCanary.stop()` to end it — unsubscribing your own `sink`
doesn't stop the underlying probes, `stop()` is what does. `bundleSecrets` is
always one-shot only — `Bundle.main` doesn't change during a run, so there's
nothing to watch.

```swift
#if DEBUG
import SwiftAuditCanary
import Combine

var cancellable: AnyCancellable?

// Sync: immediate results.
AuditCanary.run(config: .init(outputs: [.console, .onScreen], probes: .all))

// Async: same baseline, then keeps watching. Observe emits until you stop it.
cancellable = AuditCanary.run(
    config: .init(outputs: [.console, .onScreen], probes: .all),
    pollInterval: 15   // how often to re-poll keychain/container
).sink { finding in
    print("live:", finding.probe, finding.title)
}

// ...later, if needed...
AuditCanary.stop()
#endif
```

## Serving findings to anyone on the network

Every other output needs either the developer watching (`.console`/`.onScreen`)
or a server you control (`.webhook`). `.server(port:)` needs neither: it starts
an embedded HTTP server, bound to every interface (not just loopback), that
streams findings live as Server-Sent Events. Anyone on the same Wi-Fi can run
`curl -N http://<device-ip>:<port>/` or just open that URL in a browser and
watch findings scroll in real time — the "capture → serve" step with *no*
external infrastructure at all.

```swift
AuditCanary.run(config: .init(outputs: [.server(port: 8080)], probes: .all))
```

This is the one output that isn't silent. iOS's Local Network permission
prompt appears the first time another device actually connects, and you need
this in the host app's Info.plist or the OS refuses the connection:

```xml
<key>NSLocalNetworkUsageDescription</key>
<string>AuditCanary demonstrates local network exposure risk to auditors.</string>
```

A real rogue SDK would rather avoid tripping that dialog — this output exists
to make the trade-off itself part of the demonstration: `.webhook` stays quiet
but needs infrastructure, `.server` needs nothing but shows up to the user.

## What it probes

| Probe           | Demonstrates |
|-----------------|--------------|
| `keychain`      | Enumerates keychain items reachable via the app's access groups (attributes only). |
| `pasteboard`    | Reads the general clipboard. |
| `container`     | Finds databases / plists / keys in the sandbox. |
| `userDefaults`  | Dumps keys; flags token/secret-looking key names *and* values (incl. JWT-shaped strings). Extend the term list via `additionalSuspiciousTerms`. |
| `bundleSecrets` | Baked-in secrets in Info.plist and bundled resources. |
| `network`       | Installs a `URLProtocol` (global registration + `URLSessionConfiguration` swizzle) to observe **all** outbound traffic — shared/custom sessions, async/await, delegate, upload, download (the SourMint technique). |

## The lesson

If a probe can read it, so can any dependency you pull in. Treat every third-party
SDK as code running with your app's full privileges.
