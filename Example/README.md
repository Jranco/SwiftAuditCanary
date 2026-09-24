# SwiftAuditCanary — Demo app

An interactive iOS app that exercises **every probe, output, and configuration**
of the SwiftAuditCanary package in one screen, so you can see exactly what a
linked dependency can reach.

> The package is a DEBUG-only auditing tool. This demo seeds **fake** secrets on
> purpose so the probes have something to find.

## Run it

**With [XcodeGen](https://github.com/yonaskolb/XcodeGen) (fastest):**

```bash
brew install xcodegen        # if needed
cd Example
xcodegen generate
open SwiftAuditCanaryDemo.xcodeproj
```

Pick a simulator and Run. The generated `.xcodeproj` is disposable — regenerate
any time; you don't need to commit it.

**Manually (no XcodeGen):**

1. In Xcode: *File → New → Project → iOS App* (SwiftUI), name it `SwiftAuditCanaryDemo`.
2. Delete its stub `ContentView.swift` and drag in the four files from
   `Example/SwiftAuditCanaryDemo/` (`App.swift`, `ContentView.swift`,
   `DemoModel.swift`, `DemoSeeder.swift`). Use the provided `Info.plist` or copy
   its two keys into yours.
3. *File → Add Package Dependencies… → Add Local…* and select the repo root
   (the folder with `Package.swift`). Add the `SwiftAuditCanary` product to the app target.
4. Run.

## What each control does

| Section | Shows |
|---|---|
| **1 · Seed** | Writes fake secrets to UserDefaults, Keychain, clipboard, and a `credentials.sqlite` in the sandbox. Tap this first. |
| **2 · Probes** | Toggle which surfaces to scan — builds the `AuditCanaryConfig.Probes` option set. |
| **3 · Outputs** | `console`, `onScreen` overlay, silent `file`, `server` (SSE on all interfaces), `webhook` (POST). Multiple at once. |
| **4 · Suspicious terms** | Extra key/value terms for the `userDefaults` probe (`additionalSuspiciousTerms`), plus the runtime `addSuspiciousTerms` / `resetSuspiciousTerms` API. |
| **5 · Run** | `Run once` = sync snapshot (`AuditCanary.run`). `Start monitoring` = baseline + live watching (`AuditCanary.startMonitoring`) with a configurable poll interval. |
| **Live triggers** | While monitoring: fire a network request, write a UserDefaults secret, or change the clipboard — findings appear in the list in real time. |

## Things worth trying

- **Silent capture:** enable only the `file` output, Run, and watch the report
  appear in the "Silent file report" section — no console, no UI from the SDK.
- **Local-network exposure:** enable `server`, Run, then on another device on the
  same Wi-Fi open `http://<device-ip>:8080/` (or `curl -N …`) and watch findings
  stream. iOS shows its Local Network prompt on the first connection.
- **Live network interception:** Start monitoring, then tap *Make outbound
  request* — the request is observed and replayed transparently.
