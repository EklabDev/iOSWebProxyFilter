# Traffic Inspector (iOS)

Local-VPN traffic inspector ported from [AndroidAdBlocker](https://github.com/EklabDev/AndroidAdBlocker).
All packet processing happens on device. Nothing is uploaded.

**Distribution: local IPA only (sideloaded).** Not intended for App Store review.

## What it does

A `NEPacketTunnelProvider` intercepts IPv4 traffic, extracts hostnames from DNS
queries and TLS SNI, applies user-defined allow/block rules (first match wins),
logs every connection, and presents Home / Connections / Rules / Apps screens.

## Open in Xcode

Requires [XcodeGen](https://github.com/yonaskolb/XcodeGen) and a paid Apple Developer account
(Network Extension entitlements).

```bash
brew install xcodegen
cd ios
xcodegen generate
open EklabAdBlocker.xcodeproj
```

Set your Development Team on both `EklabAdBlocker` and `PacketTunnel`.
The App Group `group.dev.eklab.adblocker` and the Network Extension
(`packet-tunnel-provider`) capability must be enabled for:

- `dev.eklab.adblocker`
- `dev.eklab.adblocker.PacketTunnel`

Install on a physical device (Network Extensions do not run in the simulator).

## Sideload / IPA

From Xcode: Product → Archive → Distribute App → Development or Ad Hoc.

Or:

```bash
xcodebuild -project ios/EklabAdBlocker.xcodeproj \
  -scheme EklabAdBlocker -configuration Release \
  -archivePath build/TrafficInspector.xcarchive archive

xcodebuild -exportArchive \
  -archivePath build/TrafficInspector.xcarchive \
  -exportPath build/ipa \
  -exportOptionsPlist ExportOptions.plist
```

Install with Xcode, Apple Configurator, AltStore, or SideStore.

## Unit tests (core logic)

The parsers, rule engine, packet builders, and SQLite stores are a Swift package
and can be tested without Xcode:

```bash
swift test
```

In Xcode, Product → Test runs the same suites against the app target.

## Tunnel settings (IPv4-only v1)

| Setting | Value |
| --- | --- |
| Address | `10.0.0.2/32` |
| Route | `0.0.0.0/0` |
| MTU | 1500 |
| DNS | virtual `10.0.0.1` (catch-all `matchDomains = [""]`) |
| Upstream DNS | port-53 traffic to `10.0.0.1` is relayed to `8.8.8.8` |

IPv6 is not configured, so IPv6 traffic bypasses the tunnel.

## Known limitations

- **No per-app identity.** iOS packet tunnels cannot map a flow to a process.
  `appPackage` / `uid` are always `nil` / `-1`. APP-type rules compile but never
  match. The Apps tab is a manual bundle-ID rule list with an explanation banner.
- **IPv6 bypass.** Neither inspected nor logged.
- **DoH / DoT** queries are invisible. Mitigate with the Block QUIC toggle (UDP/443)
  plus SNI-based HOST / HOST_SUFFIX rules.
- **No TCP half-close** on Network Extension flows. A client FIN is ACKed and the
  upstream connection is closed.
- **Extension memory ceiling ~50 MB.** Relays are capped (256 flows), the IP→hostname
  cache is 512 entries, the TLS parser buffer is 64 KB, and log flushes batch at
  200 rows / 3 seconds.

## Rule engine

Enabled rules only, sorted by `priority` ascending. First match wins. No match →
allow (fail-open). Selector types: APP, HOST, HOST_SUFFIX, IP (IPv4 / CIDR / IPv6
string), TYPE. Hostname candidates: SNI → DNS query → IP cache.

Rule edits apply while the tunnel is running: the app bumps a `rules_version` row
in the shared SQLite database; the extension polls it every second.

## Layout

```
ios/
  EklabAdBlocker/     SwiftUI app
  PacketTunnel/       NEPacketTunnelProvider
  Shared/             models, engine, parsers, TUN pipeline, sqlite3 stores
  Tests/              ported Android unit tests + packet checksums
```
