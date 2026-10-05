# Implementation Plan: Rhizome (local, real-time 3D LAN map)

## Overview
Rhizome is a single Rust binary (`cargo run`). It picks the active LAN interface and each cycle collects observations from four sources: `arp -an`, an unprivileged ICMP sweep, mDNS and SSDP. A pure merge function turns those observations into device state, which is written to SQLite and pushed to a vendored 3d-force-graph UI over SSE. All I/O lives in thin adapters, and every parser, heuristic and the merge are pure functions tested against fixtures.

**Push transport: SSE.** Updates only flow from server to client, `EventSource` reconnects on its own, and because SSE is plain HTTP it is covered by the same-origin policy plus a Host check. WebSocket has no same-origin protection, so it would need a mandatory Origin gate and adds a protocol for no benefit.

---

## 1. Crates and data sources

| Concern | Choice | Justification |
|---|---|---|
| Async runtime | `tokio` (rt-multi-thread, macros, net, process, time, sync, signal) | Standard runtime. Runs subprocesses, UDP and timers on one executor. |
| HTTP server + SSE | `axum` (0.8 line; SSE is built in via `axum::response::sse`) + `tokio-stream` (`BroadcastStream`) | Serves static files, JSON and SSE with no extra framework. Middleware is easy to test with `tower::ServiceExt::oneshot`. |
| SQLite | `rusqlite` with feature `bundled` | Compiles SQLite in, so there is no system library dependency. The API is synchronous and small; call it through `spawn_blocking`. |
| mDNS | `mdns-sd` | Pure Rust browser. It uses SO_REUSEADDR/SO_REUSEPORT on 5353 so it can run alongside mDNSResponder, and it can be limited to one interface. |
| Ping (no root) | `surge-ping` with `sock_type_hint(Type::DGRAM)` | macOS allows unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP`. Async, so 254 hosts can be pinged concurrently. Fallback: `/sbin/ping -c1 -W 500 <ip>` (see Risks). |
| Interface / gateway / own MAC | `netdev` | Reads interfaces and the default gateway from the OS with no network calls. Results go into a pure selection function. |
| Subnet math | `ipnet` | Handles `Ipv4Net::hosts()` and containment checks. |
| SSDP | Hand-written on `tokio::net::UdpSocket` | An M-SEARCH is about 10 lines and the parser is pure. No crate needed. |
| OUI data | IEEE MA-L `oui.csv` (from standards-oui.ieee.org), committed at `data/oui.csv` and pulled into the binary with `include_str!`. Parsed once into a sorted `Vec<(u32, Box<str>)>` behind `OnceLock` and looked up by binary search. | Public registry data with no licensing friction. Works offline with no build.rs. About 35k rows parse in a few milliseconds. Refreshed only by a developer script. |
| Frontend assets | `rust-embed` (feature `mime-guess`) over `ui/` | Debug builds read `ui/` from disk, so UI edits need no rebuild. Release builds embed the files, giving a single binary. |
| Frontend library | `3d-force-graph` UMD `dist/3d-force-graph.min.js` (bundles three.js and d3-force-3d), pinned version, committed in `ui/vendor/` with its LICENSE and a `VERSIONS` file holding version and sha256 | No npm or build step at runtime. `cargo run` stays the only command. |
| Serialization | `serde`, `serde_json` | JSON for the API and SSE. |
| CLI / config | `clap` (derive) | `--port`, `--iface`, `--interval`, `--db`, `--no-tcp-probe`, `--max-hosts`. |
| Logging | `tracing`, `tracing-subscriber` | Structured logs to stderr only. |
| Errors | `thiserror` (lib), `anyhow` (main) | Typed errors in pure code, context in the binary. |
| DB location | `directories` | `~/Library/Application Support/rhizome/rhizome.db`. |
| Dev only | `tempfile`, `tower` (util), `http-body-util` | Store tests and in-process HTTP tests. |
| JS tests (dev only, optional) | `node --test` on ES modules | Tests pure UI logic with no bundler. Not needed for `cargo run`. |

Versions: whatever `cargo add` resolves today, pinned by the committed `Cargo.lock`. Check MSRV is ≤ 1.91 in slice 1.

**Dev scripts** (run once, outputs committed; neither runs at runtime):
- `scripts/update-oui.sh` downloads `oui.csv` and writes `data/OUI_SOURCE` with the date and sha256.
- `scripts/vendor-ui.sh` runs `npm pack 3d-force-graph@<pin>` in a temp dir, copies `package/dist/3d-force-graph.min.js` and `LICENSE` into `ui/vendor/`, and writes the sha256 into `ui/vendor/VERSIONS`.

---

## 2. Module layout

Single package with `src/lib.rs` plus a thin `src/main.rs`, so integration tests can import the library. **(P)** = pure (no I/O; takes `now: i64` ms as an argument). **(IO)** = adapter.

```
Cargo.toml / Cargo.lock
data/oui.csv, data/OUI_SOURCE
scripts/update-oui.sh, scripts/vendor-ui.sh
src/
  main.rs                 wire config → iface → store → hub → scanner task → web server; graceful shutdown
  lib.rs                  module exports
  config.rs        (P)    Config struct + clap parsing + validation (port range, interval floor ≥10s, max_hosts)
  model.rs         (P)    MacAddr, DeviceKind, Device, LivenessEvidence, ScanInputs, DeviceEvent, NetworkId (serde)
  net/
    mac.rs         (P)    parse/normalize macOS short-octet MACs ("0:1a:2b:3:4:5"), is_multicast, is_broadcast, is_locally_administered
    subnet.rs      (P)    enumerate_targets(net, self_ip, max_hosts); is_scan_target(ip, net) guard (only in-subnet unicast)
    iface_select.rs(P)    select_interface(Vec<IfaceInfo>, default_name, cli_override) → Selected{name, ip, net, mac, gateway_ip}
    iface.rs       (IO)   netdev → Vec<IfaceInfo>
  discovery/
    arp_parse.rs   (P)    parse `arp -an` text → Vec<ArpEntry{ip, mac: Option, iface, permanent}>
    arp.rs         (IO)   run /usr/sbin/arp -an (timeout, output cap) → arp_parse
    ping.rs        (IO)   ICMP DGRAM sweep, bounded concurrency → HashSet<Ipv4Addr> alive + error classification (EHOSTUNREACH/EPERM)
    tcp_probe.rs   (IO)   connect() to a few ports for ARP-known hosts that ignore ICMP; ECONNREFUSED counts as alive
    mdns_map.rs    (P)    raw mDNS resolutions → Vec<MdnsHit{ip, hostname, service_types}> (strip ".local.", sanitize)
    mdns.rs        (IO)   mdns-sd daemon pinned to iface, browse _services._dns-sd._udp then each type; rolling cache
    ssdp_parse.rs  (P)    build_msearch() bytes; parse_response(&[u8]) → Option<SsdpHit{server, st, usn, location}>
    ssdp.rs        (IO)   send M-SEARCH to 239.255.255.250:1900 from an ephemeral port, collect replies for 3s
  enrich/
    oui.rs         (P)    OuiDb::from_csv(&str); lookup(MacAddr) → Option<&str>; global embedded instance
    classify.rs    (P)    classify(&ClassifyInput{vendor, hostname, services, ssdp_server, ssdp_st, is_gw, is_self}) → DeviceKind (ordered rule table)
    sanitize.rs    (P)    strip control chars, lossy UTF-8, truncate to 255; applied to every network-sourced string
  state/
    merge.rs       (P)    merge(prev: &DeviceMap, inputs: &ScanInputs, ctx: &MergeCtx{now, baseline_at, offline_after_ms, new_window_ms}) → (DeviceMap, Vec<DeviceEvent>)
    hub.rs         (IO)   Arc<RwLock<Snapshot>> + tokio::broadcast<DeviceEvent>; snapshot() for SSE connect / lag recovery
  store/
    schema.sql            devices, meta tables; migrations via PRAGMA user_version
    sqlite.rs      (IO)   open (0700 dir / 0600 file), migrate, load(network_id), upsert_many (one txn), get/set meta
  scanner.rs       (IO)   loop: gather ScanInputs concurrently → merge → store → hub.publish; per-source error isolation; re-selects iface each cycle
  web/
    guard.rs       (P+layer) host_allowed(host, port), origin_allowed(origin, port) as pure fns + axum middleware
    headers.rs            CSP / nosniff / referrer / frame-ancestors response layer
    api.rs                GET /api/devices, GET /api/events (SSE), GET /api/status, POST /api/scan
    assets.rs             rust-embed handler for /, /app.js, /graph-model.js, /style.css, /vendor/*
    mod.rs                router assembly; bind 127.0.0.1 only
ui/
  index.html              <script src="vendor/3d-force-graph.min.js"> + <script type="module" src="app.js">
  graph-model.js   (P)    devices → {nodes, links}; style fns (color/size/particles); escapeHtml; label builder
  app.js           (IO)   EventSource, Map<id,node> reconciliation, ForceGraph3D setup, details panel (textContent only)
  style.css
  vendor/3d-force-graph.min.js, vendor/LICENSE-3d-force-graph, vendor/VERSIONS
  tests/graph-model.test.js   node --test
tests/
  fixtures/arp_macos_basic.txt, arp_macos_edge.txt, ssdp_*.txt, oui_small.csv
  http_guard.rs, http_api.rs, sse.rs, store.rs, scan_cycle.rs, live_smoke.rs (#[ignore], needs a real LAN)
```

**Core types (in `model.rs`)**
- `Device { id, mac, ip, vendor, hostname, hostname_source, kind, services, ssdp_server, is_gateway, is_self, randomized_mac, shared_mac, online, first_seen, last_seen, last_alive, is_new }`
- `id` is the MAC, or `mac@ip` when `shared_mac` is set (see Risks: extenders).
- `ScanInputs { arp, ping_alive, tcp_alive, mdns, ssdp, selected_iface, gateway_ip, scan_started_at }`
- `DeviceEvent::{Upsert(Device), Removed(id), Scan(ScanStatus)}`. Every event carries the full device, so clients can apply it idempotently.

**Merge rules (in `state/merge.rs`)**
- **Joining sources:** ARP gives the IP→MAC table. ping/tcp/mDNS/SSDP hits are joined to a device by IP. Hits whose IP is not in ARP are kept as pending and do not create devices. The self device comes from the interface; the gateway is the device whose IP equals `gateway_ip`.
- **Liveness evidence** is any of: ICMP reply, TCP probe answer, mDNS/SSDP response, or an ARP entry that is new compared with the previous snapshot. ARP presence alone is not evidence, because the cache keeps entries for about 20 minutes.
- **Online/offline:** a device is `online` if `now - last_alive < offline_after` (default 3 × interval). Self is always online.
- **New devices:** `is_new` = `first_seen > baseline_at && now - first_seen < new_window` (default 10 min). `baseline_at` is set at the end of the first scan of a network, so a fresh install does not flag everything as new.
- **IP changes:** same MAC with a new IP updates the IP. If an IP is now claimed by a different MAC, the new MAC wins and the old device keeps its last IP and drops to offline through the normal timeout.
- **Network scope:** `network_id` = gateway MAC, so history from different networks never mixes.

---

## 3. Vertical slices (TDD)

Each slice can be merged on its own and leaves `cargo run` working.

### Slice 1: ARP to a 3D star in the browser (thinnest end-to-end)
- **Goal:** `cargo run` selects the interface, runs `arp -an` once at startup and on every `/api/devices` request, and serves a page that renders the gateway at the centre, this machine, and ARP devices as spokes.
- **Files:** `Cargo.toml`, `main.rs`, `lib.rs`, `config.rs` (port only), `model.rs` (minimal), `net/mac.rs`, `net/iface_select.rs`, `net/iface.rs`, `discovery/arp_parse.rs`, `discovery/arp.rs`, `web/mod.rs`, `web/api.rs` (GET /api/devices), `web/assets.rs`, `ui/index.html`, `ui/graph-model.js`, `ui/app.js`, `ui/style.css`, `ui/vendor/*`, `scripts/vendor-ui.sh`, `tests/fixtures/arp_*.txt`.
- **Tests first:**
  - `arp_parse`:
    - normal line `? (192.168.0.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]`
    - `(incomplete)` gives `mac: None`
    - `permanent` multicast `1:0:5e:0:0:fb` is filtered
    - broadcast `ff:ff:...` is filtered
    - other interface (`on utun3`, `on bridge100`) is filtered when an iface filter is given
    - blank or garbage lines are skipped without panicking
    - CRLF and trailing whitespace are handled
  - `mac`: short octets normalize to `00:1a:2b:03:04:05`; uppercase input; invalid lengths are rejected.
  - `iface_select`:
    - default `en0` with private IPv4 is chosen
    - a `utun*` / point-to-point default is skipped in favour of `en*` with a private IPv4 and a MAC
    - a CLI override that names an unknown interface is an error
    - no candidate is an error with a clear message
  - `http_api` (oneshot): `GET /` returns 200 `text/html`; `GET /vendor/3d-force-graph.min.js` returns 200 JS; `GET /api/devices` returns a JSON array, using an injected device source.
  - `graph-model.test.js`: the gateway node has `fx=fy=fz=0`; every non-gateway node has exactly one link to the gateway; with no gateway there are no links and no crash.
- **Acceptance:**
  - `cargo run` logs `listening on http://127.0.0.1:7878 iface=en0 net=192.168.0.0/24 gw=192.168.0.1`.
  - `lsof -nP -iTCP:7878 -sTCP:LISTEN` shows only `127.0.0.1:7878`.
  - `curl -s 127.0.0.1:7878/api/devices | jq length` is ≥ `arp -an | grep ' on en0 ' | grep -vc -e incomplete -e permanent -e ff:ff:ff:ff:ff:ff`, plus 1 for self.
  - In the browser: the gateway sits at the centre in a distinct colour, this machine in another colour, other devices as spokes; the DevTools Network tab shows only 127.0.0.1 requests.

### Slice 2: Real-time loop, SSE, merge, request guards
- **Goal:** a periodic scanner task, a pure merge, a hub, and SSE (`snapshot` on connect, then `device` events). Host and Origin guards, plus security headers.
- **Files:** `state/merge.rs`, `state/hub.rs`, `scanner.rs`, `web/guard.rs`, `web/headers.rs`, `web/api.rs` (+ /api/events, /api/status), `config.rs` (+ interval), `ui/app.js` (EventSource + Map reconciliation), `ui/graph-model.js` (reconcile fn).
- **Tests first:**
  - `merge`: a new MAC produces an Upsert; an unchanged scan produces no events; an IP change produces an Upsert with the new IP; a device that vanishes from ARP stays online until `offline_after`, then goes offline; self is always online; output does not depend on input ordering.
  - `guard`:
    - `127.0.0.1:7878` and `localhost:7878` are allowed
    - wrong port, `evil.com`, `127.0.0.1.evil.com`, and empty or missing Host are rejected
    - Origin: absent is allowed for GET; `http://127.0.0.1:7878` is allowed; `null` and foreign origins are rejected
  - `sse.rs`: the first event is `snapshot`; after `hub.publish(Upsert)` the client receives `event: device`; a lagged receiver gets a fresh `snapshot`.
  - `graph-model.test.js`: reconcile keeps node object identity, so existing positions survive; removal drops the node and its link.
- **Acceptance:**
  - `curl -N 127.0.0.1:7878/api/events` streams `event: snapshot`, then `event: scan` each interval.
  - `curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.com' 127.0.0.1:7878/` returns `403`.
  - `curl ... -H 'Origin: http://evil.com' 127.0.0.1:7878/api/events` returns `403`.
  - `curl -sI 127.0.0.1:7878/ | grep -i content-security-policy` is present.
  - In the browser, toggle Wi-Fi on a phone: its node appears within one interval with no reload, and existing nodes do not jump.

### Slice 3: Active discovery with ping sweep and liveness
- **Goal:** ping every host in the subnet each cycle (this also fills the ARP cache), then read ARP. Add a TCP probe for ARP-known hosts that ignore ICMP. Detect Local Network permission denial.
- **Files:** `net/subnet.rs`, `discovery/ping.rs`, `discovery/tcp_probe.rs`, `scanner.rs`, `state/merge.rs` (evidence), `web/api.rs` (status carries warnings), `ui/app.js` (warning banner).
- **Tests first:**
  - `subnet`:
    - /24 gives 253 targets (254 hosts minus self)
    - /30 edge case
    - /16 is capped at `max_hosts` (default 1024, nearest to the gateway first)
    - `is_scan_target` rejects public, multicast, loopback, out-of-subnet and broadcast addresses
  - `merge`: ping evidence keeps a device online; ARP-only devices go offline after the window; tcp evidence counts as alive.
  - `ping` error classifier (pure): `EHOSTUNREACH` on the gateway maps to `Warning::LocalNetworkDenied`; `EPERM`/`EACCES` on socket creation maps to `Fallback::PingBinary`.
  - `#[ignore]` live test: DGRAM ping to 127.0.0.1 succeeds without root.
- **Acceptance:**
  - Run `sudo arp -a -d` once (this is only to set up the test; the app never needs root), then `cargo run`. After the first cycle, `arp -an | grep -c ' on en0 '` has grown back and the same devices appear in the UI.
  - Power off a device: its node turns translucent grey within about 3 intervals.
  - Deny Local Network access for the terminal app: the UI shows the permission banner and the logs name the exact System Settings path.

### Slice 4: Vendor, randomized MAC, classification v1, details panel
- **Goal:** OUI vendor lookup, a locally-administered flag, vendor-based kind rules, and a click-to-open details panel.
- **Files:** `data/oui.csv`, `data/OUI_SOURCE`, `scripts/update-oui.sh`, `enrich/oui.rs`, `enrich/classify.rs`, `enrich/sanitize.rs`, `state/merge.rs` (enrich step), `ui/graph-model.js` (label/escape), `ui/app.js` (panel, fly-to camera), `tests/fixtures/oui_small.csv`.
- **Tests first:**
  - `oui`:
    - fixture lookup hit and miss
    - case and separator insensitivity
    - quoted CSV fields containing commas
    - the real embedded DB has more than 30,000 entries and no duplicate prefixes
  - `mac`: `is_locally_administered` (the 0x02 bit); a randomized MAC gets vendor `None` and `randomized_mac=true`, never a wrong vendor.
  - `classify`: `is_gw` gives Gateway; `is_self` gives ThisMachine; vendor rules such as printer vendors giving Printer and Ubiquiti/TP-Link giving NetworkGear; falls through to Unknown.
  - `sanitize`: control chars stripped, length capped.
  - `graph-model.test.js`: `escapeHtml('<img src=x onerror=1>')` is inert; the label builder escapes every field.
- **Acceptance:**
  - `curl -s 127.0.0.1:7878/api/devices | jq -r '.[] | "\(.ip) \(.vendor) \(.kind)"'` shows vendors.
  - Clicking a node opens a panel with IP, MAC, vendor, kind, randomized badge, online/offline and last seen; the camera flies to the node.

### Slice 5: SQLite history, "new device", "last seen", restart persistence
- **Goal:** keep first_seen/last_seen per `(network_id, mac)`, a baseline, and the "new" highlight. On startup, load history so offline devices show immediately.
- **Files:** `store/schema.sql`, `store/sqlite.rs`, `scanner.rs` (load at start, persist each cycle via `spawn_blocking`), `state/merge.rs` (`is_new`, baseline), `config.rs` (`--db`), `ui/graph-model.js` (particles on links to new nodes, "last seen" text).
- **Schema:**
  - `devices(network_id TEXT, id TEXT, mac TEXT, last_ip TEXT, hostname TEXT, vendor TEXT, kind TEXT, randomized INTEGER, first_seen INTEGER, last_seen INTEGER, PRIMARY KEY(network_id, id))`
  - `meta(network_id TEXT, key TEXT, value TEXT, PRIMARY KEY(network_id, key))`
- **Tests first** (`store.rs` uses `:memory:` and tempfile):
  - migrate is idempotent; running it twice leaves `user_version` unchanged
  - upsert keeps `first_seen` and advances `last_seen`
  - load is scoped by network_id
  - a hostile hostname (`'); DROP TABLE devices;--`) round-trips verbatim
  - the DB file is created with mode 0600
  - `merge`: everything seen in the first scan has `is_new=false` and sets the baseline; a later arrival has `is_new=true` until the window expires
- **Acceptance:**
  - Run, stop, then `sqlite3 ~/Library/Application\ Support/rhizome/rhizome.db 'select mac,last_ip,datetime(first_seen/1000,"unixepoch"),datetime(last_seen/1000,"unixepoch") from devices'`.
  - Restart: previously seen absent devices appear as offline with "last seen …".
  - Join a new device: it shows the "new" colour and link particles, which fade after 10 minutes.
  - `stat -f %Lp` on the DB shows `600`.

### Slice 6: mDNS hostnames and service hints
- **Goal:** hostnames and service types from mDNS; classification uses services such as `_ipp`/`_printer` (Printer), `_airplay`/`_googlecast`/`_raop` (TV/Speaker), `_companion-link`/`_apple-mobdev2` (Phone/Tablet), `_ssh`/`_smb` (Computer), `_hap` (IoT).
- **Files:** `discovery/mdns.rs`, `discovery/mdns_map.rs`, `enrich/classify.rs`, `state/merge.rs` (hostname precedence: mDNS > SSDP > none), `scanner.rs`, `web/api.rs` (status: `mdns_available`).
- **Tests first:**
  - `mdns_map`: `Living-Room.local.` becomes `Living-Room`; multiple addresses map to multiple hits; IPv6 is ignored; names are sanitized.
  - `classify`: each service rule; the precedence order of services vs vendor.
  - `merge`: a hit joins by IP, so a hit for an IP not in ARP is not a device; an mDNS hit counts as liveness evidence.
  - Startup failure (port bind error) leaves the scanner running with `mdns_available=false`, tested through an injected failing source.
- **Acceptance:** compare with `dns-sd -B _services._dns-sd._udp local.` (Ctrl-C after 5s); Apple devices and printers show matching hostnames in the panel and `jq '.[].hostname'`.

### Slice 7: SSDP hints
- **Goal:** M-SEARCH `ssdp:all`; the SERVER/ST/USN headers feed classification (e.g. `InternetGatewayDevice` gives Gateway confirmation, `MediaRenderer` gives TV, `Sonos` gives Speaker). The LOCATION URL is stored as text only and never fetched in v1.
- **Files:** `discovery/ssdp_parse.rs`, `discovery/ssdp.rs`, `enrich/classify.rs`, `state/merge.rs`, `scanner.rs`.
- **Tests first:**
  - `ssdp_parse`: the M-SEARCH bytes are exact (CRLF, `MX: 2`, `MAN: "ssdp:discover"`); case-insensitive headers; a missing status line is rejected; a body over 8 KB is rejected; non-UTF-8 is handled lossily; header values are sanitized.
  - `classify`: SERVER/ST rules.
  - `merge`: the SSDP source IP must be in the subnet, otherwise the hit is dropped.
- **Acceptance:** `curl -s 127.0.0.1:7878/api/devices | jq '.[] | select(.ssdp_server) | {ip,ssdp_server,kind}'` lists the router and smart TV.

### Slice 8: Hardening and polish
- **Goal:**
  - `POST /api/scan` (rescan button) requires a matching Origin and an `X-Rhizome: 1` header
  - network-change detection (gateway MAC changes): switch network_id and send a fresh snapshot
  - re-select the interface after sleep/wake
  - shared-MAC handling for extenders
  - client-isolation hint
  - graceful shutdown on Ctrl-C
  - WebGL-unavailable message
  - README with a security section
- **Files:** `web/api.rs`, `web/guard.rs`, `scanner.rs`, `state/merge.rs`, `ui/app.js`, `README.md`.
- **Tests first:**
  - `POST /api/scan` without the header, or with a foreign Origin, returns 403; a valid request returns 202.
  - `merge`: one MAC with more than one IP in a single scan gives `shared_mac` and `mac@ip` ids.
  - A gateway MAC change produces a network-change event.
  - The client-isolation case (only gateway and self visible after a sweep) sets the status hint.
- **Acceptance:**
  - Switch Wi-Fi networks while running: the graph resets to the new network within one interval, and switching back restores the old history.
  - Ctrl-C exits cleanly with the DB intact (`sqlite3 … 'pragma integrity_check'` returns `ok`).

---

## 4. Risks and macOS gotchas

| Risk | Mitigation |
|---|---|
| **Unprivileged ICMP:** DGRAM ICMP works on macOS, but replies arrive with the IP header included (unlike Linux), and behaviour may differ by crate version. | Spike in slice 3 with the `#[ignore]` loopback test. If `surge-ping` misbehaves, fall back to `/sbin/ping -c1 -W 500 -q <ip>` with concurrency 32 (about 8s per /24). The sweep is still worth doing when replies are lost, because each attempt triggers ARP resolution. |
| **Local Network privacy (macOS 15+):** traffic to the LAN can fail silently with `EHOSTUNREACH`. Permission belongs to the responsible app (Terminal, iTerm, VS Code), not the binary. Whether a Terminal-launched CLI gets a prompt varies, so verify on Darwin 25. Rebuilt ad-hoc-signed binaries may prompt again. | At startup, ping the gateway and classify the errno. Show a banner and log: "System Settings › Privacy & Security › Local Network → enable <terminal app>". Document it in the README. Every source degrades on its own, so ARP reading still works. |
| **mDNS port 5353 is held by mDNSResponder** | `mdns-sd` binds with SO_REUSEPORT and runs alongside it. Pin to the selected interface and disable IPv6. If bind fails, set `mdns_available=false`, carry on, and show it in the UI. A later fallback could shell out to `/usr/bin/dns-sd`. |
| **Stale ARP cache:** entries live for about 20 minutes, can't be flushed without root, and `(incomplete)` entries exist. | ARP presence alone is never liveness evidence. Liveness comes from ICMP, TCP probe, mDNS/SSDP, or a new ARP entry. `(incomplete)` entries are dropped. |
| **Devices that block ICMP** (Windows firewall, sleeping iPhones) | TCP connect probe to ARP-known silent hosts on 80, 443, 22, 445, 62078 and 8080 with a 300ms timeout; `ECONNREFUSED` counts as alive. Can be turned off with `--no-tcp-probe`. Phones still go offline while asleep; that is expected and documented. |
| **MAC randomization** (iOS/Android private addresses, iOS rotating mode): one phone can appear as several "new" devices | Flag locally-administered MACs (randomized badge, no vendor). Ghost randomized devices offline for more than 7 days are hidden by default. Hostname-based correlation is out of v1 scope. |
| **Multiple interfaces / VPN:** the default route may be `utun*` (full-tunnel VPN), and `bridge100` or Docker may also be present | `iface_select` (pure, tested) prefers `--iface`, then the default route if it is broadcast-capable `en*` with a MAC, then the first active `en*` with a private IPv4. ARP lines are filtered by `on <iface>`. Selection is logged and shown in the UI status bar. |
| **Wi-Fi extenders / MAC-NAT / proxy-ARP:** many IPs behind one MAC collapse into a single node | Detect more than one IP per MAC in a scan, then key by `mac@ip` and set `shared_mac`. |
| **Large or corporate subnets (/16), IDS alerts** | Cap targets with `--max-hosts` (default 1024, nearest the gateway first), keep concurrency at 64, enforce an interval floor of 10s, and document running only on networks you're allowed to scan. |
| **Client isolation (guest/hotel Wi-Fi):** only the gateway is visible | Show a status hint ("network appears to isolate clients"). |
| **Sleep/wake and network switches** | Re-select the interface every cycle. A gateway MAC change switches network_id and sends a fresh snapshot. |
| **Outbound leakage:** reverse DNS would query the upstream resolver | Use `arp -n` and never call `getnameinfo`. Every probe target passes `is_scan_target` (in-subnet unicast), so the only other destinations are the 224.0.0.251 and 239.255.255.250 multicast groups. SSDP LOCATION is never fetched in v1. |
| **3d-force-graph `nodeLabel` renders HTML;** CSS injected by the bundle may conflict with a strict CSP | Escape every label field (tested). Use `style-src 'self' 'unsafe-inline'` only if the console shows violations, and keep `script-src 'self'`. |
| **Layout jumps on every update** | Reconcile by node identity and call `graphData` only when the node set changes. For attribute-only changes, reassign the accessor so the simulation doesn't re-heat. |
| **SQLite blocking the runtime** | Single connection behind a `Mutex`, accessed only via `spawn_blocking`, one transaction per cycle. |

---

## 5. Security notes (localhost-only service)

1. **Bind address:** hardcode `127.0.0.1` (`SocketAddr::from(([127,0,0,1], port))`). No flag exists to change it. If the port is busy, exit with a clear error.
2. **DNS rebinding:** middleware rejects with 403 any request whose `Host` is not exactly `127.0.0.1:<port>` or `localhost:<port>`. This applies to all routes, including static assets.
3. **Origin checks:**
   - SSE and any GET: if an `Origin` header is present it must equal `http://127.0.0.1:<port>` or `http://localhost:<port>`; otherwise 403.
   - No CORS headers are ever sent, so the same-origin policy stops cross-origin reads.
   - State-changing routes (`POST /api/scan`) also require `X-Rhizome: 1`. A cross-origin page can only send that custom header after a preflight, and the preflight fails.
   - All three checks are pure functions with table tests.
4. **Response headers:** `Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on `/api/*`.
5. **Untrusted LAN data (XSS):** hostnames, mDNS names and SSDP SERVER strings come from anyone on the LAN.
   - Server side: sanitize them (control chars, 255-char cap, lossy UTF-8).
   - UI: render with `textContent` only, and pass `nodeLabel` through `escapeHtml`. No `innerHTML` with device data.
6. **Shelling out:**
   - Use `Command::new("/usr/sbin/arp").args(["-an"])` (and `/sbin/ping` in fallback) with absolute paths and no shell.
   - Arguments are fixed or formatted from a typed `Ipv4Addr` that has passed `is_scan_target`, never from strings.
   - Use `tokio::time::timeout` plus `kill_on_drop(true)`, cap stdout at 1 MB, and clear the environment except `PATH=/usr/bin:/bin:/usr/sbin:/sbin`.
7. **SQL:** only `rusqlite` `params![]` with prepared statements; `format!` never builds SQL. Migrations are static SQL from `schema.sql`. Tested with a hostile hostname round-trip.
8. **Files:** the DB directory is 0700 and the file 0600. Nothing is written outside the app support dir. Logs go to stderr only and contain no external identifiers.
9. **Network input parsing:** UDP reads use fixed 8 KB buffers, reject oversize packets, and never panic on malformed input (fuzz-style fixture tests in the `ssdp_parse`/`mdns_map` tests). The SSDP socket binds an ephemeral port, not 1900, so the app never listens for inbound traffic except on the loopback HTTP port.
10. **Supply chain:** the vendored JS is pinned with its sha256 in `ui/vendor/VERSIONS` and the OUI file's hash is in `data/OUI_SOURCE`. `Cargo.lock` is committed. A `cargo deny`/`cargo audit` CI job can come later; it is out of v1 scope.

---

## Success criteria
- [ ] `cargo run` alone serves http://127.0.0.1:7878 with a 3D star centred on the gateway; `lsof` shows a loopback-only listener.
- [ ] Devices appear and disappear live over SSE without a page reload; offline devices are visually distinct within about 3 intervals.
- [ ] The gateway, this machine, online/offline and new devices are each visually distinct; clicking a node shows IP, MAC, vendor, hostname, kind, first/last seen.
- [ ] History survives restarts and is scoped per network.
- [ ] No runtime traffic leaves the subnet or the mDNS/SSDP multicast groups (check with `nettop` or Little Snitch).
- [ ] Host, Origin and XSS tests pass; all pure modules have unit tests and `cargo test` passes without network access (live tests are `#[ignore]`).

Spikes to run first, before slice 3:
1. `surge-ping` DGRAM on Darwin 25.
2. Local Network prompt behaviour for a Terminal-launched binary.
3. Whether `mdns-sd` coexists with mDNSResponder on en0.

Each takes about 30 minutes and decides whether a fallback is needed.
