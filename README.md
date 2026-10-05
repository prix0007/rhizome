# Rhizome

A single Rust binary that maps the local network you are on and shows it as a live
3D star graph in your browser. The gateway sits at the centre and every other device
is a spoke. Everything stays on your machine: there is no CDN, no telemetry and no
outbound internet traffic at runtime.

## What it does

Each cycle (default every 30 seconds) Rhizome picks the active LAN interface and collects:

- an unprivileged ICMP ping sweep of the subnet (no root needed; this also refreshes the ARP cache),
- the ARP table (`/usr/sbin/arp -an`),
- a TCP connect probe for ARP-known hosts that ignore ping,
- mDNS (hostnames and service types such as `_ipp`, `_airplay`),
- SSDP (the `SERVER` and device-type headers of UPnP devices).

These are merged into device state (vendor from the bundled IEEE OUI list, a
"private/randomized MAC" flag, a guessed device kind, online/offline, first and last seen),
stored in SQLite and pushed to the browser over Server-Sent Events.

## Run it

```sh
cargo run --release        # or just `cargo run`
```

Then open <http://127.0.0.1:7878>. Click a node to see its details; the camera flies to it.

Useful flags (`cargo run -- --help` for all of them):

| Flag | Default | Meaning |
|---|---|---|
| `--port` | 7878 | Web UI port (always on 127.0.0.1) |
| `--iface` | auto | Interface to scan, e.g. `en0` |
| `--interval` | 30 | Seconds between scans (minimum 10) |
| `--db` | `~/Library/Application Support/rhizome/rhizome.db` | History database |
| `--no-tcp-probe` | off | Skip the TCP probe of silent hosts |
| `--max-hosts` | 1024 | Cap on hosts pinged per scan (nearest the gateway first) |

Press Ctrl-C to stop; the scanner and the event streams shut down cleanly and the
database is left intact.

Only scan networks you are allowed to scan.

## macOS "Local Network" permission

Since macOS 15, access to the local network is gated by a privacy permission that belongs
to the app you launched Rhizome from (Terminal, iTerm, VS Code, ...), not to the binary.
If it is denied, LAN traffic fails silently and the map will be nearly empty. Rhizome
detects this when the gateway cannot be reached, shows a banner in the UI and logs:

> System Settings > Privacy & Security > Local Network: enable your terminal app, then restart rhizome.

Visibility also depends on the network: guest and hotel Wi-Fi often isolate clients, so
only the gateway is visible there. Phones that are asleep stop answering and show as
offline; that is expected.

## Security model

Rhizome is a localhost-only service that handles data supplied by whoever is on your LAN,
so it is defensive in both directions.

- **Loopback only.** The listener is hardcoded to `127.0.0.1`; there is no flag to change it.
- **DNS rebinding and cross-origin protection.** Every route, including static files, rejects
  with 403 any request whose `Host` is not exactly `127.0.0.1:<port>` or `localhost:<port>`, and any
  request carrying an `Origin` other than those same origins (including `null`) or a
  `Sec-Fetch-Site` other than `same-origin`/`none`. No CORS headers are ever sent. `localhost` is
  still accepted as a Host, but the only URL Rhizome prints or documents is `http://127.0.0.1:<port>`.
- **Headers.** A strict Content-Security-Policy (`script-src 'self'`, `connect-src 'self'`,
  `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`, and
  `Cache-Control: no-store` on `/api/*`.
  `style-src` allows `'unsafe-inline'` because the vendored 3d-force-graph bundle injects
  `<style>` elements; scripts never get `unsafe-inline` or `unsafe-eval`.
- **Untrusted LAN data.** Hostnames, mDNS names and SSDP headers can be written by anyone on
  the LAN. They are stripped of control, invisible and bidi characters and capped at 255 characters on the
  server, and the UI renders them with `textContent` (tooltips go through `escapeHtml`). Nothing
  device-supplied reaches `innerHTML`. SSDP `LOCATION` URLs are shown as text and never fetched.
- **Subprocesses.** Only `/usr/sbin/arp` and (as a fallback) `/sbin/ping`, by absolute path with
  no shell, a cleared environment, a timeout and a 1 MB output cap. Arguments are fixed or a typed
  IPv4 address that passed the scan-target check.
- **Probe scope.** Every probe target must be a private, in-subnet unicast host. The only other
  destinations are the mDNS and SSDP multicast groups. No reverse DNS, nothing leaves the subnet.
- **SQL and files.** Parameterised statements only. The database directory is created 0700 and the
  file is 0600. Nothing is written outside the application support directory.
- **Bounded LAN input.** At most 64 mDNS service types are browsed (names are validated first),
  the mDNS cache holds 1024 entries, SSDP keeps at most 512 observations per scan (32 per source),
  mDNS and SSDP data from addresses outside the scanned subnet is dropped, ARP entries outside it are
  ignored, and a network is capped at 2048 devices (the status bar warns when the cap is hit).
- **Network surface.** The only listener for browsers is the loopback HTTP port; the SSDP socket uses
  an ephemeral port. mDNS (via `mdns-sd`) also holds UDP 5353 sockets, shared with macOS's own mDNS
  responder, so other local interfaces could feed it packets; everything it yields is filtered to the
  scanned subnet before use.
- **Supply chain.** The vendored JavaScript (`ui/vendor/VERSIONS`) and the OUI list
  (`data/OUI_SOURCE`) are pinned with their SHA-256. `Cargo.lock` pins the Rust dependencies.

## Known limitations

- A restart within about three scan intervals of the previous run shows devices as online until
  that window passes, because the last evidence is still recent.
- Online/offline uses the wall clock; a backward clock jump keeps devices online longer.
- Locally administered (private) MACs are shown without a vendor, even for the occasional router
  or access point that uses one legitimately.
- The vendor list is the IEEE MA-L registry only; MA-M and MA-S blocks resolve to nothing useful.
- Only Ctrl-C (SIGINT) triggers the graceful shutdown, not SIGTERM. Writes are transactional, so the
  database stays consistent either way.
- mDNS and SSDP identity data is not authenticated: any host on the LAN can claim to be another
  device's hostname, services or UPnP type, which can change that device's guessed kind.
- The SHA-256 values for the vendored JavaScript and the OUI list prove files have not drifted since
  they were fetched; they are not checked against a registry-signed value.
- `--db` only tightens permissions on a directory Rhizome creates itself; it does not validate
  existing parent directories or refuse symlinks, so keep the database somewhere only you can write.
- There is no age-based pruning: devices accumulate (up to the 2048 cap) and are never removed
  automatically, including old randomized-MAC "ghost" devices.
- Rescan-on-demand, shared-MAC handling for extenders, the client-isolation hint and sleep/wake
  handling are not implemented.

## Development

```sh
cargo test                  # no network needed
cargo test -- --ignored     # live tests: need a real LAN (see the env vars in each test)
node --test ui/tests/       # UI logic tests
scripts/vendor-ui.sh        # re-vendor 3d-force-graph (dev time only)
scripts/update-oui.sh       # refresh data/oui.csv (dev time only)
```

Debug builds serve `ui/` from disk, so UI edits need no rebuild; release builds embed it.
