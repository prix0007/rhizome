<p align="center">
  <img src="ui/logo.svg" width="96" alt="Rhizome logo">
</p>

# Rhizome

**Rhizome is a local network mapper for macOS. It scans the network you are connected to
and draws it as a live 3D graph in your browser, with your router at the centre and every
device around it.** It is a single Rust binary: run it, open a page on your own machine,
and watch devices appear and disappear. Nothing leaves your computer: no cloud, no CDN, no
telemetry, no outbound internet traffic.

## Features

- **Live 3D map** of the LAN (gateway at the centre), updated over Server-Sent Events.
- **Finds devices four ways:** an unprivileged ping sweep (no root), the ARP table, mDNS and SSDP.
- **Tells you what they are:** vendor from the IEEE registry, a private/randomized-MAC flag, a
  guessed device kind (printer, TV, phone, ...), and richer details from the device itself:
  - friendly name, manufacturer and model (UPnP device descriptions and mDNS TXT records),
  - DNS name (the gateway's reverse DNS) and NetBIOS name (Windows/Samba machines),
  - latest ping round-trip time and a coarse OS family guess from the reply TTL.
- **Name your devices.** Give any device a custom name and notes; they are saved and survive restarts.
- **Remembers:** history in a local SQLite file, so offline devices keep their "last seen" and new
  arrivals are highlighted. History is kept per network.
- **Private by design:** the page is served on `127.0.0.1` only, and everything Rhizome sends stays
  on your subnet (see [Security model](#security-model)).

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
| `--no-netbios` | off | Do not send NetBIOS node-status queries (UDP 137) to hosts |
| `--no-dns` | off | Do not send reverse-DNS (PTR) queries to the gateway |
| `--no-upnp` | off | Do not fetch UPnP device descriptions from hosts |
| `--max-hosts` | 1024 | Cap on hosts pinged per scan (nearest the gateway first) |

Press Ctrl-C to stop; the scanner and the event streams shut down cleanly and the
database is left intact.

Only scan networks you are allowed to scan.

## What Rhizome collects, and how

Each cycle (default every 30 seconds) Rhizome picks the active LAN interface and gathers:

| Source | Gives you | Notes |
|---|---|---|
| ICMP ping sweep | which hosts are alive, round-trip time (`rtt_ms`), OS family guess (`os_hint`) | Unprivileged `SOCK_DGRAM` ICMP; falls back to `/sbin/ping` (RTT only, no TTL) |
| ARP table | IP to MAC mapping | `/usr/sbin/arp -an` |
| TCP connect probe | liveness of hosts that ignore ping | Skipped with `--no-tcp-probe` |
| mDNS | hostname, service types, plus `friendly_name`, `model`, `manufacturer` from TXT records | Bounded and filtered to the subnet |
| SSDP | UPnP server banner and device types | One M-SEARCH to the multicast group |
| UPnP description | `friendly_name`, `manufacturer`, `model` | HTTP fetch of the SSDP `LOCATION`, under a strict policy (below). Cached 6 hours. Skipped with `--no-upnp` |
| Gateway reverse DNS | `dns_name` | PTR queries sent **only to the gateway** on UDP 53, with recursion off (RD=0, see below). Cached 1 hour. Skipped with `--no-dns` |
| NetBIOS node status | `netbios_name` | UDP 137 unicast to hosts on the subnet. Cached; skipped with `--no-netbios` |

Every extra source is isolated: if one fails, the others and the scan carry on, and the
status bar shows a warning for that source. Slow or silent sources are cached so they cost one
short, bounded wait the first time and nothing on later scans.

Not every network yields every field. A device only reports what it chooses to expose, and many
home routers have no reverse DNS entries for their clients. Fields that are unknown are simply
absent from the JSON.

The merged result goes through a vendor lookup (the bundled IEEE OUI list), a guess at the device
kind, online/offline tracking, and is stored in SQLite and pushed to the browser.

**What happens to a value that is no longer reported.** Learned values are not frozen: the
database mirrors the live state, and a newer observation always replaces the stored one.

- UPnP fields: each successfully fetched description replaces `friendly_name`, `manufacturer` and
  `model` exactly, so a field it no longer has is dropped. A failed or not-yet-due fetch keeps the old values.
- `dns_name` / `netbios_name`: replaced by each newer answer, and dropped when a completed query for a host
  that answered ping finds no name. A silent (asleep or offline) host keeps its name.
- `os_hint`: replaced by each ping reply, kept when there is none. `rtt_ms` is only ever the latest scan's.
- Names and notes you set yourself are never touched by any of this.

### Naming and annotating devices

Names and notes are yours: they are never set or changed by anything learned from the network.

```sh
curl -X PUT http://127.0.0.1:7878/api/devices/02%3A21%3A49%3Ab8%3A2c%3A62/meta \
  -H 'Origin: http://127.0.0.1:7878' -H 'X-Rhizome: 1' -H 'Content-Type: application/json' \
  -d '{"custom_name": "Living room TV", "notes": "remote is in the drawer"}'
```

- The device id (a MAC, or `mac@ip` for devices sharing a MAC) goes in the URL, percent-encoded.
- `custom_name` is at most 64 characters, `notes` at most 500. `null` or an empty string clears a field;
  a field you leave out is left unchanged.
- The request must carry an `Origin` header that matches the page's own origin and `X-Rhizome: 1`,
  otherwise it is refused with 403. Unknown ids get 404, malformed bodies 400, bodies over 4 KB 413.
- The response is the updated device. The change is pushed to every open page and saved in SQLite
  per network, so it survives restarts.

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
- **The one state-changing endpoint.** `PUT /api/devices/{id}/meta` additionally requires an `Origin`
  header that is present and exactly the page's own origin, plus the custom header `X-Rhizome: 1`
  (a cross-origin page cannot send it without a preflight, which is never answered). The check runs
  before the body is read; bodies are capped at 4 KB, parsed strictly, length-limited and sanitised.
- **Headers.** A strict Content-Security-Policy (`script-src 'self'`, `connect-src 'self'`,
  `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`, and
  `Cache-Control: no-store` on `/api/*`.
  `style-src` allows `'unsafe-inline'` because the vendored 3d-force-graph bundle injects
  `<style>` elements; scripts never get `unsafe-inline` or `unsafe-eval`.
- **Untrusted LAN data.** Hostnames, mDNS names and TXT values, SSDP headers, UPnP descriptions, DNS
  and NetBIOS names can all be written by anyone on the LAN. They are stripped of control, invisible
  and bidi characters and capped at 255 characters on the server, and the UI renders them with
  `textContent` (tooltips go through `escapeHtml`). Nothing device-supplied reaches `innerHTML`.
- **The UPnP fetch is the only HTTP request chosen by a LAN host,** so it is locked down hard: plain
  `http://` only, to an IPv4 literal that is exactly the address the SSDP reply came from and is a
  private, in-subnet unicast host; no redirects are followed; 2 s connect and 3 s total timeouts;
  the URL's query string and fragment are dropped and only the port named in the `LOCATION` is used; the
  response is capped at 256 KB; at most 16 fetches per scan with 4 in flight, and a successful
  description is not fetched again for 6 hours. The XML is read with a real parser that never
  expands entities and never fetches a DTD: a document with a DOCTYPE is rejected outright.
- **Reverse DNS goes to the gateway only, and asks it not to recurse.** PTR queries are sent with the
  recursion-desired bit cleared (RD=0), so the gateway answers from its own lease and host tables and has no
  reason to forward your LAN addresses to its upstream resolver. If a router recurses anyway, `--no-dns`
  turns the source off. PTR queries are hand-built UDP packets sent to the
  gateway's address (and only if the gateway is itself an in-subnet host), never through the system
  resolver, so a lookup cannot reach the upstream DNS server or the internet. Replies are accepted
  only from that socket with a matching random transaction id and question, parsed with strict bounds
  (compression pointers are loop-limited, names length-capped), and answers that merely echo the
  address are dropped.
- **NetBIOS** queries are UDP unicast to in-subnet hosts, replies must come from the address *and port* that
  were asked and echo the transaction id, and `--no-netbios` turns the source off entirely.
- **The three optional sources** (`--no-upnp`, `--no-dns`, `--no-netbios`) are independent; with all three set,
  Rhizome sends nothing beyond the base scan (ping, ARP, mDNS and SSDP).
- **Subprocesses.** Only `/usr/sbin/arp` and (as a fallback) `/sbin/ping`, by absolute path with
  no shell, a cleared environment, a timeout and a 1 MB output cap. Arguments are fixed or a typed
  IPv4 address that passed the scan-target check.
- **Network scope.** Every probe target (ICMP, TCP, UPnP, NetBIOS) must be a private, in-subnet unicast
  host. The only other destinations are the mDNS and SSDP multicast groups and the gateway's DNS port.
  Nothing is sent to the internet.
- **SQL and files.** Parameterised statements only. The database directory is created 0700 and the
  file is 0600. Nothing is written outside the application support directory.
- **Bounded LAN input.** At most 64 mDNS service types are browsed (names are validated first),
  the mDNS cache holds 1024 entries, SSDP keeps at most 512 observations per scan (32 per source),
  at most 64 DNS and 64 NetBIOS lookups are sent per scan, mDNS and SSDP data from addresses outside
  the scanned subnet is dropped, ARP entries outside it are ignored, and a network is capped at
  2048 devices (the status bar warns when the cap is hit).
- **Network surface.** The only listener for browsers is the loopback HTTP port; the SSDP, DNS and
  NetBIOS sockets use ephemeral ports. mDNS (via `mdns-sd`) also holds UDP 5353 sockets, shared with
  macOS's own mDNS responder, so other local interfaces could feed it packets; everything it yields
  is filtered to the scanned subnet before use.
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
- **mDNS-derived identity is LAN-spoofable and treated as untrusted.** The mDNS library does not expose the
  source address of a packet, so `friendly_name`, `model` and `manufacturer` taken from mDNS TXT records cannot
  be tied to the host that sent them. Any LAN host can announce such records for another host's address.
  Those values are shown but never used to classify a device and never written to the database, and they
  never override a UPnP value (UPnP, DNS and NetBIOS replies are checked against the address they came from).
  mDNS hostnames and service types, which have always been used for classification, are spoofable the same way.
- mDNS, SSDP, UPnP, DNS and NetBIOS identity data is not authenticated: any host on the LAN can claim
  to be another device's name, model or type, which can change that device's guessed kind.
- The SHA-256 values for the vendored JavaScript and the OUI list prove files have not drifted since
  they were fetched; they are not checked against a registry-signed value.
- `--db` only tightens permissions on a directory Rhizome creates itself; it does not validate
  existing parent directories or refuse symlinks, so keep the database somewhere only you can write.
- There is no age-based pruning: devices accumulate (up to the 2048 cap) and are never removed
  automatically, including old randomized-MAC "ghost" devices.
- Rescan-on-demand, shared-MAC handling for extenders, the client-isolation hint and sleep/wake
  handling are not implemented.
- **DNS names** only appear if the gateway has reverse records for its clients. Many consumer routers
  answer "no such name" for every address, in which case `dns_name` stays empty.
- **NetBIOS** only answers from Windows and Samba machines, and some firewalls drop UDP 137.
- **`os_hint` is a rough guess.** It comes from the ping reply's TTL: 64 means Linux/Unix/macOS-like (it
  cannot tell those apart, or Android and iOS), 128 Windows-like, 255 network gear or embedded. It is
  absent when the `/sbin/ping` fallback is in use, and a device behind a NAT or proxy can skew it.
- **`rtt_ms` is ping latency, not network quality.** Sleeping phones and TVs answer slowly.
- **UPnP descriptions** are fetched once per host per 6 hours (and a failure is retried after
  30 minutes). That cache is in memory, so a restart fetches again; the learned fields themselves are
  stored in SQLite and shown for offline devices. Only one `LOCATION` per host is used.
- Learned names and models are remembered even if the device is later replaced by a different one
  at the same MAC; custom names and notes are last-write-wins with no history or undo.

## License

MIT; see [LICENSE](LICENSE).

## Development

```sh
cargo test                  # no network needed
cargo test -- --ignored     # live tests: need a real LAN (see the env vars in each test)
node --test ui/tests/       # UI logic tests
scripts/vendor-ui.sh        # re-vendor 3d-force-graph (dev time only)
scripts/update-oui.sh       # refresh data/oui.csv (dev time only)
```

Debug builds serve `ui/` from disk, so UI edits need no rebuild; release builds embed it.
