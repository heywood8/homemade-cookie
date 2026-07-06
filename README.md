# 🍪 homemade-cookie

One-shot installer for a **censorship-resistant VPN + web portal** on a fresh Ubuntu server.

It stands up a triple-transport VPN that looks like ordinary HTTPS, plus a password-gated web
portal (disguised as an online cookie shop) where each user logs in and sees only their own
connection QR codes — all sharing a single port `443`.

> Designed for restrictive networks (deep-packet-inspection / active probing). The server
> should live **outside** the censored country.

## What you get

| Component | Port | Role |
|---|---|---|
| **VLESS + XTLS-Vision + REALITY** (Xray) | TCP 443 | Primary VPN — indistinguishable from a real TLS visit to a cover site |
| **Hysteria2 + Salamander obfs** | UDP 443 | Backup VPN — obfuscated QUIC, punches through throttling |
| **VLESS + WebSocket + TLS** (Xray, CDN-fronted) | TCP 443 (via CDN) | Fallback VPN — for ISPs that block direct TCP/443 to this server's IP or fingerprint REALITY/QUIC; rides ordinary HTTPS to the CDN's own IPs |
| **nginx SNI router** | TCP 443 | Website and VPN share 443, routed by TLS SNI |
| **Login portal** (Python, stdlib) | (127.0.0.1) | Disguised form login; per-user pages with QR/links |
| **node_exporter + SQLite** | (127.0.0.1) | Live monitoring + per-user traffic history, no Prometheus |

```
                nginx SNI router on TCP :443 (ssl_preread — reads SNI, never decrypts)
 TLS :443 ─▶    SNI = your portal domain  ─▶ 127.0.0.1:8443  →  portal or WS-CDN (by path)
                SNI = cover site (VPN)     ─▶ 127.0.0.1:8001  →  Xray REALITY
 UDP :443 ─▶    Hysteria2 (separate transport)
```

The portal domain's nginx block routes by **path**: a secret path goes to the Xray WS-CDN
inbound (`127.0.0.1:8002`), everything else goes to the portal (`127.0.0.1:8081`). Put that
domain behind a CDN (Cloudflare) and the WS-CDN path becomes reachable even when the server's
own IP is blocked on TCP/443, because clients connect to the CDN's IPs instead.

## Requirements

- Fresh **Ubuntu 22.04 / 24.04** (x86_64 or arm64), root access.
- A **domain you control** for the portal (e.g. `connect.example.com`), **behind Cloudflare**
  (or another CDN) — required for the WS-CDN fallback to actually front a different IP than
  the VPS.
- The server must be reachable on TCP+UDP 443.

## Install

```bash
git clone https://github.com/heywood8/homemade-cookie.git
cd homemade-cookie
sudo PORTAL_DOMAIN=connect.example.com ./install.sh
```

Options (env vars): `REALITY_DEST` (cover site, default `www.twitch.tv` — avoid `apple.com`,
Apple's own ASN makes the REALITY handshake detectable on some networks), `NET_IFACE`,
`SERVER_IP`, `ENABLE_UFW=1`, `FORCE=1` (reinstall). See the top of `install.sh`.

**All secrets (REALITY keys, passwords, obfs, session secret) are generated on the server at
install time — nothing sensitive is stored in this repository.**

## After install

The installer sets up everything **except users**. Then:

1. **Create your first admin** (admins also see the monitor):
   ```bash
   vpn-user add me --admin --pass 'strong-password'
   ```
2. **DNS** (Cloudflare): add an `A` record `connect.example.com → <server-ip>`, **Proxied**
   (orange cloud); SSL/TLS mode **Full**.
3. **Firewall**: `ufw allow 22,80,443/tcp && ufw allow 443/udp && ufw --force enable`
   (or run the installer with `ENABLE_UFW=1`).

Users then open `https://connect.example.com`, log in, and scan their QR codes (Hiddify
recommended — it holds every profile and auto-fails-over). Everyone gets **REALITY** and
**Hysteria2**; the portal also shows a **WS-CDN** QR as a third, fallback option for anyone
whose ISP blocks the first two outright (see [Transports](#transports--when-to-use-which)).

## Managing users

```bash
vpn-user add    <name> [--admin] [--pass <pw>]   # create (all transports + portal login)
vpn-user del    <name>                           # remove + revoke everywhere
vpn-user list                                    # list users
vpn-user show   <name>                           # reprint login / links / QR
vpn-user passwd <name> <pw>                       # change portal password
vpn-user rotate <name>                           # new UUID + Hysteria pw (old links die)
vpn-user rebuild                                  # re-apply configs/links from the store
```

The store of record is `/etc/vpn-portal/users.json` (root/www-data, `600`) — that's the file
to back up.

## Monitoring

`https://<portal>/monitor` (admins only): live CPU / RAM / disk / network + per-user VPN
traffic, and a **traffic-history** view (last 5 hours / last week) backed by a 2-minute SQLite
sampler (`vpn-traffic-collect`, ~15 MB/day, 8-day retention). No Prometheus required.

## Security notes

- **REALITY** carries no weakness from `encryption=none` in the link — that's the VLESS layer;
  the actual encryption is TLS 1.3 (AEAD) done by REALITY.
- **Hysteria2** uses a self-signed cert, so client links carry `insecure=1`. This is gated by
  the Salamander obfuscation shared secret (a MITM without it can't even speak the protocol).
  To make it "clean", point a real domain at the box + Let's Encrypt, or use `pinSHA256`.
- Metrics endpoints (node_exporter, Xray, Hysteria stats) listen on `127.0.0.1` only.
- The portal login page is disguised (see `LOGIN_PAGE` in `portal/app.py`); customize freely.

## Transports & when to use which

| Transport | Use when | Beats |
|---|---|---|
| **① REALITY** (default) | Baseline — try this first | Passive DPI (looks like a real TLS visit to the cover site) |
| **② Hysteria2** | REALITY is slow/throttled | UDP/QUIC-friendly networks; different traffic shape than TCP |
| **③ WS-CDN** (fallback) | ① and ② both fail to connect at all | ISPs that **drop direct TCP/443 to this server's IP** or **actively fingerprint REALITY's handshake** — since WS-CDN routes through Cloudflare's own IPs with an ordinary TLS+WebSocket upgrade, there's no server IP or REALITY signature to block |

None of these beat an ISP that blocks the CDN's IP ranges or the domain itself (SNI-block) —
if even the portal page won't load over plain HTTPS, the issue is upstream of anything this
project controls.

**Diagnosing a "VPN just times out" report** — work down this list before assuming the
protocol is broken:
1. `ping`/`curl` the server's bare IP — packet loss or connect-timeout here is network path, not app config.
2. Check whether it's **all** transports or just one. All three down and the portal itself
   unreachable in a plain browser → likely the domain/CDN is blocked, not the server.
   Only REALITY down but Hysteria2 fine (or vice versa) → protocol-specific interference
   (DPI fingerprinting one, not the other); point them at WS-CDN.
3. `tail -f /var/log/xray/access.log` and `/var/log/nginx/<domain>.access.log` while the user
   reconnects — a completed TCP handshake with **no** application-layer bytes exchanged means
   the transport is being fingerprinted/reset, not just rate-limited or slow.
4. Rule out a **stale/active profile**: if any VPN profile is toggled on and failing, it can
   swallow all of the device's traffic (including the portal page itself), which looks
   identical to "the whole network is down."

## Networking & ops notes

- **IPv6 is deliberately black-holed for TCP literals, but domains still resolve to IPv4.**
  `routing.domainStrategy` is `AsIs` (xray does **not** pre-resolve domains for routing), and a
  rule sends IPv6 **literal** destinations (`"ip": ["::/0"]`) to `block`; Hysteria2 gets the
  equivalent via `outbounds: [{type: direct, direct: {mode: 4}}]`. Most VPS get only IPv4 +
  link-local with no global IPv6 route, so without this, any client that tries a dual-stack
  destination over IPv6 first (dual-stack websites, HTTP/3, connectivity-check hosts like
  `captive.apple.com`) gets forwarded into a dead route and **stalls until it times out**
  before falling back to IPv4 — felt as a slow, unstable VPN.
  ⚠️ Do **not** use `domainStrategy: IPIfNonMatch` (or any resolving strategy) together with
  the `::/0` block rule — that combination resolves dual-stack *domains* to their IPv6 address
  and black-holes them outright, breaking sites that would otherwise work fine over IPv4.
  *If your server has working global IPv6*, delete the `::/0` rule and the Hysteria `mode: 4`
  outbound to serve IPv6 natively.
- **Xray config ownership.** `xray.service` runs as `User=nobody`, and
  `/usr/local/etc/xray/config.json` is mode `600` — so it **must** be owned `nobody:nogroup`.
  `install.sh` and `vpn-user` already re-apply this on every write. If you ever hand-edit the
  file as root, restore it or Xray won't start (`permission denied`, exit 23):
  ```bash
  chown nobody:nogroup /usr/local/etc/xray/config.json && chmod 600 /usr/local/etc/xray/config.json
  xray -test -config /usr/local/etc/xray/config.json && systemctl restart xray
  ```
- **WS-CDN requires the portal domain to be genuinely CDN-fronted** (Cloudflare orange-cloud
  Proxied, not just DNS-only) — otherwise clients connect straight to the same blocked/
  fingerprinted server IP and gain nothing over REALITY. `install.sh` generates a random
  secret path (`WS_CDN_PATH` in `/etc/vpn-portal/server.env`) so the fallback endpoint isn't
  guessable from the outside; nginx routes that one path to Xray and everything else to the
  portal on the same domain/port.
- **Upgrading an existing install to add WS-CDN**: add `WS_CDN_PATH=/<random>/<random>` to
  `/etc/vpn-portal/server.env`, add the WS-CDN inbound block from
  `templates/xray-config.json` to your live `/usr/local/etc/xray/config.json` (fill in
  `__WS_CDN_PATH__`/`__DOMAIN__`), add the matching `location` block from
  `templates/nginx-site.conf` to your site file, `nginx -t && systemctl reload nginx`, then
  delete the `"template"` key from `/etc/vpn-portal/users.json` and run `vpn-user rebuild` to
  regenerate everyone's links including the new WS-CDN one.

## Layout

```
install.sh              orchestrator
bin/vpn-user            user management CLI
bin/vpn-traffic-collect traffic sampler (systemd timer)
portal/app.py           login portal + monitor (Python stdlib)
templates/              config templates (placeholders filled at install)
systemd/                unit files
```

## Disclaimer

For lawful privacy and anti-censorship use. You are responsible for complying with the laws
that apply to you. No warranty.

## License

MIT — see [LICENSE](LICENSE).
