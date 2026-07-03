# 🍪 homemade-cookie

One-shot installer for a **censorship-resistant VPN + web portal** on a fresh Ubuntu server.

It stands up a dual-protocol VPN that looks like ordinary HTTPS, plus a password-gated web
portal (disguised as an online cookie shop) where each user logs in and sees only their own
connection QR codes — all sharing a single port `443`.

> Designed for restrictive networks (deep-packet-inspection / active probing). The server
> should live **outside** the censored country.

## What you get

| Component | Port | Role |
|---|---|---|
| **VLESS + XTLS-Vision + REALITY** (Xray) | TCP 443 | Primary VPN — indistinguishable from a real TLS visit to a cover site |
| **Hysteria2 + Salamander obfs** | UDP 443 | Backup VPN — obfuscated QUIC, punches through throttling |
| **nginx SNI router** | TCP 443 | Website and VPN share 443, routed by TLS SNI |
| **Login portal** (Python, stdlib) | (127.0.0.1) | Disguised form login; per-user pages with QR/links |
| **node_exporter + SQLite** | (127.0.0.1) | Live monitoring + per-user traffic history, no Prometheus |

```
                nginx SNI router on TCP :443 (ssl_preread — reads SNI, never decrypts)
 TLS :443 ─▶    SNI = your portal domain  ─▶ 127.0.0.1:8443  →  portal (nginx TLS → app)
                SNI = cover site (VPN)     ─▶ 127.0.0.1:8001  →  Xray REALITY
 UDP :443 ─▶    Hysteria2 (separate transport)
```

## Requirements

- Fresh **Ubuntu 22.04 / 24.04** (x86_64 or arm64), root access.
- A **domain you control** for the portal (e.g. `connect.example.com`), ideally behind Cloudflare.
- The server must be reachable on TCP+UDP 443.

## Install

```bash
git clone https://github.com/heywood8/homemade-cookie.git
cd homemade-cookie
sudo PORTAL_DOMAIN=connect.example.com ./install.sh
```

Options (env vars): `REALITY_DEST` (cover site, default `www.apple.com`), `NET_IFACE`,
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

Users then open `https://connect.example.com`, log in, and scan their two QR codes (Hiddify
recommended — it supports both protocols with auto-failover).

## Managing users

```bash
vpn-user add    <name> [--admin] [--pass <pw>]   # create (both protocols + portal login)
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
