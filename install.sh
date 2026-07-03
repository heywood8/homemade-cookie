#!/usr/bin/env bash
#
# homemade-cookie - one-shot installer for a censorship-resistant VPN + web portal.
#
#   VLESS + XTLS-Vision + REALITY (TCP 443)   -- primary, looks like HTTPS to a real site
#   Hysteria2 (QUIC/UDP 443) + Salamander     -- backup
#   nginx SNI router                          -- website + VPN share port 443 by domain name
#   form-login portal (disguised)             -- each user sees only their own QR/links
#   node_exporter + SQLite traffic history    -- monitoring, no Prometheus needed
#
# Everything EXCEPT users is set up. Create your first admin afterwards with `vpn-user add`.
# ALL secrets are generated on THIS host at install time - none live in the repository.
#
# Usage:
#   sudo PORTAL_DOMAIN=connect.example.com ./install.sh
#
# Options (env vars):
#   PORTAL_DOMAIN  (required)  hostname the portal is served on
#   REALITY_DEST   (default www.apple.com)  cover site the VPN camouflages as
#   NET_IFACE      (auto)      network interface for the traffic graph
#   SERVER_IP      (auto)      public IPv4 (used to build client links)
#   ENABLE_UFW     (0)         set to 1 to configure+enable ufw (allows 22,80,443)
#   FORCE          (0)         set to 1 to reinstall over an existing install (regenerates secrets!)
#
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
log() { echo -e "\n>>> $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
: "${PORTAL_DOMAIN:?set PORTAL_DOMAIN, e.g. PORTAL_DOMAIN=connect.example.com}"
REALITY_DEST="${REALITY_DEST:-www.apple.com}"
NET_IFACE="${NET_IFACE:-$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')}"
SERVER_IP="${SERVER_IP:-$(curl -fsS4 https://api.ipify.org 2>/dev/null || true)}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -n "$NET_IFACE" ] || die "could not detect network interface; pass NET_IFACE=..."
[ -n "$SERVER_IP" ]  || die "could not detect public IP; pass SERVER_IP=..."

if [ -f /etc/vpn-portal/server.env ] && [ "${FORCE:-0}" != "1" ]; then
  die "already installed (/etc/vpn-portal/server.env exists). Set FORCE=1 to reinstall (regenerates ALL secrets and invalidates existing user links)."
fi

log "domain=$PORTAL_DOMAIN  cover=$REALITY_DEST  iface=$NET_IFACE  ip=$SERVER_IP"

# ---- 1. packages ----
log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget jq qrencode openssl ca-certificates \
        python3 python3-yaml uuid-runtime nginx libnginx-mod-stream

# ---- 2. kernel tuning: BBR + large UDP buffers ----
log "Applying sysctl tuning (BBR + UDP buffers)"
cat >/etc/sysctl.d/99-vpn-tuning.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_fastopen = 3
EOF
sysctl --system >/dev/null

# ---- 3. Xray-core ----
if ! command -v xray >/dev/null; then
  log "Installing Xray-core"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

# ---- 4. Hysteria2 ----
if ! command -v hysteria >/dev/null; then
  log "Installing Hysteria2"
  bash -c "$(curl -fsSL https://get.hy2.sh/)"
fi

# ---- 5. node_exporter ----
if ! command -v node_exporter >/dev/null; then
  log "Installing node_exporter"
  NEV=$(curl -fsSL https://api.github.com/repos/prometheus/node_exporter/releases/latest | jq -r .tag_name | sed 's/^v//')
  ARCH=amd64; case "$(uname -m)" in aarch64|arm64) ARCH=arm64;; esac
  curl -fsSL -o /tmp/ne.tgz "https://github.com/prometheus/node_exporter/releases/download/v${NEV}/node_exporter-${NEV}.linux-${ARCH}.tar.gz"
  tar xzf /tmp/ne.tgz -C /tmp
  install -m755 "/tmp/node_exporter-${NEV}.linux-${ARCH}/node_exporter" /usr/local/bin/node_exporter
  rm -rf /tmp/ne.tgz /tmp/node_exporter-*
fi
id node_exporter >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin node_exporter

# ---- 6. directories + freshly generated secrets (never in the repo) ----
log "Generating secrets + self-signed certificates"
mkdir -p /etc/vpn-portal /var/lib/vpn-portal /opt/vpn-portal /etc/nginx/ssl /etc/nginx/stream.d
KEYS=$(xray x25519)
R_PRIV=$(echo "$KEYS" | awk -F': ' '/PrivateKey/{print $2}')
R_PUB=$(echo  "$KEYS" | awk -F'PublicKey\): ' '/PublicKey/{print $2}')
SHORT_ID=$(openssl rand -hex 8)
OBFS_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-24)
HY_SECRET=$(openssl rand -hex 16)
PORTAL_SECRET=$(openssl rand -hex 32)

# Hysteria self-signed cert (CN = cover site)
openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/server.key 2>/dev/null
openssl req -x509 -new -key /etc/hysteria/server.key -days 3650 -subj "/CN=$REALITY_DEST" \
        -out /etc/hysteria/server.crt 2>/dev/null
chmod 644 /etc/hysteria/server.crt; chmod 640 /etc/hysteria/server.key
chown hysteria:hysteria /etc/hysteria/server.key /etc/hysteria/server.crt 2>/dev/null || true

# nginx origin cert (CN = portal domain; Cloudflare "Full" accepts self-signed)
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$PORTAL_DOMAIN" \
        -keyout /etc/nginx/ssl/origin.key -out /etc/nginx/ssl/origin.crt 2>/dev/null
chmod 600 /etc/nginx/ssl/origin.key

# ---- 7. render configs from templates ----
log "Writing configs"
sed -e "s|__REALITY_PRIVATE_KEY__|$R_PRIV|" -e "s|__REALITY_DEST__|$REALITY_DEST|g" \
    -e "s|__SHORT_ID__|$SHORT_ID|" "$SRC/templates/xray-config.json" > /usr/local/etc/xray/config.json
chown nobody:nogroup /usr/local/etc/xray/config.json; chmod 600 /usr/local/etc/xray/config.json

sed -e "s|__OBFS_PASSWORD__|$OBFS_PASS|" -e "s|__HY_STATS_SECRET__|$HY_SECRET|" \
    -e "s|__MASQUERADE_URL__|https://$REALITY_DEST/|" "$SRC/templates/hysteria-config.yaml" > /etc/hysteria/config.yaml

sed -e "s|__DOMAIN__|$PORTAL_DOMAIN|g" "$SRC/templates/nginx-sni-router.conf" > /etc/nginx/stream.d/sni-router.conf
sed -e "s|__DOMAIN__|$PORTAL_DOMAIN|g" "$SRC/templates/nginx-site.conf" > /etc/nginx/sites-available/vpn-portal.conf
ln -sf /etc/nginx/sites-available/vpn-portal.conf /etc/nginx/sites-enabled/vpn-portal.conf
rm -f /etc/nginx/sites-enabled/default

sed -e "s|__PORTAL_SECRET__|$PORTAL_SECRET|" -e "s|__HY_STATS_SECRET__|$HY_SECRET|" \
    -e "s|__NET_IFACE__|$NET_IFACE|" "$SRC/templates/portal.json" > /etc/vpn-portal/portal.json

# server.env: link-building params for vpn-user (on-server only; contains the obfs secret)
cat >/etc/vpn-portal/server.env <<EOF
PORTAL_DOMAIN=$PORTAL_DOMAIN
SERVER_IP=$SERVER_IP
REALITY_PUBLIC_KEY=$R_PUB
SHORT_ID_1=$SHORT_ID
REALITY_SNI=$REALITY_DEST
HY2_OBFS_PASSWORD=$OBFS_PASS
EOF

# nginx stream{} include (top level, once)
grep -q 'stream.d' /etc/nginx/nginx.conf || \
  printf '\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n' >> /etc/nginx/nginx.conf

# Cloudflare real visitor IP (harmless if you don't use Cloudflare)
if CF4=$(curl -fsSL https://www.cloudflare.com/ips-v4 2>/dev/null) && \
   CF6=$(curl -fsSL https://www.cloudflare.com/ips-v6 2>/dev/null); then
  { echo "# Restore real visitor IP from Cloudflare"; echo "set_real_ip_from 127.0.0.1;"
    for r in $CF4 $CF6; do echo "set_real_ip_from $r;"; done
    echo "real_ip_header CF-Connecting-IP;"; } > /etc/nginx/conf.d/cloudflare-realip.conf
fi

# ---- 8. install app, CLI, collector, units ----
log "Installing portal, CLI and units"
install -m755 "$SRC/portal/app.py"            /opt/vpn-portal/app.py
install -m755 "$SRC/bin/vpn-user"             /usr/local/bin/vpn-user
install -m755 "$SRC/bin/vpn-traffic-collect"  /usr/local/bin/vpn-traffic-collect
install -m644 "$SRC/systemd/vpn-portal.service" "$SRC/systemd/vpn-traffic-collect.service" \
              "$SRC/systemd/vpn-traffic-collect.timer" "$SRC/systemd/node_exporter.service" \
              /etc/systemd/system/
chmod 600 /etc/vpn-portal/portal.json /etc/vpn-portal/server.env
chown -R www-data:www-data /etc/vpn-portal /var/lib/vpn-portal /opt/vpn-portal
systemctl daemon-reload

# ---- 9. enable + start ----
log "Starting services"
systemctl enable --now node_exporter
nginx -t
systemctl restart xray            || echo "  (xray: add a user to enable it)"
systemctl enable --now hysteria-server || echo "  (hysteria: add a user to enable it)"
systemctl enable --now vpn-portal
systemctl restart nginx
systemctl enable --now vpn-traffic-collect.timer

# ---- 10. optional firewall ----
if [ "${ENABLE_UFW:-0}" = "1" ]; then
  log "Configuring ufw"
  apt-get install -y -qq ufw
  ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw allow 443/udp
  ufw --force enable
fi

# ---- done ----
cat <<EOF

============================================================
  Done. The VPN + portal are installed (no users yet).

  1) Create your first admin:
       vpn-user add <name> --admin --pass '<password>'

  2) DNS (Cloudflare): add an A record
       $PORTAL_DOMAIN  ->  $SERVER_IP   (Proxied / orange cloud)
     SSL/TLS mode: Full.

  3) Firewall (if not with ENABLE_UFW=1):
       ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp \\
         && ufw allow 443/udp && ufw --force enable

  Portal:  https://$PORTAL_DOMAIN
  Manage:  vpn-user add|del|list|show|passwd|rotate|rebuild
============================================================
EOF
