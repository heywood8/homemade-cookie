#!/usr/bin/env python3
"""Multi-user form-login portal for the VPN. Disguised as a cookie shop.

Auth against /etc/vpn-portal/users.json (managed by `vpn-user`). Each user logs in and
sees only their own REALITY + Hysteria2 links/QR. Admins additionally get /monitor with a
per-user traffic breakdown. Session cookie lasts 24h.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import sqlite3
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONF_FILE = "/etc/vpn-portal/portal.json"
USERS_FILE = "/etc/vpn-portal/users.json"
LISTEN = ("127.0.0.1", 8081)
COOKIE = "vpn_session"
TTL = 24 * 3600  # 1 day

_c = json.load(open(CONF_FILE))
SECRET = _c["secret"].encode()
_M = _c.get("metrics", {})
NODE_URL = _M.get("node", "http://127.0.0.1:9100/metrics")
XRAY_URL = _M.get("xray_vars", "http://127.0.0.1:11111/debug/vars")
HY_API = _M.get("hy_api", "http://127.0.0.1:9999")
HY_SECRET = _M.get("hy_secret", "")
NET_IFACE = _M.get("iface", "ens35")


def load_users():
    try:
        return json.load(open(USERS_FILE)).get("users", {})
    except Exception:
        return {}


# ---------------- session ----------------
def make_token(user):
    exp = str(int(time.time()) + TTL)
    sig = hmac.new(SECRET, f"{user}|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{user}|{exp}|{sig}"


def check_token(tok):
    try:
        user, exp, sig = tok.split("|")
        good = hmac.new(SECRET, f"{user}|{exp}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(good, sig) and int(exp) >= int(time.time()):
            return user
    except Exception:
        pass
    return None


# ---------------- metrics ----------------
_LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


def _http(url, headers=None, timeout=3):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _scan_node(text, wanted):
    res = {}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        try:
            key, val = line.rsplit(" ", 1)
            v = float(val)
        except ValueError:
            continue
        name = key[:key.index("{")] if "{" in key else key
        if name not in wanted:
            continue
        labels = dict(_LABEL_RE.findall(key)) if "{" in key else {}
        res.setdefault(name, []).append((labels, v))
    return res


def node_metrics():
    want = {"node_cpu_seconds_total", "node_memory_MemTotal_bytes", "node_memory_MemAvailable_bytes",
            "node_filesystem_size_bytes", "node_filesystem_avail_bytes",
            "node_network_receive_bytes_total", "node_network_transmit_bytes_total",
            "node_load1", "node_load5", "node_load15", "node_boot_time_seconds",
            "node_netstat_Tcp_CurrEstab"}
    d = _scan_node(_http(NODE_URL), want)

    def first(n):
        return d.get(n, [({}, 0.0)])[0][1]

    def fs(n):
        for lb, v in d.get(n, []):
            if lb.get("mountpoint") == "/":
                return v
        return 0.0

    def net(n):
        for lb, v in d.get(n, []):
            if lb.get("device") == NET_IFACE:
                return v
        return sum(v for lb, v in d.get(n, []) if lb.get("device", "lo") != "lo")

    return {
        "cpu_total": sum(v for _, v in d.get("node_cpu_seconds_total", [])),
        "cpu_idle": sum(v for lb, v in d.get("node_cpu_seconds_total", []) if lb.get("mode") == "idle"),
        "ncpu": len({lb.get("cpu") for lb, _ in d.get("node_cpu_seconds_total", [])}) or 1,
        "mem_total": first("node_memory_MemTotal_bytes"), "mem_avail": first("node_memory_MemAvailable_bytes"),
        "disk_total": fs("node_filesystem_size_bytes"), "disk_avail": fs("node_filesystem_avail_bytes"),
        "net_rx": net("node_network_receive_bytes_total"), "net_tx": net("node_network_transmit_bytes_total"),
        "load1": first("node_load1"), "load5": first("node_load5"), "load15": first("node_load15"),
        "boot": first("node_boot_time_seconds"), "tcp_estab": first("node_netstat_Tcp_CurrEstab"),
    }


def _xray_raw():
    try:
        return json.loads(_http(XRAY_URL)).get("stats", {})
    except Exception:
        return {}


def _hy_raw():
    try:
        h = {"Authorization": HY_SECRET}
        return json.loads(_http(HY_API + "/traffic", h)), json.loads(_http(HY_API + "/online", h))
    except Exception:
        return {}, {}


def collect_metrics(names):
    out = {"t": int(time.time() * 1000)}
    try:
        out["host"] = node_metrics()
    except Exception as e:
        out["host"] = {"error": str(e)}
    xs = _xray_raw()
    inb = xs.get("inbound", {}).get("vless-reality", {})
    xu = xs.get("user", {})
    htr, hon = _hy_raw()
    out["xray"] = {"down": inb.get("downlink", 0), "up": inb.get("uplink", 0), "users": len(xu)}
    out["hysteria"] = {"down": sum(u.get("rx", 0) for u in htr.values()),
                       "up": sum(u.get("tx", 0) for u in htr.values()),
                       "online": sum(hon.values()) if hon else 0}
    per = {}
    for n in names:
        x = xu.get(n, {})
        h = htr.get(n, {})
        per[n] = {"rl_down": x.get("downlink", 0), "rl_up": x.get("uplink", 0),
                  "hy_down": h.get("rx", 0), "hy_up": h.get("tx", 0), "online": hon.get(n, 0)}
    out["users"] = per
    return out


TRAFFIC_DB = "/var/lib/vpn-portal/traffic.db"


def traffic_window(bucket_sec, n_buckets):
    """Per-user totals + bucketed series over the last n_buckets*bucket_sec seconds."""
    now = int(time.time())
    start = (now // bucket_sec - (n_buckets - 1)) * bucket_sec
    per = {}
    series = [{"t": (start + i * bucket_sec) * 1000, "users": {}} for i in range(n_buckets)]
    try:
        con = sqlite3.connect(f"file:{TRAFFIC_DB}?mode=ro", uri=True, timeout=2)
        for u, d, up in con.execute(
                "SELECT user, SUM(down), SUM(up) FROM samples WHERE ts>=? GROUP BY user", (start,)):
            per[u] = {"down": d or 0, "up": up or 0}
        for u, b, d, up in con.execute(
                "SELECT user, (ts-?)/? AS b, SUM(down), SUM(up) FROM samples WHERE ts>=? GROUP BY user, b",
                (start, bucket_sec, start)):
            bi = int(b)
            if 0 <= bi < n_buckets:
                series[bi]["users"][u] = {"down": d or 0, "up": up or 0}
        con.close()
    except Exception:
        pass
    return {"per": per, "series": series}


# ---------------- pages ----------------
LOGIN_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Бабушкины печеньки — Личный кабинет</title>
<style>
:root{{color-scheme:light dark;--bg:#f7ecd9;--bg2:#efd9b8;--card:#fffdf8;--fg:#4a3623;--mut:#9c866b;--acc:#cf7a24;--acc2:#a85f18;--line:#e7d6bd;--err:#c0392b}}
@media (prefers-color-scheme:dark){{:root{{--bg:#241a12;--bg2:#2f2216;--card:#2c2016;--fg:#f0e4d4;--mut:#b39c81;--line:#3d2e1f}}}}
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,var(--bg),var(--bg2));color:var(--fg);
font-family:'Segoe UI',system-ui,-apple-system,Roboto,sans-serif;padding:20px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:32px 28px;width:100%;max-width:372px;
box-shadow:0 18px 50px #6b451a26}}
.logo{{font-size:2.8rem;text-align:center;line-height:1}}
.brand{{text-align:center;font-size:1.45rem;font-weight:700;letter-spacing:.2px;margin:.2rem 0 .1rem}}
.tag{{text-align:center;color:var(--mut);font-size:.85rem;margin-bottom:22px}}
h1{{font-size:1.02rem;font-weight:600;margin:0 0 4px}}
.hint{{color:var(--mut);font-size:.8rem;margin-bottom:16px}}
label{{display:block;font-size:.78rem;color:var(--mut);margin:12px 0 5px}}
input{{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:#fff;color:#3a2c1c;
font-size:1rem;outline:none}}
@media (prefers-color-scheme:dark){{input{{background:#1f160e;color:var(--fg)}}}}
input:focus{{border-color:var(--acc)}}
button{{width:100%;margin-top:22px;padding:13px;border:0;border-radius:12px;
background:linear-gradient(180deg,var(--acc),var(--acc2));color:#fff;font-size:1.02rem;font-weight:700;cursor:pointer}}
button:hover{{filter:brightness(1.05)}}
.pw-wrap{{position:relative}}
.pw-wrap input{{padding-right:46px}}
.eye{{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:auto;margin:0;padding:6px;background:none;color:var(--mut);box-shadow:none;cursor:pointer;display:flex;align-items:center;border-radius:8px}}
.eye svg{{display:block}}
.eye:hover{{filter:none;background:#88888822;color:var(--fg)}}
.eye .i-eyeoff{{display:none}}
.eye.show .i-eye{{display:none}}
.eye.show .i-eyeoff{{display:block}}
.row{{display:flex;justify-content:space-between;margin-top:14px;font-size:.78rem}}
.row a{{color:var(--acc);text-decoration:none}}
.err{{background:#c0392b1e;border:1px solid #c0392b66;color:var(--err);border-radius:12px;padding:10px 12px;
font-size:.85rem;margin-bottom:14px;text-align:center}}
.foot{{text-align:center;color:var(--mut);font-size:.72rem;margin-top:20px}}
</style></head><body>
<form class="card" method="post" action="/login" autocomplete="off">
  <div class="logo">🍪</div>
  <div class="brand">Бабушкины&nbsp;печеньки</div>
  <div class="tag">Тёплая домашняя выпечка с доставкой</div>
  <h1>Личный кабинет</h1>
  <div class="hint">Войдите, чтобы посмотреть заказы и бонусы</div>
  {error}
  <label for="u">E-mail или телефон</label>
  <input id="u" name="username" autofocus autocapitalize="none" spellcheck="false" placeholder="you@example.com">
  <label for="p">Пароль</label>
  <div class="pw-wrap">
    <input id="p" name="password" type="password" placeholder="••••••••">
    <button type="button" class="eye" tabindex="-1" aria-label="Показать пароль" onclick="var p=document.getElementById('p');p.type=p.type==='password'?'text':'password';this.classList.toggle('show')"><svg class="i-eye" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="i-eyeoff" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button>
  </div>
  <button type="submit">Войти</button>
  <div class="row"><a href="/login">Забыли пароль?</a><a href="/login">Регистрация</a></div>
  <div class="foot">© 2026 «Бабушкины печеньки» · Свежая выпечка каждый день</div>
</form></body></html>"""

ERR_HTML = '<div class="err">Неверный логин или пароль</div>'

WARM_CSS = """
:root{color-scheme:light dark;--bg:#f7ecd9;--bg2:#efd9b8;--card:#fffdf8;--fg:#4a3623;--mut:#9c866b;--acc:#cf7a24;--acc2:#a85f18;--line:#e7d6bd;--ok:#5a8a3c;--track:#eaddc6}
@media (prefers-color-scheme:dark){:root{--bg:#241a12;--bg2:#2f2216;--card:#2c2016;--fg:#f0e4d4;--mut:#b39c81;--line:#3d2e1f;--track:#3a2c1d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:'Segoe UI',system-ui,-apple-system,Roboto,sans-serif;line-height:1.5}
.wrap{max-width:920px;margin:0 auto;padding:18px 16px 55px}
.topbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.topbar .who{font-size:1.15rem;font-weight:700}
.nav{display:flex;gap:14px;align-items:center;font-size:.82rem}
.nav a{color:var(--acc);text-decoration:none}
.nav a.out{color:var(--mut)}
a{color:var(--acc)} code{background:var(--bg);border:1px solid var(--line);padding:1px 5px;border-radius:5px;font-size:.85em}
"""

PERSONAL_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Доступ к VPN</title>
<style>__CSS__
.sub{color:var(--mut);font-size:.9rem;margin:4px 0 0}
.tabs{display:flex;gap:8px;justify-content:center;margin:20px 0 8px;flex-wrap:wrap}
.tab{cursor:pointer;border:1px solid var(--line);background:var(--card);color:var(--fg);padding:9px 18px;border-radius:999px;font-size:.95rem}
.tab.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.panel{display:none}.panel.active{display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin:16px 0}
.proto{display:flex;gap:20px;flex-wrap:wrap;align-items:center}
.qr{width:210px;height:210px;background:#fff;border-radius:12px;padding:8px;flex:0 0 auto}
.qr img{width:100%;height:100%;image-rendering:pixelated}
.proto .info{flex:1;min-width:240px}
h2{font-size:1.12rem;margin:.1rem 0 .4rem}
.pill{font-size:.68rem;font-weight:600;padding:2px 9px;border-radius:999px;vertical-align:middle}
.pill.p{background:var(--acc);color:#fff}.pill.b{background:#8a7256;color:#fff}
.link{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.74rem;word-break:break-all;background:var(--bg);border:1px solid var(--line);padding:8px 10px;border-radius:9px;margin:.4rem 0;max-height:96px;overflow:auto}
button.copy{cursor:pointer;background:linear-gradient(180deg,var(--acc),var(--acc2));color:#fff;border:0;padding:8px 16px;border-radius:9px;font-size:.9rem;font-weight:600}
ol{padding-left:1.15rem}li{margin:.4rem 0}
.note{background:#cf7a241a;border:1px solid #cf7a2455;border-radius:12px;padding:12px 15px;font-size:.9rem;margin-top:14px}
footer{text-align:center;color:var(--mut);font-size:.8rem;margin-top:26px}
</style></head><body><div class="wrap">
<div class="topbar"><div><div class="who">🍪 Доступ к VPN</div><div class="sub">пользователь: <b>__NAME__</b></div></div>
<div class="nav">__NAV__<a class="out" href="/logout">Выйти ✕</a></div></div>

<div class="note"><b>Приложение: Hiddify</b> — хранит оба профиля и переключается на рабочий. Добавьте <u>оба</u>. По умолчанию — <b>REALITY</b>; если режут скорость — <b>Hysteria2</b>.</div>

<div class="tabs"><div class="tab active" data-t="mobile">📱 Телефон</div><div class="tab" data-t="desktop">💻 Компьютер</div></div>

<div class="panel active" id="mobile">
  <div class="card"><ol>
    <li>Установите <b>Hiddify</b> — <a href="https://play.google.com/store/apps/details?id=app.hiddify.com">Google&nbsp;Play</a> или <a href="https://github.com/hiddify/hiddify-app/releases">GitHub</a>.</li>
    <li><b>Отсканируйте QR</b> в Hiddify (+ → Сканировать) или нажмите <b>Копировать</b> → + → Импорт из буфера.</li>
    <li>Добавьте оба профиля, подключайтесь в режиме <b>Авто</b>.</li>
  </ol></div>
  <div class="card"><div class="proto">
    <div class="qr"><img alt="QR REALITY" src="__RQR__"></div>
    <div class="info"><h2>REALITY <span class="pill p">ОСНОВНОЙ</span></h2>
      <div class="link" id="l1">__RLINK__</div><button class="copy" data-c="l1">Скопировать ссылку ①</button></div>
  </div></div>
  <div class="card"><div class="proto">
    <div class="qr"><img alt="QR Hysteria2" src="__HQR__"></div>
    <div class="info"><h2>Hysteria2 <span class="pill b">РЕЗЕРВ</span></h2>
      <div class="link" id="l2">__HLINK__</div><button class="copy" data-c="l2">Скопировать ссылку ②</button></div>
  </div></div>
</div>

<div class="panel" id="desktop">
  <div class="card"><ol>
    <li>Скачайте <b>Hiddify</b> для Windows: <a href="https://github.com/hiddify/hiddify-app/releases">GitHub releases</a> → <code>Hiddify-Windows-Setup-x64.exe</code>.</li>
    <li>Скопируйте ссылку, затем Hiddify: <b>Профили → Новый → Из буфера обмена</b>. Добавьте обе.</li>
  </ol></div>
  <div class="card"><h2>① REALITY <span class="pill p">ОСНОВНОЙ</span></h2>
    <div class="link" id="l3">__RLINK__</div><button class="copy" data-c="l3">Скопировать ссылку ①</button></div>
  <div class="card"><h2>② Hysteria2 <span class="pill b">РЕЗЕРВ</span></h2>
    <div class="link" id="l4">__HLINK__</div><button class="copy" data-c="l4">Скопировать ссылку ②</button></div>
</div>

<footer>Оба протокола выглядят как обычный HTTPS к apple.com — определить или заблокировать нечего.</footer>
</div>
<script>
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));t.classList.add('active');document.getElementById(t.dataset.t).classList.add('active');});
document.querySelectorAll('button.copy').forEach(b=>b.onclick=()=>{const tx=document.getElementById(b.dataset.c).innerText;navigator.clipboard.writeText(tx).then(()=>{const o=b.innerText;b.innerText='✓ Скопировано';setTimeout(()=>b.innerText=o,1500)});});
</script></body></html>"""

MONITOR_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Мониторинг сервера</title>
<style>__CSS__
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(232px,1fr));gap:14px;margin-top:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px}
.card.wide{grid-column:1/-1}
.lbl{font-size:.8rem;color:var(--mut);margin-bottom:6px}
.big{font-size:1.9rem;font-weight:700;line-height:1.1}
.subm{font-size:.8rem;color:var(--mut);margin-top:7px}
.bar{height:8px;background:var(--track);border-radius:6px;overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;width:0;background:var(--acc);border-radius:6px;transition:width .5s,background .5s}
.row2{display:flex;gap:22px;font-size:1.05rem;margin-top:4px}.row2 b{font-weight:700}
canvas{width:100%;height:40px;margin-top:10px;display:block}.card.wide canvas{height:54px}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:6px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600}
td .on{color:var(--ok);font-weight:700}
.thist{display:flex;gap:6px}
.ht{cursor:pointer;font-size:.8rem;padding:4px 12px;border-radius:999px;border:1px solid var(--line);color:var(--fg)}
.ht.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.hchart{display:flex;align-items:flex-end;gap:3px;height:104px;margin-top:4px}
.hbar{flex:1;min-width:0;display:flex;flex-direction:column-reverse;cursor:pointer;border-radius:3px 3px 0 0;overflow:hidden}
.hbar:hover{outline:2px solid var(--acc);outline-offset:1px}
.seg{width:100%;min-height:1px}
.haxis{display:flex;gap:3px;margin-top:4px;font-size:.62rem;color:var(--mut)}
.haxis>div{flex:1;text-align:center;min-width:0;overflow:hidden;white-space:nowrap}
.hdetail{font-size:.8rem;margin-top:10px;min-height:1.3em}
.hlegend{display:flex;flex-wrap:wrap;gap:12px;font-size:.72rem;margin-top:10px;color:var(--mut)}
.hlegend .chip{display:flex;align-items:center;gap:5px}
.hlegend .chip i{width:11px;height:11px;border-radius:3px;display:inline-block}
</style></head><body><div class="wrap">
<div class="topbar"><div class="who">📊 Мониторинг сервера</div>
<div class="nav"><a href="/">← Профиль</a><span id="ago" style="color:var(--mut)">загрузка…</span><a class="out" href="/logout">Выйти ✕</a></div></div>
<div class="grid">
  <div class="card"><div class="lbl">Загрузка CPU</div><div class="big" id="cpu">–</div><div class="bar"><i id="cpu-bar"></i></div><canvas id="cpu-spark" width="300" height="40"></canvas></div>
  <div class="card"><div class="lbl">Оперативная память</div><div class="big" id="ram">–</div><div class="subm" id="ram-sub"></div><div class="bar"><i id="ram-bar"></i></div></div>
  <div class="card"><div class="lbl">Диск /</div><div class="big" id="disk">–</div><div class="subm" id="disk-sub"></div><div class="bar"><i id="disk-bar"></i></div></div>
  <div class="card"><div class="lbl">Система</div><div class="big" id="uptime" style="font-size:1.35rem">–</div><div class="subm">Load avg: <span id="load">–</span></div><div class="subm">Активные TCP: <b id="conns">–</b></div></div>
  <div class="card wide"><div class="lbl">Сеть · интерфейс __IFACE__</div><div class="row2"><div>↓ <b id="net-down">–</b></div><div>↑ <b id="net-up">–</b></div></div><canvas id="net-spark" width="600" height="54"></canvas></div>
  <div class="card"><div class="lbl">🛡 REALITY · всего</div><div class="row2"><div>↓ <b id="rl-down">–</b></div><div>↑ <b id="rl-up">–</b></div></div><div class="subm">сейчас ↓ <b id="rl-rate">–</b> · юзеров: <b id="rl-users">–</b></div><canvas id="rl-spark" width="300" height="40"></canvas></div>
  <div class="card"><div class="lbl">⚡ Hysteria2 · всего</div><div class="row2"><div>↓ <b id="hy-down">–</b></div><div>↑ <b id="hy-up">–</b></div></div><div class="subm">онлайн-клиентов: <b id="hy-online">–</b></div></div>
  <div class="card wide"><div class="lbl">Пользователи · трафик с последнего перезапуска сервисов (сбрасывается при изменении пользователей)</div>
    <table id="utab"><thead><tr><th>Пользователь</th><th>REALITY ↓ / ↑</th><th>Hysteria ↓ / ↑</th><th>Онлайн</th></tr></thead><tbody></tbody></table></div>
  <div class="card wide">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px">
      <div class="lbl" style="margin:0">История трафика · по пользователям</div>
      <div class="thist"><span class="ht active" data-w="h5">5 часов</span><span class="ht" data-w="w1">Неделя</span></div>
    </div>
    <div id="hist-chart" class="hchart"></div>
    <div id="hist-axis" class="haxis"></div>
    <div id="hist-detail" class="hdetail">наведите на сегмент или коснитесь столбца — покажу пользователей</div>
    <div id="hist-legend" class="hlegend"></div>
    <table id="htab"><thead><tr><th>Пользователь</th><th>↓ Скачано</th><th>↑ Загружено</th><th>Σ Всего</th></tr></thead><tbody></tbody></table>
  </div>
</div></div>
<script>
const $=id=>document.getElementById(id);let prev=null;let hist={cpu:[],net:[],rl:[]};const CAP=60;
function fmtB(n){n=+n||0;const u=['Б','КБ','МБ','ГБ','ТБ'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i];}
function fmtR(n){return fmtB(n)+'/с';}
function fmtUp(s){s=Math.max(0,s|0);const d=s/86400|0,h=(s%86400)/3600|0,m=(s%3600)/60|0;return (d?d+'д ':'')+h+'ч '+m+'м';}
function col(p){return p<70?'#5a8a3c':p<88?'#cf7a24':'#c0392b';}
function push(a,v){a.push(v);if(a.length>CAP)a.shift();}
function spark(id,arr,c){const cv=$(id);if(!cv)return;const x=cv.getContext('2d'),w=cv.width,h=cv.height;x.clearRect(0,0,w,h);if(arr.length<2)return;const mx=Math.max(...arr,1e-9);x.beginPath();arr.forEach((v,i)=>{const px=i/(CAP-1)*w,py=h-(v/mx)*(h-4)-2;i?x.lineTo(px,py):x.moveTo(px,py);});x.strokeStyle=c;x.lineWidth=2;x.stroke();x.lineTo((arr.length-1)/(CAP-1)*w,h);x.lineTo(0,h);x.closePath();x.fillStyle=c+'22';x.fill();}
async function tick(){
  let m;try{const r=await fetch('/api/metrics',{cache:'no-store'});if(r.status===401){location='/login';return;}m=await r.json();}catch(e){$('ago').textContent='нет связи';return;}
  const H=m.host||{};
  if(prev&&prev.host){
    const dt=(m.t-prev.t)/1000||1;
    const dT=H.cpu_total-prev.host.cpu_total,dI=H.cpu_idle-prev.host.cpu_idle;
    let cpu=dT>0?100*(1-dI/dT):0;cpu=Math.max(0,Math.min(100,cpu));
    $('cpu').textContent=cpu.toFixed(0)+'%';$('cpu-bar').style.width=cpu+'%';$('cpu-bar').style.background=col(cpu);push(hist.cpu,cpu);spark('cpu-spark',hist.cpu,'#cf7a24');
    const rxr=Math.max(0,(H.net_rx-prev.host.net_rx)/dt),txr=Math.max(0,(H.net_tx-prev.host.net_tx)/dt);
    $('net-down').textContent=fmtR(rxr);$('net-up').textContent=fmtR(txr);push(hist.net,rxr);spark('net-spark',hist.net,'#cf7a24');
    const rlr=Math.max(0,(m.xray.down-prev.xray.down)/dt);
    $('rl-rate').textContent=fmtR(rlr);push(hist.rl,rlr);spark('rl-spark',hist.rl,'#cf7a24');
  }
  const mu=H.mem_total-H.mem_avail,mp=H.mem_total?100*mu/H.mem_total:0;
  $('ram').textContent=mp.toFixed(0)+'%';$('ram-sub').textContent=fmtB(mu)+' / '+fmtB(H.mem_total);$('ram-bar').style.width=mp+'%';$('ram-bar').style.background=col(mp);
  const du=H.disk_total-H.disk_avail,dp=H.disk_total?100*du/H.disk_total:0;
  $('disk').textContent=dp.toFixed(0)+'%';$('disk-sub').textContent=fmtB(du)+' / '+fmtB(H.disk_total);$('disk-bar').style.width=dp+'%';$('disk-bar').style.background=col(dp);
  $('uptime').textContent=fmtUp(Date.now()/1000-(H.boot||0));
  $('load').textContent=[H.load1,H.load5,H.load15].map(v=>(+v||0).toFixed(2)).join(' / ')+' (÷'+(H.ncpu||1)+')';
  $('conns').textContent=(H.tcp_estab||0)|0;
  $('rl-down').textContent=fmtB(m.xray.down);$('rl-up').textContent=fmtB(m.xray.up);$('rl-users').textContent=m.xray.users;
  $('hy-down').textContent=fmtB(m.hysteria.down);$('hy-up').textContent=fmtB(m.hysteria.up);$('hy-online').textContent=m.hysteria.online;
  const tb=$('utab').querySelector('tbody');tb.innerHTML='';
  Object.keys(m.users||{}).sort().forEach(n=>{const u=m.users[n];const tr=document.createElement('tr');
    tr.innerHTML='<td><b>'+n+'</b></td><td>'+fmtB(u.rl_down)+' / '+fmtB(u.rl_up)+'</td><td>'+fmtB(u.hy_down)+' / '+fmtB(u.hy_up)+'</td><td>'+(u.online?'<span class=on>'+u.online+'</span>':'0')+'</td>';
    tb.appendChild(tr);});
  $('ago').textContent='обновлено только что';
  prev={t:m.t,host:{cpu_total:H.cpu_total,cpu_idle:H.cpu_idle,net_rx:H.net_rx,net_tx:H.net_tx},xray:{down:m.xray.down}};
  try{localStorage.setItem('mon_state',JSON.stringify({at:Date.now(),hist:hist,prev:prev}));}catch(e){}
}
try{const s=JSON.parse(localStorage.getItem('mon_state')||'null');if(s&&Date.now()-s.at<600000){hist=s.hist||hist;prev=s.prev||null;spark('cpu-spark',hist.cpu,'#cf7a24');spark('net-spark',hist.net,'#cf7a24');spark('rl-spark',hist.rl,'#cf7a24');}}catch(e){}
tick();setInterval(tick,3000);
let histW='h5',histData=null;
const HCOL=['#cf7a24','#8a7256','#5a8a3c','#2a7ab0','#c0392b','#9b59b6','#e0a030','#16a085','#d35400','#7f8c8d'];
let hCmap={},hSer=null;
function busers(bu){let t=0;for(const n in bu)t+=(bu[n].down||0)+(bu[n].up||0);return t;}
function fmtT(ms){const dt=new Date(ms);return histW==='h5'?(('0'+dt.getHours()).slice(-2)+':00'):['Вс','Пн','Вт','Ср','Чт','Пт','Сб'][dt.getDay()];}
function showDetail(i){if(!hSer)return;const s=hSer[i];const ns=Object.keys(s.users).filter(n=>(s.users[n].down+s.users[n].up)>0).sort((a,b)=>(s.users[b].down+s.users[b].up)-(s.users[a].down+s.users[a].up));const parts=ns.map(n=>'<span style="color:'+(hCmap[n]||'#888')+'">■</span> '+n+': ↓'+fmtB(s.users[n].down)+' ↑'+fmtB(s.users[n].up));$('hist-detail').innerHTML='<b>'+fmtT(s.t)+'</b> — '+(parts.length?parts.join('&nbsp;&nbsp;'):'нет трафика');}
function renderHist(){if(!histData)return;const d=histData[histW]||{per:{},series:[]};hSer=d.series;const names=Object.keys(d.per).sort();hCmap={};names.forEach((n,i)=>hCmap[n]=HCOL[i%HCOL.length]);const mx=Math.max(...d.series.map(s=>busers(s.users)),1);
const chart=$('hist-chart');chart.innerHTML='';d.series.forEach((s,i)=>{const bar=document.createElement('div');bar.className='hbar';names.forEach(n=>{const u=s.users[n];const v=u?(u.down+u.up):0;if(v>0){const g=document.createElement('div');g.className='seg';g.style.height=(v/mx*100)+'px';g.style.background=hCmap[n];g.title=n+': ↓'+fmtB(u.down)+' ↑'+fmtB(u.up);bar.appendChild(g);}});bar.onclick=()=>showDetail(i);chart.appendChild(bar);});
const ax=$('hist-axis');ax.innerHTML='';d.series.forEach(s=>{const e=document.createElement('div');e.textContent=fmtT(s.t);ax.appendChild(e);});
const lg=$('hist-legend');lg.innerHTML='';names.forEach(n=>{const c=document.createElement('span');c.className='chip';c.innerHTML='<i style="background:'+hCmap[n]+'"></i>'+n+' — '+fmtB((d.per[n].down||0)+(d.per[n].up||0));lg.appendChild(c);});
const tb=$('htab').querySelector('tbody');tb.innerHTML='';if(!names.length){tb.innerHTML='<tr><td colspan="4" style="color:var(--mut)">пока нет данных за период</td></tr>';}else{names.map(n=>({n:n,down:d.per[n].down,up:d.per[n].up})).sort((a,b)=>(b.down+b.up)-(a.down+a.up)).forEach(u=>{const tr=document.createElement('tr');tr.innerHTML='<td><b>'+u.n+'</b></td><td>'+fmtB(u.down)+'</td><td>'+fmtB(u.up)+'</td><td><b>'+fmtB(u.down+u.up)+'</b></td>';tb.appendChild(tr);});}
$('hist-detail').innerHTML='наведите на сегмент или коснитесь столбца — покажу пользователей';}
async function fetchTraffic(){try{const r=await fetch('/api/traffic',{cache:'no-store'});if(r.status!==200)return;histData=await r.json();renderHist();}catch(e){}}
document.querySelectorAll('.ht').forEach(t=>t.onclick=()=>{document.querySelectorAll('.ht').forEach(x=>x.classList.remove('active'));t.classList.add('active');histW=t.dataset.w;renderHist();});
fetchTraffic();setInterval(fetchTraffic,60000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "portal"
    sys_version = ""

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if body and not getattr(self, "_is_head", False):
            self.wfile.write(body)

    def _cookie(self):
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == COOKIE:
                    return v
        return None

    def _current(self):
        """Return (name, user_dict) for a valid session, else (None, None)."""
        tok = self._cookie()
        name = check_token(tok) if tok else None
        if not name:
            return None, None
        u = load_users().get(name)
        return (name, u) if u else (None, None)

    def _login_page(self, error=False, code=200):
        self._send(code, LOGIN_PAGE.format(error=ERR_HTML if error else "").encode("utf-8"))

    def do_HEAD(self):
        self._is_head = True
        self.do_GET()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /\n", ctype="text/plain; charset=utf-8")
        if path == "/login":
            return self._login_page()
        if path == "/logout":
            exp = f"{COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
            return self._send(302, extra=[("Location", "/login"), ("Set-Cookie", exp)])
        if path == "/favicon.ico":
            return self._send(204)

        name, user = self._current()
        if not user:
            if path == "/api/metrics":
                return self._send(401, b'{"error":"unauthorized"}', ctype="application/json")
            return self._send(302, extra=[("Location", "/login")])

        if path == "/api/metrics":
            if not user.get("admin"):
                return self._send(403, b'{"error":"forbidden"}', ctype="application/json")
            names = list(load_users().keys())
            return self._send(200, json.dumps(collect_metrics(names)).encode("utf-8"),
                              ctype="application/json")
        if path == "/api/traffic":
            if not user.get("admin"):
                return self._send(403, b'{"error":"forbidden"}', ctype="application/json")
            data = {"h5": traffic_window(3600, 5), "w1": traffic_window(86400, 7)}
            return self._send(200, json.dumps(data).encode("utf-8"), ctype="application/json")
        if path == "/monitor":
            if not user.get("admin"):
                return self._send(302, extra=[("Location", "/")])
            return self._send(200, MONITOR_PAGE.replace("__CSS__", WARM_CSS).replace("__IFACE__", NET_IFACE).encode("utf-8"))

        # default: personal page.
        # Escape links + neutralize '@' as &#64; so Cloudflare Email Obfuscation doesn't
        # mistake "uuid@ip" for an email and rewrite it (QR stays correct regardless).
        nav = '<a href="/monitor">📊 Мониторинг</a>' if user.get("admin") else ""
        rlink = html.escape(user.get("reality_link", "")).replace("@", "&#64;")
        hlink = html.escape(user.get("hy_link", "")).replace("@", "&#64;")
        page = (PERSONAL_PAGE.replace("__CSS__", WARM_CSS).replace("__NAME__", html.escape(name)).replace("__NAV__", nav)
                .replace("__RQR__", user.get("reality_qr", "")).replace("__HQR__", user.get("hy_qr", ""))
                .replace("__RLINK__", rlink).replace("__HLINK__", hlink))
        self._send(200, page.encode("utf-8"))

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/login":
            return self._send(404, b"not found")
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace") if length else "")
        name = (form.get("username", [""])[0]).strip().lower()
        pw = form.get("password", [""])[0]
        u = load_users().get(name)
        if u and hmac.compare_digest(pw, u.get("portal_pass", "")):
            cookie = f"{COOKIE}={make_token(name)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={TTL}"
            return self._send(302, extra=[("Location", "/"), ("Set-Cookie", cookie)])
        time.sleep(1)
        return self._login_page(error=True, code=401)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
