#!/usr/bin/python3
# ==========
# warp-subs.py - warp subscriptions service
# ==========
# SPDX-License-Identifier: 0BSD
# Copyright 2026 Neltharion01

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler;
import json;
import base64;
from urllib.parse import urlencode, quote, parse_qs, urlsplit;
from ipaddress import IPv6Address;
import requests;
import html;
import re;
from cryptography.hazmat.primitives.asymmetric import ec;
from cryptography.hazmat.primitives import serialization;

def read_json_file(path):
    f = open(path);
    data = json.load(f);
    f.close();
    return data;

config = read_json_file("config.json");

def encode_routing():
    routing = config["routing"];
    routing_base64 = base64.b64encode(json.dumps(routing, separators=",:", ensure_ascii=False).encode()).decode();
    return "happ://routing/onadd/" + routing_base64;

def encode_announce():
    announce = config["announce"];
    return "base64:" + base64.b64encode(announce.encode()).decode();

def default_sni():
    return config.get("default-sni", "apteka.ru");

WG_NAME = "WARP, WireGuard";

def default_msni():
    return config.get("default-msni", "yandex.ru");

def sub_url(wg_secret, masque_secret, sni, msni):
    return config["base"] + wg_secret + "/" + masque_secret + "?" + urlencode({"sni": sni, "msni": msni}, quote_via=quote);

class UpstreamError(Exception): pass;
def quic_signature(sni):
    try:
        res = requests.get("http://127.0.0.1:5000/warp/quic_signature", params={"sni": sni}, timeout=10);
        res.raise_for_status();
        return res.json();
    except Exception as e:
        raise UpstreamError(e);

DOWNLOAD_ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" height="24px" width="24px"><path d="M12,16L7,11L8.4,9.55l2.6,2.6V4h2v8.15l2.6-2.6L17,11l-5,5ZM6,20q-0.82,0-1.41-0.59T4,18V15H6v3H18V15h2v3q0,0.82-0.59,1.41T18,20H6Z"/></svg>';

def html_section(id, title, text, filename):
    return f"""  <h2>{title}</h2>
  <textarea id="{id}" spellcheck="false">{html.escape(text)}</textarea>
  <button type="button" data-target="{id}" data-file="{filename}">
    {DOWNLOAD_ICON}
    Скачать
  </button>
"""

def build_html(url, wg, m, sni, msni):
    f = open("sub.html", "r");
    data = f.read();
    f.close();
    sections = "";
    if wg:
        sections += html_section("config-awg", "Конфиг для AmneziaWG", build_amneziawg(wg["private_key"], wg["ipv6"], sni), "WARP.conf");
    # Exactly what an xray json subscription returns, for manual import
    sections += html_section("config-xray", "Xray JSON", build_xray(wg, m, sni, msni, pretty=True), "WARP.json");
    data = data.replace("{{SUBSCRIPTION_URL}}", html.escape(url));
    data = data.replace("{{CONFIGS}}", sections);
    return data;

def build_amneziawg(private_key, ipv6_addr, sni):
    i_packets = "";
    for i, sig in enumerate(quic_signature(sni)):
        i_packets += f"I{i+1} = <b 0x{sig}>\n";

    return f"""\
[Interface]
PrivateKey = {private_key}
Address = 172.16.0.2, {ipv6_addr}
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
RandomTrailers = on

{i_packets}
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.195.1:878
"""

def build_throne(private_key, ipv6_addr, client_id, sni):
    opts = {
        "private_key": private_key,
        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "reserved": "-".join(str(i) for i in client_id),
        "local_address": "172.16.0.2/32-" + ipv6_addr,
        "mtu": 1280,
        "enable_amnezia": "true",
        "random_trailers": "true",
    };
    for i, sig in enumerate(quic_signature(sni)):
        opts["i" + str(i+1)] = "<b 0x" + sig + ">";
    return "wg://162.159.195.1:878?" + urlencode(opts, quote_via=quote) + "#" + quote(WG_NAME);

def build_incy(wg, sni):
    return "awg://" + base64.urlsafe_b64encode(build_amneziawg(wg["private_key"], wg["ipv6"], sni).encode()).decode().rstrip("=");

def build_finalmask(sni):
    noise = [];
    for sig in quic_signature(sni):
        noise.append({
            "type": "hex",
            "packet": sig,
        });
    return {
        "udp": [{
            "type": "noise",
            "settings": {
                "noise": noise
            }
        }]
    };

XRAY_ROUTING = {
    "domainStrategy": "IPOnDemand",
    "rules": [
        {
            "type": "field",
            "ip": [
                "geoip:private",
                "geoip:ru"
            ],
            "outboundTag": "direct"
        },
        {
            "type": "field",
            "domain": [
                "geosite:category-ru",
                "api.ipify.org",
                "checkip.amazonaws.com",
                "ifconfig.me",
                "ip.mail.ru",
                "ipv4-internet.yandex.net",
                "ipv6-internet.yandex.net"
            ],
            "outboundTag": "direct"
        }
    ]
};

def xray_config(outbound, remarks):
    return {
        "routing": XRAY_ROUTING,
        "inbounds": [],
        "outbounds": [outbound],
        "remarks": remarks,
    };

def xray_wireguard(wg, sni):
    return {
        "protocol": "wireguard",
        "settings": {
            "address": [
                "172.16.0.2",
                wg["ipv6"],
            ],
            "mtu": 1280,
            "peers": [{
                "endpoint": "162.159.195.1:878",
                "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            }],
            "remoteDNS": [
                "1.1.1.1",
                "1.0.0.1",
                "2606:4700:4700::1111",
                "2606:4700:4700::1001"
            ],
            "reserved": wg["client_id"],
            "secretKey": wg["private_key"],
        },
        "streamSettings": {
            "finalmask": build_finalmask(sni),
        },
        "tag": "proxy"
    };

# Masque: no finalmask. Xray has no http version fallback, the version depends on alpn only
MASQUE_PEER_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==";
MASQUE_PROFILES = [
    {
        "name": "WARP, MASQUE/H2",
        "endpoint": "162.159.198.2", "alpn": "h2",
        "throne": {}, # sing-box defaults
    },
    {
        "name": "WARP, MASQUE/H3 (LTE)",
        "endpoint": "162.159.198.1", "alpn": "h3",
        "throne": { "http_version": 3, "disable_version_fallback": True },
    },
];

def xray_masque(m, profile, msni):
    return {
        "protocol": "masque",
        "settings": { "address": profile["endpoint"], "port": 443 },
        "streamSettings": {
            "method": "masque",
            "security": "tls",
            "tlsSettings": { "serverName": msni, "alpn": [profile["alpn"]] },
            "masqueSettings": {
                "warp": {
                    "privateKey": m["private_key"],
                    "publicKey": MASQUE_PEER_KEY,
                    "address": ["172.16.0.2/32", m["ipv6"] + "/128"],
                }
            },
        },
        "tag": "proxy",
    };

def build_throne_masque(m, profile, msni):
    cfg = {
        "address": ["172.16.0.2/32", m["ipv6"] + "/128"],
        "mtu": 1280,
        "peer_public_key": MASQUE_PEER_KEY,
        "private_key": m["private_key"],
        "server": profile["endpoint"],
        "server_port": 443,
        "tag": profile["name"],
        "tls": { "enabled": True, "server_name": msni },
        "type": "masque",
        **profile["throne"],
    };
    raw = json.dumps(cfg, sort_keys=True, separators=(",", ":"));
    # Url-safe base64 without padding, the same as Throne writes (it reads any variant)
    return "throne://add/" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=");

def build_xray(wg, m, sni, msni, pretty=False):
    configs = [];
    if wg:
        configs.append(xray_config(xray_wireguard(wg, sni), WG_NAME));
    if m:
        for profile in MASQUE_PROFILES:
            configs.append(xray_config(xray_masque(m, profile, msni), profile["name"]));
    indent = None;
    separators = ",:";
    if pretty:
        indent = 4;
        separators = (",", ": ");
    return json.dumps(configs[0] if len(configs) == 1 else configs, indent=indent, separators=separators);

# Subscription url: /warp/subs/<wireguard_secret>/<masque_secret>?sni=...&msni=...
# "_" in place of a secret means that this part is absent
# wireguard_secret = client id (3 bytes) + private key (32) + ipv6 (16), base64url
# masque_secret = private key (raw 32 byte scalar) + ipv6 (16), base64url
NO_PART = "_";
SECRET_WG_RE = re.compile(r"^[A-Za-z0-9_-]{68}$");
SECRET_MASQUE_RE = re.compile(r"^[A-Za-z0-9_-]{64}$");
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$");

class BadRequest(Exception): pass;

def parse_wg_secret(secret):
    if secret == NO_PART:
        return None;
    if not SECRET_WG_RE.match(secret):
        raise BadRequest("Bad wireguard secret");
    try:
        data = base64.urlsafe_b64decode(secret);
        return {
            "client_id": list(data[:3]),
            "private_key": base64.b64encode(data[3:35]).decode(),
            "ipv6": str(IPv6Address(data[35:51])),
        };
    except ValueError:
        raise BadRequest("Bad wireguard secret");

def parse_masque_secret(secret):
    if secret == NO_PART:
        return None;
    if not SECRET_MASQUE_RE.match(secret):
        raise BadRequest("Bad masque secret");
    try:
        data = base64.urlsafe_b64decode(secret);
        # xray and throne want the full SEC1 DER key, it is rebuilt from the raw scalar
        key = ec.derive_private_key(int.from_bytes(data[:32], "big"), ec.SECP256R1());
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption());
        return {
            "private_key": base64.b64encode(der).decode(),
            "ipv6": str(IPv6Address(data[32:48])),
        };
    except ValueError:
        raise BadRequest("Bad masque secret");

def build_body(ua, accept, url, wg, m, sni, msni):
    # Returns (body, content type)
    if ua.startswith("Throne/"):
        lines = [];
        if wg:
            lines.append(build_throne(wg["private_key"], wg["ipv6"], wg["client_id"], sni));
        if m:
            lines += [build_throne_masque(m, profile, msni) for profile in MASQUE_PROFILES];
        return "\n".join(lines), None;
    elif ua.startswith("INCY/"):
        # INCY can't parse returned xray-json, only awg link works
        return build_incy(wg, sni), None;
    # The generator page downloads the xray json with fetch(), and a browser cannot change User-Agent
    if "application/json" in accept:
        return build_xray(wg, m, sni, msni), "application/json; charset=utf-8";
    if ua.startswith("Mozilla/5.0"):
        return build_html(url, wg, m, sni, msni), "text/html; charset=utf-8";
    return build_xray(wg, m, sni, msni), "application/json; charset=utf-8";

class SubscriptionServer(BaseHTTPRequestHandler):
    # The secrets in the url contain private keys: never write them to the log
    def log_request(self, code="-", size="-"):
        path = re.sub(r"(/warp/subs/)[^?\s]*", r"\1***", self.path);
        self.log_message('"%s %s %s" %s', self.command, path, self.request_version, code);

    def send_error_simple(self, code, msg=""):
        msg = msg.encode();
        self.send_response(code);
        self.send_header("Content-Length", str(len(msg)));
        self.end_headers();
        self.wfile.write(msg);

    def do_GET(self):
        ua = self.headers.get("User-Agent", "");
        if ua.startswith("Exclave/"):
            return self.send_error_simple(500, "Unsupported client");

        url = urlsplit(self.path);
        parts = url.path.strip("/").split("/");
        if len(parts) != 4 or parts[:2] != ["warp", "subs"]:
            return self.send_error(404);

        query = parse_qs(url.query);
        sni = query.get("sni", [""])[0].strip() or default_sni();
        msni = query.get("msni", [""])[0].strip() or default_msni();
        try:
            if not HOST_RE.match(sni) or not HOST_RE.match(msni):
                raise BadRequest("Bad sni");
            wg = parse_wg_secret(parts[2]);
            m = parse_masque_secret(parts[3]);
            if not wg and not m:
                raise BadRequest("Nothing to generate");
        except BadRequest as e:
            return self.send_error(400, str(e));

        full_url = sub_url(parts[2], parts[3], sni, msni);
        try:
            cfg, content_type = build_body(ua, self.headers.get("Accept", ""), full_url, wg, m, sni, msni);
        except UpstreamError as e:
            self.log_error("signature service error: %r", e);
            return self.send_error(500);
        except Exception as e:
            self.log_error("build failed: %r", e);
            return self.send_error(500);

        res = cfg.encode();

        self.send_response(200);
        if content_type:
            self.send_header("Content-Type", content_type);
        self.send_header("Content-Length", str(len(res)));
        self.send_header("Cache-Control", "no-store");

        # Display options
        self.send_header("profile-title", config["profile-title"]);
        self.send_header("profile-update-interval", config["profile-update-interval"]);
        self.send_header("profile-web-page-url", full_url);
        self.send_header("announce", encode_announce());
        if "support-url" in config:
            self.send_header("support-url", config["support-url"]);
        # Routing for Happ and INCY
        self.send_header("routing", encode_routing());

        self.end_headers();
        return self.wfile.write(res);

def main():
    port = 5001;
    server_address = ("127.0.0.1", port);
    httpd = ThreadingHTTPServer(server_address, SubscriptionServer);
    print(f"Starting server on port {port}... Press Ctrl+C to stop.");
    try:
        httpd.serve_forever();
    except KeyboardInterrupt:
        print("\nStopping server...");
        httpd.server_close();

if __name__ == "__main__":
    main();
