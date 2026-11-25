#!/usr/bin/python3
# ==========
# wgcf_masque.py - minimal warp api client (masque)
# ==========
# SPDX-License-Identifier: 0BSD
# Copyright 2026 Claude 5.5 Sonnet

import requests;
import json;
import base64;
import sys;
import secrets;
from datetime import datetime;
from cryptography.hazmat.primitives.asymmetric import ec;
from cryptography.hazmat.primitives import serialization;

# Requests are taken from usque (github.com/Diniboy1123/usque, api/cloudflare.go)
API = "https://api.cloudflareclient.com/v0a4471";
ENDPOINT = "162.159.198.2";
SNI = "consumer-masque.cloudflareclient.com";

def read_file_json(path):
    f = open(path, "r");
    data = json.load(f);
    f.close();
    return data;
def write_file_json(path, data):
    f = open(path, "w");
    json.dump(data, f);
    f.close();

def wgcf_register_masque():
    # Masque enrollment works only on top of a regular registration, so both steps are done here.
    # The wireguard key of the first step is a throw-away one, the masque key replaces it right away
    reg = requests.post(f"{API}/reg", json={
        "key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "tos": datetime.now().astimezone().isoformat(timespec="milliseconds"),
    });
    reg.raise_for_status();
    reg = reg.json();
    # Enroll the masque key (ECDSA P-256, the api wants its SubjectPublicKeyInfo)
    key = ec.generate_private_key(ec.SECP256R1());
    pubkey = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo);
    res = requests.patch(f"{API}/reg/{reg['id']}", headers={"Authorization": "Bearer " + reg["token"]}, json={
        "key": base64.b64encode(pubkey).decode(),
        "key_type": "secp256r1",
        "tunnel_type": "masque",
    });
    res.raise_for_status();
    return key, res.json();

def strip_pem(pem):
    # The api returns the endpoint key as PEM: drop the BEGIN/END lines and line breaks
    return pem.strip().removeprefix("-----BEGIN PUBLIC KEY-----").removesuffix("-----END PUBLIC KEY-----").replace("\n", "");

def res_to_xray_masque(key, res):
    addresses = res["config"]["interface"]["addresses"];
    privkey = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption());
    return {
        "outbounds": [{
            "tag": "warp",
            "protocol": "masque",
            "settings": { "address": ENDPOINT, "port": 443 },
            "streamSettings": {
                "method": "masque",
                "security": "tls",
                "tlsSettings": { "serverName": SNI, "alpn": ["h3"] },
                "masqueSettings": {
                    "warp": {
                        "privateKey": base64.b64encode(privkey).decode(),
                        "publicKey": strip_pem(res["config"]["peers"][0]["public_key"]),
                        "address": [addresses["v4"] + "/32", addresses["v6"] + "/128"],
                    }
                }
            }
        }]
    };

def display_cfg(cfg):
    print(json.dumps(cfg));

def main():
    try:
        cfg = read_file_json("/etc/drakovpn/wgcf-masque.json");
    except FileNotFoundError as _:
        print("Generating a new WARP masque conf", file=sys.stderr)
        key, res = wgcf_register_masque();
        cfg = res_to_xray_masque(key, res);
        write_file_json("/etc/drakovpn/wgcf-masque.json", cfg);
        print("Saved to: /etc/drakovpn/wgcf-masque.json", file=sys.stderr)
    display_cfg(cfg);

if __name__ == "__main__":
    main();
