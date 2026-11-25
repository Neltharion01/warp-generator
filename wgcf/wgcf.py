#!/usr/bin/python3
# ==========
# wgcf.py - minimal warp api client
# ==========
# SPDX-License-Identifier: 0BSD
# Copyright 2026 Neltharion01

import requests;
import json;
import base64;
import sys;
from time import strftime;
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey;
from cryptography.hazmat.primitives import serialization;

def read_file_json(path):
    f = open(path, "r");
    data = json.load(f);
    f.close();
    return data;
def write_file_json(path, data):
    f = open(path, "w");
    json.dump(data, f);
    f.close();

def wg_keypair():
    key = X25519PrivateKey.generate();
    privkey = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption());
    pubkey = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw);
    return base64.b64encode(privkey).decode(), base64.b64encode(pubkey).decode();

def wgcf_register():
    API = "https://api.cloudflareclient.com/v0a2158";
    # Generate keypair
    privkey, pubkey = wg_keypair();
    # Register
    reg = requests.post(f"{API}/reg", json={"key": pubkey, "tos": strftime("%FT%T.000Z")});
    reg.raise_for_status();
    reg = reg.json();
    # Enable warp
    id = reg["id"];
    token = reg["token"];
    res = requests.patch(f"{API}/reg/{id}", json={"warp_enabled": True}, headers={"Authorization": f"Bearer {token}"});
    res.raise_for_status();
    return privkey, res.json();

def peer_to_xray(peer):
    return {
        "publicKey": peer["public_key"],
        "allowedIPs": [ "0.0.0.0/0", "::/0" ],
        "endpoint": peer["endpoint"]["host"],
    };
def id_to_reserved(id):
    return list(base64.b64decode(id));
def res_to_xray(privkey, res):
    return {
        "outbounds": [{
            "tag": "warp",
            "protocol": "wireguard",
            "streamSettings": { "sockopt": { "domainStrategy": "UseIPv4" } },
            "settings": {
                "secretKey": privkey,
                "address": [
                    res["config"]["interface"]["addresses"]["v4"],
                    res["config"]["interface"]["addresses"]["v6"],
                ],
                "peers": [peer_to_xray(peer) for peer in res["config"]["peers"]],
                "reserved": id_to_reserved(res["config"]["client_id"]),
                "mtu": 1280
            }
        }]
    };

def display_cfg(cfg):
    print(json.dumps(cfg));

def main():
    try:
        cfg = read_file_json("/etc/drakovpn/wgcf.json");
    except FileNotFoundError as _:
        print("Generating a new WARP conf", file=sys.stderr)
        privkey, res = wgcf_register();
        cfg = res_to_xray(privkey, res);
        write_file_json("/etc/drakovpn/wgcf.json", cfg);
        print("Saved to: /etc/drakovpn/wgcf.json", file=sys.stderr)
    display_cfg(cfg);

if __name__ == "__main__":
    main();
