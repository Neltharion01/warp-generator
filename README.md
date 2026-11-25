# DrakoVPN WARP Generator
Modern and user-friendly WARP generator website

For those who don't know what is "warp generator": original cloudflare api endpoint is banned in russia, so you have to proxy it and write some ui to access the proxied endpoint. Besides, you need some tricks to use it - stock 1.1.1.1 app won't work even if you have already registered with VPN on

Directory structure (SORRY, I am not Claude):
- `index.html`, `static/` - the website
- `warp-subs/` - subscriptions service backend
- `quicsig/` - signature generation backend
- `wgcf/` - OPTIONAL, just two tiny python scripts to make the same thing from cli. [wireguard](https://raw.githubusercontent.com/Neltharion01/warp-generator/refs/heads/master/wgcf/wgcf.py), [masque](https://raw.githubusercontent.com/Neltharion01/warp-generator/refs/heads/master/wgcf/wgcf_masque.py)

Make sure to remove all references to `deathwing.dedyn.io` if you plan to host this yourself. 

Relevant caddy snippet for proxying:
```
	handle /v0a2158/* {
		reverse_proxy https://api.cloudflareclient.com
	}
	handle /v0a4471/* {
		reverse_proxy https://api.cloudflareclient.com
	}
	handle /warp/subs/* {
		reverse_proxy 127.0.0.1:5001
	}
```

# License
```
SPDX-License-Identifier: 0BSD
Copyright 2026 Neltharion01
```
Feel free to reuse
