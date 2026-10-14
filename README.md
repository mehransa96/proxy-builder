# Proxy Builder

🌐 **[فارسی](README-fa.md)** | [English](README.md)

A powerful, standalone web application with six tools:

1. **🛠️ VPN Fixer v8** (default tab) — the upgraded standalone VPN Config Fixer: one config whose balancer tries several routes at once (TLS fragment / no fragment, clean CDN IPs, several fingerprints) and keeps the one that works on the current network, with the original route as fallback.
2. **🧪 Templates** — rebuild your config around one of two layouts taken from configs that connect on MCI: a REALITY-style single proxy with finalmask and a pinned server IP, or a CDN multi-address balancer.
3. **🩺 Config Fixer** — diagnose and repair a full Xray JSON config (or a link) for stock v2rayNG: browser fingerprint, classic fragment via `dialerProxy`, DNS-loop fix, clean IP, and a multi-variant test pack.
4. **🛡️ ECH** — enhance a **VLESS** or **Trojan** URL by injecting `fp` (TLS fingerprint, default `chrome`) and `ech` (ECH Config List) parameters, plus a server (IP/domain) override — producing a link ready to import into your own client.
5. **🧬 Fragment + Fingerprint** — enhance a **VLESS** or **Trojan** URL by injecting `cs` (cipher suites), `fm` (fragment mask) and `fp` (TLS fingerprint) parameters, plus a server (IP/domain) override — producing a link ready to import into your own client. Its **📥 Subscription** sub-tab fetches a subscription link (or pastes its contents) to batch-enhance every **VLESS**/**Trojan** config inside, with copy/`.txt`/base64 export.
6. **🔗 Chain Builder** — chain two proxy configurations into a single **Xray** or **Sing-box** JSON configuration for enhanced connection stability and fixed IP masking.

All processing happens in your browser. No data is sent to any server — fetching a subscription link contacts only the provider URL you entered, and pasted or dropped content never leaves your browser.

## 🚀 Features

### 🛠️ VPN Fixer v8 (default tab)
- **Same pipeline as the standalone v7 page**, now inside the app: panel domain → connection domain swap, stale CDN pins and IPv6 removed from `dns.hosts`, `UseIPv4`, SNI / ws Host filled in (`headers.Host` → `host`), policy timings, `freedom` / sniffing clean-up, history of the last five fixes. No personal domains are built in: your panel → connection domain list is stored on your device only.
- **Fragment kept, not stripped**: v7 deleted every `finalmask`. v8 adds the fragment from a config that connects on MCI (`1-3 · 50-100 · 10-20 · maxSplit 10`, Xray-core 26+), keeps the config's own, or strips it — your choice.
- **Multi-path (recommended)**: one balancer member per clean IP / address, each with and without the fragment and with chrome / edge / firefox / safari fingerprints. SNI and Host stay on your domain. `leastLoad` + `burstObservatory` pick the healthy routes every minute; the original unfragmented route is the fallback, so the same config keeps working where it already did.
- **DNS without loops**: Iranian domains and the server domain are resolved by Shecan / Begzar routed direct; other DNS (1.1.1.1, 8.8.8.8) goes through the tunnel. Replaces resolvers such as 223.5.5.5 from the input.
- **Test pack**: one single-route config per balancer member (plus the fallback) with distinct names, to see which route connects on each operator.

### 🧪 Templates
- **Analyse**: paste your full JSON config (or a link) and the tab lists what it does — transport, SNI, fingerprint, REALITY, domain fronting, finalmask, DNS pins, domestic DNS, balancers.
- **Template A — Direct + DNS pin** (modelled on a working VLESS + REALITY config): keeps your server and rebuilds the rest with a chrome fingerprint, a finalmask fragment `1-3 · 50-100 · 10-20 · maxSplit 10` plus UDP noise (Xray-core 26+), `UseIP` with happy-eyeballs, the server domain pinned to its IP in `dns.hosts` (a **Look up** button resolves it over DNS-over-HTTPS) or resolved by a direct domestic DNS, and every domestic DNS routed direct.
- **Template B — CDN multi-address balancer** (modelled on a working VLESS + ws + TLS CDN config): one balancer member per address you list (CDN edges, clean IPs, other domains), chrome / edge fingerprints, `leastLoad` + `burstObservatory`, a fallback member, Iranian DNS (Shecan / Begzar) for .ir domains and no core DNS for the server address. Optional SNI / Host / ALPN overrides for domain fronting.

### 🩺 Config Fixer
- **Diagnose**: paste a full Xray JSON config (v2rayNG **Export full configuration** / Custom) or a `vless://` / `vmess://` / `trojan://` link. The tab lists what is wrong: fingerprint `unsafe` (Go TLS, PattNG-only), `finalmask` (Xray-core 26+ only — older cores ignore it silently), no TLS fragmentation, ws/httpupgrade with ALPN `h2`, an IP address without SNI, `allowInsecure`, a `dialerProxy` pointing at a missing outbound, mux together with flow, and a DNS loop (the server domain resolved by a DNS server whose traffic is routed through the proxy itself).
- **Fix**: sets a browser uTLS fingerprint (`chrome` by default), adds the **classic fragment** — a `freedom` outbound tagged `fragment` with `packets / length / interval`, wired in through `sockopt.dialerProxy` (works on every Xray core) — removes `finalmask` and ignored `cipherSuites`, forces ALPN `http/1.1` on ws, adds a direct DNS rule for the server domain, and can swap the address for a clean IP while keeping SNI / Host. Everything else in the config is preserved. Final Mask mode is still available for PattNG.
- **Test Pack**: builds a JSON array with one config per fragment preset plus a no-fragment control, each with its own name. Import them all, run the real-delay test and keep the one that connects — no single fragment value works on every network.

### 🛡️ ECH
- **Paste & Enhance**: Paste single or multiple `vless://` or `trojan://` URLs (one per line) and get enhanced links with `fp` and `ech` parameters added.
- **Subscription Input**: Paste a subscription link to fetch it in your browser — or paste its contents (plain or base64) — to batch-enhance every VLESS/Trojan config inside with the same ECH options. The server override is ignored here (each config keeps its own address); changing the ECH options re-enhances the fetched configs without re-fetching.
- **Server Override**: The server (IP/domain) field is auto-filled from the URL for a single config and is user-editable. With multiple configs the field stays empty and only applies to all configs if you type a custom value (supports IPv4, IPv6 and domains).
- **Fingerprint**: Default `chrome`, with `unsafe`, `firefox`, `safari`, `random` and `none` options.
- **ECH presets**: The `ECH Server` selector ships prefilled with `cloudflare-ech.com + udp://1.1.1.1 (recommended)` and offers 18 cloudflare-ech.com presets over public UDP resolvers (Cloudflare, Quad9, Google, OpenDNS, AdGuard, CleanBrowsing, Control D, NextDNS). The field stays editable for manual tweaks.
- **Bare domains**: Typing just a domain (e.g. `cloudflare-ech.com`) auto-adds `+udp://8.8.8.8`; a base64 ECHConfigList passes through untouched.
- **TLS-aware**: `ech` is only added when the config uses `tls` security. Clear the field to skip it.
- **One-click Copy**: Copy the enhanced URL straight to the clipboard.
- **Export**: Download as `.txt` (one per line) or base64 `.txt` (standard subscription body).
- **Protocol Support**: **VLESS** and **Trojan**.

### 🧬 Fragment + Fingerprint
- **Paste & Enhance**: Paste single or multiple `vless://` or `trojan://` URLs (one per line) and get enhanced links with `cs`, `fm` and `fp` parameters added.
- **Full JSON configs**: Paste a whole Xray JSON config instead of a link — e.g. one exported with **Export full configuration** in v2rayNG / PattNG, or a **Custom** config. The tab detects it automatically (input starting with `{` or `[`), writes `fp` to `tlsSettings.fingerprint` (or `realitySettings.fingerprint`), `cs` to `tlsSettings.cipherSuites` and `fm` to `streamSettings.finalmask` on every VLESS / VMess / Trojan outbound, and returns the full JSON with everything else (`dns`, `routing`, `inbounds`, `policy`, `remarks`, other outbounds, existing `sockopt`) unchanged. The server override applies only when the config has a single proxy outbound. Download saves `enhanced-config.json`.
- **Multi-Config Support**: Paste bulk proxy URL lists to parse, validate, and batch enhance all URLs cleanly without remark collision.
- **Server Override**: The server (IP/domain) field is auto-filled from the URL for a single config and is user-editable. With multiple configs the field stays empty and only applies to all configs if you type a custom value (supports IPv4, IPv6 and domains).
- **Fingerprint**: Default `unsafe`, with `chrome`, `firefox`, `safari`, `random` and `none` options.
- **Fragment presets**: `fm` has `v1` (classic: `5,94,1` / `109,1` / split `355`) and `v2` (new, default: `0,104,1` / `114,1` / split `11`). Switch via the `Fragment Version` selector; the field stays editable for manual tweaks.
- **TLS-aware**: `cs` and `fm` are only added when the config uses `tls` security. Clear a field to skip that parameter.
- **Subscription sub-tab**: Paste a subscription link to fetch it directly in your browser, decode it (plain or base64) and batch-enhance every VLESS/Trojan config inside — or paste its contents / drop a saved `.txt` file to skip fetching. Uses the same `fp` / `cs` / `fm` options above; the server override is ignored (each config keeps its own address).
- **Blocked Providers**: If the provider sends no CORS headers, the error shows 3 quick steps and an **Open link** button opens the URL in a new tab for copying.
- **Export**: Copy to clipboard, download as `.txt` (one per line) or base64 `.txt` (standard subscription body).
- **No ECH here**: ECH is applied only in the **ECH** tab — subscription entries never get an `ech` parameter.
- **Protocol Support**: **VLESS** and **Trojan** are enhanced; other protocols found inside a subscription are counted as skipped.

### 🔗 Chain Builder
- **Dual Config Chaining**: Easily chain a primary proxy (e.g., Worker/CDN) with a secondary chain proxy.
- **Protocol Support**: Supports **VLESS**, **VMess**, **Trojan**, **Shadowsocks**, **SOCKS**, **HTTP**, and **SSH**.
- **Dual Output**: Generates both **Xray** and **Sing-box** JSON configurations.
- **ECH Support**: Automatically parses and includes ECH config for secure connections.

| Output | Client |
|--------|--------|
| **Xray JSON** | Use with any Xray-compatible client (v2rayN, v2rayNG, Nekoray, etc.) |
| **Sing-box JSON** | Nested tabs for different client types (see below). |

### 📦 Sing-box Sub-formats
- **Standard**: The regular Sing-box configuration.
- **Nekoray**: High compatibility format optimized for **Nekoray**.
- **Nekobox (Android)**: Optimized for Android with a **TUN inbound**, ensuring proper VPN recognition (key icon) and mobile stability.

## 🔗 How the Chain Builder Works

The application generates a configuration that routes your traffic in this sequence:

`You ➔ Config 1 (Proxy) ➔ Config 2 (Chain) ➔ Internet`

This ensures that your final outgoing IP address is that of the **Chain Proxy**, providing a consistent identity for the websites you visit.

## 🛠️ Usage

For full clipboard support, serve this folder locally — e.g. `python3 -m http.server` or `npx serve` — then open via `http://localhost:PORT` (or HTTPS); opening the file directly (`file://`) falls back to manual copy.

### 🛠️ VPN Fixer v8
1. Open the app — the **VPN Fixer v8** tab is active by default.
2. Paste your full JSON config (or a link), or pick a file.
3. Add a few clean IPs if your server is behind a CDN (the most useful option for MCI), keep **multi-path** and the **known-good fragment**, and press **اصلاح کانفیگ**.
4. Copy the result and in v2rayNG use **+ → Import config from clipboard**. If it still fails, download the **test pack** and test each route on its own.

### 🧪 Templates
1. Open the app and switch to the **Templates** tab.
2. Paste your full JSON config (or a link) and read the analysis.
3. Pick **A** (REALITY or a single TLS server; press **Look up** to pin the server IP) or **B** (TLS behind a CDN; list several addresses).
4. Press **Build from Template**, copy, and in v2rayNG use **+ → Import config from clipboard**.

### 🩺 Config Fixer
1. Open the app and switch to the **Config Fixer** tab.
2. Paste your full JSON config (or a link). Read the diagnosis.
3. Keep the defaults (chrome, classic fragment, direct DNS) and press **Fix Config** — or **Build Test Pack** to get several variants.
4. Copy the result and in v2rayNG use **+ → Import config from clipboard** (or download the `.json`).

### 🛡️ ECH
1. Open the app and switch to the **ECH** tab.
2. Paste your **VLESS** or **Trojan** URL.
3. Adjust the options if needed: server override (auto-filled from the URL), fingerprint (default `chrome`), ECH server preset or a manual value (bare domain auto-adds `+udp://8.8.8.8`).
4. Click **"Enhance URL"** and copy the resulting link — import it into your client (Xray core, Sing-box 1.13.0+, or Clash 1.19.20+).
5. For bulk configs, use the **Subscription Input** card instead: paste a link and click **"Fetch & Enhance Sub"** — or paste the subscription contents directly.

### 🧬 Fragment + Fingerprint
1. Switch to the **Fragment + Fingerprint** tab.
2. Paste your **VLESS** or **Trojan** URL.
3. Adjust the options if needed: server override (auto-filled from the URL), fingerprint, cipher suites, final mask.
4. Click **"Enhance URL"** and copy the resulting link — import it into your client.
   - **Full JSON config**: paste the whole exported JSON into the same box instead; the button becomes **"Enhance JSON"**. Copy the result (or download `enhanced-config.json`) and import it in your client as a **Custom config** (from clipboard or file).
5. For bulk configs, switch to the **📥 Subscription** sub-tab: paste your subscription **link** and click **"Fetch & Enhance"** — or paste its **contents** (or drop a saved `.txt` file) to skip fetching. If fetching is blocked, follow the 3 steps shown (open the link with **Open link**, copy, paste, fetch again). Copy or download the enhanced configs (`.txt` or base64 `.txt`).

#### ✅ Client Requirements
- **Windows**: use [PattN](https://github.com/patterniha/PattN).
- **Android**: use [PattNG](https://github.com/patterniha/PattNG).

### 🔗 Chain Builder
1. **Config 1**: Paste your first proxy URL (this can be a Cloudflare Worker, CDN, or any other proxy).
2. **Config 2**: Paste your second proxy URL (the one you want to chain through).
   - For **SSH**, click the 🔑 SSH toggle and fill in server, port, username, and password.
3. **Settings**: Adjust DNS servers or SOCKS ports if needed.
4. **Generate**: Click "Generate Chained Config" to get your JSON.
5. **Deploy**: Copy the JSON or download it as a file to use in your preferred client.

## 📋 Supported Protocols

| Protocol | URL Format | Notes |
|----------|-----------|-------|
| **VLESS** | `vless://uuid@server:port?params` | Supported by all three tools |
| **VMess** | `vmess://base64-json` | Chain Builder only |
| **Trojan** | `trojan://password@server:port?params` | Supported by all three tools |
| **Shadowsocks** | `ss://base64(method:pass)@server:port` | Chain Builder only — no transport (ws, grpc, etc.) and no TLS support |
| **SOCKS** | `socks://user:pass@server:port` | Chain Builder only — must include username and password |
| **HTTP** | `http://user:pass@server:port` | Chain Builder only — must include username and password |
| **SSH** | 4-field input (server, port, user, password) | Chain Builder only — **Sing-box only**, not supported by Xray |

## ⚠️ Important Notes

- The **Fragment + Fingerprint** tool supports **VLESS** and **Trojan** URLs only.
- **TLS is required**: the **Fragment + Fingerprint** tool only works with configs that have **TLS** enabled (security `tls` or `reality`). Non-TLS configs are not supported and will not work.
- `cs` (cipher suites) and `fm` (final mask) are only added when the config uses **tls** security.
- **SOCKS & HTTP** configs must have **username and password** included.
- **Xray** does not support **raw** (headerless TCP) configs — use TCP with http header type instead.
- **Shadowsocks** cannot have any transport (WebSocket, gRPC, HTTPUpgrade, etc.) and cannot have TLS.
- **SSH** is only supported by **Sing-box**. When SSH is used, the Xray tab is automatically disabled. Use the [sing-box client](https://sing-box.sagernet.org/) for SSH configs.

## 🔧 Supported Transports

TCP, TCP (http header), WebSocket, gRPC, HTTPUpgrade

## 🔒 Supported TLS

TLS, Reality, None

## 📦 Tech Stack

- **HTML5**: Semantic structure.
- **CSS3**: Custom variables, glassmorphism, and animations.
- **JavaScript**: Core logic for URL parsing, enhancement and JSON generation.
- **Fonts**: Inter + JetBrains Mono self-hosted locally (`fonts/`, woff2) — no font CDN requests.

## 🛡️ Credits

- The **Fragment + Fingerprint** enhancement logic (`cs` / `fm` / `fp` injection and URL export format) is based on the [PattNG](https://github.com/patterniha/PattNG) project's export-to-clipboard behavior.
- The **Chain Builder** draws inspiration and logic from the [BPB-Worker-Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) project and this [Sing-box configuration](https://gist.github.com/alireza-delavari/62e56af0d59c92b5b1798f1442f90f61).

## 📚 Decision log

Settled decisions live in `plans/README.md` (the contract — if this snapshot drifts, the log wins; if the log outgrows this mirror, collapse to pointer-only):
- VMess bulk handling is documented behavior, not a gap.
- Editable ECH presets rejected — the manual field covers custom values.
- God-file split deferred pending pure coverage (011/016/017 now done in review).
- Xray `domain+resolver` ech passthrough verified correct per Xray docs (C-11 rejected).
- Green low-importance items (packet_encoding, log mapping, remote-dns rule, link rel, credential masking) operator-scoped-out, not rejected on merit.

---
Built with ❤️ for the privacy community.