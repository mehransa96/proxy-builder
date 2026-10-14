// ===================================================================
// Proxy Builder — pure.js
// Pure helpers with no DOM or network access (testable in Node).
// Loaded before script.js; both share classic <script> global scope.
// Future pure helpers MUST go here with tests in tests/pure.test.js.
// ===================================================================

// ===== Base64 Helpers =====
function safeAtob(str) {
    if (!str) return null;
    try {
        const clean = str.trim().replace(/\s+/g, '');
        if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
        const padded = clean.replace(/-/g, '+').replace(/_/g, '/');
        const pad = padded.length % 4;
        if (pad === 1) return null;
        const final = pad ? padded + '='.repeat(4 - pad) : padded;
        const decoded = decodeURIComponent(
            atob(final)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );
        return decoded;
    } catch {
        try {
            const clean = str.trim().replace(/\s+/g, '');
            if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
            const padded = clean.replace(/-/g, '+').replace(/_/g, '/');
            const pad = padded.length % 4;
            if (pad === 1) return null;
            const final = pad ? padded + '='.repeat(4 - pad) : padded;
            const raw = atob(final);
            if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(raw)) return null;
            return raw;
        } catch {
            return null;
        }
    }
}

// Standard subscription body: UTF-8 bytes -> base64, no line breaks.
// Chunked because a spread over a few hundred KB overflows the arg limit.
function encodeUtf8ToB64(text) {
    const bytes = new TextEncoder().encode(String(text ?? ''));
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
}

// Safe wrapper around decodeURIComponent: returns the raw string
// instead of throwing on malformed percent-encoding.
function safeDecode(str) {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}

// ===== ECH Helpers =====
// ECH query server: only the DNS-query form "domain+dns-server"
// (e.g. "cloudflare-ech.com+https://dns.alidns.com/dns-query" or
// "cloudflare-ech.com+udp://1.1.1.1") carries a queryable domain.
// A raw base64 ECHConfigList can itself contain '+' (base64 alphabet),
// so it must not be split — return '' so callers fall back to sni/server.
// Split on whitespace too: a badly-encoded external link may carry a
// literal '+' which URLSearchParams decodes to a space.
function getEchQueryServer(ech) {
    if (!ech || !ech.includes('://')) return '';
    const head = ech.split(/[+\s]/)[0].trim();
    // A bare resolver with no domain part ("udp://1.1.1.1" or a lone
    // "https://..." URL from a mistyped field) is not a queryable name —
    // callers fall back to sni/server instead of emitting a URL there.
    if (!head || head.includes('://')) return '';
    return head;
}

// Default DNS appended to a bare ECH domain, BPB-style:
// "cloudflare-ech.com" becomes "cloudflare-ech.com+udp://8.8.8.8".
const ECH_DNS_DEFAULT = 'udp://8.8.8.8';

// Bare ECH domain (just a hostname, no resolver part). Dots never appear
// in standard/base64url alphabets, so a dot-containing value without
// '://', '+', '/' or '=' cannot be a base64 ECHConfigList.
function isBareEchDomain(value) {
    if (!value || value.includes('://')) return false;
    if (/[\s+=/]/.test(value)) return false;
    return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
}

// Normalize the enhancer textarea value before writing the URL param:
// bare domains are completed with the default DNS, full DNS-query forms
// and raw base64 pass through untouched, empty stays empty (skip ech).
function normalizeEchInput(raw) {
    const value = (raw || '').trim();
    if (!value) return '';
    if (isBareEchDomain(value)) return value + '+' + ECH_DNS_DEFAULT;
    return value;
}

// ===== Enhance Cores =====
// DOM-free cores behind value-in/value-out signatures: script.js wrappers
// read the option elements and delegate; bulk paths pass ignoreServer.
// NOTE the two functions DIFFER on fp==='none'/empty by design — fragment
// keeps the existing fp, ECH deletes it. Preserve the asymmetry, do not unify.
function enhanceUrlCore(raw, opts) {
    const url = raw.trim();
    if (!url) return { error: 'No URL provided' };
    // Case-insensitive on purpose — parseProxyURLSingle() accepts VLESS://
    // as well, and the bulk path would otherwise count those as "skipped".
    const scheme = url.slice(0, url.indexOf('://')).toLowerCase();
    if (scheme !== 'vless' && scheme !== 'trojan') {
        return { error: 'Only VLESS and Trojan URLs are supported' };
    }

    let u;
    try {
        u = new URL(url);
    } catch (e) {
        return { error: 'Failed to parse URL: ' + e.message };
    }

    const params = u.searchParams;
    const security = params.get('security') || 'none';

    // Server override — auto-filled from URL, user-editable, empty keeps original.
    // opts.ignoreServer skips it: a subscription holds many servers, so rewriting
    // every entry to one address would break the whole list.
    const server = (opts && opts.ignoreServer) ? '' : ((opts && opts.server) || '').trim();
    if (server) {
        const host = server.includes(':') && !server.startsWith('[')
            ? '[' + server + ']'
            : server;
        try {
            u.hostname = host;
        } catch (e) {
            return { error: 'Invalid server address: ' + e.message };
        }
    }

    // Fingerprint — always applied when selected value is non-empty
    const fp = ((opts && opts.fp) || '').trim();
    if (fp && fp !== 'none') {
        params.set('fp', fp);
    }

    // Cipher suites & fragment mask — only meaningful with TLS
    if (security === 'tls') {
        const cs = ((opts && opts.cs) || '').trim();
        if (cs) {
            params.set('cs', cs);
        }
        const fm = ((opts && opts.fm) || '').trim();
        if (fm) {
            params.set('fm', fm);
        }
    }

    // URLSearchParams encodes spaces as '+', but v2ray-style clients use '%20'
    u.search = u.search.replace(/\+/g, '%20');

    return { url: u.toString() };
}

function enhanceEchUrlCore(raw, opts) {
    const url = raw.trim();
    if (!url) return { error: 'No URL provided' };
    // Case-insensitive on purpose — parseProxyURLSingle() accepts VLESS://
    // as well, and the bulk path would otherwise count those as "skipped".
    const scheme = url.slice(0, url.indexOf('://')).toLowerCase();
    if (scheme !== 'vless' && scheme !== 'trojan') {
        return { error: 'Only VLESS and Trojan URLs are supported' };
    }

    let u;
    try {
        u = new URL(url);
    } catch (e) {
        return { error: 'Failed to parse URL: ' + e.message };
    }

    const params = u.searchParams;
    // Missing security means plaintext ('none') — Trojan links are not
    // always TLS (e.g. port-80 ws links with no security param), so never
    // assume 'tls' here; that would inject ech into a plaintext config.
    const security = params.get('security') || 'none';

    // Server override — auto-filled from URL, user-editable, empty keeps original.
    // opts.ignoreServer skips it for bulk input: a subscription holds many
    // servers, so rewriting every entry to one address would break the list.
    const server = (opts && opts.ignoreServer) ? '' : ((opts && opts.server) || '').trim();
    if (server) {
        const host = server.includes(':') && !server.startsWith('[')
            ? '[' + server + ']'
            : server;
        try {
            u.hostname = host;
        } catch (e) {
            return { error: 'Invalid server address: ' + e.message };
        }
    }

    // Fingerprint — applied when set; 'none'/empty removes an existing value
    // so "clear to skip" also strips a previously-enhanced URL.
    const fp = ((opts && opts.fp) || '').trim();
    if (fp && fp !== 'none') {
        params.set('fp', fp);
    } else {
        params.delete('fp');
    }

    // ECH config list — only meaningful with TLS. A bare domain
    // ("cloudflare-ech.com") is completed with the default DNS, BPB-style;
    // URLSearchParams serializes the '+' separator as %2B, which is what
    // Xray expects. Empty removes an existing value ("clear to skip").
    if (security === 'tls') {
        const ech = normalizeEchInput((opts && opts.ech) || '');
        if (ech) {
            params.set('ech', ech);
        } else {
            params.delete('ech');
        }
    }

    // URLSearchParams encodes spaces as '+', but v2ray-style clients use '%20'
    u.search = u.search.replace(/\+/g, '%20');

    return { url: u.toString() };
}

// ===== Full Xray JSON config (Fragment tab) =====
// v2rayNG "Export full configuration" / custom-type configs are whole Xray
// JSON documents, not share links. These helpers apply the same fp / cs / fm
// options the URL path writes as query params, but into the JSON fields the
// core reads them from: tlsSettings.fingerprint (or realitySettings for
// REALITY), tlsSettings.cipherSuites and streamSettings.finalmask. Every
// other key (dns, routing, inbounds, policy, remarks, other outbounds) is
// passed through untouched.
const FULL_CONFIG_PROTOCOLS = ['vless', 'vmess', 'trojan'];

function looksLikeJsonConfig(raw) {
    const s = String(raw || '').trim();
    return s.startsWith('{') || s.startsWith('[');
}

function parseFullConfigJson(raw) {
    let data;
    try {
        data = JSON.parse(String(raw || '').trim());
    } catch (e) {
        return { error: 'Invalid JSON: ' + e.message };
    }
    const isArray = Array.isArray(data);
    const configs = isArray ? data : [data];
    if (configs.length === 0) return { error: 'The JSON array is empty' };
    for (const cfg of configs) {
        if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg) || !Array.isArray(cfg.outbounds)) {
            return { error: 'Not an Xray config — expected an object with an "outbounds" array' };
        }
    }
    return { configs, isArray };
}

function fullConfigOutboundServer(ob) {
    const s = ob.settings || {};
    const entry = (Array.isArray(s.vnext) && s.vnext[0])
        || (Array.isArray(s.servers) && s.servers[0])
        || s;
    return { server: entry.address || '', port: entry.port || '' };
}

function fullConfigProxyOutbounds(cfg) {
    return cfg.outbounds.filter(ob => ob && typeof ob === 'object'
        && FULL_CONFIG_PROTOCOLS.includes(String(ob.protocol || '').toLowerCase()));
}

function summarizeFullConfig(raw) {
    const parsed = parseFullConfigJson(raw);
    if (parsed.error) return parsed;
    const outbounds = [];
    parsed.configs.forEach((cfg, ci) => {
        fullConfigProxyOutbounds(cfg).forEach(ob => {
            const ss = ob.streamSettings || {};
            const { server, port } = fullConfigOutboundServer(ob);
            outbounds.push({
                config: ci,
                remarks: typeof cfg.remarks === 'string' ? cfg.remarks : '',
                tag: ob.tag || '',
                protocol: String(ob.protocol).toLowerCase(),
                server: String(server),
                port: String(port),
                network: ss.network || 'tcp',
                security: ss.security || 'none'
            });
        });
    });
    if (outbounds.length === 0) {
        return { error: 'No VLESS / VMess / Trojan outbound found in the config' };
    }
    return { configCount: parsed.configs.length, isArray: parsed.isArray, outbounds };
}

function enhanceFullConfigCore(raw, opts) {
    const parsed = parseFullConfigJson(raw);
    if (parsed.error) return parsed;
    const o = opts || {};
    const fp = String(o.fp || '').trim();
    const cs = String(o.cs || '').trim();
    const fmRaw = String(o.fm || '').trim();
    let fm = null;
    if (fmRaw) {
        try {
            fm = JSON.parse(fmRaw);
        } catch (e) {
            return { error: 'Final Mask (fm) is not valid JSON: ' + e.message };
        }
        if (!fm || typeof fm !== 'object' || Array.isArray(fm)) {
            return { error: 'Final Mask (fm) must be a JSON object, e.g. {"tcp": [...]}' };
        }
    }

    const targets = [];
    parsed.configs.forEach(cfg => targets.push(...fullConfigProxyOutbounds(cfg)));
    if (targets.length === 0) {
        return { error: 'No VLESS / VMess / Trojan outbound found in the config' };
    }
    // Server override only when there is exactly one proxy outbound — the
    // same rule as bulk links: rewriting many servers to one address breaks them.
    const server = (!o.ignoreServer && targets.length === 1) ? String(o.server || '').trim() : '';

    let tlsCount = 0;
    targets.forEach(ob => {
        if (server) {
            const s = ob.settings || (ob.settings = {});
            const entry = (Array.isArray(s.vnext) && s.vnext[0])
                || (Array.isArray(s.servers) && s.servers[0]);
            if (entry) entry.address = server;
        }
        const ss = ob.streamSettings || (ob.streamSettings = {});
        const security = ss.security || 'none';
        if (fp && fp !== 'none') {
            if (security === 'tls') {
                (ss.tlsSettings || (ss.tlsSettings = {})).fingerprint = fp;
            } else if (security === 'reality') {
                (ss.realitySettings || (ss.realitySettings = {})).fingerprint = fp;
            }
        }
        // cs / fm only with TLS — same rule as enhanceUrlCore.
        if (security === 'tls') {
            tlsCount++;
            if (cs) (ss.tlsSettings || (ss.tlsSettings = {})).cipherSuites = cs;
            if (fm) ss.finalmask = JSON.parse(JSON.stringify(fm));
        }
    });

    const out = parsed.isArray ? parsed.configs : parsed.configs[0];
    return {
        json: JSON.stringify(out, null, 2),
        enhanced: targets.length,
        tls: tlsCount,
        serverApplied: !!server
    };
}

// ===== URL Parser =====
function extractLines(raw) {
    if (!raw) return [];
    return raw
        .split(/[\r\n]+/)
        .map(line => line.trim())
        .filter(line => line.length > 0);
}

// ===== Subscription Helpers =====
// One scheme list for every branch of the bulk path, so a scheme added here
// works in plain text, whole-blob base64 and per-line base64 alike.
const SUB_SCHEME = /^(vless|vmess|trojan|ss|socks5?|tg):\/\//i;

// One http(s) line = a link to fetch. Anything else that looks like a
// subscription body is enhanced straight away, with no fetch at all — the
// escape hatch for providers that block browser/CORS access.
function subIsLink(v) {
    return !/\s/.test(v) && /^https?:\/\/\S+$/i.test(v);
}

// Mirrors extractSubConfigs() instead of guessing from the first line or a
// length threshold: any line with a known scheme counts, and a short base64
// blob is accepted if it actually decodes to a config.
function subLooksLikeContent(v) {
    if (extractLines(v).some(l => SUB_SCHEME.test(l))) return true;
    const whole = safeAtob(v.replace(/\s+/g, ''));
    return !!whole && extractLines(whole).some(l => SUB_SCHEME.test(l));
}

// A single http(s) URL with an explicit port but no path, query or hash is
// far more likely an HTTP proxy address than a subscription link (those
// carry a path, a query token, or both). Userinfo is allowed: proxies
// commonly embed credentials while subscription links effectively never do.
// Fetching a proxy port would only fail confusingly, so reject it up front
// with guidance instead of treating it as a link to fetch.
function subLooksLikeProxy(v) {
    if (/\s/.test(v) || !/^https?:\/\/\S+$/i.test(v)) return false;
    let u = null;
    try {
        u = new URL(v);
    } catch (e) {
        return false;
    }
    return !!u.hostname && !!u.port &&
        (u.pathname === '/' || u.pathname === '') && !u.search && !u.hash;
}

// Returns 'link', 'content', 'proxy' or null for input that is none of those.
// Both the input handler and the post-fetch re-validation go through this,
// so a field that was replaced with junk mid-fetch can never re-enable
// the button.
function subValidate(v) {
    if (subLooksLikeProxy(v)) return 'proxy';
    if (subIsLink(v)) {
        let u = null;
        try {
            u = new URL(v);
        } catch (e) {
            u = null;
        }
        return u && u.hostname ? 'link' : null;
    }
    return subLooksLikeContent(v) ? 'content' : null;
}

// ===== Subscription Extract & Errors =====
// Moved from script.js: DOM-free bulk decode plus error classifiers, shared
// via classic <script> global scope. The timeout/message consts live here (not
// in script.js) so subErrorText() resolves them in both runtimes: browsers
// through the shared global scope, Node tests by requiring this file.
const SUB_IDLE_MS = 30000;
// Backstop for a body that trickles forever without ever going silent.
const SUB_TOTAL_MS = 5 * 60 * 1000;
const SUB_TOO_LARGE_MSG = 'That file is too large — drop a plain-text subscription file (.txt), usually a few hundred KB at most.';

// Returns every proxy line found in a subscription body, whether it arrives
// as plain text, as one base64 blob, or as a mix of plain lines and
// per-line base64 blobs.
function extractSubConfigs(body) {
    let text = (body || '').trim();
    if (!text) return [];

    const lines = extractLines(text);

    // Plain text list that also carries per-line base64 blobs: keep every
    // line, exactly as before, and append whatever the non-plain lines
    // decode to. Inputs without any base64 line return byte-identical
    // results to the old early-return.
    if (lines.some(l => SUB_SCHEME.test(l))) {
        const out = lines.slice();
        const seen = new Set(out);
        for (const line of lines) {
            if (SUB_SCHEME.test(line)) continue;
            const decoded = safeAtob(line.replace(/^\/\/.*$/, '').trim());
            if (!decoded) continue;
            for (const dl of extractLines(decoded)) {
                if (SUB_SCHEME.test(dl) && !seen.has(dl)) {
                    seen.add(dl);
                    out.push(dl);
                }
            }
        }
        return out;
    }

    // Base64 body: try the whole payload first (standard subscription format),
    // then line by line for providers that send a base64 blob per config.
    const whole = safeAtob(text.replace(/\s+/g, ''));
    if (whole) {
        const decodedLines = extractLines(whole);
        if (decodedLines.some(l => SUB_SCHEME.test(l))) {
            return decodedLines;
        }
    }

    // Last resort: some providers base64 each config on its own line. Only
    // decoded lines that actually hold a proxy scheme count — otherwise any
    // base64-looking word (an HTML file, a comment) becomes a "config".
    return extractLines(text)
        .map(l => safeAtob(l.replace(/^\/\/.*$/, '').trim()))
        .filter(Boolean)
        .flatMap(extractLines)
        .filter(l => SUB_SCHEME.test(l));
}

// Transport failures surface as TypeError in every browser, but the message
// text varies ('Failed to fetch', 'NetworkError', 'Load failed', or even
// empty), so match the name first and the text only as fallback.
function subIsBlockedError(e) {
    const msg = (e && e.message) || String(e);
    return (e && e.name === 'TypeError') || /Failed to fetch|NetworkError|Load failed/i.test(msg);
}

// Reports the fetch error honestly. A 4xx/5xx from the provider is a real
// answer, and the CORS case gets a message that points at the paste fallback.
function subErrorText(e, isOnline = (typeof navigator !== 'undefined' ? navigator.onLine !== false : true)) {
    const msg = (e && e.message) || String(e);
    if (isOnline === false) {
        return 'You appear to be offline — check your connection and try again.';
    }
    if (e && e.name === 'SubTotalTimeout') {
        return 'The download took longer than ' + Math.round(SUB_TOTAL_MS / 60000) +
            ' minutes without finishing — the provider is too slow. Retry, or paste the subscription contents into this box.';
    }
    if (e && e.name === 'AbortError') {
        return 'The connection went silent for ' + Math.round(SUB_IDLE_MS / 1000) +
            's — the provider is throttling or unreachable. Retry, or paste the subscription contents into this box.';
    }
    if (/^HTTP \d+$/.test(msg)) {
        const code = Number(msg.slice(5));
        return 'The server replied ' + code + '. ' +
            (code === 401 || code === 403
                ? 'That looks like an expired or invalid subscription link.'
                : code === 404
                    ? 'That subscription link does not exist.'
                    : 'The subscription URL is wrong or the server is refusing it.');
    }
    if (subIsBlockedError(e)) {
        return 'This provider blocks browser access (it sends no CORS headers), so the direct fetch ' +
            'was refused. Open the link in a new tab and paste its contents into this box — that always works.';
    }
    if (e && e.name === 'SubTooLarge') {
        return SUB_TOO_LARGE_MSG;
    }
    return 'Could not read the response (' + msg + ').';
}


// ===== Proxy Parsers =====
// Moved from script.js: DOM-free URL parsers shared via classic <script> global scope.

function parseProxyURLSingle(raw) {
    const url = raw.trim();
    if (!url) return null;

    const lower = url.toLowerCase();
    if (lower.startsWith('vless://')) return parseVless(url);
    if (lower.startsWith('vmess://')) return parseVmess(url);
    if (lower.startsWith('trojan://')) return parseTrojan(url);
    if (lower.startsWith('ss://')) return parseShadowsocks(url);
    // Note: socks4/socks4a are intentionally not routed here. Xray outbound
    // only supports SOCKS5 and this app always emits version 5 for sing-box,
    // so accepting socks4 input would silently misrepresent the protocol.
    if (lower.startsWith('tg://socks') || lower.startsWith('tg://socks5') || lower.startsWith('https://t.me/socks') || lower.startsWith('http://t.me/socks') || lower.startsWith('socks://') || lower.startsWith('socks5://')) return parseSocks(url);
    if (lower.startsWith('http://') || lower.startsWith('https://')) return parseHttp(url);

    try {
        const decoded = safeAtob(url);
        if (decoded) {
            if (decoded.includes('"add"')) {
                return parseVmess('vmess://' + url);
            }
            const decodedLower = decoded.toLowerCase();
            if (decodedLower.startsWith('vless://') || decodedLower.startsWith('vmess://') || decodedLower.startsWith('trojan://') || decodedLower.startsWith('ss://') || decodedLower.startsWith('socks://') || decodedLower.startsWith('socks5://') || decodedLower.startsWith('http://') || decodedLower.startsWith('https://') || decodedLower.startsWith('tg://')) {
                return parseProxyURLSingle(decoded);
            }
            if (decoded.includes('@') && decoded.includes(':')) {
                return parseSocks('socks5://' + decoded);
            }
        }
    } catch { }

    // Note: socks4/socks4a links fall through to this error on purpose.
    // Only SOCKS5 is supported (Xray outbound is SOCKS5-only).
    return { error: 'Unknown protocol. Supported: vless, vmess, trojan, ss, socks (socks5 only), http' };
}

function parseProxyURL(raw) {
    const lines = extractLines(raw);
    if (lines.length === 0) return null;
    if (lines.length === 1) return parseProxyURLSingle(lines[0]);

    const parsedList = lines.map(line => parseProxyURLSingle(line));
    const validList = parsedList.filter(p => p && !p.error);
    if (validList.length > 0) {
        return validList;
    }
    return parsedList[0] || { error: 'Unknown protocol. Supported: vless, vmess, trojan, ss, socks (socks5 only), http' };
}

// xhttp was named splithttp before Xray v24.9; links use either name.
function isXhttpNetwork(net) {
    return net === 'xhttp' || net === 'splithttp';
}

// The `extra` link param is a JSON object (headers, padding, xmux, ...).
// Returns the parsed object, or null when absent or not a JSON object.
function parseXhttpExtra(raw) {
    if (!raw) return null;
    try {
        const obj = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
    } catch (e) {
        return null;
    }
}

function parseVless(url) {
    try {
        const u = new URL(url);
        if (!u.username) return { error: 'Failed to parse VLESS URL: missing userinfo' };
        const uuid = u.username;
        if (!uuid) return { error: 'Failed to parse VLESS URL: missing userinfo' };
        const params = Object.fromEntries(u.searchParams);
        return {
            protocol: 'vless',
            uuid: uuid,
            server: u.hostname,
            port: parseInt(u.port) || 443,
            remark: safeDecode(u.hash.slice(1) || ''),
            type: params.type || 'tcp',
            headerType: params.headerType || 'none',
            host: params.host || undefined,
            path: params.path || undefined,
            serviceName: params.serviceName || undefined,
            authority: params.authority || undefined,
            mode: params.mode || undefined,
            extra: params.extra || undefined,
            security: params.security || 'none',
            sni: params.sni || undefined,
            fp: params.fp || 'chrome',
            alpn: params.alpn || undefined,
            pbk: params.pbk || undefined,
            sid: params.sid || undefined,
            spx: params.spx || undefined,
            flow: params.flow || undefined,
            encryption: params.encryption || 'none',
            // ECH support
            ech: params.ech || undefined,
            // Insecure support
            allowInsecure: params.allowInsecure === '1' || params.allowInsecure === 'true' || params.insecure === '1' || params.insecure === 'true'
        };
    } catch (e) {
        return { error: 'Failed to parse VLESS URL: ' + e.message };
    }
}

function parseVmess(url) {
    try {
        // Case-insensitive scheme strip: the router already accepts VMESS://
        const b64 = url.replace(/^vmess:\/\//i, '');
        const decoded = safeAtob(b64);
        if (!decoded) return { error: 'Failed to decode VMess base64' };
        const config = JSON.parse(decoded);
        return {
            protocol: 'vmess',
            uuid: config.id,
            server: config.add,
            port: parseInt(config.port) || 443,
            aid: parseInt(config.aid) || 0,
            remark: String(config.ps ?? ''),
            type: config.net || 'tcp',
            headerType: config.type || 'none',
            host: config.host || undefined,
            path: config.path || undefined,
            serviceName: config.path || undefined,
            authority: config.authority || undefined,
            // xhttp share links put the mode in `type` (v2rayN) or `mode`
            mode: config.mode || (isXhttpNetwork(config.net) && config.type && config.type !== 'none' ? config.type : undefined),
            extra: config.extra ? (typeof config.extra === 'string' ? config.extra : JSON.stringify(config.extra)) : undefined,
            security: config.tls || 'none',
            sni: config.sni || undefined,
            fp: config.fp || 'chrome',
            alpn: config.alpn || undefined,
            allowInsecure: config.tls === 'tls' && (config.allowInsecure === 1 || config.allowInsecure === true || config.insecure === 1 || config.insecure === true)
        };
    } catch (e) {
        return { error: 'Failed to parse VMess URL: ' + e.message };
    }
}

function parseTrojan(url) {
    try {
        const u = new URL(url);
        if (!u.username) return { error: 'Failed to parse Trojan URL: missing userinfo' };
        const password = safeDecode(u.username);
        if (!password) return { error: 'Failed to parse Trojan URL: missing userinfo' };
        const params = Object.fromEntries(u.searchParams);
        return {
            protocol: 'trojan',
            password: password,
            server: u.hostname,
            port: parseInt(u.port) || 443,
            remark: safeDecode(u.hash.slice(1) || ''),
            type: params.type || 'tcp',
            headerType: params.headerType || 'none',
            host: params.host || undefined,
            path: params.path || undefined,
            serviceName: params.serviceName || undefined,
            authority: params.authority || undefined,
            mode: params.mode || undefined,
            extra: params.extra || undefined,
            security: params.security || 'tls',
            sni: params.sni || undefined,
            fp: params.fp || 'chrome',
            alpn: params.alpn || undefined,
            pbk: params.pbk || undefined,
            sid: params.sid || undefined,
            spx: params.spx || undefined,
            ech: params.ech || undefined,
            allowInsecure: params.allowInsecure === '1' || params.allowInsecure === 'true' || params.insecure === '1' || params.insecure === 'true'
        };
    } catch (e) {
        return { error: 'Failed to parse Trojan URL: ' + e.message };
    }
}

function parseShadowsocks(url) {
    try {
        // Case-insensitive scheme strip: the router already accepts SS://
        let raw = url.replace(/^ss:\/\//i, '');
        const hashIdx = raw.indexOf('#');
        let remark = '';
        if (hashIdx !== -1) {
            remark = safeDecode(raw.slice(hashIdx + 1));
            raw = raw.slice(0, hashIdx);
        }

        let method, password, server, port;

        if (raw.includes('@')) {
            const [userPart, hostPart] = raw.split('@');
            const decoded = safeAtob(userPart) || userPart;
            const colonIdx = decoded.indexOf(':');
            method = decoded.slice(0, colonIdx);
            password = decoded.slice(colonIdx + 1);
            const hostMatch = hostPart.match(/^(.+):(\d+)/);
            if (hostMatch) {
                server = hostMatch[1];
                port = parseInt(hostMatch[2]);
            }
        } else {
            const decoded = safeAtob(raw);
            if (!decoded) return { error: 'Failed to decode SS base64' };
            const match = decoded.match(/^(.+?):(.+)@(.+):(\d+)/);
            if (match) {
                method = match[1];
                password = match[2];
                server = match[3];
                port = parseInt(match[4]);
            }
        }

        if (!server) return { error: 'Failed to parse Shadowsocks URL' };

        return {
            protocol: 'shadowsocks',
            method: method,
            password: password,
            server: server,
            port: port,
            remark: remark
        };
    } catch (e) {
        return { error: 'Failed to parse Shadowsocks URL: ' + e.message };
    }
}

function parseSocks(url) {
    try {
        let target = url.trim();
        let remark = '';
        let user, pass, server, port;

        const lower = target.toLowerCase();
        if (lower.startsWith('tg://socks') || lower.startsWith('tg://socks5') || lower.startsWith('https://t.me/socks') || lower.startsWith('http://t.me/socks')) {
            // Telegram share format carries plain SOCKS5 credentials as query params.
            // The output is still a standard SOCKS outbound, so Xray/sing-box support it.
            const u = new URL(/^tg:\/\//i.test(target) ? target.replace(/^tg:\/\/(socks5|socks)\?/i, 'http://localhost/?') : target);
            server = u.searchParams.get('server') || u.searchParams.get('host') || u.searchParams.get('ip') || '';
            port = parseInt(u.searchParams.get('port')) || 1080;
            user = u.searchParams.get('user') || u.searchParams.get('username') || undefined;
            pass = u.searchParams.get('pass') || u.searchParams.get('password') || undefined;
            // The hash fragment needs decoding, but query params are already
            // decoded by URLSearchParams, so decoding them again would throw
            // on values like "100%".
            const tgHash = u.hash.slice(1);
            remark = tgHash ? safeDecode(tgHash) : (u.searchParams.get('remark') || '');

            if (!server) return { error: 'Failed to parse Telegram SOCKS URL: missing server' };
            return {
                protocol: 'socks',
                server: server,
                port: port,
                user: user || undefined,
                pass: pass || undefined,
                remark: remark
            };
        }

        // Only socks:// and socks5:// are supported here. socks4/socks4a
        // input is rejected by the router on purpose (see above).
        let body = target.replace(/^(socks5:\/\/|socks:\/\/)/i, '');

        const hashIdx = body.indexOf('#');
        if (hashIdx !== -1) {
            remark = safeDecode(body.slice(hashIdx + 1));
            body = body.slice(0, hashIdx);
        }

        if (!body.includes('@')) {
            const decodedBody = safeAtob(body);
            if (decodedBody && (decodedBody.includes(':') || decodedBody.includes('@'))) {
                if (!remark && decodedBody.includes('#')) {
                    const dHashIdx = decodedBody.indexOf('#');
                    remark = safeDecode(decodedBody.slice(dHashIdx + 1));
                    body = decodedBody.slice(0, dHashIdx);
                } else {
                    body = decodedBody;
                }
            }
        }

        let userPart = '';
        let hostPart = body;

        if (body.includes('@')) {
            const atIdx = body.lastIndexOf('@');
            userPart = body.slice(0, atIdx);
            hostPart = body.slice(atIdx + 1);
        }

        if (userPart) {
            if (userPart.includes(':')) {
                const colonIdx = userPart.indexOf(':');
                user = safeDecode(userPart.slice(0, colonIdx));
                pass = safeDecode(userPart.slice(colonIdx + 1));
            } else {
                const decodedUser = safeAtob(userPart);
                if (decodedUser && decodedUser.includes(':')) {
                    const colonIdx = decodedUser.indexOf(':');
                    user = decodedUser.slice(0, colonIdx);
                    pass = decodedUser.slice(colonIdx + 1);
                } else {
                    user = safeDecode(userPart);
                }
            }
        }

        let searchParams = null;
        if (hostPart.includes('?')) {
            const qIdx = hostPart.indexOf('?');
            try {
                searchParams = new URLSearchParams(hostPart.slice(qIdx + 1));
            } catch { }
            hostPart = hostPart.slice(0, qIdx);
        }
        hostPart = hostPart.replace(/\/+$/, '');
        // A stray path (socks://host/extra) is not part of the server name.
        hostPart = hostPart.split('/')[0];

        if (hostPart.startsWith('[')) {
            const closeBracket = hostPart.indexOf(']');
            if (closeBracket !== -1) {
                server = hostPart.slice(1, closeBracket);
                const portPart = hostPart.slice(closeBracket + 1);
                if (portPart.startsWith(':')) {
                    port = parseInt(portPart.slice(1)) || 1080;
                } else {
                    port = 1080;
                }
            } else {
                server = hostPart;
                port = 1080;
            }
        } else if (hostPart.includes(':')) {
            const lastColon = hostPart.lastIndexOf(':');
            server = hostPart.slice(0, lastColon);
            port = parseInt(hostPart.slice(lastColon + 1)) || 1080;
        } else {
            server = hostPart;
            port = 1080;
        }

        if (searchParams) {
            if (!user && (searchParams.get('user') || searchParams.get('username'))) {
                user = searchParams.get('user') || searchParams.get('username');
            }
            if (!pass && (searchParams.get('pass') || searchParams.get('password'))) {
                pass = searchParams.get('pass') || searchParams.get('password');
            }
            if (!remark && searchParams.get('remark')) {
                remark = searchParams.get('remark');
            }
        }

        if (!server) return { error: 'Failed to parse SOCKS URL: missing server' };

        return {
            protocol: 'socks',
            server: server,
            port: port,
            user: user || undefined,
            pass: pass || undefined,
            remark: remark
        };
    } catch (e) {
        return { error: 'Failed to parse SOCKS URL: ' + e.message };
    }
}

function parseHttp(url) {
    try {
        let target = url.trim();
        let remark = '';
        let user, pass, server, port;

        const lower = target.toLowerCase();
        if (lower.startsWith('tg://http') || lower.startsWith('https://t.me/http') || lower.startsWith('http://t.me/http')) {
            const u = new URL(/^tg:\/\//i.test(target) ? target.replace(/^tg:\/\/http\?/i, 'http://localhost/?') : target);
            server = u.searchParams.get('server') || u.searchParams.get('host') || u.searchParams.get('ip') || '';
            port = parseInt(u.searchParams.get('port')) || 80;
            user = u.searchParams.get('user') || u.searchParams.get('username') || undefined;
            pass = u.searchParams.get('pass') || u.searchParams.get('password') || undefined;
            // Same double-decode guard as in parseSocks: hash needs decoding,
            // query params are already decoded by URLSearchParams.
            const tgHash = u.hash.slice(1);
            remark = tgHash ? safeDecode(tgHash) : (u.searchParams.get('remark') || '');

            if (!server) return { error: 'Failed to parse HTTP URL: missing server' };
            return {
                protocol: 'http',
                server: server,
                port: port,
                user: user || undefined,
                pass: pass || undefined,
                remark: remark
            };
        }

        let body = target.replace(/^(https:\/\/|http:\/\/)/i, '');

        const hashIdx = body.indexOf('#');
        if (hashIdx !== -1) {
            remark = safeDecode(body.slice(hashIdx + 1));
            body = body.slice(0, hashIdx);
        }

        if (!body.includes('@')) {
            const decodedBody = safeAtob(body);
            if (decodedBody && (decodedBody.includes(':') || decodedBody.includes('@'))) {
                if (!remark && decodedBody.includes('#')) {
                    const dHashIdx = decodedBody.indexOf('#');
                    remark = safeDecode(decodedBody.slice(dHashIdx + 1));
                    body = decodedBody.slice(0, dHashIdx);
                } else {
                    body = decodedBody;
                }
            }
        }

        let userPart = '';
        let hostPart = body;

        if (body.includes('@')) {
            const atIdx = body.lastIndexOf('@');
            userPart = body.slice(0, atIdx);
            hostPart = body.slice(atIdx + 1);
        }

        if (userPart) {
            if (userPart.includes(':')) {
                const colonIdx = userPart.indexOf(':');
                user = safeDecode(userPart.slice(0, colonIdx));
                pass = safeDecode(userPart.slice(colonIdx + 1));
            } else {
                const decodedUser = safeAtob(userPart);
                if (decodedUser && decodedUser.includes(':')) {
                    const colonIdx = decodedUser.indexOf(':');
                    user = decodedUser.slice(0, colonIdx);
                    pass = decodedUser.slice(colonIdx + 1);
                } else {
                    user = safeDecode(userPart);
                }
            }
        }

        let searchParams = null;
        if (hostPart.includes('?')) {
            const qIdx = hostPart.indexOf('?');
            try {
                searchParams = new URLSearchParams(hostPart.slice(qIdx + 1));
            } catch { }
            hostPart = hostPart.slice(0, qIdx);
        }
        hostPart = hostPart.replace(/\/+$/, '');
        // A stray path (http://host/extra) is not part of the server name.
        hostPart = hostPart.split('/')[0];

        if (hostPart.startsWith('[')) {
            const closeBracket = hostPart.indexOf(']');
            if (closeBracket !== -1) {
                server = hostPart.slice(1, closeBracket);
                const portPart = hostPart.slice(closeBracket + 1);
                if (portPart.startsWith(':')) {
                    port = parseInt(portPart.slice(1)) || 80;
                } else {
                    port = 80;
                }
            } else {
                server = hostPart;
                port = 80;
            }
        } else if (hostPart.includes(':')) {
            const lastColon = hostPart.lastIndexOf(':');
            server = hostPart.slice(0, lastColon);
            port = parseInt(hostPart.slice(lastColon + 1)) || 80;
        } else {
            server = hostPart;
            port = 80;
        }

        if (searchParams) {
            if (!user && (searchParams.get('user') || searchParams.get('username'))) {
                user = searchParams.get('user') || searchParams.get('username');
            }
            if (!pass && (searchParams.get('pass') || searchParams.get('password'))) {
                pass = searchParams.get('pass') || searchParams.get('password');
            }
            if (!remark && searchParams.get('remark')) {
                remark = searchParams.get('remark');
            }
        }

        if (!server) return { error: 'Failed to parse HTTP URL: missing server' };

        return {
            protocol: 'http',
            server: server,
            port: port,
            user: user || undefined,
            pass: pass || undefined,
            remark: remark
        };
    } catch (e) {
        return { error: 'Failed to parse HTTP URL: ' + e.message };
    }
}

// ===== Display Helpers =====
// Coerce first: callers may pass through unknown JSON types (e.g. a numeric
// VMess "ps"), and String() is idempotent for strings.
function maskString(str) {
    str = String(str ?? '');
    if (!str || str.length <= 8) return str;
    return str.slice(0, 4) + '••••' + str.slice(-4);
}

function truncateStr(str, max) {
    str = String(str ?? '');
    if (!str || str.length <= max) return str;
    return str.slice(0, max) + '…';
}

// ===== Presets =====
// Fragment presets — switching only overwrites the textarea on explicit
// selector change, so manual edits are always preserved.
const FRAGMENT_PRESETS = {
    v1: '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}',
    v2: '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}'
};
// ECH presets (own tab) — selecting one overwrites the textarea, so
// anything typed by hand afterwards is preserved. 'none' only clears it.
// The textarea ships prefilled with the default (ech-1) preset value.
const ECH_PRESETS = {
    'ech-1': 'cloudflare-ech.com+udp://1.1.1.1',
    'ech-2': 'cloudflare-ech.com+udp://9.9.9.9',
    'ech-3': 'cloudflare-ech.com+udp://208.67.222.222',
    'ech-4': 'cloudflare-ech.com+udp://8.8.8.8',
    'ech-5': 'cloudflare-ech.com+udp://1.0.0.1',
    'ech-6': 'cloudflare-ech.com+udp://8.8.4.4',
    'ech-7': 'cloudflare-ech.com+udp://149.112.112.112',
    'ech-8': 'cloudflare-ech.com+udp://208.67.220.220',
    'ech-9': 'cloudflare-ech.com+udp://76.76.19.19',
    'ech-10': 'cloudflare-ech.com+udp://76.76.2.0',
    'ech-11': 'cloudflare-ech.com+udp://94.140.14.14',
    'ech-12': 'cloudflare-ech.com+udp://94.140.15.15',
    'ech-13': 'cloudflare-ech.com+udp://64.6.64.6',
    'ech-14': 'cloudflare-ech.com+udp://64.6.65.6',
    'ech-15': 'cloudflare-ech.com+udp://45.90.28.0',
    'ech-16': 'cloudflare-ech.com+udp://45.90.30.0',
    'ech-17': 'cloudflare-ech.com+udp://185.228.168.9',
    'ech-18': 'cloudflare-ech.com+udp://185.228.169.9'
};

// ===== Config Builders =====
// Moved verbatim from script.js (DOM-free): Xray + sing-box outbound builders.
// Shared via classic <script> global scope; Node tests import via module.exports.

    function buildStreamSettings(params, isChain) {
        const stream = {};
        // splithttp is the old name of xhttp; Xray emits xhttpSettings for both
        const netType = isXhttpNetwork(params.type) ? 'xhttp' : (params.type || 'tcp');

        // Network
        stream.network = netType;

        // Security
        const security = params.security || 'none';
        stream.security = security;

        // Sockopt
        if (isChain) {
            stream.sockopt = {
                domainStrategy: 'UseIPv4',
                dialerProxy: 'proxy'
            };
        } else {
            stream.sockopt = {
                domainStrategy: 'UseIP'
            };
        }

        // Transport settings — only add when there's actual content
        switch (netType) {
            case 'ws':
                stream.wsSettings = {};
                if (params.host) stream.wsSettings.host = params.host;
                if (params.path) stream.wsSettings.path = params.path;
                if (!params.host && !params.path) stream.wsSettings.path = '/';
                break;

            case 'grpc':
                stream.grpcSettings = {};
                if (params.authority) stream.grpcSettings.authority = params.authority;
                if (params.mode) stream.grpcSettings.multiMode = params.mode === 'multi';
                if (params.serviceName) stream.grpcSettings.serviceName = params.serviceName;
                break;

            case 'httpupgrade':
                stream.httpupgradeSettings = {};
                if (params.host) stream.httpupgradeSettings.host = params.host;
                stream.httpupgradeSettings.path = params.path || '/';
                break;

            case 'xhttp': {
                stream.xhttpSettings = {};
                if (params.host) stream.xhttpSettings.host = params.host;
                stream.xhttpSettings.path = params.path || '/';
                if (params.mode) stream.xhttpSettings.mode = params.mode;
                const extra = parseXhttpExtra(params.extra);
                if (extra) stream.xhttpSettings.extra = extra;
                break;
            }

            case 'tcp':
            case 'raw':
                // Only add rawSettings if headerType is 'http'
                if (params.headerType === 'http') {
                    stream.rawSettings = {
                        header: {
                            type: 'http',
                            request: {
                                headers: {},
                                path: params.path ? params.path.split(',') : ['/'],
                                method: 'GET',
                                version: '1.1'
                            }
                        }
                    };
                    if (params.host) {
                        stream.rawSettings.header.request.headers.Host = params.host.split(',');
                    }
                }
                // For plain TCP (headerType=none), no rawSettings needed
                break;
        }

        // TLS settings
        if (security === 'tls') {
            stream.tlsSettings = {
                serverName: params.sni || params.server,
                fingerprint: params.fp || 'chrome',
                alpn: params.alpn ? params.alpn.split(',').map(s => s.trim()).filter(Boolean) : ['http/1.1'],
                allowInsecure: !!params.allowInsecure
            };
            // ECH support
            if (params.ech) {
                stream.tlsSettings.echConfigList = params.ech;
            }
        } else if (security === 'reality') {
            stream.realitySettings = {
                serverName: params.sni || params.server,
                fingerprint: params.fp || 'chrome',
                publicKey: params.pbk || '',
                shortId: params.sid || '',
                spiderX: params.spx || '',
                show: false,
                allowInsecure: !!params.allowInsecure
            };
        }

        return stream;
    }

    function buildProxyOutbound(params) {
        const streamSettings = buildStreamSettings(params, false);
        const outbound = {
            protocol: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol,
            tag: 'proxy'
        };

        switch (params.protocol) {
            case 'vless':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            encryption: params.encryption || 'none'
                        }]
                    }]
                };
                if (params.flow) outbound.settings.vnext[0].users[0].flow = params.flow;
                break;

            case 'vmess':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            alterId: params.aid || 0,
                            security: 'auto'
                        }]
                    }]
                };
                break;

            case 'trojan':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        password: params.password
                    }]
                };
                break;

            case 'shadowsocks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        method: params.method,
                        password: params.password
                    }]
                };
                break;

            case 'socks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            case 'http':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            default:
                return null;
        }

        outbound.streamSettings = streamSettings;
        return outbound;
    }

    function buildChainOutbound(params) {
        const streamSettings = buildStreamSettings(params, true);
        const outbound = {
            protocol: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol,
            tag: 'chain'
        };

        switch (params.protocol) {
            case 'vless':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            encryption: params.encryption || 'none'
                        }]
                    }]
                };
                if (params.flow) outbound.settings.vnext[0].users[0].flow = params.flow;
                break;

            case 'vmess':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            alterId: params.aid || 0,
                            security: 'auto'
                        }]
                    }]
                };
                break;

            case 'trojan':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        password: params.password
                    }]
                };
                break;

            case 'shadowsocks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        method: params.method,
                        password: params.password
                    }]
                };
                break;

            case 'socks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            case 'http':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            default:
                return null;
        }

        outbound.streamSettings = streamSettings;
        return outbound;
    }

    function buildSingboxOutbound(params, tag, detourTag) {
        const outbound = {
            tag: tag,
            type: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol
        };

        // If this is a chain outbound, set detour
        if (detourTag) {
            outbound.detour = detourTag;
        }

        outbound.server = params.server;
        outbound.server_port = params.port;

        // Protocol-specific settings
        switch (params.protocol) {
            case 'vless':
                outbound.uuid = params.uuid;
                outbound.packet_encoding = '';
                outbound.network = 'tcp';
                if (params.flow) outbound.flow = params.flow;
                break;

            case 'vmess':
                outbound.uuid = params.uuid;
                outbound.security = 'auto';
                outbound.alter_id = params.aid || 0;
                outbound.network = 'tcp';
                break;

            case 'trojan':
                outbound.password = params.password;
                outbound.network = 'tcp';
                break;

            case 'shadowsocks':
                outbound.method = params.method;
                outbound.password = params.password;
                outbound.network = 'tcp';
                break;

            case 'socks':
                outbound.version = '5';
                outbound.network = 'tcp';
                // Auth credentials are only emitted when both username and
                // password are present, same as the Xray builder above.
                // A user-only credential would produce a broken outbound.
                if (params.user && params.pass) {
                    outbound.username = params.user;
                    outbound.password = params.pass;
                }
                break;

            case 'http':
                // Same rule as socks above: both username and password required.
                if (params.user && params.pass) {
                    outbound.username = params.user;
                    outbound.password = params.pass;
                }
                break;

            case 'ssh':
                outbound.type = 'ssh';
                outbound.user = params.user || 'root';
                outbound.password = params.password;
                // SSH has no TLS/transport, return early
                return outbound;

            default:
                return outbound;
        }

        // TLS settings
        const security = params.security || 'none';
        if (security === 'tls' || security === 'reality') {
            const tls = {
                enabled: true,
                server_name: params.sni || params.host || params.server
            };

            if (params.allowInsecure) tls.insecure = true;

            // ALPN
            if (params.alpn) {
                const alpnList = params.alpn.split(',').map(s => s.trim()).filter(Boolean);
                if (alpnList.length) tls.alpn = alpnList;
            }

            // uTLS fingerprint
            if (params.fp) {
                tls.utls = {
                    enabled: true,
                    fingerprint: params.fp
                };
            }

            // Reality
            if (security === 'reality' && params.pbk) {
                tls.reality = {
                    enabled: true,
                    public_key: params.pbk,
                    short_id: params.sid || ''
                };
            }

            // ECH — param format: "query_server_name+dns_server" e.g. "workers.dev+udp://8.8.8.8"
            if (params.ech) {
                const echQueryServer = getEchQueryServer(params.ech);
                tls.record_fragment = false;
                tls.ech = {
                    enabled: true,
                    query_server_name: echQueryServer || params.sni || params.server
                };
            }

            outbound.tls = tls;
        }

        // Transport settings
        const transportType = params.type || 'tcp';
        switch (transportType) {
            case 'ws': {
                const wsTransport = {
                    type: 'ws',
                    path: (params.path || '/').split('?ed=')[0],
                    headers: {}
                };
                if (params.host) wsTransport.headers.Host = params.host;

                // Early data from ?ed= in path
                const edMatch = (params.path || '').match(/[?&]ed=(\d+)/);
                if (edMatch) {
                    wsTransport.max_early_data = parseInt(edMatch[1]);
                    wsTransport.early_data_header_name = 'Sec-WebSocket-Protocol';
                }
                outbound.transport = wsTransport;
                break;
            }

            case 'grpc': {
                outbound.transport = {
                    type: 'grpc',
                    service_name: params.serviceName || ''
                };
                break;
            }

            case 'httpupgrade': {
                outbound.transport = {
                    type: 'httpupgrade',
                    host: params.host,
                    path: (params.path || '/').split('?ed=')[0]
                };
                break;
            }

            case 'xhttp':
            case 'splithttp': {
                // Upstream sing-box has no xhttp transport; forks that add it
                // use this shape, and upstream rejects it loudly instead of
                // silently dialing plain TCP.
                outbound.transport = {
                    type: 'xhttp',
                    path: params.path || '/'
                };
                if (params.host) outbound.transport.host = params.host;
                if (params.mode) outbound.transport.mode = params.mode;
                break;
            }

            case 'tcp': {
                if (params.headerType === 'http') {
                    outbound.transport = {
                        type: 'http',
                        host: params.host ? params.host.split(',') : undefined,
                        path: params.path || '/',
                        method: 'GET',
                        headers: {
                            'Connection': ['keep-alive'],
                            'Content-Type': ['application/octet-stream']
                        }
                    };
                }
                break;
            }

            case 'raw': {
                // raw = tcp without header in Sing-box
                break;
            }
        }

        // Enable TCP fast open if available
        if (params.tfo) outbound.tcp_fast_open = true;

        return outbound;
    }

// ===== Config Fixer (full Xray JSON, stock v2rayNG / any Xray core) =====
// Diagnoses and repairs a full Xray config. Unlike the Fragment tab (which
// targets PattNG: fp=unsafe + cs + finalmask), the fixer defaults to what a
// stock v2rayNG core understands: a browser uTLS fingerprint and the classic
// freedom-outbound fragment wired in through sockopt.dialerProxy.
const FIXER_FRAGMENT_TAG = 'fragment';
// Starting points only — the right values depend on the network, which is
// why the fixer can also emit one config per preset as a test pack.
const FIXER_FRAGMENT_PRESETS = {
    f1: { label: 'tlshello · 10-20 · 10-20', packets: 'tlshello', length: '10-20', interval: '10-20' },
    f2: { label: 'tlshello · 100-200 · 10-20', packets: 'tlshello', length: '100-200', interval: '10-20' },
    f3: { label: 'tlshello · 1-3 · 1-3', packets: 'tlshello', length: '1-3', interval: '1-3' },
    f4: { label: '1-3 · 1-5 · 1-2', packets: '1-3', length: '1-5', interval: '1-2' },
    f5: { label: '1-1 · 3-5 · 5-10', packets: '1-1', length: '3-5', interval: '5-10' }
};
const FIXER_DOMESTIC_DNS = ['178.22.122.100', '185.55.226.26'];
const FIXER_FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized', 'unsafe'];

function isIpAddress(host) {
    const h = String(host || '').replace(/^\[|\]$/g, '');
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
}

// Does an Xray DNS "domains" rule list (domain:/full:/keyword/regexp) match
// the host? geosite:/ext: entries cannot be evaluated here and return null.
function dnsDomainsMatch(domains, host) {
    let unknown = false;
    for (const d of domains || []) {
        const s = String(d);
        if (s.startsWith('domain:')) {
            const v = s.slice(7);
            if (host === v || host.endsWith('.' + v)) return true;
        } else if (s.startsWith('full:')) {
            if (host === s.slice(5)) return true;
        } else if (s.startsWith('regexp:')) {
            try { if (new RegExp(s.slice(7)).test(host)) return true; } catch { }
        } else if (s.startsWith('geosite:') || s.startsWith('ext:')) {
            unknown = true;
        } else if (s.startsWith('keyword:')) {
            if (host.includes(s.slice(8))) return true;
        } else if (s && host.includes(s)) {
            return true;
        }
    }
    return unknown ? null : false;
}

// Which outbound a DNS query from a given inbound tag / to a given address
// takes: the first rule matching the tag or the literal IP, otherwise the
// default (first) outbound. geoip:/geosite: rules cannot be evaluated here.
function routeForDnsQuery(cfg, tag, address) {
    const rules = (cfg.routing && Array.isArray(cfg.routing.rules)) ? cfg.routing.rules : [];
    const ip = String(address || '').replace(/^\w+:\/\//, '').replace(/:\d+$/, '');
    for (const r of rules) {
        if (!r) continue;
        if (tag && Array.isArray(r.inboundTag) && r.inboundTag.includes(tag)) return r.outboundTag || '';
        if (ip && Array.isArray(r.ip) && r.ip.includes(ip)) return r.outboundTag || '';
    }
    const first = cfg.outbounds.find(o => o);
    return first ? (first.tag || '') : '';
}

// How the proxy server's own domain gets resolved when sockopt asks the core
// to resolve it (UseIP*). A DNS server with its own tag is routed by that
// tag, not by the module tag. Returns { via, direct }.
function serverDnsPath(cfg, host) {
    const dns = cfg.dns || {};
    if (dns.hosts && Object.prototype.hasOwnProperty.call(dns.hosts, host)) return { via: 'dns.hosts', direct: true };
    const servers = Array.isArray(dns.servers) ? dns.servers : [];
    const moduleTag = dns.tag || '';
    const proxyTags = fullConfigProxyOutbounds(cfg).map(o => o.tag || '');
    const path = (addr, tag) => {
        if (/^(localhost|fakedns)$/i.test(addr)) return { via: addr, direct: true };
        return { via: addr, direct: !proxyTags.includes(routeForDnsQuery(cfg, tag, addr)) };
    };
    for (const s of servers) {
        if (s && typeof s === 'object' && Array.isArray(s.domains) && dnsDomainsMatch(s.domains, host) === true) {
            return path(String(s.address || ''), s.tag || moduleTag);
        }
    }
    const first = servers.find(s => typeof s === 'string' || (s && !Array.isArray(s.domains)));
    if (!first) return { via: 'system DNS', direct: true };
    if (typeof first === 'string') return path(first, moduleTag);
    return path(String(first.address || ''), first.tag || moduleTag);
}

function outboundHasClassicFragment(cfg, ob) {
    const ss = ob.streamSettings || {};
    const dp = ss.sockopt && ss.sockopt.dialerProxy;
    if (!dp) return false;
    const target = cfg.outbounds.find(o => o && o.tag === dp);
    return !!(target && target.protocol === 'freedom' && target.settings && target.settings.fragment);
}

function diagnoseFullConfig(raw) {
    const parsed = parseFullConfigJson(raw);
    if (parsed.error) return parsed;
    const items = [];
    const add = (level, code, msg) => items.push({ level, code, msg });
    parsed.configs.forEach((cfg, ci) => {
        const prefix = parsed.configs.length > 1 ? '#' + (ci + 1) + ' ' : '';
        const proxies = fullConfigProxyOutbounds(cfg);
        if (proxies.length === 0) {
            add('error', 'no-proxy', prefix + 'No VLESS / VMess / Trojan outbound found.');
            return;
        }
        proxies.forEach(ob => {
            const name = prefix + (ob.tag ? '"' + ob.tag + '"' : String(ob.protocol));
            const ss = ob.streamSettings || {};
            const security = ss.security || 'none';
            const network = ss.network || 'tcp';
            const sec = security === 'tls' ? (ss.tlsSettings || {}) : security === 'reality' ? (ss.realitySettings || {}) : null;
            const { server } = fullConfigOutboundServer(ob);
            const host = String(server || '');
            if (!sec) {
                add('warn', 'no-tls', name + ': no TLS — fragment and fingerprint have no effect; the connection is plain to DPI.');
            } else {
                const fp = sec.fingerprint || '';
                if (fp === 'unsafe') {
                    add('error', 'fp-unsafe', name + ': fingerprint "unsafe" sends Go\'s own TLS ClientHello instead of a browser one. It is meant for PattNG with custom cipher suites; on stock v2rayNG it is easy for DPI to spot. Use chrome.');
                } else if (!fp) {
                    add('info', 'fp-empty', name + ': no fingerprint set (the core defaults to chrome).');
                } else {
                    add('ok', 'fp', name + ': fingerprint ' + fp + '.');
                }
                if (security === 'tls' && !sec.serverName && isIpAddress(host)) {
                    add('error', 'no-sni', name + ': address is an IP but tlsSettings.serverName (SNI) is empty — the TLS handshake will fail on a CDN.');
                }
                if (sec.allowInsecure) {
                    add('warn', 'insecure', name + ': allowInsecure is on — certificate is not verified.');
                }
                const alpn = Array.isArray(sec.alpn) ? sec.alpn : [];
                if ((network === 'ws' || network === 'httpupgrade') && alpn.includes('h2')) {
                    add('info', 'alpn-h2', name + ': ALPN offers h2 on ' + network + '. Some CDN setups accept this (a known-good MCI config uses it); if the server rejects the handshake, try http/1.1.');
                }
                if (sec.cipherSuites && fp && fp !== 'unsafe') {
                    add('info', 'cs-ignored', name + ': cipherSuites is ignored while a uTLS fingerprint (' + fp + ') is set.');
                }
            }
            const hasClassic = outboundHasClassicFragment(cfg, ob);
            const dp = ss.sockopt && ss.sockopt.dialerProxy;
            if (dp && !cfg.outbounds.some(o => o && o.tag === dp)) {
                add('error', 'dialer-missing', name + ': sockopt.dialerProxy points to "' + dp + '", but no outbound has that tag.');
            }
            if (ss.finalmask) {
                add('info', 'finalmask', name + ': uses streamSettings.finalmask — needs Xray-core 26+ (PattNG / a recent v2rayNG). Older cores ignore it silently; the classic fragment works on every core.');
            }
            if (sec && !hasClassic && !ss.finalmask) {
                add('info', 'no-fragment', name + ': no TLS fragmentation — the SNI leaves in one packet. Fine for REALITY or a fronted CDN SNI; for a plain TLS SNI on a filtered network, fragmentation can help.');
            } else if (hasClassic) {
                add('ok', 'fragment', name + ': classic fragment via dialerProxy "' + dp + '".');
            }
            const ds = ss.sockopt && ss.sockopt.domainStrategy;
            if (host && !isIpAddress(host) && ds && /^Use/i.test(ds)) {
                const p = serverDnsPath(cfg, host);
                if (p && !p.direct) {
                    add('warn', 'dns-loop', name + ': the server domain ' + host + ' is resolved by ' + p.via + ', and that DNS traffic is routed through the proxy itself — a possible loop that can stop it from connecting. Enable "Resolve server domain directly".');
                } else if (p) {
                    add('ok', 'dns', name + ': server domain resolved directly via ' + p.via + '.');
                }
            }
            if (ob.mux && ob.mux.enabled && ob.settings && Array.isArray(ob.settings.vnext)
                && ob.settings.vnext.some(v => (v.users || []).some(u => u && u.flow))) {
                add('error', 'mux-flow', name + ': mux cannot be used together with flow (XTLS Vision).');
            }
        });
    });
    return { items };
}

function ensureServerDnsDirect(cfg, host) {
    const p = serverDnsPath(cfg, host);
    if (!p || p.direct) return false;
    cfg.dns = cfg.dns || {};
    cfg.dns.servers = Array.isArray(cfg.dns.servers) ? cfg.dns.servers : [];
    const tag = 'server-dns';
    // A domestic resolver, as in known-good MCI configs: 8.8.8.8 over plain
    // UDP is often blocked or poisoned on filtered networks.
    cfg.dns.servers.unshift({ address: FIXER_DOMESTIC_DNS[0], domains: ['full:' + host], skipFallback: true, tag });
    cfg.routing = cfg.routing || {};
    cfg.routing.rules = Array.isArray(cfg.routing.rules) ? cfg.routing.rules : [];
    const directTag = (cfg.outbounds.find(o => o && o.protocol === 'freedom' && o.tag !== FIXER_FRAGMENT_TAG) || {}).tag;
    if (!directTag) {
        cfg.outbounds.push({ protocol: 'freedom', settings: {}, tag: 'direct' });
    }
    cfg.routing.rules.unshift({ type: 'field', inboundTag: [tag], outboundTag: directTag || 'direct' });
    return true;
}

// opts: {
//   fp: 'keep' | fingerprint,
//   fragmentMode: 'classic' | 'finalmask' | 'none' | 'keep',
//   fragment: { packets, length, interval },   // classic mode
//   finalmask: JSON string,                     // finalmask mode
//   alpnFix: bool,            // force http/1.1 on ws/httpupgrade when h2 is listed
//   address: string,          // clean IP / host override (single proxy only)
//   dnsFix: bool,             // resolve the server domain outside the proxy
//   remarks: string           // replaces remarks when non-empty
// }
function fixFullConfigCore(raw, opts) {
    const parsed = parseFullConfigJson(raw);
    if (parsed.error) return parsed;
    const o = opts || {};
    const mode = o.fragmentMode || 'classic';
    let fm = null;
    if (mode === 'finalmask') {
        try {
            fm = JSON.parse(String(o.finalmask || ''));
        } catch (e) {
            return { error: 'Final Mask (fm) is not valid JSON: ' + e.message };
        }
        if (!fm || typeof fm !== 'object' || Array.isArray(fm)) {
            return { error: 'Final Mask (fm) must be a JSON object, e.g. {"tcp": [...]}' };
        }
    }
    const frag = o.fragment || {};
    if (mode === 'classic' && !String(frag.packets || '').trim()) {
        return { error: 'Fragment "packets" is empty — use tlshello or a range like 1-3' };
    }
    let targets = 0;
    parsed.configs.forEach(cfg => { targets += fullConfigProxyOutbounds(cfg).length; });
    if (targets === 0) return { error: 'No VLESS / VMess / Trojan outbound found in the config' };
    const address = targets === 1 ? String(o.address || '').trim() : '';
    const changes = [];
    const note = c => { if (!changes.includes(c)) changes.push(c); };

    parsed.configs.forEach(cfg => {
        const proxies = fullConfigProxyOutbounds(cfg);
        let usesClassic = false;
        proxies.forEach(ob => {
            const ss = ob.streamSettings || (ob.streamSettings = {});
            const security = ss.security || 'none';
            const network = ss.network || 'tcp';
            const secKey = security === 'tls' ? 'tlsSettings' : security === 'reality' ? 'realitySettings' : '';
            const s = ob.settings || (ob.settings = {});
            const entry = (Array.isArray(s.vnext) && s.vnext[0]) || (Array.isArray(s.servers) && s.servers[0]);
            const oldHost = entry ? String(entry.address || '') : '';

            if (secKey && o.fp && o.fp !== 'keep') {
                const sec = ss[secKey] || (ss[secKey] = {});
                if (sec.fingerprint !== o.fp) { sec.fingerprint = o.fp; note('fingerprint → ' + o.fp); }
                if (o.fp !== 'unsafe' && sec.cipherSuites) { delete sec.cipherSuites; note('removed cipherSuites (ignored with a uTLS fingerprint)'); }
            }
            if (secKey === 'tlsSettings' && o.alpnFix && (network === 'ws' || network === 'httpupgrade')) {
                const tls = ss.tlsSettings;
                if (Array.isArray(tls.alpn) && tls.alpn.includes('h2')) { tls.alpn = ['http/1.1']; note('ALPN → http/1.1'); }
            }
            if (address && entry && address !== oldHost) {
                // Keep SNI and Host pointing at the original domain so a CDN
                // still routes the request when the address becomes an IP.
                if (secKey === 'tlsSettings' && oldHost && !isIpAddress(oldHost)) {
                    const tls = ss.tlsSettings;
                    if (!tls.serverName) tls.serverName = oldHost;
                }
                if (network === 'ws' && oldHost && !isIpAddress(oldHost)) {
                    const ws = ss.wsSettings || (ss.wsSettings = {});
                    const hasHost = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host));
                    if (!hasHost) ws.host = oldHost;
                }
                if (network === 'httpupgrade' && oldHost && !isIpAddress(oldHost)) {
                    const hu = ss.httpupgradeSettings || (ss.httpupgradeSettings = {});
                    if (!hu.host) hu.host = oldHost;
                }
                entry.address = address;
                note('server address → ' + address + ' (SNI / Host kept)');
            }

            if (mode === 'classic' && secKey) {
                if (ss.finalmask) { delete ss.finalmask; note('removed finalmask'); }
                ss.sockopt = ss.sockopt || {};
                ss.sockopt.dialerProxy = FIXER_FRAGMENT_TAG;
                usesClassic = true;
            } else if (mode === 'finalmask' && secKey === 'tlsSettings') {
                ss.finalmask = JSON.parse(JSON.stringify(fm));
                if (ss.sockopt && ss.sockopt.dialerProxy === FIXER_FRAGMENT_TAG) delete ss.sockopt.dialerProxy;
                note('finalmask fragment set');
            } else if (mode === 'none') {
                if (ss.finalmask) { delete ss.finalmask; note('removed finalmask'); }
                if (ss.sockopt && ss.sockopt.dialerProxy === FIXER_FRAGMENT_TAG) { delete ss.sockopt.dialerProxy; note('removed fragment'); }
            }

            const host = entry ? String(entry.address || '') : '';
            const ds = ss.sockopt && ss.sockopt.domainStrategy;
            if (o.dnsFix && host && !isIpAddress(host) && ds && /^Use/i.test(ds)) {
                if (ensureServerDnsDirect(cfg, host)) note('server domain now resolved directly (no DNS loop)');
            }
        });

        // The fragment outbound: (re)written when used, dropped when not.
        const idx = cfg.outbounds.findIndex(x => x && x.tag === FIXER_FRAGMENT_TAG);
        if (usesClassic) {
            const fragOb = {
                protocol: 'freedom',
                settings: {
                    domainStrategy: 'AsIs',
                    fragment: {
                        packets: String(frag.packets).trim(),
                        length: String(frag.length || '').trim(),
                        interval: String(frag.interval || '').trim()
                    }
                },
                streamSettings: { sockopt: { tcpNoDelay: true } },
                tag: FIXER_FRAGMENT_TAG
            };
            if (idx >= 0) cfg.outbounds[idx] = fragOb; else cfg.outbounds.push(fragOb);
            note('classic fragment ' + fragOb.settings.fragment.packets + ' / ' + fragOb.settings.fragment.length + ' / ' + fragOb.settings.fragment.interval + ' via dialerProxy');
        } else if (idx >= 0 && mode !== 'keep') {
            const stillUsed = cfg.outbounds.some(x => x && x.streamSettings && x.streamSettings.sockopt && x.streamSettings.sockopt.dialerProxy === FIXER_FRAGMENT_TAG);
            if (!stillUsed) cfg.outbounds.splice(idx, 1);
        }
        if (o.remarks && String(o.remarks).trim()) cfg.remarks = String(o.remarks).trim();
    });

    const out = parsed.isArray ? parsed.configs : parsed.configs[0];
    return { json: JSON.stringify(out, null, 2), config: out, changes };
}

// One config per fragment preset (plus a no-fragment control), each with its
// own remarks, so the working settings can be found by testing on the phone.
function buildFixTestPack(raw, opts, presetKeys) {
    const base = parseFullConfigJson(raw);
    if (base.error) return base;
    if (base.isArray) return { error: 'The test pack needs a single config, not an array' };
    const baseRemarks = (opts && opts.remarks) || base.configs[0].remarks || 'config';
    const keys = (presetKeys && presetKeys.length) ? presetKeys : Object.keys(FIXER_FRAGMENT_PRESETS);
    const list = [];
    for (const k of keys) {
        const p = FIXER_FRAGMENT_PRESETS[k];
        if (!p) continue;
        const r = fixFullConfigCore(raw, Object.assign({}, opts, {
            fragmentMode: 'classic',
            fragment: p,
            remarks: baseRemarks + ' | ' + p.label
        }));
        if (r.error) return r;
        list.push(r.config);
    }
    const ctl = fixFullConfigCore(raw, Object.assign({}, opts, { fragmentMode: 'none', remarks: baseRemarks + ' | no fragment' }));
    if (ctl.error) return ctl;
    list.push(ctl.config);
    return { json: JSON.stringify(list, null, 2), configs: list };
}

// A share link (vless / vmess / trojan) → a full config in the shape
// v2rayNG exports, so it can go through the same fixer.
function linkToFullConfig(link) {
    const p = parseProxyURLSingle(String(link || '').trim());
    if (!p || p.error) return { error: (p && p.error) || 'Not a proxy link' };
    if (!FULL_CONFIG_PROTOCOLS.includes(p.protocol)) return { error: 'Only VLESS / VMess / Trojan links can be turned into a full config' };
    const proxy = buildProxyOutbound(p);
    proxy.streamSettings = proxy.streamSettings || {};
    proxy.streamSettings.sockopt = { domainStrategy: 'UseIPv4' };
    const cfg = {
        dns: {
            servers: [
                '1.1.1.1',
                { address: '223.5.5.5', domains: ['geosite:private', 'domain:ir', 'geosite:category-ir'], skipFallback: true, tag: 'domestic-dns0' }
            ],
            tag: 'dns-module'
        },
        inbounds: [{
            listen: '127.0.0.1', port: 10808, protocol: 'socks',
            settings: { auth: 'noauth', udp: true, userLevel: 8 },
            sniffing: { destOverride: ['http', 'tls'], enabled: true, routeOnly: true },
            tag: 'socks'
        }],
        log: { loglevel: 'warning' },
        outbounds: [
            proxy,
            { protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' }, tag: 'direct' },
            { protocol: 'blackhole', settings: { response: { type: 'http' } }, tag: 'block' }
        ],
        remarks: p.remark || (p.protocol.toUpperCase() + ' ' + p.server),
        routing: {
            domainStrategy: 'IPIfNonMatch',
            rules: [
                { network: 'udp', outboundTag: 'block', port: '443', type: 'field' },
                { domain: ['geosite:private'], outboundTag: 'direct', type: 'field' },
                { domain: ['domain:ir', 'geosite:category-ir'], outboundTag: 'direct', type: 'field' },
                { ip: ['geoip:private', 'geoip:ir'], outboundTag: 'direct', type: 'field' },
                { inboundTag: ['domestic-dns0'], outboundTag: 'direct', type: 'field' },
                { inboundTag: ['dns-module'], outboundTag: 'proxy', type: 'field' }
            ]
        }
    };
    return { json: JSON.stringify(cfg, null, 2), config: cfg };
}

// ===== Working-config templates (Templates tab) =====
// Two client-side layouts taken from configs that connect on MCI. They keep
// the user's own server (address / id / transport) and rebuild everything
// around it. Neither changes the server side: template A suits REALITY or a
// plain TLS server, template B a TLS server reachable through a CDN.
const TEMPLATE_A_FRAGMENT = { packets: '1-3', length: '50-100', delay: '10-20', maxSplit: '10' };
const TEMPLATE_B_FINGERPRINTS = ['chrome', 'chrome', 'chrome', 'edge'];
const TEMPLATE_IR_DOMAINS = ['domain:ir', 'domain:xn--mgba3a4f16a', 'geosite:category-ir'];

function cloneJson(v) { return JSON.parse(JSON.stringify(v)); }

// Accepts a full JSON config or a share link; returns the first
// VLESS / VMess / Trojan outbound plus the source config.
function templateSourceOutbound(raw) {
    let text = String(raw || '').trim();
    if (!looksLikeJsonConfig(text)) {
        const conv = linkToFullConfig(text.split(/\r?\n/)[0]);
        if (conv.error) return conv;
        text = conv.json;
    }
    const parsed = parseFullConfigJson(text);
    if (parsed.error) return parsed;
    const cfg = parsed.configs[0];
    const ob = fullConfigProxyOutbounds(cfg)[0];
    if (!ob) return { error: 'No VLESS / VMess / Trojan outbound found in the config' };
    const copy = cloneJson(ob);
    copy.streamSettings = copy.streamSettings || {};
    const s = copy.settings || (copy.settings = {});
    const entry = (Array.isArray(s.vnext) && s.vnext[0]) || (Array.isArray(s.servers) && s.servers[0]);
    if (!entry) return { error: 'The proxy outbound has no server address' };
    return { cfg, ob: copy, entry, remarks: cfg.remarks || '' };
}

function templateCommon(remarks) {
    return {
        log: { loglevel: 'warning' },
        inbounds: [{
            listen: '127.0.0.1', port: 10808, protocol: 'socks',
            settings: { auth: 'noauth', udp: true, userLevel: 8 },
            sniffing: { destOverride: ['http', 'tls', 'quic'], enabled: true, routeOnly: true },
            tag: 'socks'
        }],
        policy: {
            levels: { 8: { connIdle: 300, downlinkOnly: 1, handshake: 4, uplinkOnly: 1 } },
            system: { statsOutboundUplink: true, statsOutboundDownlink: true }
        },
        remarks: remarks,
        stats: {}
    };
}

function templateSecKey(ss) {
    return ss.security === 'tls' ? 'tlsSettings' : ss.security === 'reality' ? 'realitySettings' : '';
}

// Template A — one proxy, finalmask fragment (+ UDP noise), server domain
// pinned in dns.hosts or resolved by a direct domestic DNS (no DNS loop).
// opts: { fp, fragment: {packets,length,delay,maxSplit} | null, noise, pinIp, remarks }
function buildTemplateA(raw, opts) {
    const src = templateSourceOutbound(raw);
    if (src.error) return src;
    const o = opts || {};
    const ob = src.ob;
    const ss = ob.streamSettings;
    const secKey = templateSecKey(ss);
    const notes = [];
    ob.tag = 'proxy';
    if (secKey && o.fp && o.fp !== 'keep') ss[secKey].fingerprint = o.fp;
    if (secKey === 'tlsSettings' && ss.tlsSettings.fingerprint !== 'unsafe') delete ss.tlsSettings.cipherSuites;
    delete ss.finalmask;
    const fm = {};
    if (o.fragment && secKey) {
        const f = o.fragment;
        if (!String(f.packets || '').trim()) return { error: 'Fragment "packets" is empty — use tlshello or a range like 1-3' };
        const settings = { packets: String(f.packets).trim(), length: String(f.length || '').trim(), delay: String(f.delay || '').trim() };
        if (String(f.maxSplit || '').trim()) settings.maxSplit = String(f.maxSplit).trim();
        fm.tcp = [{ type: 'fragment', settings }];
    }
    if (o.noise) fm.udp = [{ type: 'noise', settings: { noise: [{ rand: '10-20', delay: '10-16' }] } }];
    if (fm.tcp || fm.udp) { ss.finalmask = fm; notes.push('finalmask needs Xray-core 26+ (PattNG / a recent v2rayNG)'); }
    const sock = Object.assign({}, ss.sockopt || {});
    if (sock.dialerProxy === FIXER_FRAGMENT_TAG) delete sock.dialerProxy;
    sock.domainStrategy = 'UseIP';
    sock.happyEyeballs = { interleave: 2, maxConcurrentTry: 4, prioritizeIPv6: false, tryDelayMs: 250 };
    ss.sockopt = sock;

    const host = String(src.entry.address || '');
    const hosts = {
        'domain:googleapis.cn': 'googleapis.com',
        'dns.google': ['8.8.8.8', '8.8.4.4'],
        'one.one.one.one': ['1.1.1.1', '1.0.0.1']
    };
    const irDomains = ['domain:ir', 'geosite:category-ir'];
    const pin = String(o.pinIp || '').trim();
    if (host && !isIpAddress(host)) {
        if (pin) {
            if (!isIpAddress(pin)) return { error: 'Server IP to pin must be an IP address' };
            hosts[host] = pin;
            notes.push(host + ' pinned to ' + pin + ' (no DNS lookup for the server)');
        } else if (dnsDomainsMatch(['domain:ir'], host) !== true) {
            irDomains.unshift('full:' + host);
            notes.push(host + ' resolved by the direct domestic DNS');
        } else {
            notes.push(host + ' resolved by the direct domestic DNS (.ir)');
        }
    }
    const cfg = templateCommon(o.remarks || src.remarks || 'Template A');
    cfg.dns = {
        hosts,
        servers: [
            '1.1.1.1',
            { address: '223.5.5.5', domains: ['geosite:private'], skipFallback: true, tag: 'domestic-dns_0_0' },
            { address: '223.5.5.5', domains: irDomains, skipFallback: true, tag: 'domestic-dns_1_0' }
        ],
        tag: 'dns-module'
    };
    cfg.outbounds = [
        ob,
        { protocol: 'freedom', streamSettings: { network: 'tcp', sockopt: { domainStrategy: 'UseIP' } }, tag: 'direct' },
        { protocol: 'blackhole', settings: { response: { type: 'http' } }, tag: 'block' }
    ];
    cfg.routing = {
        domainStrategy: 'IPIfNonMatch',
        rules: [
            { network: 'udp', outboundTag: 'block', port: '443', type: 'field' },
            { ip: ['geoip:private'], outboundTag: 'direct', type: 'field' },
            { domain: ['geosite:private'], outboundTag: 'direct', type: 'field' },
            { domain: ['domain:ir', 'geosite:category-ir'], outboundTag: 'direct', type: 'field' },
            { ip: ['geoip:ir'], outboundTag: 'direct', type: 'field' },
            { inboundTag: ['domestic-dns_0_0', 'domestic-dns_1_0'], outboundTag: 'direct', type: 'field' },
            { inboundTag: ['dns-module'], outboundTag: 'proxy', type: 'field' }
        ]
    };
    if (!secKey) notes.push('no TLS / REALITY on this server — fragment and fingerprint cannot apply');
    return { json: JSON.stringify(cfg, null, 2), config: cfg, notes };
}

// Template B — the same TLS server reached through several addresses (CDN
// edges / clean IPs / other domains), each a balancer member with its own
// fingerprint; leastLoad picks the fastest, burstObservatory keeps testing.
// Server addresses are resolved by the system (no sockopt domainStrategy),
// so the proxy never waits on its own DNS.
// opts: { addresses: [..], sni, host, alpn: 'keep'|'h2'|'http/1.1', remarks }
function buildTemplateB(raw, opts) {
    const src = templateSourceOutbound(raw);
    if (src.error) return src;
    const o = opts || {};
    const base = src.ob;
    const ss = base.streamSettings;
    if (ss.security !== 'tls') return { error: 'Template B needs a TLS server (ws / grpc / httpupgrade / xhttp behind a CDN). Use template A for REALITY.' };
    const origHost = String(src.entry.address || '');
    let addresses = (Array.isArray(o.addresses) ? o.addresses : String(o.addresses || '').split(/[\s,]+/))
        .map(a => String(a).trim()).filter(Boolean);
    if (addresses.length === 0) addresses = [origHost];
    addresses = addresses.filter((a, i) => addresses.indexOf(a) === i).slice(0, 16);
    const tls = ss.tlsSettings || (ss.tlsSettings = {});
    const sni = String(o.sni || '').trim() || tls.serverName || (isIpAddress(origHost) ? '' : origHost);
    if (!sni) return { error: 'The server has no SNI (serverName) and its address is an IP — enter the SNI' };
    const net = ss.network || 'tcp';
    const hostOverride = String(o.host || '').trim();
    const notes = [];
    const members = addresses.map((addr, i) => {
        const ob = cloneJson(base);
        const s = ob.streamSettings;
        const e = (ob.settings.vnext || ob.settings.servers)[0];
        e.address = addr;
        ob.tag = 'lb-' + i;
        s.tlsSettings.serverName = sni;
        s.tlsSettings.fingerprint = TEMPLATE_B_FINGERPRINTS[i % TEMPLATE_B_FINGERPRINTS.length];
        delete s.tlsSettings.cipherSuites;
        if (o.alpn && o.alpn !== 'keep') s.tlsSettings.alpn = [o.alpn];
        if (net === 'ws') {
            const ws = s.wsSettings || (s.wsSettings = {});
            const current = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host)) || '';
            const h = hostOverride || current || sni;
            if (ws.headers) { delete ws.headers.Host; delete ws.headers.host; if (!Object.keys(ws.headers).length) delete ws.headers; }
            ws.host = h;
        } else if (net === 'httpupgrade') {
            const hu = s.httpupgradeSettings || (s.httpupgradeSettings = {});
            hu.host = hostOverride || hu.host || sni;
        } else if (net === 'xhttp' || net === 'splithttp') {
            const xs = s.xhttpSettings || s.splithttpSettings || (s.xhttpSettings = {});
            xs.host = hostOverride || xs.host || sni;
        }
        delete s.finalmask;
        if (s.sockopt) {
            delete s.sockopt.domainStrategy;
            if (s.sockopt.dialerProxy === FIXER_FRAGMENT_TAG) delete s.sockopt.dialerProxy;
            if (!Object.keys(s.sockopt).length) delete s.sockopt;
        }
        return ob;
    });
    const fallback = cloneJson(members[0]);
    fallback.tag = 'fallback';
    fallback.streamSettings.tlsSettings.fingerprint = 'ios';

    const cfg = templateCommon(o.remarks || src.remarks || 'Template B');
    cfg.dns = {
        tag: 'dns',
        queryStrategy: 'UseIPv4',
        servers: [
            { address: FIXER_DOMESTIC_DNS[0], domains: TEMPLATE_IR_DOMAINS.slice(), expectIPs: ['geoip:ir'], skipFallback: true, tag: 'domestic-dns' },
            { address: FIXER_DOMESTIC_DNS[1], domains: TEMPLATE_IR_DOMAINS.slice(), skipFallback: true, tag: 'domestic-dns-2' },
            '1.1.1.1',
            '8.8.8.8'
        ]
    };
    cfg.outbounds = members.concat([
        fallback,
        { tag: 'direct', protocol: 'freedom', streamSettings: { sockopt: { domainStrategy: 'UseIP' } } },
        { tag: 'block', protocol: 'blackhole' },
        { tag: 'dns-out', protocol: 'dns' }
    ]);
    cfg.routing = {
        domainStrategy: 'IPIfNonMatch',
        rules: [
            { type: 'field', inboundTag: ['domestic-dns', 'domestic-dns-2'], outboundTag: 'direct' },
            { type: 'field', inboundTag: ['dns'], balancerTag: 'auto' },
            { type: 'field', port: '53', outboundTag: 'dns-out' },
            { type: 'field', network: 'udp', port: '443', outboundTag: 'block' },
            { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
            { type: 'field', domain: ['geosite:private'], outboundTag: 'direct' },
            { type: 'field', ip: ['geoip:ir'], outboundTag: 'direct' },
            { type: 'field', domain: TEMPLATE_IR_DOMAINS.slice(), outboundTag: 'direct' },
            { type: 'field', port: '0-65535', balancerTag: 'auto' }
        ],
        balancers: [{
            tag: 'auto',
            selector: ['lb-'],
            strategy: { type: 'leastLoad', settings: { expected: Math.min(4, members.length) } },
            fallbackTag: 'fallback'
        }]
    };
    cfg.burstObservatory = {
        subjectSelector: ['lb-'],
        pingConfig: {
            destination: 'http://www.gstatic.com/generate_204',
            interval: '1m', sampling: 2, timeout: '8s', httpMethod: 'GET',
            connectivity: 'https://snapp.ir'
        }
    };
    notes.push(members.length + ' balancer member(s) · SNI ' + sni);
    if (members.length === 1) notes.push('add more CDN addresses / clean IPs to get real load balancing');
    return { json: JSON.stringify(cfg, null, 2), config: cfg, notes };
}

// What a (known-good) config does, in plain words — used to compare a
// working config with a failing one.
function describeConfigTechniques(raw) {
    const parsed = parseFullConfigJson(raw);
    if (parsed.error) return parsed;
    const cfg = parsed.configs[0];
    const out = [];
    const proxies = fullConfigProxyOutbounds(cfg);
    proxies.forEach(ob => {
        const ss = ob.streamSettings || {};
        const { server } = fullConfigOutboundServer(ob);
        const host = String(server || '');
        const name = (ob.tag || ob.protocol) + ': ';
        const sec = ss.security === 'tls' ? ss.tlsSettings || {} : ss.security === 'reality' ? ss.realitySettings || {} : null;
        const net = ss.network || 'tcp';
        let line = name + ob.protocol + ' · ' + net + ' · ' + (ss.security || 'none') + ' · ' + host;
        if (sec) line += ' · SNI ' + (sec.serverName || '—') + ' · fp ' + (sec.fingerprint || '—');
        if (sec && Array.isArray(sec.alpn)) line += ' · ALPN ' + sec.alpn.join(',');
        out.push(line);
        if (ss.security === 'reality') out.push(name + 'REALITY — borrows the TLS identity of ' + (sec.serverName || 'a big site') + '; no certificate or CDN needed');
        if (ss.security === 'tls' && sec.serverName && host && sec.serverName !== host && !isIpAddress(host)) out.push(name + 'SNI differs from the address (domain fronting through a CDN)');
        const ws = ss.wsSettings || {};
        const wsHost = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host));
        if (net === 'ws' && wsHost && sec && wsHost !== sec.serverName) out.push(name + 'ws Host "' + wsHost + '" differs from the SNI (CDN routes on Host)');
        if (ss.finalmask) out.push(name + 'finalmask ' + Object.keys(ss.finalmask).join(' + ') + ' (Xray-core 26+)');
        if (outboundHasClassicFragment(cfg, ob)) out.push(name + 'classic fragment via dialerProxy');
        const ds = ss.sockopt && ss.sockopt.domainStrategy;
        if (!ds && !isIpAddress(host)) out.push(name + 'no sockopt.domainStrategy — server address resolved by the system, not the core');
        if (cfg.dns && cfg.dns.hosts && host && cfg.dns.hosts[host]) out.push(name + 'server domain pinned in dns.hosts → ' + [].concat(cfg.dns.hosts[host]).join(', '));
    });
    const servers = (cfg.dns && Array.isArray(cfg.dns.servers)) ? cfg.dns.servers : [];
    const tagged = servers.filter(s => s && typeof s === 'object' && s.tag);
    const directTagged = tagged.filter(s => !proxies.map(p => p.tag).includes(routeForDnsQuery(cfg, s.tag, s.address)));
    const directAddrs = directTagged.map(s => String(s.address)).filter((a, i, arr) => arr.indexOf(a) === i);
    if (directAddrs.length) out.push('domestic DNS ' + directAddrs.join(', ') + ' routed direct');
    const bal = cfg.routing && Array.isArray(cfg.routing.balancers) ? cfg.routing.balancers : [];
    bal.forEach(b => out.push('balancer "' + b.tag + '" (' + ((b.strategy && b.strategy.type) || 'random') + ') over ' + (b.selector || []).join(', ') + (b.fallbackTag ? ', fallback ' + b.fallbackTag : '')));
    if (cfg.burstObservatory || cfg.observatory) out.push('observatory keeps health-checking the members');
    return { items: out };
}

// Node test harness: browsers ignore this block (`module` is undefined there).
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        safeAtob, encodeUtf8ToB64, safeDecode, extractLines,
        isXhttpNetwork, parseXhttpExtra,
        getEchQueryServer, ECH_DNS_DEFAULT, isBareEchDomain, normalizeEchInput,
        ECH_PRESETS, FRAGMENT_PRESETS, SUB_SCHEME,
        enhanceUrlCore, enhanceEchUrlCore,
        looksLikeJsonConfig, parseFullConfigJson, summarizeFullConfig, enhanceFullConfigCore,
        FIXER_FRAGMENT_PRESETS, FIXER_FINGERPRINTS, FIXER_FRAGMENT_TAG, isIpAddress, dnsDomainsMatch,
        diagnoseFullConfig, fixFullConfigCore, buildFixTestPack, linkToFullConfig,
        FIXER_DOMESTIC_DNS, TEMPLATE_A_FRAGMENT, buildTemplateA, buildTemplateB, describeConfigTechniques,
        parseProxyURLSingle, parseProxyURL, parseVless, parseVmess, parseTrojan, parseShadowsocks, parseSocks, parseHttp,
        buildStreamSettings, buildProxyOutbound, buildChainOutbound, buildSingboxOutbound,
        maskString, truncateStr,
        subIsLink, subLooksLikeContent, subLooksLikeProxy, subValidate,
        SUB_IDLE_MS, SUB_TOTAL_MS, SUB_TOO_LARGE_MSG,
        extractSubConfigs, subIsBlockedError, subErrorText
    };
}
