import { connect } from "cloudflare:sockets";

const WS_OPEN = 1;
const MAX_HEADER_BYTES = 1024 * 16;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const password = normalizePassword(env.PASSWORD);
    const runtime = buildRuntime(request, env, password);

    if (url.pathname === "/") {
      return htmlResponse(renderLandingPage(runtime), false);
    }

    if (url.pathname === "/healthz") {
      return jsonResponse({
        status: password ? "ok" : "setup_required",
        relay: Boolean(password),
        proxy: Boolean(runtime.proxy),
        forceProxy: runtime.forceProxy,
        runtime: "cloudflare-workers",
      });
    }

    if (password) {
      const basePath = `/${password}`;
      if (url.pathname === basePath) {
        const shareUri = buildShareUri(runtime, password);
        return htmlResponse(renderDashboardPage(runtime, password, shareUri), true);
      }

      if (url.pathname === `${basePath}/uri`) {
        return textResponse(buildShareUri(runtime, password));
      }

      if (url.pathname === `${basePath}/clash`) {
        return textResponse(buildClashConfig(runtime, password), "application/yaml;charset=utf-8", "edgeferry-clash.yaml");
      }

      if (url.pathname === `${basePath}/singbox`) {
        return jsonResponse(buildSingBoxConfig(runtime, password));
      }

      if (url.pathname === `${basePath}/json`) {
        return jsonResponse({
          name: runtime.siteName,
          endpoint: runtime.endpointHost,
          port: runtime.endpointPort,
          host: runtime.hostHeader,
          tls: runtime.tls,
          path: runtime.path,
          proxyConfigured: Boolean(runtime.proxy),
          forceProxy: runtime.forceProxy,
        });
      }
    }

    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
      if (!password) {
        return textResponse("PASSWORD secret is not configured", "text/plain;charset=utf-8", null, 503);
      }
      return handleWebSocket(request, env, password, url);
    }

    return htmlResponse(renderNotFoundPage(runtime), false, 404);
  },
};

function normalizePassword(value) {
  const password = String(value || "").trim();
  return /^[A-Za-z0-9._-]{6,64}$/.test(password) ? password : "";
}

function buildRuntime(request, env, password) {
  const url = new URL(request.url);
  const requestHost = url.hostname;
  const endpointHost = normalizeHost(env.ENDPOINT_HOST) || requestHost;
  const endpointPort = toPort(env.ENDPOINT_PORT, 443);
  const tls = String(env.TLS || "true").toLowerCase() !== "false";
  const proxy = parseEndpoint(env.PROXY_IP, env.PROXY_PORT || "443");

  return {
    siteName: cleanLabel(env.SITE_NAME, "EdgeFerry"),
    hostHeader: normalizeHost(env.SNI) || requestHost,
    endpointHost,
    endpointPort,
    tls,
    path: normalizePath(env.WS_PATH),
    proxy,
    forceProxy: parseBoolean(env.FORCE_PROXY),
    passwordConfigured: Boolean(password),
  };
}

function normalizeHost(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw.includes("://") ? raw : `https://${raw}`);
    return parsed.hostname;
  } catch {
    return "";
  }
}

function normalizePath(value) {
  const path = String(value || "/?ed=2048").trim();
  return path.startsWith("/") ? path : "/?ed=2048";
}

function cleanLabel(value, fallback) {
  const label = String(value || "").replace(/[<>]/g, "").trim();
  return (label || fallback).slice(0, 48);
}

function toPort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : fallback;
}

function parseBoolean(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").toLowerCase());
}

function parseEndpoint(value, fallbackPort) {
  const raw = String(value || "").trim();
  if (!raw) return null;

  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    if (end < 0) return null;
    const hostname = raw.slice(1, end);
    const port = raw.slice(end + 1).replace(/^:/, "") || fallbackPort;
    return hostname ? { hostname, port: toPort(port, 443) } : null;
  }

  const match = raw.match(/^(.+):(\d{1,5})$/);
  if (match && !match[1].includes(":")) {
    return { hostname: match[1], port: toPort(match[2], 443) };
  }

  return { hostname: raw, port: toPort(fallbackPort, 443) };
}

function buildShareUri(runtime, password) {
  const params = new URLSearchParams();
  params.set("security", runtime.tls ? "tls" : "none");
  if (runtime.tls) params.set("sni", runtime.hostHeader);
  params.set("type", "ws");
  params.set("host", runtime.hostHeader);
  params.set("path", runtime.path);

  const user = encodeURIComponent(password);
  const label = encodeURIComponent(runtime.siteName);
  return `trojan://${user}@${runtime.endpointHost}:${runtime.endpointPort}?${params.toString()}#${label}`;
}

function buildClashConfig(runtime, password) {
  const name = yamlString(runtime.siteName);
  return [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "proxies:",
    `  - name: ${name}`,
    "    type: trojan",
    `    server: ${yamlString(runtime.endpointHost)}`,
    `    port: ${runtime.endpointPort}`,
    `    password: ${yamlString(password)}`,
    "    udp: true",
    "    network: ws",
    `    tls: ${runtime.tls}`,
    `    sni: ${yamlString(runtime.hostHeader)}`,
    "    ws-opts:",
    `      path: ${yamlString(runtime.path)}`,
    "      headers:",
    `        Host: ${yamlString(runtime.hostHeader)}`,
    "proxy-groups:",
    "  - name: PROXY",
    "    type: select",
    "    proxies:",
    `      - ${name}`,
    "rules:",
    "  - MATCH,PROXY",
    "",
  ].join("\n");
}

function buildSingBoxConfig(runtime, password) {
  return {
    log: { level: "info" },
    outbounds: [
      {
        type: "trojan",
        tag: runtime.siteName,
        server: runtime.endpointHost,
        server_port: runtime.endpointPort,
        password,
        tls: {
          enabled: runtime.tls,
          server_name: runtime.hostHeader,
        },
        transport: {
          type: "ws",
          path: runtime.path,
          headers: { Host: runtime.hostHeader },
        },
      },
      { type: "direct", tag: "direct" },
    ],
    route: { final: runtime.siteName },
  };
}

function yamlString(value) {
  return JSON.stringify(String(value));
}

async function handleWebSocket(request, env, password, url) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  const override = readProxyOverride(url);
  const runtime = buildRuntime(request, env, password);
  const proxy = override || runtime.proxy;
  const expectedPassword = sha224Hex(password);

  let headerBuffer = new Uint8Array(0);
  let state = null;
  let closed = false;
  let queue = Promise.resolve();

  const close = (code = 1000, reason = "closed") => {
    if (closed) return;
    closed = true;
    safeClose(server, code, reason);
  };

  async function open(endpoint, parsed, isProxy) {
    let socket;
    try {
      socket = connect({ hostname: endpoint.hostname, port: endpoint.port });
      const writer = socket.writable.getWriter();
      state = { socket, writer, endpoint, isProxy };
      await writer.write(parsed.payload);
      monitorSocket(socket, parsed.payload);
    } catch (error) {
      console.warn("edgeferry upstream connect failed", safeError(error));
      if (!isProxy && proxy) {
        await open(proxy, parsed, true);
        return;
      }
      close(1011, "upstream unavailable");
    }
  }

  async function monitorSocket(socket, payload) {
    const reader = socket.readable.getReader();
    let received = false;
    try {
      while (!closed) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        received = true;
        if (server.readyState === WS_OPEN) server.send(value);
      }
    } catch (error) {
      console.warn("edgeferry upstream read failed", safeError(error));
    } finally {
      try { reader.releaseLock(); } catch {}
    }

    if (!received && !closed && !state?.isProxy && proxy) {
      await open(proxy, { payload }, true);
      return;
    }
    close(1000, "upstream closed");
  }

  async function processChunk(raw) {
    if (closed) return;
    const bytes = toBytes(raw);
    if (!bytes.byteLength) return;

    if (state) {
      await state.writer.write(bytes);
      return;
    }

    headerBuffer = concatBytes(headerBuffer, bytes);
    if (headerBuffer.byteLength > MAX_HEADER_BYTES) {
      close(1009, "header too large");
      return;
    }

    const parsed = parseTrojanHeader(headerBuffer, expectedPassword);
    if (parsed.needMore) return;
    if (parsed.error) {
      console.warn("edgeferry protocol rejected", parsed.error);
      close(1008, parsed.error);
      return;
    }

    state = { connecting: true };
    if (runtime.forceProxy && proxy) {
      await open(proxy, parsed, true);
    } else {
      await open({ hostname: parsed.address, port: parsed.port }, parsed, false);
    }
  }

  server.addEventListener("message", (event) => {
    queue = queue
      .then(() => processChunk(event.data))
      .catch((error) => {
        console.warn("edgeferry websocket processing failed", safeError(error));
        close(1011, "processing failed");
      });
  });

  server.addEventListener("close", () => close(1000, "client closed"));
  server.addEventListener("error", () => close(1011, "websocket error"));

  const earlyData = decodeEarlyData(request.headers.get("sec-websocket-protocol"));
  if (earlyData?.byteLength) queue = queue.then(() => processChunk(earlyData));

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

function readProxyOverride(url) {
  const marker = "/pyip=";
  const index = url.pathname.indexOf(marker);
  if (index < 0) return null;
  try {
    return parseEndpoint(decodeURIComponent(url.pathname.slice(index + marker.length)), "443");
  } catch {
    return null;
  }
}

function decodeEarlyData(header) {
  if (!header) return null;
  const token = header.split(",")[0].trim();
  if (!token) return null;
  try {
    const base64 = token.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function parseTrojanHeader(input, expectedPassword) {
  const bytes = toBytes(input);
  if (bytes.byteLength < 58) return { needMore: true };
  if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
    return { error: "invalid password delimiter" };
  }

  const passwordHash = new TextDecoder().decode(bytes.slice(0, 56)).toLowerCase();
  if (passwordHash !== expectedPassword.toLowerCase()) {
    return { error: "authentication failed" };
  }

  let offset = 58;
  if (bytes.byteLength < offset + 3) return { needMore: true };
  const command = bytes[offset++];
  if (command !== 1) return { error: "unsupported command" };

  const addressType = bytes[offset++];
  let address = "";

  if (addressType === 1) {
    if (bytes.byteLength < offset + 4) return { needMore: true };
    address = Array.from(bytes.slice(offset, offset + 4)).join(".");
    offset += 4;
  } else if (addressType === 3) {
    if (bytes.byteLength < offset + 1) return { needMore: true };
    const length = bytes[offset++];
    if (bytes.byteLength < offset + length) return { needMore: true };
    address = new TextDecoder().decode(bytes.slice(offset, offset + length));
    offset += length;
  } else if (addressType === 4) {
    if (bytes.byteLength < offset + 16) return { needMore: true };
    const groups = [];
    for (let index = 0; index < 16; index += 2) {
      groups.push(((bytes[offset + index] << 8) | bytes[offset + index + 1]).toString(16));
    }
    address = groups.join(":");
    offset += 16;
  } else {
    return { error: "unsupported address type" };
  }

  if (!address || bytes.byteLength < offset + 4) return { needMore: true };
  const port = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2;

  if (bytes[offset] !== 0x0d || bytes[offset + 1] !== 0x0a) {
    return { error: "invalid request delimiter" };
  }
  offset += 2;

  return {
    address,
    port,
    payload: bytes.slice(offset),
  };
}

function toBytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === "string") return new TextEncoder().encode(value);
  return new Uint8Array(0);
}

function concatBytes(first, second) {
  const output = new Uint8Array(first.byteLength + second.byteLength);
  output.set(first, 0);
  output.set(second, first.byteLength);
  return output;
}

function safeClose(socket, code, reason) {
  try {
    if (socket.readyState === WS_OPEN || socket.readyState === 2) {
      socket.close(code, reason);
    }
  } catch {}
}

function safeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function sha224Hex(value) {
  const message = new TextEncoder().encode(String(value));
  const bitLength = BigInt(message.length) * 8n;
  const paddedLength = Math.ceil((message.length + 9) / 64) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(message);
  bytes[message.length] = 0x80;

  let length = bitLength;
  for (let index = 0; index < 8; index += 1) {
    bytes[paddedLength - 1 - index] = Number(length & 0xffn);
    length >>= 8n;
  }

  const hash = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
  ];

  const constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  const schedule = new Uint32Array(64);
  for (let block = 0; block < bytes.length; block += 64) {
    for (let index = 0; index < 16; index += 1) {
      const position = block + index * 4;
      schedule[index] = ((bytes[position] << 24) | (bytes[position + 1] << 16) | (bytes[position + 2] << 8) | bytes[position + 3]) >>> 0;
    }
    for (let index = 16; index < 64; index += 1) {
      const s0 = rotateRight(schedule[index - 15], 7) ^ rotateRight(schedule[index - 15], 18) ^ (schedule[index - 15] >>> 3);
      const s1 = rotateRight(schedule[index - 2], 17) ^ rotateRight(schedule[index - 2], 19) ^ (schedule[index - 2] >>> 10);
      schedule[index] = (schedule[index - 16] + s0 + schedule[index - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + choice + constants[index] + schedule[index]) >>> 0;
      const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  return hash.slice(0, 7).map((word) => word.toString(16).padStart(8, "0")).join("");
}

function rotateRight(value, shift) {
  return (value >>> shift) | (value << (32 - shift));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sharedStyles() {
  return `
    :root {
      color-scheme: dark;
      --bg: #080b10;
      --panel: #10161e;
      --panel-2: #141c26;
      --line: #263242;
      --line-soft: #1b2532;
      --text: #f2f6fb;
      --muted: #94a1b2;
      --orange: #ff8a4c;
      --teal: #4ad7c6;
      --red: #ff6b71;
      --radius: 6px;
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px),
        var(--bg);
      background-size: 42px 42px;
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      line-height: 1.55;
    }
    a { color: inherit; }
    button, input { font: inherit; }
    .shell { width: min(1120px, calc(100% - 40px)); margin: 0 auto; padding: 26px 0 60px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 4px 0 38px; }
    .brand { display: inline-flex; align-items: center; gap: 12px; font-weight: 700; letter-spacing: .2px; }
    .mark { width: 28px; height: 28px; border: 1px solid var(--orange); border-radius: 5px; position: relative; }
    .mark::before, .mark::after { content: ""; position: absolute; background: var(--orange); }
    .mark::before { width: 12px; height: 1px; left: 7px; top: 8px; transform: rotate(-38deg); }
    .mark::after { width: 12px; height: 1px; left: 8px; bottom: 8px; transform: rotate(38deg); }
    .top-meta { color: var(--muted); font-size: 12px; letter-spacing: .14em; text-transform: uppercase; }
    .status-row { display: flex; flex-wrap: wrap; gap: 8px; margin: 20px 0 0; }
    .chip { display: inline-flex; align-items: center; gap: 8px; padding: 7px 10px; border: 1px solid var(--line); border-radius: 999px; color: #cbd5e1; font-size: 12px; background: rgba(16,22,30,.78); }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--teal); box-shadow: 0 0 0 3px rgba(74,215,198,.1); }
    .dot.warn { background: var(--orange); box-shadow: 0 0 0 3px rgba(255,138,76,.12); }
    .hero { padding: 18px 0 34px; border-bottom: 1px solid var(--line-soft); }
    .kicker { color: var(--orange); font-size: 12px; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
    h1 { margin: 12px 0 14px; max-width: 760px; font-size: 52px; line-height: 1.02; letter-spacing: -1.8px; }
    h2 { margin: 0 0 10px; font-size: 22px; line-height: 1.2; letter-spacing: -.4px; }
    h3 { margin: 0 0 8px; font-size: 15px; }
    p { margin: 0; color: var(--muted); }
    .lead { max-width: 650px; font-size: 17px; line-height: 1.75; }
    .accent { color: var(--orange); }
    .grid { display: grid; gap: 14px; }
    .split { grid-template-columns: minmax(0, 1.3fr) minmax(300px, .7fr); margin-top: 28px; align-items: start; }
    .stats { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 20px; }
    .metric, .panel { border: 1px solid var(--line); border-radius: var(--radius); background: rgba(16,22,30,.94); }
    .metric { padding: 16px; min-height: 100px; }
    .metric-label { color: var(--muted); font-size: 11px; letter-spacing: .13em; text-transform: uppercase; }
    .metric-value { margin-top: 10px; font-size: 17px; font-weight: 650; overflow-wrap: anywhere; }
    .panel { padding: 20px; }
    .panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
    .panel-note { color: var(--muted); font-size: 13px; max-width: 480px; }
    .access-panel { padding: 22px; }
    .access-form { display: grid; gap: 10px; margin-top: 18px; }
    .field { width: 100%; height: 46px; padding: 0 13px; color: var(--text); background: #0a0f15; border: 1px solid #2b394a; border-radius: 5px; outline: none; }
    .field:focus { border-color: var(--orange); box-shadow: 0 0 0 3px rgba(255,138,76,.12); }
    .btn { min-height: 42px; padding: 0 15px; border: 1px solid transparent; border-radius: 5px; background: var(--orange); color: #1a0e08; font-weight: 750; cursor: pointer; }
    .btn:hover { filter: brightness(1.06); }
    .btn.secondary { color: var(--text); background: #17202b; border-color: var(--line); font-weight: 600; }
    .btn.small { min-height: 32px; padding: 0 10px; font-size: 12px; }
    .btn.inline { display: inline-flex; align-items: center; justify-content: center; text-decoration: none; }
    .mono { font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace; }
    .endpoint-box { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; align-items: center; padding: 14px; background: #080d13; border: 1px solid var(--line-soft); border-radius: 5px; }
    .endpoint-value { min-width: 0; color: #dce7f5; font-size: 13px; overflow-wrap: anywhere; }
    .config-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); margin-top: 14px; }
    .config-card { display: flex; flex-direction: column; justify-content: space-between; min-height: 150px; padding: 16px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel-2); }
    .config-card p { font-size: 13px; margin: 6px 0 18px; }
    .config-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .checklist { display: grid; gap: 12px; margin: 0; padding: 0; list-style: none; }
    .checklist li { display: grid; grid-template-columns: 18px minmax(0, 1fr); gap: 10px; color: #cbd5e1; font-size: 14px; }
    .checklist li::before { content: ""; width: 8px; height: 8px; margin-top: 7px; border: 1px solid var(--teal); border-radius: 2px; background: rgba(74,215,198,.15); }
    .warning { margin-top: 14px; padding: 13px 14px; border-left: 3px solid var(--orange); background: rgba(255,138,76,.07); color: #e6c7b6; font-size: 13px; }
    .footer { display: flex; justify-content: space-between; gap: 20px; padding-top: 26px; color: #657386; font-size: 12px; }
    .toast { position: fixed; right: 22px; bottom: 22px; padding: 10px 14px; border: 1px solid #345247; border-radius: 5px; background: #10221d; color: #c9f4e8; font-size: 13px; opacity: 0; transform: translateY(8px); transition: .18s ease; pointer-events: none; }
    .toast.show { opacity: 1; transform: translateY(0); }
    .code-label { color: var(--muted); font-size: 11px; letter-spacing: .13em; text-transform: uppercase; margin-bottom: 7px; }
    .stack { display: grid; gap: 14px; }
    .muted { color: var(--muted); }
    .danger { color: var(--red); }
    @media (max-width: 860px) {
      h1 { font-size: 38px; letter-spacing: -1px; }
      .split, .stats, .config-grid { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .topbar { padding-bottom: 26px; }
    }
    @media (max-width: 560px) {
      .shell { width: min(100% - 24px, 1120px); padding-top: 16px; }
      h1 { font-size: 31px; letter-spacing: -.5px; }
      .lead { font-size: 15px; }
      .stats { grid-template-columns: 1fr; }
      .endpoint-box { grid-template-columns: 1fr; }
      .footer { flex-direction: column; gap: 6px; }
      .panel, .access-panel { padding: 16px; }
    }
  `;
}

function baseDocument(title, body, script = "") {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <meta name="color-scheme" content="dark">
  <title>${escapeHtml(title)}</title>
  <style>${sharedStyles()}</style>
</head>
<body>
  ${body}
  <div class="toast" id="toast">已复制</div>
  ${script ? `<script>${script}</script>` : ""}
</body>
</html>`;
}

function renderLandingPage(runtime) {
  const proxyStatus = runtime.proxy ? "Upstream proxy ready" : "Direct upstream";
  const proxyClass = runtime.proxy ? "dot" : "dot warn";
  const passwordStatus = runtime.passwordConfigured ? "Access key configured" : "Setup required";
  const passwordClass = runtime.passwordConfigured ? "dot" : "dot warn";

  const body = `
    <main class="shell">
      <header class="topbar">
        <div class="brand"><span class="mark" aria-hidden="true"></span><span>${escapeHtml(runtime.siteName)}</span></div>
        <div class="top-meta">Edge relay control plane</div>
      </header>

      <section class="hero">
        <div class="kicker">Private edge transport</div>
        <h1>One secure relay.<br><span class="accent">No exposed origin.</span></h1>
        <p class="lead">Trojan over WebSocket, running at the edge. Open the private console with your access key, then copy a ready-to-use endpoint into Clash, sing-box or your mobile client.</p>
        <div class="status-row">
          <span class="chip"><span class="${passwordClass}"></span>${escapeHtml(passwordStatus)}</span>
          <span class="chip"><span class="${proxyClass}"></span>${escapeHtml(proxyStatus)}</span>
          <span class="chip"><span class="dot"></span>WebSocket transport</span>
        </div>
      </section>

      <section class="grid split">
        <div class="panel access-panel">
          <div class="panel-head">
            <div>
              <div class="code-label">Private console</div>
              <h2>Open your relay</h2>
              <p class="panel-note">The access key is the same value configured as the Cloudflare secret <span class="mono">PASSWORD</span>.</p>
            </div>
          </div>
          <form class="access-form" id="access-form">
            <label class="code-label" for="access-key">Access key</label>
            <input class="field mono" id="access-key" name="key" type="password" autocomplete="current-password" spellcheck="false" placeholder="Enter access key" required>
            <button class="btn" type="submit">Open console</button>
          </form>
          <div class="warning">The console URL contains your access key. Keep it private, do not post screenshots, and rotate the secret if it is exposed.</div>
        </div>

        <div class="stack">
          <div class="panel">
            <div class="code-label">Runtime</div>
            <h3>Cloudflare edge</h3>
            <p>Global anycast front door, WebSocket bridge and per-request upstream selection. No database and no stored sessions.</p>
          </div>
          <div class="panel">
            <div class="code-label">Upstream</div>
            <h3>CF CDN aware</h3>
            <p>Set <span class="mono">PROXY_IP</span> to route Cloudflare-fronted destinations through your own stable upstream.</p>
          </div>
        </div>
      </section>

      <footer class="footer">
        <span>${escapeHtml(runtime.siteName)} · independent edge relay implementation</span>
        <span class="mono">/healthz</span>
      </footer>
    </main>`;

  const script = `
    const form = document.getElementById('access-form');
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const key = document.getElementById('access-key').value.trim();
      if (!key) return;
      location.assign('/' + encodeURIComponent(key));
    });
  `;

  return baseDocument(`${runtime.siteName} · Relay console`, body, script);
}

function renderDashboardPage(runtime, password, shareUri) {
  const basePath = `/${password}`;
  const proxyLabel = runtime.proxy ? `${runtime.proxy.hostname}:${runtime.proxy.port}` : "Not configured";
  const endpointLabel = `${runtime.endpointHost}:${runtime.endpointPort}`;
  const transportLabel = runtime.tls ? "TLS / WebSocket" : "Plain / WebSocket";

  const body = `
    <main class="shell">
      <header class="topbar">
        <div class="brand"><span class="mark" aria-hidden="true"></span><span>${escapeHtml(runtime.siteName)}</span></div>
        <div class="top-meta">Private control deck</div>
      </header>

      <section class="hero">
        <div class="status-row" style="margin-top:0">
          <span class="chip"><span class="dot"></span>Relay online</span>
          <span class="chip"><span class="dot"></span>Key verified</span>
        </div>
        <h1 style="margin-top:22px">Relay console.</h1>
        <p class="lead">Your private endpoint is ready. Copy the Trojan URI or download a client configuration, then keep this URL out of shared screenshots and public bookmarks.</p>
      </section>

      <section class="grid stats">
        <div class="metric"><div class="metric-label">Endpoint</div><div class="metric-value mono">${escapeHtml(endpointLabel)}</div></div>
        <div class="metric"><div class="metric-label">Transport</div><div class="metric-value">${escapeHtml(transportLabel)}</div></div>
        <div class="metric"><div class="metric-label">Upstream</div><div class="metric-value mono">${escapeHtml(proxyLabel)}</div></div>
        <div class="metric"><div class="metric-label">Route mode</div><div class="metric-value">${runtime.forceProxy ? "Proxy first" : "Direct first"}</div></div>
      </section>

      <section class="grid" style="margin-top:14px">
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="code-label">Primary endpoint</div>
              <h2>Trojan URI</h2>
              <p class="panel-note">A single import string with WebSocket host, SNI and path already filled in.</p>
            </div>
            <button class="btn small" data-copy="${escapeHtml(shareUri)}">Copy URI</button>
          </div>
          <div class="endpoint-box">
            <div class="endpoint-value mono" id="share-uri">${escapeHtml(shareUri)}</div>
            <button class="btn secondary small" data-copy="${escapeHtml(shareUri)}">Copy</button>
          </div>
        </div>
      </section>

      <section class="grid config-grid">
        <article class="config-card">
          <div><div class="code-label">YAML</div><h3>Clash / Mihomo</h3><p>Proxy, group and a minimal MATCH rule in one file.</p></div>
          <div class="config-actions"><a class="btn secondary small inline" href="${basePath}/clash">Download</a><button class="btn small" data-copy="${basePath}/clash">Copy URL</button></div>
        </article>
        <article class="config-card">
          <div><div class="code-label">JSON</div><h3>sing-box</h3><p>Trojan outbound with TLS and WebSocket transport.</p></div>
          <div class="config-actions"><a class="btn secondary small inline" href="${basePath}/singbox">Open</a><button class="btn small" data-copy="${basePath}/singbox">Copy URL</button></div>
        </article>
        <article class="config-card">
          <div><div class="code-label">Plain text</div><h3>Share URI</h3><p>Raw URI for clients that accept manual import.</p></div>
          <div class="config-actions"><a class="btn secondary small inline" href="${basePath}/uri">Open</a><button class="btn small" data-copy="${basePath}/uri">Copy URL</button></div>
        </article>
      </section>

      <section class="grid split" style="grid-template-columns:minmax(0,1fr) minmax(0,.8fr)">
        <div class="panel">
          <div class="code-label">Operational notes</div>
          <h2>Before you connect</h2>
          <ul class="checklist">
            <li><span>Use a password with at least 16 random characters and store it as a Cloudflare secret.</span></li>
            <li><span>Set <span class="mono">PROXY_IP</span> if destinations behind Cloudflare CDN fail on the direct route.</span></li>
            <li><span>Keep <span class="mono">FORCE_PROXY=true</span> only when all traffic should use your upstream.</span></li>
            <li><span>Rotate the key immediately if this console URL is shared or indexed.</span></li>
          </ul>
        </div>
        <div class="panel">
          <div class="code-label">Configuration</div>
          <h2>Runtime values</h2>
          <div class="stack">
            <div><div class="metric-label">Host header</div><div class="mono">${escapeHtml(runtime.hostHeader)}</div></div>
            <div><div class="metric-label">WebSocket path</div><div class="mono">${escapeHtml(runtime.path)}</div></div>
            <div><div class="metric-label">TLS</div><div>${runtime.tls ? "Enabled" : "Disabled"}</div></div>
          </div>
          <div class="warning">This page is rendered under your secret path and sent with <span class="mono">no-store</span>. It is still visible to anyone who knows the URL.</div>
        </div>
      </section>

      <footer class="footer">
        <span>${escapeHtml(runtime.siteName)} · private edge relay</span>
        <span class="mono">No telemetry · No third-party assets</span>
      </footer>
    </main>`;

  const script = `
    const toast = document.getElementById('toast');
    async function copyText(value) {
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        const area = document.createElement('textarea');
        area.value = value;
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        area.remove();
      }
      toast.classList.add('show');
      window.clearTimeout(window.__edgeferryToast);
      window.__edgeferryToast = window.setTimeout(() => toast.classList.remove('show'), 1200);
    }
    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-copy]');
      if (!button) return;
      const value = button.getAttribute('data-copy');
      if (!value) return;
      if (value.startsWith('/')) copyText(location.origin + value);
      else copyText(value);
    });
  `;

  return baseDocument(`${runtime.siteName} · Relay console`, body, script);
}

function renderNotFoundPage(runtime) {
  const body = `
    <main class="shell">
      <header class="topbar"><div class="brand"><span class="mark"></span><span>${escapeHtml(runtime.siteName)}</span></div><div class="top-meta">404</div></header>
      <section class="hero">
        <div class="kicker">Nothing here</div>
        <h1>Route not found.</h1>
        <p class="lead">This path is not part of the relay surface. Return to the console entry page or check the deployment path.</p>
        <div class="status-row"><a class="btn inline" href="/">Back to entry</a></div>
      </section>
    </main>`;
  return baseDocument(`${runtime.siteName} · Not found`, body);
}

function htmlResponse(html, privatePage, status = 200) {
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html;charset=utf-8",
      "cache-control": privatePage ? "no-store" : "public, max-age=60",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

function textResponse(value, contentType = "text/plain;charset=utf-8", filename = null, status = 200) {
  const headers = {
    "content-type": contentType,
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  };
  if (filename) headers["content-disposition"] = `attachment; filename="${filename}"`;
  return new Response(value, { status, headers });
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value, null, 2), {
    status,
    headers: {
      "content-type": "application/json;charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}
