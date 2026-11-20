import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs
  .readFileSync(new URL("../_worker.js", import.meta.url), "utf8")
  .replace('import { connect } from "cloudflare:sockets";', "const connect = () => { throw new Error('not available in tests'); };")
  .replace("export default {", "const defaultExport = {")
  .concat("\nglobalThis.__edgeferry = { sha224Hex, parseTrojanHeader, buildRuntime, buildShareUri, renderLandingPage, renderDashboardPage, escapeHtml, defaultExport };");

const sandbox = {
  TextEncoder,
  TextDecoder,
  URL,
  URLSearchParams,
  Uint8Array,
  Uint32Array,
  DataView,
  ArrayBuffer,
  BigInt,
  Math,
  JSON,
  Response,
  Request,
  Headers,
  WebSocketPair: class {},
  atob,
  btoa,
  console,
};
sandbox.globalThis = sandbox;
vm.runInNewContext(source, sandbox, { filename: "_worker.js" });

const { sha224Hex, parseTrojanHeader, buildRuntime, buildShareUri, renderLandingPage, renderDashboardPage, escapeHtml, defaultExport } = sandbox.__edgeferry;

function makeTrojanHeader({ passwordHash, command = 1, address = "example.com", port = 443, payload = "hello" }) {
  const domain = new TextEncoder().encode(address);
  const payloadBytes = new TextEncoder().encode(payload);
  const bytes = new Uint8Array(56 + 2 + 1 + 1 + 1 + domain.length + 2 + 2 + payloadBytes.length);
  bytes.set(new TextEncoder().encode(passwordHash), 0);
  bytes[56] = 0x0d;
  bytes[57] = 0x0a;
  let offset = 58;
  bytes[offset++] = command;
  bytes[offset++] = 3;
  bytes[offset++] = domain.length;
  bytes.set(domain, offset);
  offset += domain.length;
  bytes[offset++] = (port >> 8) & 0xff;
  bytes[offset++] = port & 0xff;
  bytes[offset++] = 0x0d;
  bytes[offset++] = 0x0a;
  bytes.set(payloadBytes, offset);
  return bytes;
}

test("SHA-224 matches known vectors", () => {
  assert.equal(sha224Hex(""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
  assert.equal(sha224Hex("abc"), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
  assert.equal(sha224Hex("The quick brown fox jumps over the lazy dog"), "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
});

test("Trojan header parser accepts a valid request", () => {
  const hash = sha224Hex("test-secret");
  const header = makeTrojanHeader({ passwordHash: hash });
  const parsed = parseTrojanHeader(header, hash);
  assert.equal(parsed.address, "example.com");
  assert.equal(parsed.port, 443);
  assert.equal(new TextDecoder().decode(parsed.payload), "hello");
});

test("Trojan header parser waits for fragmented input", () => {
  const hash = sha224Hex("test-secret");
  const header = makeTrojanHeader({ passwordHash: hash });
  const parsed = parseTrojanHeader(header.slice(0, 30), hash);
  assert.equal(parsed.needMore, true);
});

test("Trojan header parser rejects a bad password and unsupported command", () => {
  const goodHash = sha224Hex("test-secret");
  const badHash = sha224Hex("wrong-secret");
  assert.equal(parseTrojanHeader(makeTrojanHeader({ passwordHash: badHash }), goodHash).error, "authentication failed");
  assert.equal(parseTrojanHeader(makeTrojanHeader({ passwordHash: goodHash, command: 2 }), goodHash).error, "unsupported command");
});

test("Runtime and share URI use the configured public endpoint", () => {
  const request = new Request("https://worker.example.com/");
  const runtime = buildRuntime(request, {
    PASSWORD: "test-secret",
    ENDPOINT_HOST: "edge.example.net",
    ENDPOINT_PORT: "8443",
    SNI: "worker.example.com",
    PROXY_IP: "upstream.example.com:443",
    SITE_NAME: "Test Ferry",
  }, "test-secret");
  assert.equal(runtime.endpointHost, "edge.example.net");
  assert.equal(runtime.endpointPort, 8443);
  assert.equal(runtime.proxy.hostname, "upstream.example.com");
  const uri = buildShareUri(runtime, "test-secret");
  assert.match(uri, /^trojan:\/\/test-secret@edge\.example\.net:8443\?/);
  assert.match(uri, /security=tls/);
  assert.match(uri, /sni=worker\.example\.com/);
});

test("HTML renderers escape request-derived values", () => {
  const request = new Request("https://worker.example.com/");
  const runtime = buildRuntime(request, { PASSWORD: "test-secret", SITE_NAME: "<script>alert(1)</script>" }, "test-secret");
  const landing = renderLandingPage(runtime);
  const dashboard = renderDashboardPage(runtime, "test-secret", "trojan://test-secret@example.com:443?x=1#demo");
  assert.equal(landing.includes("<script>alert(1)</script>"), false);
  assert.match(landing, /scriptalert\(1\)\/script/);
  assert.match(dashboard, /Relay console\./);
  assert.equal(escapeHtml('a"b'), "a&quot;b");
});

test("Worker routes landing, health, dashboard and config without leaking secrets at root", async () => {
  const env = { PASSWORD: "test-secret", SITE_NAME: "EdgeFerry" };
  const landing = await defaultExport.fetch(new Request("https://worker.example.com/"), env, {});
  const landingHtml = await landing.text();
  assert.equal(landing.status, 200);
  assert.match(landingHtml, /Open your relay/);
  assert.equal(landingHtml.includes("test-secret@"), false);

  const health = await defaultExport.fetch(new Request("https://worker.example.com/healthz"), env, {});
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, "ok");

  const dashboard = await defaultExport.fetch(new Request("https://worker.example.com/test-secret"), env, {});
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.headers.get("cache-control"), "no-store");
  assert.match(await dashboard.text(), /Relay console\./);

  const clash = await defaultExport.fetch(new Request("https://worker.example.com/test-secret/clash"), env, {});
  assert.equal(clash.status, 200);
  assert.match(await clash.text(), /type: trojan/);
});

test("Worker refuses WebSocket traffic until PASSWORD is configured", async () => {
  const request = new Request("https://worker.example.com/socket", {
    headers: { Upgrade: "websocket" },
  });
  const response = await defaultExport.fetch(request, {}, {});
  assert.equal(response.status, 503);
});
