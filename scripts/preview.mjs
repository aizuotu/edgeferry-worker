import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = fileURLToPath(new URL("..", import.meta.url));
const source = fs
  .readFileSync(path.join(root, "_worker.js"), "utf8")
  .replace('import { connect } from "cloudflare:sockets";', "const connect = () => {};")
  .replace("export default {", "const defaultExport = {")
  .concat("\nglobalThis.__edgeferry = { buildRuntime, buildShareUri, renderLandingPage, renderDashboardPage };");

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

const { buildRuntime, buildShareUri, renderLandingPage, renderDashboardPage } = sandbox.__edgeferry;
const request = new Request("https://edge.example.com/");
const runtime = buildRuntime(request, {
  PASSWORD: "demo-secret",
  SITE_NAME: "EdgeFerry",
  PROXY_IP: "upstream.example.com:443",
  SNI: "edge.example.com",
}, "demo-secret");

const landing = renderLandingPage(runtime);
const dashboard = renderDashboardPage(runtime, "demo-secret", buildShareUri(runtime, "demo-secret"));

const output = path.join(root, ".preview");
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, "landing.html"), landing, "utf8");
fs.writeFileSync(path.join(output, "dashboard.html"), dashboard, "utf8");

const server = http.createServer((req, res) => {
  const mobile = (source) => `<!doctype html><html><body style="margin:0;background:#05080c;display:grid;place-items:center;min-height:100vh"><iframe src="${source}" title="Mobile preview" style="width:390px;height:844px;border:1px solid #253140;background:#080b10"></iframe></body></html>`;
  const body = req.url === "/demo"
    ? dashboard
    : req.url === "/mobile"
      ? mobile("/")
      : req.url === "/mobile-demo"
        ? mobile("/demo")
        : landing;
  res.writeHead(200, { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  res.end(body);
});

server.listen(4173, "127.0.0.1", () => {
  console.log("EdgeFerry preview: http://127.0.0.1:4173/");
  console.log("Dashboard preview: http://127.0.0.1:4173/demo");
  console.log("Mobile previews: http://127.0.0.1:4173/mobile and /mobile-demo");
});
