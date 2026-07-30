import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { URL } from "node:url";

const PORT = Number(process.env.PORT || 8080);
const SITE_PASSWORD = process.env.SITE_PASSWORD || "";
const UPSTREAM_URL = (process.env.UPSTREAM_URL || "").replace(/\/$/, "");
const UPSTREAM_PROBE_PATH = process.env.UPSTREAM_PROBE_PATH || "/";
const UPSTREAM_PROBE_TIMEOUT_MS = Number(process.env.UPSTREAM_PROBE_TIMEOUT_MS || 2500);

if (!SITE_PASSWORD) {
  console.error("SITE_PASSWORD is required");
  process.exit(1);
}
if (!UPSTREAM_URL) {
  console.error("UPSTREAM_URL is required (e.g. http://OpenSEO.railway.internal:8080)");
  process.exit(1);
}

const COOKIE = "openseo_gate";
const token = () =>
  createHmac("sha256", SITE_PASSWORD).update("openseo-gate-v1").digest("hex");

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return timingSafeEqual(aa, bb);
}

function parseCookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function isAuthed(req) {
  const value = parseCookies(req.headers.cookie)[COOKIE];
  return Boolean(value && safeEqual(value, token()));
}

function wantsHtml(req) {
  const accept = req.headers.accept || "";
  return accept.includes("text/html") || accept === "" || accept === "*/*";
}

// The MCP endpoint implements its own OAuth flow. These routes must reach the
// upstream unchanged so MCP clients can receive its WWW-Authenticate challenge
// and discover the authorization server.
function isMcpAuthRoute(pathname) {
  return pathname === "/mcp" || pathname.startsWith("/.well-known/");
}

const sharedCss = `
  :root {
    color-scheme: dark;
    --ink: #f2efe8;
    --muted: #8b867c;
    --line: rgba(242, 239, 232, 0.12);
    --fill: rgba(242, 239, 232, 0.06);
    --accent: #f2efe8;
    --danger: #e8a0a0;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    display: grid;
    place-items: center;
    font-family: "Instrument Sans", "Segoe UI", sans-serif;
    color: var(--ink);
    background:
      radial-gradient(900px 500px at 50% -10%, rgba(242, 239, 232, 0.07), transparent 55%),
      #0c0d10;
  }
  .wrap {
    width: min(320px, 88vw);
    text-align: center;
  }
  .brand {
    margin: 0 0 1.75rem;
    font-size: 1.35rem;
    font-weight: 560;
    letter-spacing: -0.03em;
  }
  form { text-align: left; }
  input[type=password] {
    width: 100%;
    padding: 0.85rem 0;
    border: 0;
    border-bottom: 1px solid var(--line);
    background: transparent;
    color: inherit;
    font: inherit;
    font-size: 1rem;
    letter-spacing: 0.08em;
  }
  input[type=password]::placeholder { color: var(--muted); letter-spacing: 0; }
  input[type=password]:focus {
    outline: none;
    border-bottom-color: rgba(242, 239, 232, 0.45);
  }
  button {
    margin-top: 1.5rem;
    width: 100%;
    padding: 0.8rem 1rem;
    border: 0;
    border-radius: 999px;
    background: var(--accent);
    color: #0c0d10;
    font: inherit;
    font-weight: 600;
    font-size: 0.92rem;
    cursor: pointer;
  }
  button:hover { filter: brightness(0.96); }
  .err {
    margin: 0 0 0.9rem;
    color: var(--danger);
    font-size: 0.85rem;
    text-align: center;
  }
  .loading {
    display: grid;
    justify-items: center;
    gap: 1.25rem;
  }
  .spinner {
    width: 1.35rem;
    height: 1.35rem;
    border-radius: 50%;
    border: 1.5px solid var(--line);
    border-top-color: var(--ink);
    animation: spin 0.9s linear infinite;
  }
  .hint {
    margin: 0;
    color: var(--muted);
    font-size: 0.88rem;
    letter-spacing: 0.01em;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
`;

const fontLink =
  '<link rel="preconnect" href="https://fonts.googleapis.com" />' +
  '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />' +
  '<link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600&display=swap" rel="stylesheet" />';

function loginPage(error = "") {
  const err = error ? `<p class="err">${error}</p>` : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenSEO</title>
  ${fontLink}
  <style>${sharedCss}</style>
</head>
<body>
  <div class="wrap">
    <p class="brand">OpenSEO</p>
    ${err}
    <form method="post" action="/__gate/login">
      <input id="password" name="password" type="password" placeholder="Password" autocomplete="current-password" autofocus required />
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`;
}

function startingPage(nextPath = "/") {
  const safeNext = encodeURIComponent(nextPath.startsWith("/") ? nextPath : "/");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenSEO</title>
  ${fontLink}
  <style>${sharedCss}</style>
</head>
<body>
  <div class="wrap loading">
    <p class="brand">OpenSEO</p>
    <div class="spinner" aria-hidden="true"></div>
    <p class="hint">Starting…</p>
  </div>
  <script>
    const next = decodeURIComponent(${JSON.stringify(safeNext)});
    async function tick() {
      try {
        const res = await fetch("/__gate/upstream", { cache: "no-store" });
        const data = await res.json();
        if (data && data.ok) {
          location.replace(next || "/");
          return;
        }
      } catch (e) {}
      setTimeout(tick, 4000);
    }
    tick();
  </script>
</body>
</html>`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function setAuthCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${encodeURIComponent(token())}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=2592000`,
  );
}

function clearAuthCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`,
  );
}

function probeUpstream() {
  return new Promise((resolve) => {
    const upstream = new URL(UPSTREAM_PROBE_PATH, UPSTREAM_URL + "/");
    const lib = upstream.protocol === "https:" ? httpsRequest : httpRequest;
    const req = lib(
      {
        protocol: upstream.protocol,
        hostname: upstream.hostname,
        port: upstream.port || (upstream.protocol === "https:" ? 443 : 80),
        path: upstream.pathname + upstream.search,
        method: "GET",
        headers: { accept: "*/*" },
        timeout: UPSTREAM_PROBE_TIMEOUT_MS,
      },
      (res) => {
        res.resume();
        resolve({
          ok: (res.statusCode || 500) < 500,
          statusCode: res.statusCode || 0,
        });
      },
    );
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, error: "timeout" });
    });
    req.on("error", (err) => {
      resolve({ ok: false, error: err.message });
    });
    req.end();
  });
}

function sendStarting(req, res, nextPath = "/") {
  if (wantsHtml(req) && req.method === "GET") {
    res.writeHead(503, {
      "content-type": "text/html; charset=utf-8",
      "retry-after": "5",
    });
    res.end(startingPage(nextPath));
    return;
  }
  res.writeHead(503, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: "upstream_starting", ok: false }));
}

function proxy(req, res) {
  const upstream = new URL(req.url || "/", UPSTREAM_URL);
  const lib = upstream.protocol === "https:" ? httpsRequest : httpRequest;
  const headers = { ...req.headers };
  delete headers["connection"];
  if (req.headers.host) {
    headers["x-forwarded-host"] = req.headers.host;
    headers["x-forwarded-proto"] = "https";
    headers.host = req.headers.host;
  }

  const pReq = lib(
    {
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port || (upstream.protocol === "https:" ? 443 : 80),
      path: upstream.pathname + upstream.search,
      method: req.method,
      headers,
    },
    (pRes) => {
      res.writeHead(pRes.statusCode || 502, pRes.headers);
      pRes.pipe(res);
    },
  );
  pReq.on("error", (err) => {
    console.error("upstream error", err.message);
    if (!res.headersSent) {
      sendStarting(req, res, req.url || "/");
    } else {
      res.end();
    }
  });
  req.pipe(pReq);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/__gate/health") {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end("ok");
    return;
  }

  if (url.pathname === "/__gate/upstream") {
    const result = await probeUpstream();
    res.writeHead(result.ok ? 200 : 503, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(JSON.stringify(result));
    return;
  }

  if (url.pathname === "/__gate/logout") {
    clearAuthCookie(res);
    res.writeHead(302, { Location: "/" });
    res.end();
    return;
  }

  if (url.pathname === "/__gate/login" && req.method === "POST") {
    const body = await readBody(req);
    const params = new URLSearchParams(body.toString("utf8"));
    const password = params.get("password") || "";
    if (safeEqual(password, SITE_PASSWORD)) {
      setAuthCookie(res);
      const upstream = await probeUpstream();
      if (!upstream.ok) {
        res.writeHead(303, { Location: "/__gate/starting" });
        res.end();
        return;
      }
      res.writeHead(302, { Location: "/" });
      res.end();
      return;
    }
    res.writeHead(401, { "content-type": "text/html; charset=utf-8" });
    res.end(loginPage("Wrong password."));
    return;
  }

  if (url.pathname === "/__gate/starting") {
    if (!isAuthed(req)) {
      res.writeHead(302, { Location: "/" });
      res.end();
      return;
    }
    const next = url.searchParams.get("next") || "/";
    sendStarting(req, res, next);
    return;
  }

  if (isMcpAuthRoute(url.pathname)) {
    proxy(req, res);
    return;
  }

  if (!isAuthed(req)) {
    if (wantsHtml(req) && req.method === "GET") {
      res.writeHead(401, { "content-type": "text/html; charset=utf-8" });
      res.end(loginPage());
      return;
    }
    res.writeHead(401, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ error: "unauthorized" }));
    return;
  }

  const upstream = await probeUpstream();
  if (!upstream.ok && wantsHtml(req) && req.method === "GET") {
    sendStarting(req, res, req.url || "/");
    return;
  }

  proxy(req, res);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`auth-gateway listening on :${PORT} → ${UPSTREAM_URL}`);
});
