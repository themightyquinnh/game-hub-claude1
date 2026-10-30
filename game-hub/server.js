import express from "express";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public")));

// Block requests to private/internal addresses (SSRF protection).
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  const l = ip.toLowerCase();
  return l === "::1" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80");
}

async function assertPublic(hostname) {
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivate(a.address))) {
    throw new Error("Blocked address");
  }
}

// Turn whatever the user typed into a URL: real URL, domain, or search query.
function toUrl(input) {
  input = (input || "").trim();
  if (/^https?:\/\//i.test(input)) return input;
  if (/^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(input)) return "https://" + input;
  return "https://html.duckduckgo.com/html/?q=" + encodeURIComponent(input);
}

const prox = (u) => "/proxy?url=" + encodeURIComponent(u);

function rewriteHtml(html, base) {
  const abs = (v) => { try { return new URL(v, base).href; } catch { return null; } };
  html = html.replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
  html = html.replace(
    /(\s(?:href|src|action|poster)\s*=\s*)(["'])(.*?)\2/gi,
    (m, pre, q, val) => {
      if (/^(#|javascript:|data:|mailto:|blob:)/i.test(val)) return m;
      const u = abs(val.replace(/&amp;/g, "&"));
      return u ? `${pre}${q}${prox(u)}${q}` : m;
    }
  );
  // DuckDuckGo wraps result links in /l/?uddg=<real url>
  html = html.replace(/\/proxy\?url=[^"']*uddg%3D([^"'&]+)[^"']*/g, (m, enc) =>
    prox(decodeURIComponent(decodeURIComponent(enc)))
  );
  return html;
}

app.all("/proxy", express.raw({ type: "*/*", limit: "5mb" }), async (req, res) => {
  try {
    const target = toUrl(req.query.url);
    const u = new URL(target);
    if (!/^https?:$/.test(u.protocol)) throw new Error("Bad protocol");
    await assertPublic(u.hostname);

    const headers = {
      "user-agent": req.headers["user-agent"] || "Mozilla/5.0",
      accept: req.headers.accept || "*/*",
      "accept-language": req.headers["accept-language"] || "en-US,en;q=0.9",
    };
    const init = { method: req.method, headers, redirect: "manual" };
    if (!["GET", "HEAD"].includes(req.method) && Buffer.isBuffer(req.body) && req.body.length) {
      init.body = req.body;
      if (req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];
    }

    const r = await fetch(u.href, init);

    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      return res.redirect(prox(new URL(r.headers.get("location"), u.href).href));
    }

    const type = r.headers.get("content-type") || "";
    res.status(r.status);
    if (type) res.set("content-type", type);

    if (type.includes("text/html")) {
      const html = rewriteHtml(await r.text(), u.href);
      res.send(html);
    } else {
      res.send(Buffer.from(await r.arrayBuffer()));
    }
  } catch (e) {
    res.status(502).send(`<body style="font-family:sans-serif;padding:2rem;background:#111;color:#eee">
      <h2>Couldn't load that page</h2><p>${String(e.message).replace(/</g, "&lt;")}</p></body>`);
  }
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
