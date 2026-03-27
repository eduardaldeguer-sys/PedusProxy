const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({
  windowMs: 60_000, max: 100,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many requests — slow down a bit." },
});
app.use("/proxy", limiter);

// ─────────────────────────────────────────────────────────────
// Security
// ─────────────────────────────────────────────────────────────
const BLOCKED = ["localhost", "127.", "0.0.0.0", "::1", "10.", "192.168.", "172.16.", "169.254."];

function isBlocked(u) {
  try {
    const h = new URL(u).hostname.toLowerCase();
    return BLOCKED.some(b => h.startsWith(b) || h === b.replace(".", ""));
  } catch { return true; }
}

// ─────────────────────────────────────────────────────────────
// URL helpers
// ─────────────────────────────────────────────────────────────
function toAbsolute(href, base) {
  if (!href) return href;
  href = href.trim();
  if (
    href.startsWith("data:") || href.startsWith("javascript:") ||
    href.startsWith("mailto:") || href.startsWith("tel:") ||
    href.startsWith("#") || href === ""
  ) return href;
  try {
    if (href.startsWith("//")) href = new URL(base).protocol + href;
    return new URL(href, base).href;
  } catch { return href; }
}

function proxify(href, base, proxyBase) {
  const abs = toAbsolute(href, base);
  if (!abs) return href;
  if (
    abs.startsWith("data:") || abs.startsWith("javascript:") ||
    abs.startsWith("mailto:") || abs.startsWith("tel:") || abs === "#"
  ) return abs;
  if (!abs.startsWith("http")) return href;
  return `${proxyBase}?url=${encodeURIComponent(abs)}`;
}

function rewriteSrcset(srcset, base, proxyBase) {
  return srcset.split(",").map(s => {
    const parts = s.trim().split(/\s+/);
    if (parts[0]) parts[0] = proxify(parts[0], base, proxyBase);
    return parts.join(" ");
  }).join(", ");
}

// ─────────────────────────────────────────────────────────────
// CSS rewriter: url(), @import
// ─────────────────────────────────────────────────────────────
function rewriteCss(css, baseUrl, proxyBase) {
  // url('...') / url("...") / url(...)
  css = css.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (_, quote, u) => {
      u = u.trim();
      if (u.startsWith("data:")) return `url(${quote}${u}${quote})`;
      return `url(${quote}${proxify(u, baseUrl, proxyBase)}${quote})`;
    }
  );
  // @import "..."
  css = css.replace(
    /@import\s+(['"])([^'"]+)\1/gi,
    (_, q, u) => `@import ${q}${proxify(u, baseUrl, proxyBase)}${q}`
  );
  // @import url(...)
  css = css.replace(
    /@import\s+url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (_, q, u) => `@import url(${q}${proxify(u, baseUrl, proxyBase)}${q})`
  );
  return css;
}

// ─────────────────────────────────────────────────────────────
// Browser-like headers
// ─────────────────────────────────────────────────────────────
function buildHeaders(targetUrl, isCss) {
  return {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": isCss
      ? "text/css,*/*;q=0.1"
      : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": isCss ? "style" : "document",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
  };
}

const STRIP_HEADERS = [
  "content-security-policy","content-security-policy-report-only",
  "x-frame-options","x-xss-protection","strict-transport-security",
  "cross-origin-embedder-policy","cross-origin-opener-policy",
  "cross-origin-resource-policy","permissions-policy",
  "report-to","nel","set-cookie","expect-ct",
];

// ─────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────
let totalRequests = 0;

// ─────────────────────────────────────────────────────────────
// PROXY ENDPOINT
// ─────────────────────────────────────────────────────────────
app.get("/proxy", async (req, res) => {
  let targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: "Missing ?url= parameter." });
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = "https://" + targetUrl;

  try { new URL(targetUrl); }
  catch { return res.status(400).json({ error: "Invalid URL." }); }

  if (isBlocked(targetUrl)) return res.status(403).json({ error: "Domain not allowed." });

  totalRequests++;
  const proxyBase = `${req.protocol}://${req.get("host")}/proxy`;
  const isCssUrl = /\.css(\?.*)?$/i.test(new URL(targetUrl).pathname);

  try {
    const response = await axios.get(targetUrl, {
      timeout: 20000,
      maxRedirects: 8,
      responseType: "arraybuffer",
      headers: buildHeaders(targetUrl, isCssUrl),
      decompress: true,
      validateStatus: () => true,
    });

    // Strip security headers from response
    STRIP_HEADERS.forEach(h => res.removeHeader(h));
    res.setHeader("Access-Control-Allow-Origin", "*");

    const rawCT = response.headers["content-type"] || "";
    const ct = rawCT.toLowerCase();

    // ── Binary assets: images, fonts, wasm, audio, video ──────────────────
    if (
      ct.includes("image/") || ct.includes("font/") ||
      ct.includes("application/font") || ct.includes("application/x-font") ||
      ct.includes("application/wasm") || ct.includes("audio/") ||
      ct.includes("video/") || ct.includes("application/octet-stream")
    ) {
      res.setHeader("Content-Type", rawCT);
      res.setHeader("Cache-Control", "public, max-age=3600");
      return res.status(response.status).send(response.data);
    }

    // ── CSS ────────────────────────────────────────────────────────────────
    if (ct.includes("text/css") || isCssUrl) {
      const rewritten = rewriteCss(response.data.toString("utf-8"), targetUrl, proxyBase);
      res.setHeader("Content-Type", "text/css; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=300");
      return res.status(response.status).send(rewritten);
    }

    // ── JavaScript ─────────────────────────────────────────────────────────
    if (ct.includes("javascript") || ct.includes("ecmascript")) {
      res.setHeader("Content-Type", rawCT);
      return res.status(response.status).send(response.data);
    }

    // ── JSON / XML ─────────────────────────────────────────────────────────
    if (ct.includes("json") || ct.includes("xml")) {
      res.setHeader("Content-Type", rawCT);
      return res.status(response.status).send(response.data);
    }

    // ── HTML (main processing) ─────────────────────────────────────────────
    if (ct.includes("text/html") || ct === "") {
      const html = response.data.toString("utf-8");
      const $ = cheerio.load(html, { decodeEntities: false });

      // 1. Remove security meta + base tags
      $('meta[http-equiv="Content-Security-Policy"]').remove();
      $('meta[http-equiv="content-security-policy"]').remove();
      $('meta[http-equiv="X-Frame-Options"]').remove();
      $("base").remove(); // KEY: <base> tag breaks relative URL rewriting

      // 2. <link href> — stylesheets, preloads, icons
      $("link[href]").each((_, el) => {
        const v = $(el).attr("href");
        if (v) $(el).attr("href", proxify(v, targetUrl, proxyBase));
      });

      // 3. <script src>
      $("script[src]").each((_, el) => {
        const v = $(el).attr("src");
        if (v) $(el).attr("src", proxify(v, targetUrl, proxyBase));
      });

      // 4. Inline <style> blocks
      $("style").each((_, el) => {
        const css = $(el).html();
        if (css) $(el).html(rewriteCss(css, targetUrl, proxyBase));
      });

      // 5. Inline style="" attributes
      $("[style]").each((_, el) => {
        const s = $(el).attr("style");
        if (s && s.includes("url(")) $(el).attr("style", rewriteCss(s, targetUrl, proxyBase));
      });

      // 6. Images — src, srcset, lazy-load attributes
      $("img").each((_, el) => {
        ["src","data-src","data-lazy","data-original","data-lazy-src","data-echo","data-bg"].forEach(a => {
          const v = $(el).attr(a);
          if (v && !v.startsWith("data:")) $(el).attr(a, proxify(v, targetUrl, proxyBase));
        });
        const ss = $(el).attr("srcset");
        if (ss) $(el).attr("srcset", rewriteSrcset(ss, targetUrl, proxyBase));
        $(el).removeAttr("loading"); // disable native lazy loading
      });

      // 7. <source> (picture / video / audio)
      $("source").each((_, el) => {
        const v = $(el).attr("src");
        if (v) $(el).attr("src", proxify(v, targetUrl, proxyBase));
        const ss = $(el).attr("srcset");
        if (ss) $(el).attr("srcset", rewriteSrcset(ss, targetUrl, proxyBase));
      });

      // 8. <video> <audio> src
      $("video[src], audio[src]").each((_, el) => {
        const v = $(el).attr("src");
        if (v) $(el).attr("src", proxify(v, targetUrl, proxyBase));
      });

      // 9. <a href>
      $("a[href]").each((_, el) => {
        const v = $(el).attr("href");
        if (v && !v.startsWith("javascript:") && !v.startsWith("mailto:") && !v.startsWith("tel:") && v !== "#") {
          $(el).attr("href", proxify(v, targetUrl, proxyBase));
        }
      });

      // 10. <form action>
      $("form[action]").each((_, el) => {
        const v = $(el).attr("action");
        if (v) $(el).attr("action", proxify(v, targetUrl, proxyBase));
      });

      // 11. SVG xlink:href / href
      $("use, image").each((_, el) => {
        ["href","xlink:href"].forEach(a => {
          const v = $(el).attr(a);
          if (v && !v.startsWith("#")) $(el).attr(a, proxify(v, targetUrl, proxyBase));
        });
      });

      // 12. background / poster attributes
      $("[background]").each((_, el) => {
        const v = $(el).attr("background");
        if (v) $(el).attr("background", proxify(v, targetUrl, proxyBase));
      });
      $("[poster]").each((_, el) => {
        const v = $(el).attr("poster");
        if (v) $(el).attr("poster", proxify(v, targetUrl, proxyBase));
      });

      // ── Inject toolbar ──────────────────────────────────────────────────
      const safeUrl = targetUrl.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
      $("head").prepend(`<style id="__pedus__">
        #__pb__{all:initial;position:fixed!important;top:0!important;left:0!important;
          right:0!important;z-index:2147483647!important;display:flex!important;
          align-items:center!important;gap:10px!important;padding:7px 14px!important;
          height:46px!important;background:#09090f!important;
          border-bottom:1px solid rgba(0,255,180,.22)!important;
          box-shadow:0 2px 24px rgba(0,255,180,.08)!important;
          font-family:'Courier New',monospace!important;box-sizing:border-box!important;}
        #__pb__ *{all:unset;box-sizing:border-box;}
        #__pl__{color:#00ffb4!important;font-weight:700!important;font-size:13px!important;
          letter-spacing:2px!important;white-space:nowrap!important;cursor:pointer!important;
          text-decoration:none!important;}
        #__pl__:hover{opacity:.8!important;}
        #__pi__{display:block!important;flex:1!important;min-width:0!important;
          background:rgba(255,255,255,.05)!important;
          border:1px solid rgba(0,255,180,.25)!important;border-radius:7px!important;
          padding:5px 12px!important;color:#e0e0e0!important;font-size:12px!important;
          font-family:'Courier New',monospace!important;outline:none!important;}
        #__pi__:focus{border-color:#00ffb4!important;
          box-shadow:0 0 0 2px rgba(0,255,180,.12)!important;}
        #__pbtn__{display:block!important;background:#00ffb4!important;color:#09090f!important;
          border:none!important;border-radius:7px!important;padding:6px 18px!important;
          font-weight:800!important;font-size:12px!important;cursor:pointer!important;
          white-space:nowrap!important;font-family:'Courier New',monospace!important;
          box-shadow:0 0 16px rgba(0,255,180,.28)!important;}
        #__pbtn__:hover{opacity:.88!important;}
        body{margin-top:46px!important;}
      </style>`);

      $("body").prepend(`<div id="__pb__">
        <a id="__pl__" href="/">⌂ PEDUS</a>
        <input id="__pi__" type="text" value="${safeUrl}" placeholder="Enter URL…"
               onkeydown="if(event.key==='Enter')location.href='/proxy?url='+encodeURIComponent(this.value)"/>
        <button id="__pbtn__" onclick="location.href='/proxy?url='+encodeURIComponent(document.getElementById('__pi__').value)">GO →</button>
      </div>`);

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(200).send($.html());
    }

    // Fallback
    res.setHeader("Content-Type", rawCT || "application/octet-stream");
    return res.status(response.status).send(response.data);

  } catch (err) {
    console.error(`[Pedus] ${targetUrl}:`, err.message);
    const code = err.response?.status || 500;
    const msg =
      err.code === "ENOTFOUND"     ? `Domain not found: "${new URL(targetUrl).hostname}"`
      : err.code === "ECONNREFUSED" ? "Server refused the connection."
      : err.code === "ETIMEDOUT" || err.code === "ECONNABORTED"
                                    ? "Request timed out — the site may be offline."
      : err.response?.status === 403 ? "The site blocked this request (403)."
      : err.response?.status === 404 ? "Page not found (404)."
      : err.response?.status === 429 ? "Rate limited by that server. Try again later."
      : `Error: ${err.message}`;

    return res.status(code).send(`<!DOCTYPE html><html><head><meta charset="utf-8">
      <title>Pedus Error</title>
      <style>*{margin:0;padding:0;box-sizing:border-box;}
      body{font-family:'Courier New',monospace;background:#09090f;color:#d4d4e8;
           display:flex;align-items:center;justify-content:center;min-height:100vh;}
      .card{background:#0e0e1a;border:1px solid rgba(255,78,106,.3);border-radius:16px;
            padding:40px 48px;max-width:520px;text-align:center;}
      .icon{font-size:48px;margin-bottom:20px;}
      h2{color:#ff4e6a;font-size:22px;margin-bottom:12px;letter-spacing:1px;}
      p{color:#8888aa;line-height:1.7;font-size:13px;margin-bottom:24px;}
      code{background:rgba(255,255,255,.06);padding:3px 8px;border-radius:4px;
           font-size:12px;color:#ffb347;word-break:break-all;}
      a{display:inline-block;background:#00ffb4;color:#09090f;padding:10px 24px;
        border-radius:8px;font-weight:700;text-decoration:none;font-size:13px;
        margin-top:20px;letter-spacing:.5px;}
      a:hover{opacity:.85;}</style></head><body>
      <div class="card">
        <div class="icon">⚠</div>
        <h2>PROXY ERROR</h2>
        <p>${msg}</p>
        <code>${targetUrl.substring(0,100)}${targetUrl.length>100?"…":""}</code>
        <br><a href="/">← Back to Pedus</a>
      </div></body></html>`);
  }
});

// ─────────────────────────────────────────────────────────────
// Stats API
// ─────────────────────────────────────────────────────────────
app.get("/api/stats", (_req, res) => {
  res.json({
    requests: totalRequests,
    uptime: Math.floor(process.uptime()),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  });
});

// SPA fallback
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`\n⚡ Pedus Proxy → http://localhost:${PORT}\n`));
