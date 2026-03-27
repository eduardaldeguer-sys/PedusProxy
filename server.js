const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const url = require("url");

const app = express();
const PORT = process.env.PORT || 3000;

// ── Security & Middleware ──────────────────────────────────────────────────────
app.use(cors());
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Rate limiting: max 60 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please wait a moment." },
});
app.use("/proxy", limiter);

// ── Blocked domains (basic safety) ───────────────────────────────────────────
const BLOCKED_DOMAINS = [
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "10.",
  "192.168.",
  "172.16.",
  "::1",
];

function isBlockedDomain(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    const hostname = parsed.hostname.toLowerCase();
    return BLOCKED_DOMAINS.some((b) => hostname.includes(b));
  } catch {
    return true;
  }
}

// ── URL rewriting helper ──────────────────────────────────────────────────────
function rewriteUrl(resourceUrl, baseUrl, proxyBase) {
  try {
    if (!resourceUrl || resourceUrl.startsWith("data:") || resourceUrl.startsWith("javascript:") || resourceUrl.startsWith("#")) {
      return resourceUrl;
    }
    const absolute = new URL(resourceUrl, baseUrl).href;
    return `${proxyBase}?url=${encodeURIComponent(absolute)}`;
  } catch {
    return resourceUrl;
  }
}

// ── Main Proxy Endpoint ───────────────────────────────────────────────────────
app.get("/proxy", async (req, res) => {
  let targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).json({ error: "Missing ?url= parameter" });
  }

  // Auto-add https if missing
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = "https://" + targetUrl;
  }

  // Validate URL
  try {
    new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  if (isBlockedDomain(targetUrl)) {
    return res.status(403).json({ error: "This domain is not allowed." });
  }

  const proxyBase = `${req.protocol}://${req.get("host")}/proxy`;

  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      maxRedirects: 5,
      responseType: "arraybuffer",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
      },
      decompress: true,
    });

    const contentType = response.headers["content-type"] || "";

    // Pass non-HTML content directly (images, CSS, JS, fonts, etc.)
    if (!contentType.includes("text/html")) {
      // Rewrite CSS urls if needed
      if (contentType.includes("text/css")) {
        let css = response.data.toString("utf-8");
        css = css.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, u) => {
          const rewritten = rewriteUrl(u, targetUrl, proxyBase);
          return `url('${rewritten}')`;
        });
        res.setHeader("Content-Type", contentType);
        return res.send(css);
      }

      res.setHeader("Content-Type", contentType);
      // Remove CSP and security headers that would block content
      res.removeHeader("content-security-policy");
      res.removeHeader("x-frame-options");
      return res.send(response.data);
    }

    // ── HTML processing ────────────────────────────────────────────────────
    const html = response.data.toString("utf-8");
    const $ = cheerio.load(html, { decodeEntities: false });
    const parsedBase = new URL(targetUrl);
    const baseOrigin = parsedBase.origin;

    // Inject proxy base tag & toolbar
    $("head").prepend(`
      <base href="${targetUrl}">
      <style id="pedus-bar-style">
        #pedus-toolbar {
          position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
          background: linear-gradient(135deg, #0a0a0f 0%, #12121e 100%);
          border-bottom: 1px solid rgba(0,255,180,0.25);
          display: flex; align-items: center; gap: 12px; padding: 8px 16px;
          font-family: 'Courier New', monospace; font-size: 12px;
          box-shadow: 0 2px 20px rgba(0,255,180,0.1);
        }
        #pedus-logo { color: #00ffb4; font-weight: 700; font-size: 14px; white-space: nowrap; letter-spacing: 1px; }
        #pedus-url-input {
          flex: 1; background: rgba(255,255,255,0.06); border: 1px solid rgba(0,255,180,0.3);
          border-radius: 6px; padding: 5px 12px; color: #e0e0e0; font-size: 12px;
          font-family: 'Courier New', monospace; outline: none; min-width: 0;
        }
        #pedus-url-input:focus { border-color: #00ffb4; box-shadow: 0 0 0 2px rgba(0,255,180,0.15); }
        #pedus-go-btn {
          background: #00ffb4; color: #0a0a0f; border: none; border-radius: 6px;
          padding: 6px 16px; font-weight: 700; cursor: pointer; font-size: 12px;
          font-family: 'Courier New', monospace; white-space: nowrap; letter-spacing: 0.5px;
          transition: opacity 0.2s;
        }
        #pedus-go-btn:hover { opacity: 0.85; }
        #pedus-home-btn {
          color: #00ffb4; text-decoration: none; font-size: 18px; line-height: 1;
          padding: 2px 4px; transition: opacity 0.2s;
        }
        #pedus-home-btn:hover { opacity: 0.7; }
        body { margin-top: 44px !important; }
      </style>
    `);

    $("body").prepend(`
      <div id="pedus-toolbar">
        <a id="pedus-home-btn" href="/" title="Pedus Proxy Home">⌂</a>
        <span id="pedus-logo">PEDUS</span>
        <input id="pedus-url-input" type="text" value="${targetUrl}" placeholder="Enter URL..." 
               onkeydown="if(event.key==='Enter'){window.location='/proxy?url='+encodeURIComponent(this.value)}"/>
        <button id="pedus-go-btn" onclick="window.location='/proxy?url='+encodeURIComponent(document.getElementById('pedus-url-input').value)">GO →</button>
      </div>
    `);

    // Rewrite <a href>
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href && !href.startsWith("#") && !href.startsWith("javascript:") && !href.startsWith("mailto:") && !href.startsWith("tel:")) {
        $(el).attr("href", rewriteUrl(href, targetUrl, proxyBase));
      }
    });

    // Rewrite <img src>, <source src/srcset>, <video src>, <audio src>
    $("img[src], video[src], audio[src], source[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (src) $(el).attr("src", rewriteUrl(src, targetUrl, proxyBase));
    });

    $("img[srcset], source[srcset]").each((_, el) => {
      const srcset = $(el).attr("srcset");
      if (srcset) {
        const rewritten = srcset
          .split(",")
          .map((s) => {
            const parts = s.trim().split(/\s+/);
            parts[0] = rewriteUrl(parts[0], targetUrl, proxyBase);
            return parts.join(" ");
          })
          .join(", ");
        $(el).attr("srcset", rewritten);
      }
    });

    // Rewrite <link href> (CSS, favicon, etc.)
    $("link[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href) $(el).attr("href", rewriteUrl(href, targetUrl, proxyBase));
    });

    // Rewrite <script src>
    $("script[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (src) $(el).attr("src", rewriteUrl(src, targetUrl, proxyBase));
    });

    // Rewrite <form action>
    $("form[action]").each((_, el) => {
      const action = $(el).attr("action");
      if (action) $(el).attr("action", rewriteUrl(action, targetUrl, proxyBase));
    });

    // Remove CSP meta tags
    $('meta[http-equiv="Content-Security-Policy"]').remove();
    $('meta[http-equiv="X-Frame-Options"]').remove();

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.removeHeader("x-frame-options");
    res.removeHeader("content-security-policy");
    res.send($.html());
  } catch (err) {
    console.error(`[Proxy Error] ${targetUrl}:`, err.message);

    const code = err.response?.status || 500;
    const message =
      err.code === "ECONNREFUSED"
        ? "Could not connect to the server."
        : err.code === "ENOTFOUND"
        ? "Domain not found. Check the URL."
        : err.code === "ETIMEDOUT" || err.code === "ECONNABORTED"
        ? "Request timed out. The site may be slow or unavailable."
        : err.response?.status === 403
        ? "The site blocked this request (403 Forbidden)."
        : err.response?.status === 404
        ? "Page not found (404)."
        : `Something went wrong (${err.message})`;

    res.status(code).json({ error: message, url: targetUrl });
  }
});

// ── Stats endpoint ────────────────────────────────────────────────────────────
let requestCount = 0;
app.use("/proxy", (req, res, next) => { requestCount++; next(); });

app.get("/api/stats", (req, res) => {
  res.json({ requests: requestCount, uptime: Math.floor(process.uptime()) });
});

// ── Fallback to SPA ───────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`\n🚀 Pedus Proxy running on http://localhost:${PORT}\n`);
});
