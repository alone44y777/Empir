// ============================================================
// Devp: Dark Empire | Owner: Sardar Daud Arain
// Serverless Website Source, API & Asset Inspector (Zero-Deps)
// ============================================================

const MAX_HTML_BYTES = 1.8 * 1024 * 1024; // 1.8 MB memory guard
const FETCH_TIMEOUT_MS = 7500; // 7.5s timeout guard

const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^\[::1\]$/,
  /^169\.254\./,
  /\.local$/i,
  /\.internal$/i
];

const SOCIAL_DOMAINS = [
  { name: "WhatsApp", regex: /(?:wa\.me|api\.whatsapp\.com|chat\.whatsapp\.com|whatsapp\.com\/channel)/i },
  { name: "Telegram", regex: /(?:t\.me|telegram\.me|telegram\.dog)/i },
  { name: "YouTube", regex: /(?:youtube\.com|youtu\.be)/i },
  { name: "Instagram", regex: /instagram\.com/i },
  { name: "Facebook", regex: /(?:facebook\.com|fb\.com|fb\.me)/i },
  { name: "X / Twitter", regex: /(?:twitter\.com|x\.com)/i },
  { name: "TikTok", regex: /tiktok\.com/i },
  { name: "GitHub", regex: /github\.com/i },
  { name: "LinkedIn", regex: /linkedin\.com/i },
  { name: "Discord", regex: /(?:discord\.gg|discord\.com\/invite)/i },
  { name: "Snapchat", regex: /snapchat\.com/i },
  { name: "Pinterest", regex: /pinterest\.com/i }
];

function isBlockedHost(hostname) {
  return PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(hostname));
}

function normalizeUrl(raw) {
  if (!raw || typeof raw !== "string") return null;
  let cleaned = raw.trim();
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = "https://" + cleaned;
  }
  try {
    const parsed = new URL(cleaned);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    if (!parsed.hostname || !parsed.hostname.includes(".")) return null;
    if (isBlockedHost(parsed.hostname)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function resolveAbsolute(baseUrl, relativeUrl) {
  if (!relativeUrl) return null;
  const trimmed = relativeUrl.trim();
  if (
    !trimmed ||
    trimmed.startsWith("data:") ||
    trimmed.startsWith("javascript:") ||
    trimmed.startsWith("mailto:") ||
    trimmed.startsWith("tel:") ||
    trimmed === "#"
  ) {
    return null;
  }
  try {
    return new URL(trimmed, baseUrl).href;
  } catch {
    return null;
  }
}

function injectTwoPlaceBranding(html) {
  // PLACE 1: Top Header Comment
  const topBanner =
    `<!-- =====================================================\n` +
    `     Devp  : Dark Empire\n` +
    `     Owner : Sardar Daud Arain\n` +
    `===================================================== -->\n`;

  // PLACE 2: Bottom Footer Comment
  const bottomBanner =
    `\n<!-- =====================================================\n` +
    `     Devp  : Dark Empire\n` +
    `     Owner : Sardar Daud Arain\n` +
    `===================================================== -->`;

  return topBanner + html.trim() + bottomBanner;
}

async function safeFetchText(url, timeoutMs = FETCH_TIMEOUT_MS, maxBytes = MAX_HTML_BYTES) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();

  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9"
      }
    });

    const elapsed = Date.now() - start;
    const reader = res.body ? res.body.getReader() : null;
    let received = 0;
    const chunks = [];

    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maxBytes) {
          controller.abort();
          break;
        }
        chunks.push(value);
      }
    }

    const combined = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const text = new TextDecoder("utf-8", { fatal: false }).decode(combined);

    return {
      ok: true,
      status: res.status,
      finalUrl: res.url || url,
      headers: Object.fromEntries(res.headers.entries()),
      responseTimeMs: elapsed,
      truncated: received > maxBytes,
      text
    };
  } catch (err) {
    return {
      ok: false,
      error: err.name === "AbortError" ? "Target site timed out or exceeded size limit." : err.message
    };
  } finally {
    clearTimeout(timer);
  }
}

function extractMeta(html, baseUrl) {
  const getTag = (regex) => {
    const m = html.match(regex);
    return m ? m[1].replace(/\s+/g, " ").trim() : null;
  };

  const title = getTag(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const description =
    getTag(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i) ||
    getTag(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
  const keywords =
    getTag(/<meta[^>]+name=["']keywords["'][^>]+content=["']([^"']*)["']/i) ||
    getTag(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']keywords["']/i);
  const ogTitle =
    getTag(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']/i) ||
    getTag(/<meta[^>]+content=["']([^"']*)["'][^>]+property=["']og:title["']/i);
  const ogImageRaw =
    getTag(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']/i) ||
    getTag(/<meta[^>]+content=["']([^"']*)["'][^>]+property=["']og:image["']/i);
  const canonicalRaw =
    getTag(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i) ||
    getTag(/<link[^>]+href=["']([^"']*)["'][^>]+rel=["']canonical["']/i);

  return {
    title,
    description,
    keywords,
    og_title: ogTitle,
    og_image: resolveAbsolute(baseUrl, ogImageRaw),
    canonical: resolveAbsolute(baseUrl, canonicalRaw)
  };
}

function extractLogos(html, baseUrl, ogImage) {
  const logoSet = new Map();

  const addLogo = (rawUrl, type) => {
    const abs = resolveAbsolute(baseUrl, rawUrl);
    if (abs && !logoSet.has(abs)) {
      logoSet.set(abs, { type, url: abs });
    }
  };

  // 1. Favicon & Apple Touch Icons
  const linkTags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of linkTags) {
    const rel = (tag.match(/rel=["']([^"']+)["']/i) || [])[1] || "";
    const href = (tag.match(/href=["']([^"']+)["']/i) || [])[1] || "";
    if (/icon|apple-touch-icon|mask-icon/i.test(rel) && href) {
      addLogo(href, rel.toLowerCase());
    }
  }

  // 2. <img> tags with "logo" or "brand" in src, alt, class, or id
  const imgTags = html.match(/<img\b[^>]*>/gi) || [];
  for (const tag of imgTags) {
    const src = (tag.match(/src=["']([^"']+)["']/i) || [])[1] || "";
    if (src && /logo|brand|navbar-brand|site-icon/i.test(tag)) {
      addLogo(src, "brand-image");
    }
  }

  // 3. OpenGraph Logo/Image fallback
  if (ogImage && /logo|icon|brand/i.test(ogImage)) {
    addLogo(ogImage, "og-brand-image");
  }

  return Array.from(logoSet.values());
}

function extractSocialLinks(html, baseUrl) {
  const socialMap = new Map();
  const hrefMatches = html.matchAll(/href=["']([^"']+)["']/gi);

  for (const match of hrefMatches) {
    const abs = resolveAbsolute(baseUrl, match[1]);
    if (!abs) continue;

    for (const platform of SOCIAL_DOMAINS) {
      if (platform.regex.test(abs)) {
        if (!socialMap.has(abs)) {
          socialMap.set(abs, {
            platform: platform.name,
            url: abs
          });
        }
        break;
      }
    }
  }

  return Array.from(socialMap.values());
}

function extractAssets(html, baseUrl) {
  const cssSet = new Set();
  const jsSet = new Set();

  const linkTags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of linkTags) {
    const rel = (tag.match(/rel=["']([^"']+)["']/i) || [])[1] || "";
    const href = (tag.match(/href=["']([^"']+)["']/i) || [])[1] || "";
    if (/stylesheet/i.test(rel) && href) {
      const abs = resolveAbsolute(baseUrl, href);
      if (abs) cssSet.add(abs);
    }
  }

  const scriptTags = html.match(/<script\b[^>]*src=["'][^"']+["'][^>]*>/gi) || [];
  for (const tag of scriptTags) {
    const src = (tag.match(/src=["']([^"']+)["']/i) || [])[1] || "";
    const abs = resolveAbsolute(baseUrl, src);
    if (abs) jsSet.add(abs);
  }

  return {
    stylesheets: Array.from(cssSet),
    scripts: Array.from(jsSet)
  };
}

function extractWebApis(contentBlob, baseUrl) {
  const apiSet = new Set();

  // Pattern 1: Full URLs containing /api/, /v1/, /v2/, /v3/, /graphql, /rest/, or api. subdomain
  const fullApiRegex =
    /https?:\/\/[a-zA-Z0-9.-]+(?:\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%-]*)?(?:\/api\/|\/v[1-9]\d*\/|\/graphql|\/rest\/|api\.[a-zA-Z0-9.-]+)[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%-]*/gi;

  for (const m of contentBlob.matchAll(fullApiRegex)) {
    const clean = m[0].replace(/['"`),;\\]+$/, "");
    if (clean.length <= 220) apiSet.add(clean);
  }

  // Pattern 2: Relative API routes inside fetch("/api/...") or axios.get('/api/...')
  const relApiRegex = /["'`](\/(?:api|v[1-9]\d*|graphql|rest)\/[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+)["'`]/gi;
  for (const m of contentBlob.matchAll(relApiRegex)) {
    const abs = resolveAbsolute(baseUrl, m[1]);
    if (abs && abs.length <= 220) apiSet.add(abs);
  }

  return Array.from(apiSet);
}

function detectTechHints(html, headers) {
  const hints = new Set();
  const server = (headers["server"] || "").toLowerCase();
  const powered = (headers["x-powered-by"] || "").toLowerCase();

  if (server.includes("cloudflare") || headers["cf-ray"]) hints.add("Cloudflare");
  if (server.includes("vercel") || headers["x-vercel-id"]) hints.add("Vercel");
  if (server.includes("netlify") || headers["x-nf-request-id"]) hints.add("Netlify");
  if (powered.includes("next.js") || /\/_next\//i.test(html)) hints.add("Next.js");
  if (powered.includes("php")) hints.add("PHP");
  if (/wp-content|wp-includes/i.test(html)) hints.add("WordPress");
  if (/cdn\.shopify\.com/i.test(html)) hints.add("Shopify");
  if (/react|__REACT_DEVTOOLS/i.test(html)) hints.add("React");
  if (/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|data-v-[a-f0-9]+/i.test(html)) hints.add("Vue.js");
  if (/tailwindcss|tailwind\.min\.css/i.test(html)) hints.add("Tailwind CSS");
  if (/bootstrap(?:\.min)?\.(?:css|js)/i.test(html)) hints.add("Bootstrap");

  return Array.from(hints);
}

export default async function handler(req, res) {
  res.setHeader("X-Developer", "Dark Empire");
  res.setHeader("X-Owner", "Sardar Daud Arain");
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const query = req.query || {};
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const rawUrl = query.url || body.url;
  const mode = String(query.mode || body.mode || "full").toLowerCase();
  const deepScan = String(query.deep || body.deep || "true").toLowerCase() !== "false";

  // API Documentation / Home Endpoint when no URL is given
  if (!rawUrl) {
    res.setHeader("Cache-Control", "public, s-maxage=3600");
    return res.status(200).json({
      status: "online",
      service: "Website Source, API, Logo & Social Extractor",
      endpoints: {
        full_report: "/api/inspect?url=https://example.com",
        raw_html_only: "/api/inspect?url=https://example.com&mode=html",
        apis_only: "/api/inspect?url=https://example.com&mode=apis",
        logos_only: "/api/inspect?url=https://example.com&mode=logos",
        socials_only: "/api/inspect?url=https://example.com&mode=socials"
      },
      params: {
        url: "Target website URL (required)",
        mode: "full | html | apis | logos | socials (default: full)",
        deep: "true | false - scans top linked JS files for hidden API endpoints (default: true)"
      },
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  const parsedUrl = normalizeUrl(rawUrl);
  if (!parsedUrl) {
    return res.status(400).json({
      success: false,
      error: "Invalid or restricted URL. Please provide a valid public http/https website URL.",
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  // Prevent self-loop requests
  const currentHost = (req.headers.host || "").split(":")[0].toLowerCase();
  if (currentHost && parsedUrl.hostname.toLowerCase() === currentHost) {
    return res.status(400).json({
      success: false,
      error: "Self-inspection loop is not allowed.",
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  const result = await safeFetchText(parsedUrl.href);
  if (!result.ok) {
    return res.status(502).json({
      success: false,
      error: result.error || "Unable to fetch target website.",
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  const baseUrl = result.finalUrl;
  const rawHtml = result.text;
  const brandedHtml = injectTwoPlaceBranding(rawHtml);

  // Mode: Raw HTML Download / View
  if (mode === "html" || mode === "raw") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
    return res.status(200).send(brandedHtml);
  }

  const meta = extractMeta(rawHtml, baseUrl);
  const logos = extractLogos(rawHtml, baseUrl, meta.og_image);
  const socialLinks = extractSocialLinks(rawHtml, baseUrl);
  const assets = extractAssets(rawHtml, baseUrl);
  const techHints = detectTechHints(rawHtml, result.headers);

  // Deep scan up to 3 external JS bundles to discover embedded API endpoints
  let combinedScanText = rawHtml;
  if (deepScan && assets.scripts.length > 0 && (mode === "full" || mode === "apis")) {
    const topScripts = assets.scripts.slice(0, 3);
    const scriptResults = await Promise.all(
      topScripts.map((jsUrl) => safeFetchText(jsUrl, 3500, 400 * 1024))
    );
    for (const sr of scriptResults) {
      if (sr.ok && sr.text) {
        combinedScanText += "\n" + sr.text;
      }
    }
  }

  const webApis = extractWebApis(combinedScanText, baseUrl);

  // Edge Cache for long-term stability and low Vercel usage
  res.setHeader("Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");

  if (mode === "apis") {
    return res.status(200).json({
      success: true,
      target: baseUrl,
      total_apis: webApis.length,
      web_apis: webApis,
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  if (mode === "logos") {
    return res.status(200).json({
      success: true,
      target: baseUrl,
      total_logos: logos.length,
      logos,
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  if (mode === "socials") {
    return res.status(200).json({
      success: true,
      target: baseUrl,
      total_socials: socialLinks.length,
      social_links: socialLinks,
      branding: {
        devp: "Dark Empire",
        owner: "Sardar Daud Arain"
      }
    });
  }

  // Default: Full Comprehensive Response
  return res.status(200).json({
    success: true,
    target: {
      input_url: parsedUrl.href,
      final_url: baseUrl,
      status_code: result.status,
      response_time_ms: result.responseTimeMs,
      truncated: result.truncated
    },
    meta,
    tech_hints: techHints,
    web_apis: {
      count: webApis.length,
      list: webApis
    },
    logos: {
      count: logos.length,
      list: logos
    },
    social_links: {
      count: socialLinks.length,
      list: socialLinks
    },
    assets: {
      stylesheets_count: assets.stylesheets.length,
      scripts_count: assets.scripts.length,
      stylesheets: assets.stylesheets,
      scripts: assets.scripts
    },
    stats: {
      html_characters: brandedHtml.length,
      html_lines: brandedHtml.split("\n").length
    },
    source_code: brandedHtml,
    branding: {
      devp: "Dark Empire",
      owner: "Sardar Daud Arain"
    }
  });
  }
                                  
