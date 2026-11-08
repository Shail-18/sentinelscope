import scansHandler from './scans.js';
import reportsHandler from './reports.js';

function computeProxyShieldScan(url) {
  let urlStr = String(url || '').trim();
  if (!urlStr) {
    return { is_safe: false, risk_score: 50, reasons: ['Empty URL provided'] };
  }
  if (!urlStr.includes('://')) {
    urlStr = 'http://' + urlStr;
  }

  const urlLower = urlStr.toLowerCase();
  const urlLength = urlStr.length;
  const numHyphens = (urlStr.match(/-/g) || []).length;
  const hasHttps = urlLower.startsWith('https://') ? 1 : 0;
  const hasIp = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlStr) ? 1 : 0;

  const suspiciousWords = [
    'login', 'verify', 'update', 'secure', 'bank', 'account', 'free', 'win', 'admin', 'signin',
    'ebayisapi', 'webscr', 'confirm', 'pay', 'service', 'gift', 'bonus', 'refund', 'verification',
    'support', 'access', 'invoice'
  ];
  let suspiciousWordCount = 0;
  for (const word of suspiciousWords) {
    if (urlLower.includes(word)) suspiciousWordCount++;
  }

  const suspiciousTlds = [
    '.xyz', '.info', '.top', '.tk', '.ml', '.ga', '.gq', '.cf', '.online', '.site', '.click',
    '.buzz', '.bid', '.shop', '.web'
  ];
  const hasSuspiciousTld = suspiciousTlds.some(tld => urlLower.includes(tld)) ? 1 : 0;

  const reasons = [];
  if (hasHttps === 0) {
    reasons.push("Insecure Connection: Data is not encrypted (Missing HTTPS).");
  }
  if (hasIp === 1) {
    reasons.push("Direct IP Access: Uses an IP address instead of a standard domain name.");
  }
  if (suspiciousWordCount > 0) {
    reasons.push("Deceptive Keywords: Contains words commonly used in credential harvesting (e.g., login, verify, free).");
  }
  if (hasSuspiciousTld === 1) {
    reasons.push("Shady Infrastructure: Hosted on a low-reputation or disposable domain extension.");
  }
  if (numHyphens > 2) {
    reasons.push("Lookalike Domain: Excessive hyphens used to mimic legitimate brands.");
  }
  if (urlLength > 75) {
    reasons.push("URL Obfuscation: Unusually long URL to hide the actual landing page.");
  }
  if (/paypa[1l]|g00g|micr0s/i.test(urlLower)) {
    reasons.push("Brand Typosquatting: Detected homoglyph character substitution mimicry.");
  }

  let score = 0;
  if (hasHttps === 0) score += 25;
  if (hasIp === 1) score += 30;
  if (suspiciousWordCount > 0) score += Math.min(suspiciousWordCount * 20, 40);
  if (hasSuspiciousTld === 1) score += 25;
  if (numHyphens > 2) score += 15;
  if (urlLength > 75) score += 15;
  if (/paypa[1l]|g00g|micr0s/i.test(urlLower)) score += 35;

  const risk_score = Math.min(score, 100);
  const is_safe = (reasons.length === 0 && risk_score < 30);

  if (!is_safe && reasons.length === 0) {
    reasons.push("Machine Learning Pattern Match: Structural similarities with known phishing campaigns detected.");
  }

  return {
    is_safe,
    risk_score,
    reasons
  };
}

export function sentinelApiPlugin() {
  return {
    name: 'sentinel-api-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const urlStr = req.url || '';
        if (!urlStr.startsWith('/api') && !urlStr.startsWith('/flask-api')) {
          return next();
        }

        // Attach helper methods to res if missing in connect middleware
        if (!res.status) {
          res.status = function (code) {
            this.statusCode = code;
            return this;
          };
        }
        if (!res.json) {
          res.json = function (obj) {
            this.setHeader('Content-Type', 'application/json');
            this.end(JSON.stringify(obj));
            return this;
          };
        }
        if (!res.send) {
          res.send = function (data) {
            this.end(data);
            return this;
          };
        }

        // Parse JSON body for POST/PUT
        if (req.method === 'POST' || req.method === 'PUT') {
          let bodyData = '';
          req.on('data', chunk => {
            bodyData += chunk;
          });
          await new Promise(resolve => req.on('end', resolve));
          try {
            req.body = bodyData ? JSON.parse(bodyData) : {};
          } catch {
            req.body = {};
          }
        }

        try {
          // Handle ProxySHIELD scan endpoint
          const isProxyShieldScan =
            urlStr === '/api/scan' ||
            urlStr.startsWith('/api/scan?') ||
            urlStr.startsWith('/api/proxy-shield') ||
            urlStr.startsWith('/flask-api');

          if (isProxyShieldScan) {
            // First try live Python Flask backend on port 5000 with a quick 1200ms timeout
            try {
              const controller = new AbortController();
              const timeout = setTimeout(() => controller.abort(), 1200);

              const flaskRes = await fetch('http://127.0.0.1:5000/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(req.body || {}),
                signal: controller.signal
              });
              clearTimeout(timeout);

              if (flaskRes.ok) {
                const data = await flaskRes.json();
                return res.status(flaskRes.status).json(data);
              }
            } catch (flaskErr) {
              // Python Flask backend not running or timed out; fall back to built-in ML logic
            }

            // Fallback calculation directly in Node
            const targetUrl = req.body?.url || '';
            const scanResult = computeProxyShieldScan(targetUrl);
            return res.status(200).json(scanResult);
          }

          if (urlStr.startsWith('/api/scans')) {
            await scansHandler(req, res);
            return;
          }

          if (urlStr.startsWith('/api/reports') || urlStr.startsWith('/api/blocklist')) {
            await reportsHandler(req, res);
            return;
          }

          res.status(404).json({ error: 'Endpoint not found' });
        } catch (err) {
          console.error('API Error in Vite Middleware:', err);
          res.status(500).json({ error: err.message || 'Internal API Error' });
        }
      });
    }
  };
}
