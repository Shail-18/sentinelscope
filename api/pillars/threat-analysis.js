import dns from 'node:dns/promises';

const KNOWN_BRANDS = [
  { name: 'PayPal', primaryDomain: 'paypal.com', aliases: ['paypal.com', 'paypal-objects.com'] },
  { name: 'Google', primaryDomain: 'google.com', aliases: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com'] },
  { name: 'Microsoft', primaryDomain: 'microsoft.com', aliases: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'login.microsoftonline.com'] },
  { name: 'Apple', primaryDomain: 'apple.com', aliases: ['apple.com', 'icloud.com', 'id.apple.com'] },
  { name: 'Amazon', primaryDomain: 'amazon.com', aliases: ['amazon.com', 'aws.amazon.com', 'amazon.co.uk', 'amazon.de'] },
  { name: 'Netflix', primaryDomain: 'netflix.com', aliases: ['netflix.com'] },
  { name: 'Chase Bank', primaryDomain: 'chase.com', aliases: ['chase.com', 'chaseonline.chase.com'] },
  { name: 'Bank of America', primaryDomain: 'bankofamerica.com', aliases: ['bankofamerica.com'] },
  { name: 'Wells Fargo', primaryDomain: 'wellsfargo.com', aliases: ['wellsfargo.com'] },
  { name: 'Facebook', primaryDomain: 'facebook.com', aliases: ['facebook.com', 'meta.com', 'fb.com'] },
  { name: 'Instagram', primaryDomain: 'instagram.com', aliases: ['instagram.com'] },
  { name: 'Binance', primaryDomain: 'binance.com', aliases: ['binance.com'] },
  { name: 'Coinbase', primaryDomain: 'coinbase.com', aliases: ['coinbase.com'] },
  { name: 'Steam', primaryDomain: 'steampowered.com', aliases: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'Roblox', primaryDomain: 'roblox.com', aliases: ['roblox.com'] },
  { name: 'eBay', primaryDomain: 'ebay.com', aliases: ['ebay.com'] },
  { name: 'Walmart', primaryDomain: 'walmart.com', aliases: ['walmart.com'] },
  { name: 'USPS', primaryDomain: 'usps.com', aliases: ['usps.com'] },
  { name: 'DHL', primaryDomain: 'dhl.com', aliases: ['dhl.com'] },
  { name: 'FedEx', primaryDomain: 'fedex.com', aliases: ['fedex.com'] }
];

const SUSPICIOUS_URL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'verif', 'account-update',
  'billing', 'update-billing', 'security-alert', 'secure-banking', 'confirm-identity', 'kyc',
  'wallet', 'metamask', 'seed-phrase', 'suspended', 'action-required', 'auth', 'token',
  'recover', 'restore-account', 'unusual-activity', 'free-gift', 'free-nitro', 'reward'
];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function normalizeHomoglyphs(str) {
  return str
    .replace(/[0]/g, 'o')
    .replace(/[1l|!]/g, 'l')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm')
    .replace(/[3]/g, 'e')
    .replace(/[4@]/g, 'a')
    .replace(/[5$]/g, 's')
    .replace(/[7]/g, 't')
    .replace(/[8]/g, 'b')
    .replace(/[9]/g, 'g');
}

export async function checkDomainAge(domain) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: controller.signal
    }).catch(() => null);
    clearTimeout(timeout);

    if (res && res.ok) {
      const data = await res.json();
      const events = data.events || [];
      const regEvent = events.find(e => e.eventAction === 'registration' || e.eventAction === 'creation');
      if (regEvent && regEvent.eventDate) {
        const regDate = new Date(regEvent.eventDate);
        const ageDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
        return { registeredDate: regEvent.eventDate, ageDays, isNew: ageDays < 90, source: 'RDAP' };
      }
    }
  } catch {}

  // Fallback: Check DNS SOA record for serial/refresh or assume unknown
  try {
    const soa = await dns.resolveSoa(domain).catch(() => null);
    if (soa) {
      return { registeredDate: null, ageDays: null, isNew: false, source: 'DNS-SOA-Active' };
    }
  } catch {}

  return { registeredDate: null, ageDays: null, isNew: false, source: 'Unknown' };
}

export function detectLookalikeAndKeywords(targetHost, urlObj) {
  const findings = [];
  let score = 0;
  const hostLower = targetHost.toLowerCase();
  const normalized = normalizeHomoglyphs(hostLower);
  const segments = hostLower.split('.');
  const baseName = segments.length >= 2 ? segments[segments.length - 2] : hostLower;
  const normalizedBase = normalizeHomoglyphs(baseName);

  let detectedImpersonation = null;

  for (const brand of KNOWN_BRANDS) {
    const brandLower = brand.name.toLowerCase().replace(/\s+/g, '');
    const isRealDomain = brand.aliases.some(alias => hostLower === alias || hostLower.endsWith('.' + alias));
    if (isRealDomain) continue;

    // Check 1: Brand name embedded in subdomain or secondary segment (e.g. paypal.com.attacker.com)
    if (hostLower.includes(brandLower) || normalized.includes(brandLower)) {
      detectedImpersonation = brand.name;
      findings.push({
        level: 'high',
        category: 'Brand Impersonation',
        title: `Targeted brand lookalike (${brand.name})`,
        detail: `The domain "${hostLower}" contains the brand name "${brand.name}" but is not owned by or registered to the official domain (${brand.primaryDomain}).`,
        points: 40
      });
      score += 40;
      break;
    }

    // Check 2: Typosquatting / Levenshtein distance on base name (e.g. paypa1, micros0ft, googl)
    const dist = levenshtein(normalizedBase, brandLower);
    if (dist > 0 && dist <= 2 && Math.abs(normalizedBase.length - brandLower.length) <= 2) {
      detectedImpersonation = brand.name;
      findings.push({
        level: 'high',
        category: 'Typosquatting',
        title: `Typosquatting detected (${brand.name})`,
        detail: `"${baseName}" is an engineered lookalike of official "${brand.name}" (Levenshtein distance: ${dist}). Typical homoglyph or character substitution fraud pattern.`,
        points: 45
      });
      score += 45;
      break;
    }
  }

  // Check 3: Punycode (IDN Homograph attack)
  if (hostLower.includes('xn--')) {
    findings.push({
      level: 'high',
      category: 'Internationalized Domain',
      title: 'Punycode / Homograph attack risk',
      detail: `Domain uses Punycode ("xn--"). Attackers frequently use Cyrillic or Greek homoglyphs to visually mimic Latin brand letters in browsers.`,
      points: 25
    });
    score += 25;
  }

  // Check 4: Suspicious URL keywords
  const matchedKeywords = [];
  const fullUrlStr = urlObj.href.toLowerCase();
  for (const kw of SUSPICIOUS_URL_KEYWORDS) {
    if (fullUrlStr.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  if (matchedKeywords.length > 0) {
    const pts = Math.min(matchedKeywords.length * 8, 25);
    findings.push({
      level: matchedKeywords.length >= 2 ? 'high' : 'warning',
      category: 'Suspicious Keywords',
      title: `High-risk lure keywords in URL (${matchedKeywords.slice(0, 4).join(', ')})`,
      detail: `URL contains common phishing & credential capture triggers: "${matchedKeywords.join('", "')}".`,
      points: pts
    });
    score += pts;
  }

  // Check 5: Hyphen and subdomain stuffing
  const hyphenCount = (hostLower.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    findings.push({
      level: 'warning',
      category: 'Domain Structure',
      title: 'Excessive hyphenation',
      detail: `Domain contains ${hyphenCount} hyphens, a technique often used to bypass brand trademark filters.`,
      points: 10
    });
    score += 10;
  }

  if (segments.length >= 4) {
    findings.push({
      level: 'warning',
      category: 'Domain Structure',
      title: 'Deeply nested subdomains',
      detail: `Domain has ${segments.length} labels. Deep subdomain hierarchies are frequently used in dynamic phishing infrastructure.`,
      points: 10
    });
    score += 10;
  }

  return { findings, score, detectedImpersonation };
}

export async function analyzePageContent(urlObj) {
  const findings = [];
  let score = 0;
  let pageData = {
    fetched: false,
    title: '',
    redirectHops: 0,
    hiddenRedirects: [],
    forms: [],
    crossDomainLogins: []
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    let currentUrl = urlObj.href;
    let redirectCount = 0;
    let res = null;
    let finalHtml = '';

    while (redirectCount < 5) {
      res = await fetch(currentUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelScope-SecurityBot/2.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        redirect: 'manual',
        signal: controller.signal
      });

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        redirectCount++;
        const loc = res.headers.get('location');
        if (!loc) break;
        const nextUrl = new URL(loc, currentUrl).href;
        const fromHost = new URL(currentUrl).hostname;
        const toHost = new URL(nextUrl).hostname;
        if (fromHost !== toHost) {
          findings.push({
            level: 'warning',
            category: 'Redirect Chain',
            title: `Cross-domain redirect (${fromHost} -> ${toHost})`,
            detail: `Initial request was redirected to a different origin: ${nextUrl}. Phishing campaigns frequently chain redirects to evade automated scanners.`,
            points: 15
          });
          score += 15;
        }
        currentUrl = nextUrl;
      } else {
        finalHtml = await res.text();
        pageData.fetched = true;
        break;
      }
    }
    clearTimeout(timeout);
    pageData.redirectHops = redirectCount;

    if (pageData.fetched && finalHtml) {
      // 1. Extract Page Title
      const titleMatch = finalHtml.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (titleMatch) {
        pageData.title = titleMatch[1].trim();
      }

      // 2. Hidden Meta Refresh Redirect
      const metaRefresh = finalHtml.match(/<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']([0-9]+)\s*;\s*url=([^"']+)["']/i);
      if (metaRefresh) {
        const delay = parseInt(metaRefresh[1], 10);
        const target = metaRefresh[2];
        pageData.hiddenRedirects.push({ type: 'meta-refresh', delay, target });
        findings.push({
          level: 'high',
          category: 'Hidden Redirect',
          title: `Meta refresh redirect detected (${delay}s delay)`,
          detail: `Page contains an automated HTML meta refresh redirecting to "${target}". Often used in cloaking and evasion kits.`,
          points: 25
        });
        score += 25;
      }

      // 3. Client-side JS Redirect detection
      if (/(window\.location|document\.location|location\.replace|location\.href)\s*=\s*['"][^'"]+['"]/i.test(finalHtml)) {
        findings.push({
          level: 'warning',
          category: 'Hidden Redirect',
          title: 'Client-side script redirection pattern',
          detail: 'Inline JavaScript detected instructing browser to rewrite window.location.',
          points: 10
        });
        score += 10;
      }

      // 4. Form Action & Cross-domain Login analysis
      const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
      let formMatch;
      const targetHost = urlObj.hostname.toLowerCase();

      while ((formMatch = formRegex.exec(finalHtml)) !== null) {
        const formAttrs = formMatch[1];
        const formInner = formMatch[2];

        const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
        const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);
        const action = actionMatch ? actionMatch[1].trim() : '';
        const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

        const hasPassword = /type=["']password["']/i.test(formInner);
        const hasUserOrEmail = /type=["']email["']|name=["'](username|user|email|login|account|pass)/i.test(formInner);

        if (hasPassword || hasUserOrEmail) {
          pageData.forms.push({ action, method, hasPassword, hasUserOrEmail });

          // Cross-domain POST check
          if (action.startsWith('http://') || action.startsWith('https://')) {
            try {
              const actionUrl = new URL(action);
              if (actionUrl.hostname.toLowerCase() !== targetHost) {
                pageData.crossDomainLogins.push(action);
                findings.push({
                  level: 'high',
                  category: 'Credential Harvesting',
                  title: 'CRITICAL: Login form posts credentials to external domain',
                  detail: `A login/password form on "${targetHost}" submits data to an external foreign domain: "${actionUrl.hostname}". This is a primary signature of phishing credential harvesters.`,
                  points: 50
                });
                score += 50;
              }
            } catch {}
          } else if (action.startsWith('http:')) {
            findings.push({
              level: 'high',
              category: 'Credential Security',
              title: 'Insecure unencrypted credential submission',
              detail: `Password form action posts over unencrypted HTTP: "${action}". Credentials can be intercepted in transit.`,
              points: 30
            });
            score += 30;
          }
        }
      }

      // 5. Brand Impersonation in Content (Title mismatch)
      if (pageData.title) {
        for (const brand of KNOWN_BRANDS) {
          const isReal = brand.aliases.some(alias => targetHost === alias || targetHost.endsWith('.' + alias));
          if (!isReal && pageData.title.toLowerCase().includes(brand.name.toLowerCase())) {
            findings.push({
              level: 'high',
              category: 'Brand Impersonation',
              title: `Brand impersonation in page title (${brand.name})`,
              detail: `Page title claims to be "${pageData.title}" referencing ${brand.name}, but host "${targetHost}" has no legitimate affiliation.`,
              points: 35
            });
            score += 35;
            break;
          }
        }
      }
    }
  } catch (err) {
    findings.push({
      level: 'info',
      category: 'Content Fetch',
      title: 'Live page inspection limited',
      detail: `Could not retrieve live DOM (${err.message}). Heuristics calculated based on domain & origin signals.`,
      points: 0
    });
  }

  return { findings, score, pageData };
}

export async function runThreatAnalysisPillar(urlObj) {
  const host = urlObj.hostname;
  const { findings: lookalikeFindings, score: lookalikeScore, detectedImpersonation } = detectLookalikeAndKeywords(host, urlObj);
  const domainAgeInfo = await checkDomainAge(host);

  const ageFindings = [];
  let ageScore = 0;
  if (domainAgeInfo.isNew && domainAgeInfo.ageDays !== null) {
    ageFindings.push({
      level: 'high',
      category: 'Domain Age',
      title: `Newly registered domain (${domainAgeInfo.ageDays} days old)`,
      detail: `Domain was registered on ${new Date(domainAgeInfo.registeredDate).toLocaleDateString()} (${domainAgeInfo.ageDays} days ago). Over 70% of phishing domains are under 90 days old.`,
      points: 30
    });
    ageScore += 30;
  } else if (domainAgeInfo.ageDays !== null && domainAgeInfo.ageDays > 365) {
    ageFindings.push({
      level: 'good',
      category: 'Domain Age',
      title: `Established domain age (${Math.floor(domainAgeInfo.ageDays / 365)} years old)`,
      detail: `Domain has been registered since ${new Date(domainAgeInfo.registeredDate).toLocaleDateString()}. Long-standing domain age significantly decreases likelihood of disposable phishing campaign.`,
      points: 0
    });
  }

  const { findings: contentFindings, score: contentScore, pageData } = await analyzePageContent(urlObj);

  const allFindings = [...lookalikeFindings, ...ageFindings, ...contentFindings];
  const totalScore = Math.min(lookalikeScore + ageScore + contentScore, 100);

  return {
    pillar: 'Threat Analysis (Phishing Detection)',
    score: totalScore,
    riskLevel: totalScore >= 50 ? 'High' : totalScore >= 20 ? 'Moderate' : 'Low',
    detectedImpersonation,
    domainAge: domainAgeInfo,
    pageData,
    findings: allFindings
  };
}

