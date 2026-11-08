import net from 'node:net';
import dns from 'node:dns/promises';

const COMMON_PORTS = [
  { port: 21, service: 'FTP', risk: 'high', desc: 'Unencrypted file transfer service' },
  { port: 22, service: 'SSH', risk: 'info', desc: 'Secure shell remote administration' },
  { port: 25, service: 'SMTP', risk: 'info', desc: 'Mail exchange server' },
  { port: 80, service: 'HTTP', risk: 'info', desc: 'Standard unencrypted web server' },
  { port: 443, service: 'HTTPS', risk: 'good', desc: 'Standard secure web server' },
  { port: 3306, service: 'MySQL', risk: 'high', desc: 'Exposed database server (should not be WAN-facing)' },
  { port: 3389, service: 'RDP', risk: 'high', desc: 'Windows Remote Desktop exposed to Internet' },
  { port: 5432, service: 'PostgreSQL', risk: 'high', desc: 'Exposed database server' },
  { port: 6379, service: 'Redis', risk: 'high', desc: 'Exposed in-memory cache/database (often unauthenticated)' },
  { port: 8080, service: 'HTTP-Alt', risk: 'warning', desc: 'Alternative web port / proxy / dev interface' },
  { port: 8443, service: 'HTTPS-Alt', risk: 'info', desc: 'Alternative secure web / admin portal' },
  { port: 27017, service: 'MongoDB', risk: 'high', desc: 'Exposed NoSQL database' }
];

const SENSITIVE_PATHS = [
  { path: '/.env', label: 'Environment configuration file', critical: true },
  { path: '/.git/HEAD', label: 'Exposed Git repository metadata', critical: true },
  { path: '/config.json', label: 'Application configuration file', critical: true },
  { path: '/wp-admin/', label: 'WordPress administration panel', critical: false },
  { path: '/admin', label: 'Administrative login portal', critical: false }
];

const OUTDATED_VERSIONS = [
  { pattern: /apache\/([0-1]\.|2\.[0-3]\.|2\.4\.[0-9]\b|2\.4\.[1-4][0-9]\b)/i, name: 'Apache HTTP Server < 2.4.50', cve: 'CVE-2021-41773 path traversal / RCE risk' },
  { pattern: /nginx\/([0]\.|1\.[0-9]\b|1\.1[0-8]\b)/i, name: 'Legacy Nginx < 1.18', cve: 'Multiple historical security advisories' },
  { pattern: /php\/([4-6]\.|7\.[0-3]\.)/i, name: 'End-of-Life PHP < 7.4', cve: 'Unsupported PHP version lacking security patches' },
  { pattern: /microsoft-iis\/([5-7]\.)/i, name: 'Legacy Microsoft IIS < 8.0', cve: 'Outdated Windows Server platform' },
  { pattern: /openssl\/0\./i, name: 'Legacy OpenSSL 0.9.x', cve: 'Heartbleed and POODLE vulnerable generation' }
];

function checkPort(host, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      status = 'open';
      socket.destroy();
      resolve(status);
    });

    socket.on('timeout', () => {
      status = 'filtered/timeout';
      socket.destroy();
      resolve(status);
    });

    socket.on('error', () => {
      status = 'closed';
      resolve(status);
    });

    socket.connect(port, host);
  });
}

export async function scanPorts(host) {
  const openPorts = [];
  try {
    // Fast DNS check with 1500ms timeout
    const addresses = await Promise.race([
      dns.resolve4(host),
      new Promise(r => setTimeout(() => r([]), 1500))
    ]).catch(() => []);
    if (!addresses.length) return { openPorts, scannedCount: COMMON_PORTS.length };
    const ip = addresses[0];

    // Check ports in parallel with concurrency
    const checks = COMMON_PORTS.map(async (p) => {
      const status = await checkPort(ip, p.port, 1200);
      if (status === 'open') {
        openPorts.push({ ...p, status });
      }
    });

    await Promise.all(checks);
  } catch {}

  return { openPorts, scannedCount: COMMON_PORTS.length };
}

export async function probeAdminPanelsAndFiles(originUrl) {
  const discovered = [];
  const base = originUrl.replace(/\/+$/, '');

  const probes = SENSITIVE_PATHS.map(async (item) => {
    try {
      const target = `${base}${item.path}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);

      const res = await fetch(target, {
        method: 'HEAD',
        headers: { 'User-Agent': 'SentinelScope/2.0 Web Hygiene Probe' },
        redirect: 'manual',
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (res.status === 200 || (res.status >= 300 && res.status < 400)) {
        let isConfirmedLeak = false;
        if (item.critical && res.status === 200) {
          // Confirm body for false positives like custom 404 pages
          const bodyController = new AbortController();
          const bodyTimeout = setTimeout(() => bodyController.abort(), 2000);
          const bodyRes = await fetch(target, {
            method: 'GET',
            headers: { 'User-Agent': 'SentinelScope/2.0' },
            signal: bodyController.signal
          }).catch(() => null);
          clearTimeout(bodyTimeout);

          if (bodyRes && bodyRes.ok) {
            const text = (await bodyRes.text()).slice(0, 1000);
            if (item.path === '/.env' && /(DB_PASSWORD|APP_KEY|SECRET|API_KEY|DATABASE_URL)=/i.test(text)) {
              isConfirmedLeak = true;
            } else if (item.path === '/.git/HEAD' && text.startsWith('ref: refs/')) {
              isConfirmedLeak = true;
            } else if (item.path === '/config.json' && text.trim().startsWith('{')) {
              isConfirmedLeak = true;
            }
          }
        }

        discovered.push({
          path: item.path,
          label: item.label,
          status: res.status,
          critical: item.critical,
          confirmedLeak: isConfirmedLeak
        });
      }
    } catch {}
  });

  await Promise.all(probes);
  return discovered;
}

export function evaluateSecurityHeaders(headers) {
  const findings = [];
  let headerScore = 100; // Deductions for missing/poor headers

  const h = headers || {};
  const csp = h['content-security-policy'];
  const hsts = h['strict-transport-security'];
  const xfo = h['x-frame-options'];
  const xcto = h['x-content-type-options'];
  const rp = h['referrer-policy'];
  const pp = h['permissions-policy'] || h['feature-policy'];

  // 1. Content Security Policy (CSP)
  if (!csp) {
    findings.push({
      level: 'warning',
      category: 'Security Headers',
      header: 'Content-Security-Policy',
      title: 'Content Security Policy (CSP) missing',
      detail: 'Site does not restrict which scripts, styles, or media can be loaded. High susceptibility to Cross-Site Scripting (XSS) and data injection.',
      points: 20
    });
    headerScore -= 20;
  } else {
    findings.push({
      level: 'good',
      category: 'Security Headers',
      header: 'Content-Security-Policy',
      title: 'CSP header enabled',
      detail: `Content-Security-Policy is enforced (${csp.length > 50 ? csp.slice(0, 47) + '...' : csp}).`,
      points: 0
    });
  }

  // 2. Strict Transport Security (HSTS)
  if (!hsts) {
    findings.push({
      level: 'warning',
      category: 'Security Headers',
      header: 'Strict-Transport-Security',
      title: 'HSTS header missing',
      detail: 'Site does not instruct browsers to remember HTTPS connection. Susceptible to SSL stripping and man-in-the-middle downgrade attacks.',
      points: 20
    });
    headerScore -= 20;
  } else {
    const hasSubdomains = /includeSubDomains/i.test(hsts);
    const hasPreload = /preload/i.test(hsts);
    findings.push({
      level: 'good',
      category: 'Security Headers',
      header: 'Strict-Transport-Security',
      title: 'HSTS active' + (hasSubdomains ? ' (with includeSubDomains)' : ''),
      detail: `Strict-Transport-Security header configured (${hsts}).${hasPreload ? ' Eligible for browser preload list.' : ''}`,
      points: 0
    });
  }

  // 3. X-Frame-Options
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    findings.push({
      level: 'warning',
      category: 'Security Headers',
      header: 'X-Frame-Options',
      title: 'Clickjacking protection missing (X-Frame-Options / frame-ancestors)',
      detail: 'The page can be embedded inside an iframe on malicious websites, leaving visitors vulnerable to clickjacking credential theft.',
      points: 15
    });
    headerScore -= 15;
  } else {
    findings.push({
      level: 'good',
      category: 'Security Headers',
      header: 'X-Frame-Options',
      title: 'Clickjacking protection enforced',
      detail: xfo ? `X-Frame-Options set to "${xfo}".` : 'frame-ancestors directive configured in CSP.',
      points: 0
    });
  }

  // 4. X-Content-Type-Options
  if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
    findings.push({
      level: 'info',
      category: 'Security Headers',
      header: 'X-Content-Type-Options',
      title: 'MIME-sniffing protection missing',
      detail: 'Missing "X-Content-Type-Options: nosniff". Browsers may attempt to guess file MIME types, potentially executing disguised scripts.',
      points: 5
    });
    headerScore -= 5;
  } else {
    findings.push({
      level: 'good',
      category: 'Security Headers',
      header: 'X-Content-Type-Options',
      title: 'MIME-sniffing protection enabled',
      detail: 'X-Content-Type-Options: nosniff is correctly present.',
      points: 0
    });
  }

  // 5. Referrer-Policy
  if (!rp) {
    findings.push({
      level: 'info',
      category: 'Security Headers',
      header: 'Referrer-Policy',
      title: 'Referrer Policy not specified',
      detail: 'Sensitive URL parameters and paths may leak in the HTTP Referer header when navigating to external websites.',
      points: 5
    });
    headerScore -= 5;
  } else {
    findings.push({
      level: 'good',
      category: 'Security Headers',
      header: 'Referrer-Policy',
      title: 'Referrer Policy configured',
      detail: `Referrer-Policy is set to "${rp}".`,
      points: 0
    });
  }

  // 6. Permissions-Policy
  if (!pp) {
    findings.push({
      level: 'info',
      category: 'Security Headers',
      header: 'Permissions-Policy',
      title: 'Permissions-Policy missing',
      detail: 'Browser hardware APIs (camera, geolocation, microphone, payment) are not explicitly restricted.',
      points: 5
    });
    headerScore -= 5;
  } else {
    findings.push({
      level: 'good',
      category: 'Security Headers',
      header: 'Permissions-Policy',
      title: 'Permissions-Policy configured',
      detail: 'Hardware and browser feature access is restricted.',
      points: 0
    });
  }

  const hygieneGrade = headerScore >= 90 ? 'A+' : headerScore >= 80 ? 'A' : headerScore >= 65 ? 'B' : headerScore >= 50 ? 'C' : headerScore >= 35 ? 'D' : 'F';

  return { findings, headerScore: Math.max(headerScore, 0), hygieneGrade };
}

export function inspectServerAndCookies(headers, rawCookies) {
  const findings = [];
  const serverBanner = headers['server'] || '';
  const poweredBy = headers['x-powered-by'] || '';
  const aspNet = headers['x-aspnet-version'] || '';

  // Server banner leak & outdated version detection
  if (serverBanner) {
    let outdatedMatch = null;
    for (const out of OUTDATED_VERSIONS) {
      if (out.pattern.test(serverBanner)) {
        outdatedMatch = out;
        break;
      }
    }

    if (outdatedMatch) {
      findings.push({
        level: 'high',
        category: 'Outdated Software',
        title: `Outdated server software: ${outdatedMatch.name}`,
        detail: `Server banner discloses "${serverBanner}". Vulnerable platform: ${outdatedMatch.cve}.`,
        points: 30
      });
    } else if (/\d+\.\d+/.test(serverBanner)) {
      findings.push({
        level: 'warning',
        category: 'Information Disclosure',
        title: 'Server version disclosed in banner',
        detail: `Server header exposes exact software version ("${serverBanner}"). Helps attackers map known vulnerabilities.`,
        points: 10
      });
    }
  }

  if (poweredBy) {
    findings.push({
      level: 'info',
      category: 'Information Disclosure',
      title: 'Technology stack exposed (X-Powered-By)',
      detail: `Discloses backend engine: "${poweredBy}". Revealing stack components simplifies targeted exploitation.`,
      points: 5
    });
  }

  if (aspNet) {
    findings.push({
      level: 'warning',
      category: 'Information Disclosure',
      title: 'ASP.NET version disclosed',
      detail: `Exposes .NET runtime version: "${aspNet}".`,
      points: 10
    });
  }

  // Cookie security inspection
  const cookieFindings = [];
  const cookieList = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];

  for (const cookieStr of cookieList) {
    const parts = cookieStr.split(';').map(p => p.trim());
    const nameVal = parts[0] || '';
    const name = nameVal.split('=')[0];

    const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
    const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
    const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));
    const sameSiteVal = sameSitePart ? sameSitePart.split('=')[1].toLowerCase() : null;

    if (!hasSecure) {
      cookieFindings.push({
        level: 'warning',
        category: 'Insecure Cookie',
        title: `Cookie "${name}" missing Secure flag`,
        detail: 'Cookie can be transmitted over unencrypted HTTP connections, exposing session tokens to eavesdropping.',
        points: 15
      });
    }

    if (!hasHttpOnly && !name.toLowerCase().includes('csrf') && !name.toLowerCase().includes('token')) {
      cookieFindings.push({
        level: 'warning',
        category: 'Insecure Cookie',
        title: `Cookie "${name}" missing HttpOnly flag`,
        detail: 'Cookie is accessible to client-side scripts via document.cookie, making it vulnerable to XSS session hijacking.',
        points: 15
      });
    }

    if (!sameSiteVal || sameSiteVal === 'none' && !hasSecure) {
      cookieFindings.push({
        level: 'info',
        category: 'Insecure Cookie',
        title: `Cookie "${name}" missing strict SameSite policy`,
        detail: 'Lacks SameSite=Lax or SameSite=Strict protection, increasing vulnerability to Cross-Site Request Forgery (CSRF).',
        points: 5
      });
    }
  }

  return { findings: [...findings, ...cookieFindings], serverBanner, poweredBy, cookieCount: cookieList.length };
}

export async function runWebSecurityPillar(host, originUrl, headers, rawCookies) {
  const { findings: headerFindings, headerScore, hygieneGrade } = evaluateSecurityHeaders(headers);
  const { findings: bannerAndCookieFindings, serverBanner, poweredBy } = inspectServerAndCookies(headers, rawCookies);
  const { openPorts } = await scanPorts(host);
  const exposedPanels = await probeAdminPanelsAndFiles(originUrl);

  const findings = [...headerFindings, ...bannerAndCookieFindings];
  let riskScore = 100 - headerScore; // baseline risk from missing headers

  // Add findings for open dangerous ports
  for (const p of openPorts) {
    if (p.risk === 'high') {
      findings.push({
        level: 'high',
        category: 'Exposed Ports',
        title: `CRITICAL: Publicly accessible database/admin port ${p.port} (${p.service})`,
        detail: `Port ${p.port} (${p.desc}) is open to the public internet. Sensitive internal infrastructure must be firewalled.`,
        points: 35
      });
      riskScore += 35;
    } else if (p.risk === 'warning') {
      findings.push({
        level: 'warning',
        category: 'Exposed Ports',
        title: `Open non-standard port ${p.port} (${p.service})`,
        detail: `Port ${p.port} (${p.desc}) is publicly responsive.`,
        points: 10
      });
      riskScore += 10;
    }
  }

  // Add findings for exposed admin panels / sensitive files
  for (const ep of exposedPanels) {
    if (ep.confirmedLeak) {
      findings.push({
        level: 'high',
        category: 'Exposed Sensitive Files',
        title: `CRITICAL: Sensitive file exposed (${ep.path})`,
        detail: `Publicly accessible configuration or source file: "${ep.path}" (${ep.label}). Direct exposure of secrets or repository metadata.`,
        points: 50
      });
      riskScore += 50;
    } else if (ep.critical) {
      findings.push({
        level: 'high',
        category: 'Exposed Sensitive Files',
        title: `Sensitive endpoint responsive (${ep.path} - HTTP ${ep.status})`,
        detail: `Target endpoint "${ep.path}" (${ep.label}) returned HTTP ${ep.status}.`,
        points: 25
      });
      riskScore += 25;
    } else if (ep.path.includes('admin') || ep.path.includes('cpanel')) {
      findings.push({
        level: 'info',
        category: 'Admin Panel',
        title: `Administrative interface reachable (${ep.path})`,
        detail: `Administrative portal "${ep.path}" (${ep.label}) responded with HTTP ${ep.status}. Ensure multi-factor authentication (MFA) and rate limiting are enforced.`,
        points: 5
      });
    }
  }

  const finalScore = Math.min(Math.max(riskScore, 0), 100);

  return {
    pillar: 'Web Security Assessment',
    hygieneGrade,
    score: finalScore,
    riskLevel: finalScore >= 50 ? 'High' : finalScore >= 25 ? 'Moderate' : 'Low',
    serverBanner,
    poweredBy,
    openPorts,
    exposedPanels,
    findings
  };
}
