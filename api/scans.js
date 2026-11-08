import net from 'node:net';
import https from 'node:https';
import dns from 'node:dns/promises';
import { runThreatAnalysisPillar } from './pillars/threat-analysis.js';
import { runWebSecurityPillar } from './pillars/web-security.js';
import { runCertificateValidationPillar } from './pillars/certificate-validation.js';
import { runThreatIntelligencePillar } from './pillars/threat-intel.js';
import { getScans, saveScan, getReports } from './storage.js';

function publicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a, b, c] = ip.split('.').map(Number);
  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0 && c === 113)
  );
}

async function quickOriginProbe(host) {
  try {
    const addresses = await dns.resolve4(host).catch(() => []);
    const ip = addresses.length ? addresses[0] : null;

    return await new Promise((resolve) => {
      const opts = {
        hostname: host,
        port: 443,
        path: '/',
        method: 'HEAD',
        servername: host,
        rejectUnauthorized: false,
        headers: {
          'User-Agent': 'Mozilla/5.0 SentinelScope/2.0 Security Scanner',
          Accept: '*/*'
        },
        timeout: 5000
      };
      if (ip && publicIPv4(ip)) {
        opts.lookup = (_h, _o, cb) => cb(null, ip, 4);
      }

      const req = https.request(opts, (res) => {
        const out = {
          status: res.statusCode,
          headers: res.headers || {},
          rawCookies: res.headers['set-cookie'] || []
        };
        res.destroy();
        resolve(out);
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ status: null, headers: {}, rawCookies: [] });
      });

      req.on('error', () => {
        resolve({ status: null, headers: {}, rawCookies: [] });
      });

      req.end();
    });
  } catch {
    return { status: null, headers: {}, rawCookies: [] };
  }
}

function parseTarget(input) {
  if (typeof input !== 'string' || !input.trim() || input.length > 2048) {
    throw new Error('Enter a valid website URL or domain.');
  }
  let raw = input.trim();
  if (!raw.includes('://')) raw = 'https://' + raw;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('Enter a valid website URL.');
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP or HTTPS URLs are supported.');
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host.includes('.') || net.isIP(host) === 4 || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Enter a valid public domain name (e.g. example.com).');
  }

  return { host, original: url.href, urlObj: url, protocol: url.protocol };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    if (req.method === 'GET') {
      const scans = await getScans();
      return res.status(200).json(scans);
    }

    if (req.method === 'POST') {
      let target;
      try {
        target = parseTarget(req.body?.url);
      } catch (e) {
        return res.status(400).json({ error: e.message });
      }

      // Step 1: Initial Origin Probe (Headers, Cookies, Status)
      const originProbe = await quickOriginProbe(target.host);
      const communityReports = await getReports();

      // Step 2: Run All 4 Pillars Concurrently
      const [threatAnalysis, certValidation, threatIntel, webSecurity] = await Promise.all([
        runThreatAnalysisPillar(target.urlObj),
        runCertificateValidationPillar(target.host),
        runThreatIntelligencePillar(target.host, target.original, communityReports),
        runWebSecurityPillar(target.host, `https://${target.host}`, originProbe.headers, originProbe.rawCookies)
      ]);

      // Step 3: Compute Multi-Pillar Composite Risk Score
      // Weights: Threat Analysis 35%, External Intel 25%, Web Security 20%, Cert Validation 20%
      const compositeScore = Math.round(
        (threatAnalysis.score * 0.35) +
        (threatIntel.score * 0.25) +
        (webSecurity.score * 0.20) +
        (certValidation.score * 0.20)
      );

      const finalScore = Math.min(Math.max(compositeScore, 0), 100);

      // Determine Verdict
      let verdict = 'Low risk';
      if (
        finalScore >= 45 ||
        threatIntel.externalMatches.length > 0 ||
        threatAnalysis.score >= 50 ||
        threatIntel.community.isBlocklisted
      ) {
        verdict = 'High risk';
      } else if (finalScore >= 20 || threatAnalysis.score >= 25 || webSecurity.score >= 40) {
        verdict = 'Needs review';
      }

      // Combine structured findings across all 4 pillars
      const combinedFindings = [
        ...threatAnalysis.findings,
        ...webSecurity.findings,
        ...certValidation.findings,
        ...threatIntel.findings
      ];

      const scanRecord = {
        domain: target.host,
        url: target.original,
        score: finalScore,
        verdict,
        http_status: originProbe.status,
        pillarScores: {
          threatAnalysis: threatAnalysis.score,
          webSecurity: webSecurity.score,
          certificateValidation: certValidation.score,
          threatIntel: threatIntel.score
        },
        pillars: {
          threatAnalysis,
          webSecurity,
          certificateValidation: certValidation,
          threatIntel
        },
        certificate: certValidation.certificate,
        findings: combinedFindings
      };

      const saved = await saveScan(scanRecord);
      return res.status(201).json(saved);
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('Scan API handler error:', err);
    return res.status(500).json({ error: err.message || 'Assessment failed.' });
  }
}
