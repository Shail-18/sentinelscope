import fs from 'node:fs';
import path from 'node:path';
import supabase from './db-client.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'sentinel_store.json');

const INITIAL_REPORTS = [
  {
    id: 1,
    domain: 'paypa1.com',
    category: 'Phishing',
    severity: 'Critical',
    details: 'Visual homoglyph replacing lowercase "l" with digit "1". Fake login screen harvested user email, password, and credit card number.',
    status: 'Confirmed',
    upvotes: 18,
    downvotes: 0,
    created_at: new Date(Date.now() - 36 * 3600 * 1000).toISOString()
  },
  {
    id: 2,
    domain: 'secure-login-chase.com',
    category: 'Impersonation',
    severity: 'High',
    details: 'Typosquatting domain targeting Chase Bank customers. Sends SMS smishing lures asking victims to verify their debit card PIN.',
    status: 'Confirmed',
    upvotes: 12,
    downvotes: 1,
    created_at: new Date(Date.now() - 24 * 3600 * 1000).toISOString()
  },
  {
    id: 3,
    domain: 'update-appleid-verify.net',
    category: 'Malicious redirect',
    severity: 'High',
    details: 'Impersonates Apple Support notification. Uses HTTP meta-refresh redirect to bypass basic automated web crawler scanners.',
    status: 'Confirmed',
    upvotes: 9,
    downvotes: 0,
    created_at: new Date(Date.now() - 15 * 3600 * 1000).toISOString()
  },
  {
    id: 4,
    domain: 'metamask-restore-seed.io',
    category: 'Phishing',
    severity: 'Critical',
    details: 'Cryptocurrency drainer prompt requesting 12-word secret recovery seed phrase to unlock account.',
    status: 'Confirmed',
    upvotes: 24,
    downvotes: 0,
    created_at: new Date(Date.now() - 8 * 3600 * 1000).toISOString()
  },
  {
    id: 5,
    domain: 'cdn-fastdelivery-static.top',
    category: 'Other',
    severity: 'Medium',
    details: 'Suspicious new domain serving fake package tracking popups with hidden browser notification spam.',
    status: 'Under Review',
    upvotes: 1,
    downvotes: 0,
    created_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
  }
];

const INITIAL_SCANS = [
  {
    id: 1,
    domain: 'paypa1.com',
    url: 'https://paypa1.com',
    score: 92,
    verdict: 'High risk',
    pillarScores: {
      threatAnalysis: 95,
      webSecurity: 70,
      certificateValidation: 60,
      threatIntel: 90
    },
    findings: [
      { level: 'high', title: 'Typosquatting detected (PayPal)', detail: 'Engineered lookalike replacing "l" with digit "1".' },
      { level: 'high', title: 'CRITICAL: Verified phishing on PhishTank', detail: 'Identified across external threat feeds as credential harvester.' },
      { level: 'high', title: 'COMMUNITY BLOCKLIST: Confirmed threat', detail: '18 community confirmation votes.' }
    ],
    certificate: {
      subject: 'paypa1.com',
      issuer: 'Let\'s Encrypt',
      valid_from: new Date(Date.now() - 5 * 86400000).toISOString(),
      valid_to: new Date(Date.now() + 85 * 86400000).toISOString(),
      fingerprint256: '8F:E2:4C:19:67:3A:9D:B1:05:44:81:CC:E4:F2:70:A9:1B:3E:55:01:29:43:AA:BC:09:66:31:DE:F7:88:20:11'
    },
    http_status: 200,
    created_at: new Date(Date.now() - 12 * 3600 * 1000).toISOString()
  },
  {
    id: 2,
    domain: 'github.com',
    url: 'https://github.com',
    score: 5,
    verdict: 'Low risk',
    pillarScores: {
      threatAnalysis: 0,
      webSecurity: 10,
      certificateValidation: 0,
      threatIntel: 0
    },
    findings: [
      { level: 'good', title: 'Clean across external intelligence feeds', detail: 'No entries on URLhaus, OpenPhish, or Safe Browsing.' },
      { level: 'good', title: 'Publicly trusted certificate chain', detail: 'Issued by DigiCert Global Root G2.' },
      { level: 'good', title: 'HSTS enabled with preload', detail: 'Strict-Transport-Security enforced with includeSubDomains.' },
      { level: 'good', title: 'Established domain age (16+ years)', detail: 'Registered in 2007.' }
    ],
    certificate: {
      subject: 'github.com',
      issuer: 'DigiCert Inc',
      valid_from: new Date(Date.now() - 60 * 86400000).toISOString(),
      valid_to: new Date(Date.now() + 300 * 86400000).toISOString(),
      fingerprint256: '3E:91:AA:56:88:C1:44:D0:12:90:EE:FF:55:23:71:09:88:76:34:11:00:81:65:21:DD:99:A3:42:10:87:66:33'
    },
    http_status: 200,
    created_at: new Date(Date.now() - 4 * 3600 * 1000).toISOString()
  }
];

function loadLocalStore() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
      const initialData = {
        reports: INITIAL_REPORTS,
        scans: INITIAL_SCANS,
        nextReportId: 10,
        nextScanId: 10
      };
      fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), 'utf-8');
      return initialData;
    }
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return { reports: INITIAL_REPORTS, scans: INITIAL_SCANS, nextReportId: 10, nextScanId: 10 };
  }
}

function saveLocalStore(data) {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write local store:', err);
  }
}

export async function getScans() {
  if (process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      const { data, error } = await supabase.from('security_scans').select('*').order('created_at', { ascending: false }).limit(50);
      if (!error && Array.isArray(data) && data.length > 0) return data;
    } catch {}
  }
  const store = loadLocalStore();
  return store.scans;
}

export async function saveScan(scanRecord) {
  let saved = null;
  if (process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      const { data, error } = await supabase.from('security_scans').insert(scanRecord).select('*').single();
      if (!error && data) saved = data;
    } catch {}
  }

  const store = loadLocalStore();
  const newScan = {
    ...scanRecord,
    id: store.nextScanId++ || Date.now(),
    created_at: new Date().toISOString()
  };
  store.scans.unshift(newScan);
  saveLocalStore(store);
  return saved || newScan;
}

export async function getReports() {
  if (process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      const { data, error } = await supabase.from('threat_reports').select('*').order('created_at', { ascending: false }).limit(50);
      if (!error && Array.isArray(data) && data.length > 0) return data;
    } catch {}
  }
  const store = loadLocalStore();
  return store.reports;
}

export async function saveReport(reportInput) {
  const store = loadLocalStore();
  const newReport = {
    id: store.nextReportId++ || Date.now(),
    domain: String(reportInput.domain).trim().toLowerCase(),
    category: reportInput.category || 'Phishing',
    severity: reportInput.severity || 'High',
    details: reportInput.details || '',
    status: 'Under Review',
    upvotes: 1,
    downvotes: 0,
    created_at: new Date().toISOString()
  };

  store.reports.unshift(newReport);
  saveLocalStore(store);

  if (process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      await supabase.from('threat_reports').insert({
        domain: newReport.domain,
        category: newReport.category,
        details: newReport.details,
        status: newReport.status
      });
    } catch {}
  }

  return newReport;
}

export async function voteReport(reportId, type = 'up') {
  const store = loadLocalStore();
  const idNum = Number(reportId);
  const report = store.reports.find(r => r.id === idNum);
  if (!report) throw new Error('Report not found');

  if (type === 'up') {
    report.upvotes = (report.upvotes || 0) + 1;
  } else if (type === 'down') {
    report.downvotes = (report.downvotes || 0) + 1;
  }

  const net = (report.upvotes || 0) - (report.downvotes || 0);
  if (net >= 2) {
    report.status = 'Confirmed';
  } else if (net <= -2) {
    report.status = 'False Positive';
  } else {
    report.status = 'Under Review';
  }

  saveLocalStore(store);
  return report;
}

export async function getCommunityBlocklist() {
  const reports = await getReports();
  const confirmed = reports.filter(r => r.status === 'Confirmed' || ((r.upvotes || 0) - (r.downvotes || 0) >= 2));
  return confirmed.map(r => ({
    domain: r.domain,
    category: r.category,
    severity: r.severity || 'High',
    upvotes: r.upvotes,
    downvotes: r.downvotes,
    confirmed_at: r.created_at,
    details: r.details
  }));
}

export async function exportBlocklist(format = 'txt') {
  const list = await getCommunityBlocklist();
  if (format === 'json') {
    return {
      contentType: 'application/json',
      filename: `sentinelscope-blocklist-${Date.now()}.json`,
      content: JSON.stringify({
        generated_at: new Date().toISOString(),
        feed: 'SentinelScope Community Blocklist',
        total_threats: list.length,
        indicators: list
      }, null, 2)
    };
  }

  if (format === 'csv') {
    const rows = ['Domain,Category,Severity,Upvotes,ConfirmedAt,Details'];
    for (const item of list) {
      const cleanDetails = (item.details || '').replace(/"/g, '""');
      rows.push(`"${item.domain}","${item.category}","${item.severity}",${item.upvotes},"${item.confirmed_at}","${cleanDetails}"`);
    }
    return {
      contentType: 'text/csv',
      filename: `sentinelscope-blocklist-${Date.now()}.csv`,
      content: rows.join('\n')
    };
  }

  // Default: Plain text DNS / hosts file format
  const lines = [
    '# SentinelScope Collaborative Threat Intelligence Community Blocklist',
    `# Export Date: ${new Date().toISOString()}`,
    `# Active malicious indicators: ${list.length}`,
    '# Format: 0.0.0.0 <domain>',
    ''
  ];
  for (const item of list) {
    lines.push(`0.0.0.0 ${item.domain}`);
  }
  return {
    contentType: 'text/plain',
    filename: `sentinelscope-blocklist-${Date.now()}.txt`,
    content: lines.join('\n')
  };
}

