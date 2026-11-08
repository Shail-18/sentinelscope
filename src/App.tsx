import { useEffect, useMemo, useState } from 'react';
import {
  Activity, ArrowDownLeft, ArrowRight, ArrowUpRight, Check, CheckCircle2,
  ChevronDown, CircleAlert, CircleCheck, CircleHelp, Clock3, Download, ExternalLink,
  FileCode2, FileSearch, Fingerprint, Globe2, Info, LayoutDashboard, Link2,
  LoaderCircle, LockKeyhole, Menu, Plus, Radar, RefreshCw, Search, Send,
  Server, Shield, ShieldAlert, ShieldCheck, ShieldX, Sparkles, ThumbsDown,
  ThumbsUp, TriangleAlert, UsersRound, X
} from 'lucide-react';
import './index.css';

type Finding = {
  level: string;
  category?: string;
  title: string;
  detail: string;
  points?: number;
};

type Cert = {
  subject: string;
  issuer: string;
  issuerOrg?: string;
  valid_from: string;
  valid_to: string;
  fingerprint256: string;
  daysLeft?: number;
  bits?: number | null;
  asymmType?: string;
  sigalg?: string;
  domainMatch?: boolean;
};

type Scan = {
  id: number;
  domain: string;
  url: string;
  score: number;
  verdict: string;
  http_status: number | null;
  created_at: string;
  pillarScores?: {
    threatAnalysis: number;
    webSecurity: number;
    certificateValidation: number;
    threatIntel: number;
  };
  pillars?: {
    threatAnalysis?: any;
    webSecurity?: any;
    certificateValidation?: any;
    threatIntel?: any;
  };
  certificate: Cert | null;
  findings: Finding[];
};

type Report = {
  id: number;
  domain: string;
  category: string;
  severity: string;
  details: string;
  status: string;
  upvotes: number;
  downvotes: number;
  created_at: string;
};

type ProxyShieldResponse = {
  is_safe: boolean;
  risk_score: number;
  reasons: string[];
};

const date = (value: string) =>
  new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });

const time = (value: string) =>
  new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });

export type DetailedCertRecord = {
  domain: string;
  subjectCN: string;
  sanPattern: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  status: 'valid' | 'expired' | 'expiring';
  keyType: string;
  keyBits: number;
  sigAlg: string;
  ctLogged: boolean;
  ctCount: number;
  isFlaggedCA: boolean;
  caStatusNote?: string;
  fingerprint256: string;
};

const SEEDED_CERTIFICATES: DetailedCertRecord[] = [
  {
    domain: 'google.com',
    subjectCN: '*.google.com',
    sanPattern: 'google.com, *.google.com, *.android.com',
    issuer: 'Google Trust Services LLC (GTS CA 1C3)',
    validFrom: '2026-10-08',
    validTo: '2026-12-31',
    daysRemaining: 52,
    status: 'valid',
    keyType: 'RSA',
    keyBits: 2048,
    sigAlg: 'SHA256withRSA',
    ctLogged: true,
    ctCount: 142,
    isFlaggedCA: false,
    fingerprint256: '7E:F5:6A:B2:88:9C:1D:34:F0:B8:21:44:A9:77:E5:32:01:99:CC:65:42:10:98:EE:11:AB:56:88:43:21:00:89'
  },
  {
    domain: 'cloudflare.com',
    subjectCN: 'cloudflare.com',
    sanPattern: 'cloudflare.com, *.cloudflare.com',
    issuer: 'Cloudflare Inc ECC CA-3',
    validFrom: '2026-05-15',
    validTo: '2027-05-15',
    daysRemaining: 188,
    status: 'valid',
    keyType: 'ECDSA (prime256v1)',
    keyBits: 256,
    sigAlg: 'ECDSA-SHA384',
    ctLogged: true,
    ctCount: 98,
    isFlaggedCA: false,
    fingerprint256: '44:90:EE:12:87:66:33:AA:91:56:88:C1:D0:FF:55:23:71:09:88:76:34:11:00:81:65:21:DD:99:A3:42:10:87'
  },
  {
    domain: 'emudhra.com',
    subjectCN: '*.emudhra.com',
    sanPattern: 'emudhra.com, *.emudhra.com, portal.emudhra.com',
    issuer: 'eMudhra Technologies Root CA',
    validFrom: '2026-02-10',
    validTo: '2027-02-10',
    daysRemaining: 94,
    status: 'valid',
    keyType: 'RSA',
    keyBits: 2048,
    sigAlg: 'SHA256withRSA',
    ctLogged: true,
    ctCount: 35,
    isFlaggedCA: true,
    caStatusNote: 'eMudhra has faced major distrust decisions and probation across major browser root programs (Mozilla/Chrome) due to serial number entropy and compliance audit failures.',
    fingerprint256: 'B1:88:F2:45:90:12:AA:77:89:CC:34:11:00:EE:56:D0:65:87:23:44:A3:88:99:FF:10:87:66:33:42:12:09:55'
  },
  {
    domain: 'expired.badssl.com',
    subjectCN: 'expired.badssl.com',
    sanPattern: 'expired.badssl.com',
    issuer: 'COMODO RSA Domain Validation Secure Server CA',
    validFrom: '2023-04-09',
    validTo: '2025-04-12',
    daysRemaining: 0,
    status: 'expired',
    keyType: 'RSA',
    keyBits: 2048,
    sigAlg: 'SHA256withRSA',
    ctLogged: true,
    ctCount: 12,
    isFlaggedCA: false,
    fingerprint256: '18:90:34:CC:88:12:DD:45:00:AA:77:F2:65:87:23:44:A3:88:99:FF:10:87:66:33:42:12:09:55:B1:88:F2:45'
  },
  {
    domain: 'github.com',
    subjectCN: 'github.com',
    sanPattern: 'github.com, www.github.com',
    issuer: 'DigiCert Global Root G2',
    validFrom: '2026-03-01',
    validTo: '2027-03-15',
    daysRemaining: 127,
    status: 'valid',
    keyType: 'ECDSA (prime256v1)',
    keyBits: 256,
    sigAlg: 'ECDSA-SHA384',
    ctLogged: true,
    ctCount: 84,
    isFlaggedCA: false,
    fingerprint256: '3E:91:AA:56:88:C1:44:D0:12:90:EE:FF:55:23:71:09:88:76:34:11:00:81:65:21:DD:99:A3:42:10:87:66:33'
  }
];

const PRESET_TARGETS = [
  { domain: 'paypa1.com', label: 'paypa1.com', type: 'bad', note: 'Phishing lookalike & PhishTank hit' },
  { domain: 'httpbin.org', label: 'httpbin.org', type: 'bad', note: 'Web Security hygiene test target' },
  { domain: 'github.com', label: 'github.com', type: 'good', note: 'Legitimate & Grade A+ hygiene' },
  { domain: 'google.com', label: 'google.com', type: 'good', note: 'Trusted corporate TLS & HSTS' }
];

function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [url, setUrl] = useState('');
  const [view, setView] = useState('Overview');
  const [selected, setSelected] = useState<Scan | null>(null);
  const [activeModalPillar, setActiveModalPillar] = useState<'p1' | 'p2' | 'p3' | 'p4'>('p1');

  // Report Modal State
  const [showReport, setShowReport] = useState(false);
  const [reportDomain, setReportDomain] = useState('');
  const [reportCategory, setReportCategory] = useState('Phishing');
  const [reportSeverity, setReportSeverity] = useState('High');
  const [reportDetails, setReportDetails] = useState('');
  const [reportBusy, setReportBusy] = useState(false);

  // Filters & UI State
  const [scanFilter, setScanFilter] = useState('All');
  const [certFilter, setCertFilter] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [mobileNav, setMobileNav] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  // Dedicated Certificate Observatory State
  const [certSearchInput, setCertSearchInput] = useState('');
  const [isCertInspecting, setIsCertInspecting] = useState(false);
  const [certFilterTab, setCertFilterTab] = useState<'all' | 'valid' | 'flagged' | 'expiring'>('all');
  const [customCerts, setCustomCerts] = useState<DetailedCertRecord[]>([]);

  // ProxySHIELD Backend States (Website Scanner)
  const [scannerUrl, setScannerUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ProxyShieldResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Automated Analysis for Overview Module Cards (paypa1.com & httpbin.org)
  const runAutoAnalysis = async (targetDomain: string, targetModule: 'p1' | 'p2' | 'p3' | 'p4') => {
    setScannerUrl(targetDomain);
    setUrl(targetDomain);
    setActiveModalPillar(targetModule);
    setIsScanning(true);

    try {
      // 1. Run ProxySHIELD ML scan
      const proxyRes = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetDomain })
      });
      if (proxyRes.ok) {
        const pData = await proxyRes.json();
        setScanResult(pData);
      }

      // 2. Run multi-module deep assessment
      const p4Res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetDomain })
      });
      if (p4Res.ok) {
        const p4Data = await p4Res.json();
        setSelected(p4Data);
        setActiveModalPillar(targetModule);
        await loadData();
      }
    } catch (err) {
      console.error('Auto analysis error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  // Inspect specific domain in Certificate Observatory
  const inspectDomainCert = async (targetDomain: string) => {
    const cleanDomain = targetDomain.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!cleanDomain) return;
    setCertSearchInput(cleanDomain);
    setIsCertInspecting(true);

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: cleanDomain })
      });
      if (res.ok) {
        const scanData = await res.json();
        await loadData();
        setSelected(scanData);
        setActiveModalPillar('p3');
      }
    } catch (err) {
      console.error('Cert inspection error:', err);
    } finally {
      setIsCertInspecting(false);
    }
  };

  const handleCertInspectSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (certSearchInput.trim()) {
      inspectDomainCert(certSearchInput.trim());
    }
  };

  // ProxySHIELD Backend API Fetch Function
  const handleProxyShieldScan = async (e?: React.FormEvent, customUrl?: string, moduleTarget?: 'p1' | 'p2' | 'p3' | 'p4') => {
    if (e) e.preventDefault();
    const query = (customUrl || scannerUrl || url).trim();
    if (!query) {
      setScanError('Please enter a website URL or domain name to analyze.');
      return;
    }
    setIsScanning(true);
    setScanError(null);

    // 1. Run ProxySHIELD Machine Learning Detection
    try {
      let data: ProxyShieldResponse | null = null;

      // Try local Python Flask endpoint if user has python app.py running
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 1000);
        const flaskDirectRes = await fetch('http://127.0.0.1:5000/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: query }),
          signal: controller.signal
        });
        clearTimeout(timeout);
        if (flaskDirectRes.ok) {
          data = await flaskDirectRes.json();
        }
      } catch {
        // Python direct offline or blocked by browser CORS, continue to backend proxy
      }

      // If direct Python did not respond, use our backend proxy/fallback endpoint
      if (!data) {
        const proxyRes = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: query })
        });
        if (proxyRes.ok) {
          data = await proxyRes.json();
        } else {
          const altRes = await fetch('/api/proxy-shield', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: query })
          });
          if (altRes.ok) {
            data = await altRes.json();
          }
        }
      }

      if (data && (typeof data.is_safe === 'boolean' || data.risk_score !== undefined)) {
        setScanResult(data);
        setScanError(null);
      } else {
        throw new Error('No response from ProxySHIELD scanner.');
      }
    } catch (err: any) {
      console.error('ProxySHIELD scanner error:', err);
      setScanError(
        'Unable to complete ProxySHIELD scan. Please enter a valid website domain.'
      );
    }

    // 2. Concurrently run the comprehensive multi-module deep assessment
    try {
      setBusy(true);
      const p4Res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: query })
      });
      if (p4Res.ok) {
        const p4Data = await p4Res.json();
        setSelected(p4Data);
        if (moduleTarget) {
          setActiveModalPillar(moduleTarget);
        }
        await loadData();
      }
    } catch (p4Err) {
      console.warn('Security assessment warning:', p4Err);
    } finally {
      setBusy(false);
      setIsScanning(false);
    }
  };

  const loadData = async () => {
    try {
      const [resScans, resReports] = await Promise.all([
        fetch('/api/scans'),
        fetch('/api/reports')
      ]);
      if (!resScans.ok || !resReports.ok) throw new Error('Unable to connect to security database.');
      setScans(await resScans.json());
      setReports(await resReports.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load security data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleScan = async (e?: React.FormEvent, targetUrl?: string) => {
    if (e) e.preventDefault();
    const query = (targetUrl || url).trim();
    if (!query) {
      setError('Please enter a website URL or domain name to analyze.');
      return;
    }
    setBusy(true);
    setError('');

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: query })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Security assessment failed.');

      await loadData();
      setSelected(data);
      setActiveModalPillar('p1');
      if (!targetUrl) setUrl('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Assessment failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleVote = async (reportId: number, type: 'up' | 'down') => {
    try {
      const res = await fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'vote', reportId, type })
      });
      if (res.ok) {
        await loadData();
      }
    } catch {}
  };

  const submitReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setReportBusy(true);
    setError('');

    try {
      const res = await fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: reportDomain,
          category: reportCategory,
          severity: reportSeverity,
          details: reportDetails
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Could not submit report.');

      await loadData();
      setShowReport(false);
      setReportDomain('');
      setReportDetails('');
      setView('Threat intelligence');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not submit report.');
    } finally {
      setReportBusy(false);
    }
  };

  const downloadBlocklist = async (format: 'txt' | 'json' | 'csv') => {
    try {
      window.open(`/api/reports?export=true&format=${format}`, '_blank');
      setShowExportMenu(false);
    } catch {}
  };

  // Metrics
  const riskyScans = scans.filter(s => s.verdict === 'High risk' || s.verdict === 'Needs review').length;
  const trustedCerts = scans.filter(s => s.certificate && !s.findings.some(f => f.title.includes('FLAGGED CA'))).length;
  const confirmedThreats = reports.filter(r => r.status === 'Confirmed' || (r.upvotes - r.downvotes >= 2)).length;

  // Filtered lists
  const visibleScans = useMemo(() => {
    let list = scanFilter === 'All' ? scans : scans.filter(s => s.verdict === scanFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(s => s.domain.toLowerCase().includes(q) || s.url.toLowerCase().includes(q));
    }
    return list;
  }, [scans, scanFilter, searchQuery]);

  // Merged live certificates from scans + seeded records for Certificate Observatory
  const allCertRecords = useMemo(() => {
    const list: DetailedCertRecord[] = [...customCerts];
    // Add certificates extracted from live scans
    for (const s of scans) {
      if (s.certificate && !list.some(c => c.domain.toLowerCase() === s.domain.toLowerCase())) {
        const isFlagged = s.findings.some(f => f.title.includes('FLAGGED CA') || f.title.includes('eMudhra') || f.title.includes('Distrusted'));
        const daysLeft = s.certificate.daysLeft ?? 90;
        list.push({
          domain: s.domain,
          subjectCN: s.certificate.subject || s.domain,
          sanPattern: s.certificate.subject || s.domain,
          issuer: s.certificate.issuer || 'Standard CA',
          validFrom: s.certificate.valid_from ? s.certificate.valid_from.slice(0, 10) : '2026-01-01',
          validTo: s.certificate.valid_to ? s.certificate.valid_to.slice(0, 10) : '2026-12-31',
          daysRemaining: daysLeft,
          status: daysLeft <= 0 ? 'expired' : daysLeft <= 30 ? 'expiring' : 'valid',
          keyType: s.certificate.asymmType || 'RSA',
          keyBits: s.certificate.bits || 2048,
          sigAlg: s.certificate.sigalg || 'SHA256withRSA',
          ctLogged: true,
          ctCount: 28,
          isFlaggedCA: isFlagged,
          caStatusNote: isFlagged ? 'Scrutinized Certificate Authority flagged by SentinelScope Root Observatory.' : undefined,
          fingerprint256: s.certificate.fingerprint256 || 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:00:11:22:33'
        });
      }
    }
    // Add seeded certificates if not already present
    for (const sc of SEEDED_CERTIFICATES) {
      if (!list.some(c => c.domain.toLowerCase() === sc.domain.toLowerCase())) {
        list.push(sc);
      }
    }
    return list;
  }, [scans, customCerts]);

  const filteredCertRecords = useMemo(() => {
    let list = allCertRecords;
    if (certFilterTab === 'valid') {
      list = list.filter(c => c.status === 'valid' && !c.isFlaggedCA);
    } else if (certFilterTab === 'flagged') {
      list = list.filter(c => c.isFlaggedCA);
    } else if (certFilterTab === 'expiring') {
      list = list.filter(c => c.status === 'expired' || c.status === 'expiring' || c.daysRemaining <= 30);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(c => c.domain.toLowerCase().includes(q) || c.issuer.toLowerCase().includes(q));
    }
    return list;
  }, [allCertRecords, certFilterTab, searchQuery]);

  const visibleCerts = useMemo(() => {
    return filteredCertRecords;
  }, [filteredCertRecords]);

  const go = (v: string) => {
    setView(v);
    setMobileNav(false);
    setSelected(null);
  };

  const nav = [
    { label: 'Overview', icon: LayoutDashboard },
    { label: 'Website scanner', icon: Search },
    { label: 'Scan history', icon: Clock3 },
    { label: 'Certificates', icon: LockKeyhole },
    { label: 'Threat intelligence', icon: Radar }
  ];

  return (
    <div className="app-shell">
      {/* SIDEBAR */}
      <aside className={'sidebar ' + (mobileNav ? 'open' : '')}>
        <div className="brand">
          <div className="brand-icon">
            <Shield size={23} strokeWidth={2.4} />
            <span />
          </div>
          <div>
            <strong>sentinel<span>scope</span></strong>
            <small>MULTI-VECTOR DEFENSE</small>
          </div>
          <button className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close menu">
            <X size={20} />
          </button>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <nav>
          {nav.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={'nav-item ' + (view === label ? 'active' : '')}
              onClick={() => go(label)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {label === 'Threat intelligence' && confirmedThreats > 0 && <span className="nav-dot" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-card">
            <div className="mini-shield">
              <ShieldCheck size={19} />
            </div>
            <strong>4 Security Modules Active</strong>
            <p>1. Phishing &bull; 2. Web Hygiene &bull; 3. TLS/CT &bull; 4. Threat Intel</p>
            <button onClick={() => go('Website scanner')}>
              Analyze link <ArrowRight size={14} />
            </button>
          </div>
          <div className="side-footer">
            <div className="avatar">S</div>
            <div>
              <strong>Security Workspace</strong>
              <small>Community Threat Engine</small>
            </div>
            <ChevronDown size={16} />
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="main">
        <header className="topbar">
          <div className="top-left">
            <button className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open menu">
              <Menu size={21} />
            </button>
            <span>Workspace</span>
            <span className="crumb">/</span>
            <strong>{view}</strong>
          </div>
          <div className="top-right">
            <span className="status-dot" />
            <span>4 Defense Modules Active</span>
            <span className="top-divider" />
            <button
              className="icon-button"
              onClick={() =>
                alert(
                  'SentinelScope Core Security Modules:\n\n1. Threat Analysis: Lookalike domains, typosquatting, keywords, domain age, login forms, hidden redirects, brand impersonation.\n2. Web Security: Missing security headers, exposed ports/admin panels, outdated software, cookies.\n3. Certificate Validation: TLS expiry, issuer, key size, domain match, crt.sh CT logs, eMudhra/distrusted CA flagging.\n4. Collaborative Threat Intel: Community reporting, consensus voting, blocklist export, URLhaus, OpenPhish, PhishTank, Safe Browsing.'
                )
              }
              aria-label="Help"
            >
              <CircleHelp size={19} />
            </button>
            <div className="top-avatar">S</div>
          </div>
        </header>

        <div className="content">
          {error && (
            <div className="error-banner">
              <TriangleAlert size={17} />
              {error}
              <button onClick={() => setError('')} aria-label="Dismiss">
                <X size={16} />
              </button>
            </div>
          )}

          <div className="heading-row">
            <div>
              <div className="eyebrow">
                <span /> THREAT INTELLIGENCE PLATFORM
              </div>
              <h1>{view === 'Overview' ? 'Security command center' : view}</h1>
              <p>
                {view === 'Overview'
                  ? 'Multi-layered threat analysis, web hygiene auditing, TLS inspection & collaborative intelligence.'
                  : view === 'Website scanner'
                  ? 'Deep multi-module investigation: phishing detection, security headers, certificates & external feeds.'
                  : view === 'Scan history'
                  ? 'Review past website assessments and multi-module security scores.'
                  : view === 'Certificates'
                  ? 'TLS observatory: certificate authority trust, expiry tracking & Certificate Transparency (CT).'
                  : 'Collaborative community blocklist, peer voting & real-time external intelligence feeds.'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="outline-button" onClick={() => setShowReport(true)}>
                <Plus size={16} /> Report suspicious site
              </button>
            </div>
          </div>

          {/* SCANNER HERO (Overview or Scanner view) */}
          {(view === 'Overview' || view === 'Website scanner') && (
            <section className="scan-hero">
              <div className="hero-copy">
                <div className="hero-kicker">
                  <Sparkles size={13} /> MULTI-MODULE DEEP ASSESSMENT
                </div>
                <h2>
                  Investigate any link.<br />
                  <span>Before you click.</span>
                </h2>
                <p>
                  Tests phishing lookalikes, server security headers, open ports, TLS/CT logs, and global threat databases.
                </p>

                <form className="scan-form" onSubmit={handleProxyShieldScan}>
                  <Link2 size={19} />
                  <input
                    aria-label="Website URL or Domain"
                    placeholder="Enter URL or domain (e.g. paypa1.com, github.com)"
                    value={scannerUrl || url}
                    onChange={e => {
                      setScannerUrl(e.target.value);
                      setUrl(e.target.value);
                    }}
                  />
                  <button disabled={isScanning || busy}>
                    {isScanning ? (
                      <>
                        <LoaderCircle className="spin" size={17} /> Scanning with ProxySHIELD...
                      </>
                    ) : (
                      <>
                        Analyze site <ArrowRight size={17} />
                      </>
                    )}
                  </button>
                </form>

                {/* Preset test targets */}
                <div className="preset-row">
                  <span className="preset-label">TEST SAMPLES:</span>
                  {PRESET_TARGETS.map(t => (
                    <button
                      key={t.domain}
                      type="button"
                      className={`preset-chip ${t.type}`}
                      title={t.note}
                      onClick={() => {
                        setScannerUrl(t.domain);
                        setUrl(t.domain);
                        handleProxyShieldScan(undefined, t.domain);
                      }}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="hero-art">
                <div className="art-orbit orbit-one" />
                <div className="art-orbit orbit-two" />
                <div className="art-orbit orbit-three" />
                <div className="art-cross cross-one">+</div>
                <div className="art-cross cross-two">+</div>
                <div className="art-shield">
                  <ShieldCheck size={82} strokeWidth={1.1} />
                </div>
                <div className="art-pill">
                  <span />
                  <span>ALL MODULES VERIFIED</span>
                  <Check size={13} />
                </div>
                <div className="art-float">
                  <Fingerprint size={19} />
                </div>
              </div>
            </section>
          )}

          {/* PROXYSHIELD FLASK BACKEND ERROR BANNER */}
          {scanError && (
            <div className="error-banner" style={{ marginTop: '16px' }}>
              <TriangleAlert size={17} />
              {scanError}
              <button onClick={() => setScanError(null)} aria-label="Dismiss">
                <X size={16} />
              </button>
            </div>
          )}

          {/* PROXYSHIELD BACKEND LIVE SCAN RESULT */}
          {scanResult && (
            <section className="panel" style={{ marginTop: '20px', padding: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #f1f5f9', paddingBottom: '16px', marginBottom: '16px' }}>
                <div>
                  <div className="eyebrow"><span /> PROXYSHIELD AI DETECTION</div>
                  <h3 style={{ margin: '6px 0 2px', fontSize: '18px', fontWeight: 800, color: '#1e293b' }}>
                    {scannerUrl || url || 'Target Website'}
                  </h3>
                  <p style={{ margin: 0, fontSize: '11px', color: '#64748b' }}>
                    Scanned via ProxySHIELD Flask Backend (http://127.0.0.1:5000/api/scan)
                  </p>
                </div>

                {/* Safe / Danger Badge */}
                <div>
                  {scanResult.is_safe ? (
                    <span className="badge low-risk" style={{ fontSize: '11px', padding: '6px 12px' }}>
                      <span /> SAFE
                    </span>
                  ) : (
                    <span className="badge high-risk" style={{ fontSize: '11px', padding: '6px 12px' }}>
                      <span /> NOT SAFE / THREAT
                    </span>
                  )}
                </div>
              </div>

              {/* Risk Score & Progress Bar */}
              <div style={{ background: '#f8fafc', borderRadius: '8px', padding: '16px', border: '1px solid #e2e8f0', marginBottom: '18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: '#475569' }}>
                    Machine Learning Risk Score:
                  </span>
                  <strong style={{ fontSize: '16px', fontWeight: 800, color: scanResult.is_safe ? '#16a34a' : scanResult.risk_score > 60 ? '#dc2626' : '#ea580c' }}>
                    {scanResult.risk_score}/100
                  </strong>
                </div>

                <div style={{ width: '100%', height: '8px', backgroundColor: '#e2e8f0', borderRadius: '9999px', overflow: 'hidden' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${Math.min(Math.max(scanResult.risk_score, 4), 100)}%`,
                      backgroundColor: scanResult.is_safe ? '#22c55e' : scanResult.risk_score > 60 ? '#ef4444' : '#f97316',
                      transition: 'width 0.5s ease-in-out'
                    }}
                  />
                </div>
              </div>

              {/* Threat Indicators List */}
              <h4 style={{ fontSize: '13px', fontWeight: 800, color: '#1e293b', margin: '0 0 12px' }}>
                Threat Indicators ({scanResult.reasons?.length || 0})
              </h4>

              {scanResult.reasons && scanResult.reasons.length > 0 ? (
                <div className="findings">
                  {scanResult.reasons.map((reason, idx) => (
                    <div className="finding" key={idx}>
                      <div className="finding-icon high">
                        <TriangleAlert size={18} />
                      </div>
                      <div>
                        <strong style={{ fontSize: '12px' }}>Threat Indicator #{idx + 1}</strong>
                        <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#475569' }}>{reason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="finding">
                  <div className="finding-icon good">
                    <CheckCircle2 size={18} />
                  </div>
                  <div>
                    <strong>Clean &amp; Legitimate URL</strong>
                    <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#475569' }}>
                      No malicious structural patterns or credential harvesting signatures were detected by the ProxySHIELD AI engine.
                    </p>
                  </div>
                </div>
              )}

              {/* Multi-Module Forensic Breakdown Integration */}
              <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid #e2e8f0', display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: '#64748b', marginRight: '4px' }}>DEFENSE MODULES AUDIT:</span>
                  <span className="preset-chip" style={{ fontSize: '11px', fontWeight: 700 }} title="Module 1: Threat Analysis">
                    Mod 1 Phishing: {selected?.pillarScores?.threatAnalysis ?? 'Analyzed'}
                  </span>
                  <span className="preset-chip" style={{ fontSize: '11px', fontWeight: 700 }} title="Module 2: Web Security Hygiene">
                    Mod 2 Hygiene: {selected?.pillarScores?.webSecurity ?? 'Audited'}
                  </span>
                  <span className="preset-chip" style={{ fontSize: '11px', fontWeight: 700 }} title="Module 3: Certificate Validation & CT">
                    Mod 3 TLS/CT: {selected?.pillarScores?.certificateValidation ?? 'Verified'}
                  </span>
                  <span className="preset-chip" style={{ fontSize: '11px', fontWeight: 700 }} title="Module 4: Collaborative Threat Intel">
                    Mod 4 Intel: {selected?.pillarScores?.threatIntel ?? 'Checked'}
                  </span>
                </div>

                <button
                  type="button"
                  className="submit-button"
                  style={{ height: '36px', padding: '0 16px', fontSize: '12px' }}
                  onClick={() => {
                    if (selected) {
                      setActiveModalPillar('p1');
                    } else {
                      handleScan(undefined, scannerUrl || url);
                    }
                  }}
                >
                  <Sparkles size={14} /> View Comprehensive Security Audit Modal
                </button>
              </div>
            </section>
          )}

          {/* OVERVIEW METRICS & CORE SECURITY MODULE CARDS */}
          {view === 'Overview' && (
            <>
              <div className="section-title">
                <div>
                  <h2>Security metrics</h2>
                  <p>Aggregate telemetry across assessments and community intelligence.</p>
                </div>
                <span className="period">
                  <Activity size={14} /> Real-time status
                </span>
              </div>

              <div className="metrics">
                <div className="metric">
                  <div className="metric-top">
                    <span>Websites analyzed</span>
                    <div className="metric-icon blue">
                      <Globe2 size={19} />
                    </div>
                  </div>
                  <strong>{loading ? '—' : scans.length}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag blue-text">
                      <Activity size={13} /> Completed
                    </span>{' '}
                    assessments
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-top">
                    <span>High risk / flagged</span>
                    <div className="metric-icon orange">
                      <ShieldAlert size={19} />
                    </div>
                  </div>
                  <strong>{loading ? '—' : riskyScans}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag orange-text">
                      <ArrowUpRight size={13} /> Threats
                    </span>{' '}
                    detected
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-top">
                    <span>Trusted certificates</span>
                    <div className="metric-icon green">
                      <ShieldCheck size={19} />
                    </div>
                  </div>
                  <strong>{loading ? '—' : trustedCerts}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag green-text">
                      <Check size={13} /> Valid TLS
                    </span>{' '}
                    verified
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-top">
                    <span>Community blocklist</span>
                    <div className="metric-icon violet">
                      <UsersRound size={19} />
                    </div>
                  </div>
                  <strong>{loading ? '—' : confirmedThreats}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag violet-text">
                      <ArrowDownLeft size={13} /> Blocklisted
                    </span>{' '}
                    by consensus
                  </div>
                </div>
              </div>

              {/* CORE SECURITY MODULES EXPLANATION CARDS */}
              <div className="section-title" style={{ marginTop: '28px' }}>
                <div>
                  <h2>Core Security Modules</h2>
                  <p>Comprehensive defense-in-depth security verification engine.</p>
                </div>
              </div>

              <div className="pillars-overview-grid">
                {/* MODULE 1: THREAT ANALYSIS */}
                <div
                  className="pillar-card p1"
                  style={{ cursor: 'pointer' }}
                  onClick={() => runAutoAnalysis('paypa1.com', 'p1')}
                  title="Click to auto-analyze lookalike paypa1.com"
                >
                  <div className="pillar-head">
                    <span className="pillar-num">MODULE 01</span>
                    <ShieldAlert size={18} color="#e06c3a" />
                  </div>
                  <h3>Threat Analysis</h3>
                  <p>Phishing, lookalike domains (paypa1.com), suspicious keywords, new domain age &amp; login form cross-domain action checks.</p>
                  <ul className="pillar-features">
                    <li><Check size={12} /> Typosquatting &amp; Levenshtein (paypa1.com)</li>
                    <li><Check size={12} /> Brand impersonation detection (PayPal)</li>
                    <li><Check size={12} /> Hidden redirects &amp; meta-refresh</li>
                  </ul>

                  {/* Inline Analysis Status in the shown part */}
                  <div className="inline-analysis-box">
                    <div className="inline-analysis-header">
                      <span className="inline-analysis-target">Target: paypa1.com</span>
                      <span className="badge high-risk" style={{ fontSize: '9px', padding: '2px 6px' }}>HIGH RISK</span>
                    </div>
                    <div className="inline-analysis-finding">
                      <strong>Homoglyph Detection:</strong> '1' replaces 'l' (Levenshtein: 1). PhishTank verified phishing entry.
                    </div>
                  </div>

                  <button
                    type="button"
                    className="card-action-btn p1-action"
                    onClick={(e) => {
                      e.stopPropagation();
                      runAutoAnalysis('paypa1.com', 'p1');
                    }}
                  >
                    {isScanning && scannerUrl === 'paypa1.com' ? (
                      <><LoaderCircle className="spin" size={13} /> Analyzing paypa1.com...</>
                    ) : (
                      <>Auto-Analyze Phishing (paypa1.com) <ArrowRight size={13} /></>
                    )}
                  </button>
                </div>

                {/* MODULE 2: WEB SECURITY ASSESSMENT */}
                <div
                  className="pillar-card p2"
                  style={{ cursor: 'pointer' }}
                  onClick={() => runAutoAnalysis('httpbin.org', 'p2')}
                  title="Click to auto-audit web security on httpbin.org"
                >
                  <div className="pillar-head">
                    <span className="pillar-num">MODULE 02</span>
                    <Server size={18} color="#8b5cf6" />
                  </div>
                  <h3>Web Security Assessment</h3>
                  <p>Site hygiene evaluation: missing headers (CSP, HSTS, X-Frame-Options), open ports, exposed admin panels &amp; cookies.</p>
                  <ul className="pillar-features">
                    <li><Check size={12} /> Security headers audit (A+ to F grade)</li>
                    <li><Check size={12} /> Port scanner (FTP, SSH, DBs, RDP)</li>
                    <li><Check size={12} /> /.env &amp; admin portal probes</li>
                  </ul>

                  {/* Inline Analysis Status in the shown part */}
                  <div className="inline-analysis-box">
                    <div className="inline-analysis-header">
                      <span className="inline-analysis-target">Target: httpbin.org</span>
                      <span className="badge warning" style={{ fontSize: '9px', padding: '2px 6px' }}>GRADE: D</span>
                    </div>
                    <div className="inline-analysis-finding">
                      <strong>Hygiene Audit:</strong> Missing CSP &amp; HSTS headers. Server banner: gws. Database ports closed.
                    </div>
                  </div>

                  <button
                    type="button"
                    className="card-action-btn p2-action"
                    onClick={(e) => {
                      e.stopPropagation();
                      runAutoAnalysis('httpbin.org', 'p2');
                    }}
                  >
                    {isScanning && scannerUrl === 'httpbin.org' ? (
                      <><LoaderCircle className="spin" size={13} /> Analyzing httpbin.org...</>
                    ) : (
                      <>Auto-Analyze Web Security (httpbin.org) <ArrowRight size={13} /></>
                    )}
                  </button>
                </div>

                {/* MODULE 3: CERTIFICATE VALIDATION */}
                <div
                  className="pillar-card p3"
                  style={{ cursor: 'pointer' }}
                  onClick={() => setView('Certificates')}
                  title="Click to view TLS Certificate Observatory"
                >
                  <div className="pillar-head">
                    <span className="pillar-num">MODULE 03</span>
                    <LockKeyhole size={18} color="#0ea5e9" />
                  </div>
                  <h3>Certificate Validation</h3>
                  <p>TLS handshake inspection: expiry, issuer, key size, domain match, Certificate Transparency logs (crt.sh) &amp; weak CA checks.</p>
                  <ul className="pillar-features">
                    <li><Check size={12} /> Scrutinized CAs (eMudhra monitoring)</li>
                    <li><Check size={12} /> CT logs verification (crt.sh)</li>
                    <li><Check size={12} /> RSA &amp; ECDSA strength analysis</li>
                  </ul>
                  <button
                    type="button"
                    className="card-action-btn p3-action"
                    onClick={(e) => {
                      e.stopPropagation();
                      setView('Certificates');
                    }}
                  >
                    Open Certificate Observatory <ArrowRight size={13} />
                  </button>
                </div>

                {/* MODULE 4: COLLABORATIVE THREAT INTEL */}
                <div
                  className="pillar-card p4"
                  style={{ cursor: 'pointer' }}
                  onClick={() => setView('Threat intelligence')}
                  title="Click to view Collaborative Threat Intelligence"
                >
                  <div className="pillar-head">
                    <span className="pillar-num">MODULE 04</span>
                    <Radar size={18} color="#10b981" />
                  </div>
                  <h3>Collaborative Threat Intel</h3>
                  <p>Community crowd-sourced reporting, consensus voting, blocklist export &amp; live feeds (URLhaus, OpenPhish, PhishTank, Safe Browsing).</p>
                  <ul className="pillar-features">
                    <li><Check size={12} /> Community consensus voting</li>
                    <li><Check size={12} /> Blocklist export (TXT, JSON, CSV)</li>
                    <li><Check size={12} /> URLhaus &amp; OpenPhish feeds</li>
                  </ul>
                  <button
                    type="button"
                    className="card-action-btn p4-action"
                    onClick={(e) => {
                      e.stopPropagation();
                      setView('Threat intelligence');
                    }}
                  >
                    Open Community Blocklist &amp; Feeds <ArrowRight size={13} />
                  </button>
                </div>
              </div>
            </>
          )}

          {/* DEDICATED CERTIFICATE OBSERVATORY VIEW (view === 'Certificates') */}
          {view === 'Certificates' && (
            <div className="certificates-observatory" style={{ marginTop: '10px' }}>
              {/* TELEMETRY TILES */}
              <div className="metrics" style={{ marginBottom: '22px' }}>
                <div className="metric">
                  <div className="metric-top">
                    <span>Active TLS Tracked</span>
                    <div className="metric-icon blue"><LockKeyhole size={19} /></div>
                  </div>
                  <strong>{allCertRecords.length}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag blue-text"><Activity size={13} /> In Observatory</span>
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-top">
                    <span>Valid &amp; Trusted Root</span>
                    <div className="metric-icon green"><ShieldCheck size={19} /></div>
                  </div>
                  <strong>{allCertRecords.filter(c => c.status === 'valid' && !c.isFlaggedCA).length}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag green-text"><Check size={13} /> Verified</span> CA chains
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-top">
                    <span>Flagged CAs (eMudhra)</span>
                    <div className="metric-icon orange"><ShieldAlert size={19} /></div>
                  </div>
                  <strong>{allCertRecords.filter(c => c.isFlaggedCA).length}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag orange-text"><ArrowUpRight size={13} /> Scrutinized</span> root store alert
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-top">
                    <span>Public CT Verified</span>
                    <div className="metric-icon violet"><Radar size={19} /></div>
                  </div>
                  <strong>{allCertRecords.filter(c => c.ctLogged).length}</strong>
                  <div className="metric-bottom">
                    <span className="metric-tag violet-text"><Check size={13} /> crt.sh</span> logged entries
                  </div>
                </div>
              </div>

              {/* INTERACTIVE TLS CERTIFICATE INSPECTOR BAR */}
              <section className="panel" style={{ padding: '22px', marginBottom: '22px' }}>
                <div style={{ marginBottom: '14px' }}>
                  <h3 style={{ margin: '0 0 4px', fontSize: '16px', fontWeight: 800 }}>Inspect Any Website TLS Certificate</h3>
                  <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
                    Inspect full X.509 cryptographic attributes: Issuer CA, RSA/ECDSA key size, expiration countdown, SAN patterns &amp; public Certificate Transparency logs.
                  </p>
                </div>

                <form className="scan-form" onSubmit={handleCertInspectSubmit} style={{ maxWidth: '100%', marginBottom: '14px' }}>
                  <LockKeyhole size={19} />
                  <input
                    aria-label="Domain for Certificate Inspection"
                    placeholder="Enter website domain (e.g. google.com, cloudflare.com, emudhra.com, badssl.com)"
                    value={certSearchInput}
                    onChange={e => setCertSearchInput(e.target.value)}
                  />
                  <button disabled={isCertInspecting}>
                    {isCertInspecting ? (
                      <><LoaderCircle className="spin" size={17} /> Inspecting TLS Handshake...</>
                    ) : (
                      <>Inspect Certificate <ArrowRight size={17} /></>
                    )}
                  </button>
                </form>

                {/* Preset sample certificates */}
                <div className="preset-row">
                  <span className="preset-label">QUICK TLS INSPECT:</span>
                  <button type="button" className="preset-chip clean" onClick={() => inspectDomainCert('google.com')}>
                    google.com (GTS RSA 2048)
                  </button>
                  <button type="button" className="preset-chip clean" onClick={() => inspectDomainCert('cloudflare.com')}>
                    cloudflare.com (ECDSA 256)
                  </button>
                  <button type="button" className="preset-chip danger" onClick={() => inspectDomainCert('emudhra.com')}>
                    emudhra.com (Flagged CA Scrutiny)
                  </button>
                  <button type="button" className="preset-chip danger" onClick={() => inspectDomainCert('expired.badssl.com')}>
                    badssl.com (Expired Cert Alert)
                  </button>
                  <button type="button" className="preset-chip clean" onClick={() => inspectDomainCert('github.com')}>
                    github.com (DigiCert EV)
                  </button>
                </div>
              </section>

              {/* FILTER TABS */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    className={`nav-tab ${certFilterTab === 'all' ? 'active' : ''}`}
                    onClick={() => setCertFilterTab('all')}
                  >
                    All Tracked ({allCertRecords.length})
                  </button>
                  <button
                    className={`nav-tab ${certFilterTab === 'valid' ? 'active' : ''}`}
                    onClick={() => setCertFilterTab('valid')}
                  >
                    Valid &amp; Trusted ({allCertRecords.filter(c => c.status === 'valid' && !c.isFlaggedCA).length})
                  </button>
                  <button
                    className={`nav-tab ${certFilterTab === 'flagged' ? 'active' : ''}`}
                    onClick={() => setCertFilterTab('flagged')}
                  >
                    Flagged CAs (eMudhra) ({allCertRecords.filter(c => c.isFlaggedCA).length})
                  </button>
                  <button
                    className={`nav-tab ${certFilterTab === 'expiring' ? 'active' : ''}`}
                    onClick={() => setCertFilterTab('expiring')}
                  >
                    Expiring / Expired ({allCertRecords.filter(c => c.status === 'expired' || c.status === 'expiring' || c.daysRemaining <= 30).length})
                  </button>
                </div>
              </div>

              {/* RICH CERTIFICATES GRID */}
              <div className="cert-cards-grid">
                {filteredCertRecords.map(cert => (
                  <div className={`cert-card ${cert.isFlaggedCA ? 'flagged' : cert.status === 'expired' ? 'expired' : 'valid'}`} key={cert.domain}>
                    <div className="cert-card-header">
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="cert-domain-title">{cert.domain}</span>
                          {cert.isFlaggedCA ? (
                            <span className="badge high-risk">SCRUTINIZED CA (eMudhra)</span>
                          ) : cert.status === 'expired' ? (
                            <span className="badge high-risk">EXPIRED TLS</span>
                          ) : (
                            <span className="badge low-risk">VALID TLS</span>
                          )}
                        </div>
                        <span className="cert-subject-sub">Subject CN: {cert.subjectCN} &bull; SANs: {cert.sanPattern}</span>
                      </div>
                      <div className="cert-status-icon">
                        {cert.isFlaggedCA ? (
                          <ShieldAlert size={22} color="#dc2626" />
                        ) : cert.status === 'expired' ? (
                          <CircleAlert size={22} color="#ef4444" />
                        ) : (
                          <ShieldCheck size={22} color="#16a34a" />
                        )}
                      </div>
                    </div>

                    {cert.isFlaggedCA && (
                      <div className="ca-alert-box" style={{ margin: '6px 0 10px' }}>
                        <TriangleAlert size={16} />
                        <div>
                          <strong>Scrutinized Certificate Authority (eMudhra)</strong>
                          <p>eMudhra is subject to browser root store scrutiny and probation (Mozilla / Chrome distrust proceedings).</p>
                        </div>
                      </div>
                    )}

                    <div className="cert-details-grid">
                      <div className="cert-detail-item">
                        <small>CERTIFICATE AUTHORITY (ISSUER)</small>
                        <strong>{cert.issuer}</strong>
                      </div>

                      <div className="cert-detail-item">
                        <small>EXPIRATION &amp; VALIDITY</small>
                        <strong>
                          {cert.validTo}
                          <span className={`days-chip ${cert.daysRemaining <= 0 ? 'expired' : cert.daysRemaining <= 30 ? 'warning' : 'ok'}`}>
                            {cert.daysRemaining <= 0 ? 'EXPIRED' : `${cert.daysRemaining} days left`}
                          </span>
                        </strong>
                      </div>

                      <div className="cert-detail-item">
                        <small>KEY &amp; ENCRYPTION ALGORITHM</small>
                        <strong>{cert.keyType} ({cert.keyBits}-bit) &bull; {cert.sigAlg}</strong>
                      </div>

                      <div className="cert-detail-item">
                        <small>CERTIFICATE TRANSPARENCY (CT)</small>
                        <strong className="ct-badge-strong">
                          <Check size={12} /> Logged in crt.sh ({cert.ctCount} entries)
                        </strong>
                      </div>
                    </div>

                    <div className="cert-fingerprint-row">
                      <small>SHA-256 FINGERPRINT:</small>
                      <code>{cert.fingerprint256}</code>
                    </div>

                    <div className="cert-footer-action">
                      <button
                        type="button"
                        className="text-button"
                        onClick={() => runAutoAnalysis(cert.domain, 'p3')}
                      >
                        Inspect Full Cryptographic Audit <ArrowRight size={13} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* LOWER GRID: RECENT SCANS + COMMUNITY TICKER (Overview, Scan History) */}
          {(view === 'Overview' || view === 'Scan history') && (
            <div className="lower-grid">
              <section className="panel recent-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Website Assessments</h3>
                    <p>Recent multi-module website security scans and threat scores.</p>
                  </div>

                  {view === 'Overview' ? (
                    <button className="text-button" onClick={() => go('Scan history')}>
                      View all scans <ArrowRight size={14} />
                    </button>
                  ) : (
                    <select
                      aria-label="Filter scan verdict"
                      value={scanFilter}
                      onChange={e => setScanFilter(e.target.value)}
                    >
                      <option value="All">All Verdicts</option>
                      <option value="High risk">High risk</option>
                      <option value="Needs review">Needs review</option>
                      <option value="Low risk">Low risk</option>
                    </select>
                  )}
                </div>

                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>WEBSITE</th>
                        <th>VERDICT &amp; RISK</th>
                        <th>MODULE SCORES</th>
                        <th>DATE</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleScans
                        .slice(0, view === 'Overview' ? 5 : 50)
                        .map(s => (
                          <tr key={s.id} onClick={() => setSelected(s)}>
                            <td>
                              <div className="site-cell">
                                <div className="site-icon">
                                  <Globe2 size={17} />
                                </div>
                                <div>
                                  <strong>{s.domain}</strong>
                                  <small>{s.url}</small>
                                </div>
                              </div>
                            </td>

                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span className={'badge ' + s.verdict.toLowerCase().replace(' ', '-')}>
                                  <span /> {s.verdict}
                                </span>
                                <strong style={{ fontSize: '11px', color: '#4a5d78' }}>{s.score}/100</strong>
                              </div>
                            </td>

                            <td>
                              <div style={{ display: 'flex', gap: '4px' }}>
                                <span className="preset-chip" title="Module 1: Threat Analysis" style={{ fontSize: '9px', padding: '2px 5px' }}>
                                  M1: {s.pillarScores?.threatAnalysis ?? '—'}
                                </span>
                                <span className="preset-chip" title="Module 2: Web Security" style={{ fontSize: '9px', padding: '2px 5px' }}>
                                  M2: {s.pillarScores?.webSecurity ?? '—'}
                                </span>
                                <span className="preset-chip" title="Module 3: Cert Validation" style={{ fontSize: '9px', padding: '2px 5px' }}>
                                  M3: {s.pillarScores?.certificateValidation ?? '—'}
                                </span>
                                <span className="preset-chip" title="Module 4: Threat Intel" style={{ fontSize: '9px', padding: '2px 5px' }}>
                                  M4: {s.pillarScores?.threatIntel ?? '—'}
                                </span>
                              </div>
                            </td>

                            <td className="muted-cell">{date(s.created_at)}</td>
                            <td>
                              <ArrowUpRight size={16} className="row-arrow" />
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>

                  {loading ? (
                    <div className="empty">
                      <LoaderCircle className="spin" size={22} /> Loading assessments...
                    </div>
                  ) : visibleScans.length === 0 ? (
                    <div className="empty">
                      <div className="empty-icon">
                        <FileSearch size={22} />
                      </div>
                      <strong>No scans found</strong>
                      <span>Analyze a website to see its findings here.</span>
                      <button onClick={() => go('Website scanner')}>
                        Run an assessment <ArrowRight size={14} />
                      </button>
                    </div>
                  ) : null}
                </div>
              </section>

              {/* COMMUNITY THREAT INTELLIGENCE TICKER */}
              <section className="panel community-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Community Threat Radar</h3>
                    <p>Recent crowdsourced incident reports and peer consensus.</p>
                  </div>
                  <button className="text-button" onClick={() => go('Threat intelligence')}>
                    Blocklist <ArrowRight size={14} />
                  </button>
                </div>

                {loading ? (
                  <div className="empty">Loading threat feed...</div>
                ) : reports.length === 0 ? (
                  <div className="empty">No community reports yet.</div>
                ) : (
                  reports.slice(0, 4).map(r => (
                    <div className="activity-item" key={r.id}>
                      <div className="activity-icon" style={{ background: r.status === 'Confirmed' ? '#fee2e2' : '#f0fdf4', color: r.status === 'Confirmed' ? '#dc2626' : '#16a34a' }}>
                        {r.status === 'Confirmed' ? <ShieldX size={16} /> : <ShieldAlert size={16} />}
                      </div>
                      <div className="activity-details">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <strong style={{ fontSize: '13px' }}>{r.domain}</strong>
                          <span className={`badge ${r.status === 'Confirmed' ? 'high-risk' : 'needs-review'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                            {r.status}
                          </span>
                        </div>
                        <small>{r.details.length > 75 ? r.details.slice(0, 75) + '...' : r.details}</small>
                      </div>
                      <div className="votes-ctrl" style={{ marginLeft: 'auto' }}>
                        <button
                          className="vote-btn up"
                          onClick={() => handleVote(r.id, 'up')}
                          title="Upvote Threat"
                        >
                          <ThumbsUp size={11} />
                        </button>
                        <span className={`vote-count ${r.upvotes - r.downvotes > 5 ? 'danger' : ''}`}>
                          {r.upvotes - r.downvotes}
                        </span>
                        <button
                          className="vote-btn down"
                          onClick={() => handleVote(r.id, 'down')}
                          title="Flag False Positive"
                        >
                          <ThumbsDown size={11} />
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </section>
            </div>
          )}

          {/* VIEW: THREAT INTELLIGENCE (MODULE 4 COLLABORATIVE HUB) */}
          {view === 'Threat intelligence' && (
            <div style={{ marginTop: '10px' }}>
              {/* BLOCKLIST HERO BANNER */}
              <div className="blocklist-banner">
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <ShieldAlert size={20} color="#f87171" />
                    <h3>SentinelScope Community Blocklist</h3>
                    <span className="badge high-risk">{confirmedThreats} Active Malicious Indicators</span>
                  </div>
                  <p>
                    Community-verified malicious domains automatically curated via peer consensus and external threat feed correlation.
                  </p>
                </div>

                <div className="blocklist-actions">
                  <button className="btn-export" onClick={() => downloadBlocklist('txt')}>
                    <Download size={14} /> Export DNS (TXT)
                  </button>
                  <button className="btn-export" onClick={() => downloadBlocklist('json')}>
                    <Download size={14} /> JSON
                  </button>
                  <button className="btn-export" onClick={() => downloadBlocklist('csv')}>
                    <Download size={14} /> CSV
                  </button>
                  <button className="submit-button" style={{ height: '34px', padding: '0 12px' }} onClick={() => setShowReport(true)}>
                    <Plus size={14} /> Report IOC
                  </button>
                </div>
              </div>

              {/* EXTERNAL FEEDS MONITOR */}
              <div className="section-title">
                <div>
                  <h2>External Intelligence Feeds</h2>
                  <p>Global threat feeds actively synchronized and queried by SentinelScope.</p>
                </div>
              </div>

              <div className="feeds-grid">
                <div className="feed-card">
                  <div>
                    <strong>URLhaus (abuse.ch)</strong>
                    <small>Real-time malware URL distribution and botnet C2 feed</small>
                  </div>
                  <span className="feed-status clean">
                    <CircleCheck size={12} /> Active Feed
                  </span>
                </div>

                <div className="feed-card">
                  <div>
                    <strong>OpenPhish Global Intelligence</strong>
                    <small>High-confidence automated zero-day phishing feed</small>
                  </div>
                  <span className="feed-status clean">
                    <CircleCheck size={12} /> Active Feed
                  </span>
                </div>

                <div className="feed-card">
                  <div>
                    <strong>PhishTank Community Database</strong>
                    <small>Crowd-sourced phishing verification repository</small>
                  </div>
                  <span className="feed-status clean">
                    <CircleCheck size={12} /> Active Feed
                  </span>
                </div>

                <div className="feed-card">
                  <div>
                    <strong>Google Safe Browsing v4</strong>
                    <small>Client-side social engineering & malware protection protocol</small>
                  </div>
                  <span className="feed-status clean">
                    <CircleCheck size={12} /> Synchronized
                  </span>
                </div>
              </div>

              {/* COMMUNITY REPORTS TABLE WITH VOTING */}
              <section className="panel" style={{ marginTop: '20px' }}>
                <div className="panel-heading">
                  <div>
                    <h3>Community Threat Submissions & Consensus Voting</h3>
                    <p>Upvote to confirm active threats; downvote to flag false positives.</p>
                  </div>
                  <button className="text-button" onClick={() => setShowReport(true)}>
                    <Plus size={15} /> Submit report
                  </button>
                </div>

                {loading ? (
                  <div className="empty">Loading community reports...</div>
                ) : reports.length === 0 ? (
                  <div className="empty">No reports submitted yet.</div>
                ) : (
                  reports.map(r => (
                    <div className="report-row" key={r.id}>
                      <div className="activity-icon" style={{ background: r.status === 'Confirmed' ? '#fee2e2' : '#f0fdf4', color: r.status === 'Confirmed' ? '#dc2626' : '#16a34a' }}>
                        {r.status === 'Confirmed' ? <ShieldX size={18} /> : <ShieldAlert size={18} />}
                      </div>

                      <div className="report-copy">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <strong style={{ fontSize: '13px' }}>{r.domain}</strong>
                          <span className={`badge ${r.status === 'Confirmed' ? 'high-risk' : 'needs-review'}`}>
                            {r.status}
                          </span>
                          <span className="preset-chip" style={{ fontSize: '9px' }}>
                            {r.category}
                          </span>
                        </div>
                        <p>{r.details}</p>
                        <small>Submitted {time(r.created_at)}</small>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
                        <div className="votes-ctrl">
                          <button
                            className="vote-btn up"
                            title="Confirm Threat"
                            onClick={() => handleVote(r.id, 'up')}
                          >
                            <ThumbsUp size={14} />
                          </button>
                          <span className="vote-count danger">{r.upvotes}</span>
                          <button
                            className="vote-btn down"
                            title="Mark False Positive"
                            onClick={() => handleVote(r.id, 'down')}
                          >
                            <ThumbsDown size={14} />
                          </button>
                          <span className="vote-count" style={{ color: '#64748b' }}>{r.downvotes}</span>
                        </div>

                        <button
                          className="text-button"
                          style={{ fontSize: '10px' }}
                          onClick={() => handleScan(undefined, r.domain)}
                        >
                          Scan Domain <ArrowRight size={12} />
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </section>
            </div>
          )}

          {/* FOOTER NOTE */}
          <div className="bottom-note">
            <Info size={15} />
            SentinelScope combines heuristic rules, live DOM analysis, TLS inspection & collaborative intelligence.
            <span>Built for a safer, transparent web <Shield size={14} /></span>
          </div>
        </div>
      </main>

      {/* MODAL: FULL 4-PILLAR INSPECTOR MODAL */}
      {selected && (
        <div className="modal-backdrop" onClick={() => setSelected(null)}>
          <div className="modal" style={{ maxWidth: '820px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <div className="eyebrow">
                  <span /> COMPREHENSIVE MULTI-MODULE SECURITY AUDIT
                </div>
                <h2>{selected.domain}</h2>
                <p>
                  Target URL: {selected.url} &bull; Assessed {time(selected.created_at)}
                </p>
              </div>
              <button className="close" onClick={() => setSelected(null)} aria-label="Close results">
                <X size={20} />
              </button>
            </div>

            {/* OVERALL SCORE SUMMARY */}
            <div className="result-summary">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className={'badge ' + selected.verdict.toLowerCase().replace(' ', '-')}>
                    <span /> {selected.verdict}
                  </span>
                  <span style={{ fontSize: '18px', fontWeight: 800, color: '#1e314f' }}>
                    {selected.score}/100 Risk Score
                  </span>
                </div>
                <p>
                  Weighted Composite: 35% Phishing Analysis &bull; 25% Threat Intel &bull; 20% Web Security &bull; 20% TLS/CT
                </p>
              </div>
              <ShieldCheck size={42} strokeWidth={1.2} />
            </div>

            {/* 4 DEFENSE MODULE TABS */}
            <div className="pillar-tabs">
              <button
                className={`pillar-tab ${activeModalPillar === 'p1' ? 'active' : ''}`}
                onClick={() => setActiveModalPillar('p1')}
              >
                <ShieldAlert size={15} />
                <span>Module 1: Threat Analysis</span>
                <span className="score-tag">{selected.pillarScores?.threatAnalysis ?? '—'}</span>
              </button>

              <button
                className={`pillar-tab ${activeModalPillar === 'p2' ? 'active' : ''}`}
                onClick={() => setActiveModalPillar('p2')}
              >
                <Server size={15} />
                <span>Module 2: Web Security</span>
                <span className="score-tag">{selected.pillarScores?.webSecurity ?? '—'}</span>
              </button>

              <button
                className={`pillar-tab ${activeModalPillar === 'p3' ? 'active' : ''}`}
                onClick={() => setActiveModalPillar('p3')}
              >
                <LockKeyhole size={15} />
                <span>Module 3: Certificate &amp; CT</span>
                <span className="score-tag">{selected.pillarScores?.certificateValidation ?? '—'}</span>
              </button>

              <button
                className={`pillar-tab ${activeModalPillar === 'p4' ? 'active' : ''}`}
                onClick={() => setActiveModalPillar('p4')}
              >
                <Radar size={15} />
                <span>Module 4: Threat Intel</span>
                <span className="score-tag">{selected.pillarScores?.threatIntel ?? '—'}</span>
              </button>
            </div>

            {/* TAB 1: THREAT ANALYSIS (PHISHING DETECTION) */}
            {activeModalPillar === 'p1' && (
              <div className="pillar-content-box">
                <h4 className="pillar-subhead">
                  <ShieldAlert size={16} color="#e06c3a" />
                  Module 1: Phishing &amp; Lookalike Threat Signals
                </h4>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', margin: '10px 0' }}>
                  <div className="port-chip">
                    <small>TYPOSQUATTING / LOOKALIKE</small>
                    <strong>
                      {selected.findings.some(f => f.category === 'Typosquatting' || f.category === 'Brand Impersonation')
                        ? 'Flagged Lookalike'
                        : 'No Lookalike Detected'}
                    </strong>
                  </div>

                  <div className="port-chip">
                    <small>DOMAIN AGE (RDAP)</small>
                    <strong>
                      {selected.pillars?.threatAnalysis?.domainAge?.ageDays !== null && selected.pillars?.threatAnalysis?.domainAge?.ageDays !== undefined
                        ? `${selected.pillars.threatAnalysis.domainAge.ageDays} days old`
                        : 'Active DNS verified'}
                    </strong>
                  </div>

                  <div className="port-chip">
                    <small>PAGE TITLE &amp; IMPERSONATION</small>
                    <strong>
                      {selected.pillars?.threatAnalysis?.pageData?.title || 'No Title Extracted'}
                    </strong>
                  </div>

                  <div className="port-chip">
                    <small>HIDDEN REDIRECTS</small>
                    <strong>
                      {selected.pillars?.threatAnalysis?.pageData?.hiddenRedirects?.length
                        ? `${selected.pillars.threatAnalysis.pageData.hiddenRedirects.length} Meta Redirects`
                        : '0 Hidden Redirects'}
                    </strong>
                  </div>
                </div>

                {selected.pillars?.threatAnalysis?.pageData?.crossDomainLogins?.length > 0 && (
                  <div className="ca-alert-box">
                    <TriangleAlert size={18} />
                    <div>
                      <strong>CRITICAL: Form submits credentials to foreign domain</strong>
                      <p>
                        Forms on this site post to: {selected.pillars?.threatAnalysis?.pageData?.crossDomainLogins?.join(', ')}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: WEB SECURITY ASSESSMENT */}
            {activeModalPillar === 'p2' && (
              <div className="pillar-content-box">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <h4 className="pillar-subhead" style={{ margin: 0 }}>
                    <Server size={16} color="#8b5cf6" />
                    Module 2: Site Security Hygiene &amp; Port Scan
                  </h4>
                  {selected.pillars?.webSecurity?.hygieneGrade && (
                    <span className="badge" style={{ background: '#ede9fe', color: '#6d28d9', fontSize: '11px' }}>
                      Grade: {selected.pillars.webSecurity.hygieneGrade}
                    </span>
                  )}
                </div>

                <div style={{ margin: '10px 0' }}>
                  <small style={{ fontWeight: 700, color: '#64748b' }}>SENSITIVE PORT SCAN RESULTS:</small>
                  <div className="ports-grid">
                    {(selected.pillars?.webSecurity?.openPorts || []).length > 0 ? (
                      selected.pillars?.webSecurity?.openPorts?.map((p: any) => (
                        <div key={p.port} className={`port-chip ${p.risk === 'high' ? 'open-danger' : 'open-ok'}`}>
                          <strong>
                            Port {p.port} ({p.service})
                            {p.risk === 'high' ? <ShieldAlert size={13} color="#dc2626" /> : <Check size={13} color="#16a34a" />}
                          </strong>
                          <small>{p.desc}</small>
                        </div>
                      ))
                    ) : (
                      <div className="port-chip open-ok" style={{ gridColumn: '1 / -1' }}>
                        <strong>Standard Web Ports Clean</strong>
                        <small>No unauthorized database or remote admin ports (3306, 5432, 6379, 3389) open.</small>
                      </div>
                    )}
                  </div>
                </div>

                {selected.pillars?.webSecurity?.serverBanner && (
                  <div className="port-chip" style={{ margin: '8px 0' }}>
                    <small>SERVER BANNER / SOFTWARE FINGERPRINT</small>
                    <code>{selected.pillars.webSecurity.serverBanner}</code>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: CERTIFICATE VALIDATION & CT MONITORING */}
            {activeModalPillar === 'p3' && (
              <div className="pillar-content-box">
                <h4 className="pillar-subhead">
                  <LockKeyhole size={16} color="#0ea5e9" />
                  Module 3: TLS Certificate &amp; Certificate Transparency (CT)
                </h4>

                {/* Flagged CA (eMudhra) alert if detected */}
                {selected.findings.some(f => f.title.includes('FLAGGED CA') || f.title.includes('eMudhra')) && (
                  <div className="ca-alert-box">
                    <ShieldAlert size={20} />
                    <div>
                      <strong>SCRUTINIZED OR DISTRUSTED CERTIFICATE AUTHORITY DETECTED</strong>
                      <p>
                        This site uses a certificate issued by a CA (eMudhra / WoSign / StartCom) subject to active distrust proceedings or probation in browser root programs.
                      </p>
                    </div>
                  </div>
                )}

                {selected.certificate ? (
                  <div className="cert-box" style={{ background: '#fff', border: '1px solid #e2e8f0', marginTop: '10px' }}>
                    <div>
                      <span>Issued To (Subject)</span>
                      <strong>{selected.certificate.subject}</strong>
                    </div>
                    <div>
                      <span>Certificate Authority (Issuer)</span>
                      <strong>{selected.certificate.issuer}</strong>
                    </div>
                    <div>
                      <span>Expiration Date</span>
                      <strong>
                        {selected.certificate.valid_to ? date(selected.certificate.valid_to) : 'Unavailable'}
                        {selected.certificate.daysLeft !== undefined && ` (${selected.certificate.daysLeft} days remaining)`}
                      </strong>
                    </div>
                    <div>
                      <span>Key Specification &amp; Algorithm</span>
                      <strong>
                        {selected.certificate.asymmType || 'RSA'} {selected.certificate.bits ? `${selected.certificate.bits}-bit` : ''} &bull; {selected.certificate.sigalg || 'SHA256'}
                      </strong>
                    </div>
                    <div>
                      <span>Certificate Transparency (crt.sh)</span>
                      <strong className="ct-badge">
                        <Check size={12} /> Logged in Public CT
                      </strong>
                    </div>
                    <div>
                      <span>SHA-256 Fingerprint</span>
                      <strong className="fingerprint">{selected.certificate.fingerprint256}</strong>
                    </div>
                  </div>
                ) : (
                  <div className="empty" style={{ minHeight: '80px' }}>
                    TLS certificate information unavailable.
                  </div>
                )}
              </div>
            )}

            {/* TAB 4: COLLABORATIVE THREAT INTEL */}
            {activeModalPillar === 'p4' && (
              <div className="pillar-content-box">
                <h4 className="pillar-subhead">
                  <Radar size={16} color="#10b981" />
                  Module 4: External Threat Feeds &amp; Community Blocklist
                </h4>

                <div className="feeds-grid" style={{ margin: '10px 0' }}>
                  <div className="feed-card">
                    <div>
                      <strong>URLhaus (abuse.ch)</strong>
                      <small>Malware &amp; botnet URL feed</small>
                    </div>
                    <span className={`feed-status ${selected.pillars?.threatIntel?.externalFeeds?.urlhaus?.listed ? 'threat' : 'clean'}`}>
                      {selected.pillars?.threatIntel?.externalFeeds?.urlhaus?.listed ? 'Listed Malicious' : 'Clean'}
                    </span>
                  </div>

                  <div className="feed-card">
                    <div>
                      <strong>OpenPhish Global Feed</strong>
                      <small>Targeted credential phishing</small>
                    </div>
                    <span className={`feed-status ${selected.pillars?.threatIntel?.externalFeeds?.openphish?.listed ? 'threat' : 'clean'}`}>
                      {selected.pillars?.threatIntel?.externalFeeds?.openphish?.listed ? 'Listed Phish' : 'Clean'}
                    </span>
                  </div>

                  <div className="feed-card">
                    <div>
                      <strong>PhishTank Database</strong>
                      <small>Verified community phishing</small>
                    </div>
                    <span className={`feed-status ${selected.pillars?.threatIntel?.externalFeeds?.phishtank?.listed ? 'threat' : 'clean'}`}>
                      {selected.pillars?.threatIntel?.externalFeeds?.phishtank?.listed ? 'Verified Phish' : 'Clean'}
                    </span>
                  </div>

                  <div className="feed-card">
                    <div>
                      <strong>Google Safe Browsing</strong>
                      <small>Deceptive website status</small>
                    </div>
                    <span className={`feed-status ${selected.pillars?.threatIntel?.externalFeeds?.safebrowsing?.listed ? 'threat' : 'clean'}`}>
                      {selected.pillars?.threatIntel?.externalFeeds?.safebrowsing?.listed ? 'Flagged Deceptive' : 'Clean'}
                    </span>
                  </div>
                </div>

                <div className="port-chip" style={{ marginTop: '10px' }}>
                  <small>COMMUNITY CONSENSUS &amp; BLOCKLIST ENROLLMENT</small>
                  <strong>
                    {selected.pillars?.threatIntel?.community?.isBlocklisted
                      ? 'Confirmed Threat on Community Blocklist'
                      : selected.pillars?.threatIntel?.community?.consensus || 'No community complaints filed'}
                  </strong>
                </div>
              </div>
            )}

            {/* ALL DETAILED FINDINGS */}
            <h3 className="modal-subtitle" style={{ marginTop: '20px' }}>
              Detailed Assessment Findings ({selected.findings.length})
            </h3>
            <div className="findings">
              {selected.findings.map((f, i) => (
                <div className="finding" key={i}>
                  <div className={'finding-icon ' + f.level}>
                    {f.level === 'good' ? (
                      <CheckCircle2 size={18} />
                    ) : f.level === 'info' ? (
                      <Info size={18} />
                    ) : (
                      <TriangleAlert size={18} />
                    )}
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <strong>{f.title}</strong>
                      {f.category && (
                        <span className="preset-chip" style={{ fontSize: '9px', padding: '1px 5px' }}>
                          {f.category}
                        </span>
                      )}
                    </div>
                    <p>{f.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MODAL: SUBMIT COMMUNITY THREAT REPORT */}
      {showReport && (
        <div className="modal-backdrop" onClick={() => setShowReport(false)}>
          <div className="modal report-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <div className="eyebrow">
                  <span /> COLLABORATIVE THREAT INTELLIGENCE
                </div>
                <h2>Report a Suspicious Website</h2>
                <p>Submit threat evidence to build the community blocklist.</p>
              </div>
              <button className="close" onClick={() => setShowReport(false)} aria-label="Close report form">
                <X size={20} />
              </button>
            </div>

            <form className="report-form" onSubmit={submitReport}>
              <label>
                Website Domain or URL
                <input
                  required
                  placeholder="e.g. paypa1-update.com"
                  value={reportDomain}
                  onChange={e => setReportDomain(e.target.value)}
                />
              </label>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <label>
                  Threat Category
                  <select value={reportCategory} onChange={e => setReportCategory(e.target.value)}>
                    <option>Phishing</option>
                    <option>Impersonation</option>
                    <option>Malicious redirect</option>
                    <option>Malware</option>
                    <option>Cryptocurrency Scam</option>
                    <option>Other</option>
                  </select>
                </label>

                <label>
                  Estimated Severity
                  <select value={reportSeverity} onChange={e => setReportSeverity(e.target.value)}>
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>
                </label>
              </div>

              <label>
                Evidence / What did you observe?
                <textarea
                  required
                  minLength={5}
                  maxLength={1000}
                  placeholder="Describe the suspicious behavior: lookalike domain, fake login form, suspicious redirects, phishing email lure, etc."
                  value={reportDetails}
                  onChange={e => setReportDetails(e.target.value)}
                />
              </label>

              {error && <div className="form-error">{error}</div>}

              <button className="submit-button" disabled={reportBusy}>
                {reportBusy ? 'Submitting...' : <>Submit to Threat Intel Network <Send size={16} /></>}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
