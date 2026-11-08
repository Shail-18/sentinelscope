import tls from 'node:tls';
import https from 'node:https';

const DISTRUSTED_OR_SCRUTINIZED_CAS = [
  {
    name: 'eMudhra',
    pattern: /emudhra/i,
    status: 'High Scrutiny / Distrust Actions',
    severity: 'high',
    desc: 'eMudhra has faced major distrust decisions and probation across major browser root programs (Mozilla/Chrome) due to serial number entropy and compliance audit failures.'
  },
  {
    name: 'WoSign / StartCom',
    pattern: /(wosign|startcom)/i,
    status: 'Distrusted',
    severity: 'high',
    desc: 'Permanently distrusted by Google, Apple, and Mozilla for backdating certificates and falsifying validation records.'
  },
  {
    name: 'CNNIC',
    pattern: /cnnic/i,
    status: 'Restricted / Scrutinized',
    severity: 'warning',
    desc: 'Subject to strict white-listing and monitoring after unauthorized intermediate certificate issuance.'
  },
  {
    name: 'Camerfirma',
    pattern: /camerfirma/i,
    status: 'Distrusted',
    severity: 'high',
    desc: 'Revoked from browser root stores following recurring compliance and incident response failures.'
  },
  {
    name: 'DarkMatter',
    pattern: /darkmatter/i,
    status: 'Distrusted',
    severity: 'high',
    desc: 'Denied entry into root trust stores due to cyber-espionage and surveillance concerns.'
  },
  {
    name: 'DigiNotar',
    pattern: /diginotar/i,
    status: 'Compromised / Blacklisted',
    severity: 'high',
    desc: 'Historically compromised Dutch CA involved in rogue wild-card certificate issuance.'
  }
];

function checkDomainMatch(targetHost, cert) {
  if (!cert) return { match: false, matchedPattern: null };
  const host = targetHost.toLowerCase();
  const altNames = (cert.subjectaltname || '')
    .split(',')
    .map(s => s.trim().replace(/^DNS:/i, '').toLowerCase())
    .filter(Boolean);

  const namesToCheck = [...altNames];
  if (cert.subject?.CN) namesToCheck.push(cert.subject.CN.toLowerCase());

  for (const pattern of namesToCheck) {
    if (pattern === host) return { match: true, matchedPattern: pattern };
    if (pattern.startsWith('*.')) {
      const wildcardBase = pattern.slice(2);
      const hostParts = host.split('.');
      const baseParts = wildcardBase.split('.');
      if (hostParts.length === baseParts.length + 1 && host.endsWith('.' + wildcardBase)) {
        return { match: true, matchedPattern: pattern };
      }
    }
  }

  return { match: false, matchedPattern: null };
}

export async function fetchCtLogs(domain) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'SentinelScope/2.0 CT-Inspector' },
      signal: controller.signal
    }).catch(() => null);
    clearTimeout(timeout);

    if (res && res.ok) {
      const logs = await res.json();
      if (Array.isArray(logs) && logs.length > 0) {
        return {
          logged: true,
          count: logs.length,
          latestCertId: logs[0]?.id || null,
          firstLogged: logs[logs.length - 1]?.entry_timestamp || null,
          latestLogged: logs[0]?.entry_timestamp || null,
          issuersSeen: [...new Set(logs.map(l => l.issuer_name).filter(Boolean))].slice(0, 5)
        };
      }
    }
  } catch {}

  return { logged: null, count: 0, latestCertId: null, firstLogged: null, latestLogged: null, issuersSeen: [] };
}

export async function inspectTlsCertificate(host) {
  return new Promise((resolve) => {
    const options = {
      host: host,
      port: 443,
      servername: host,
      rejectUnauthorized: false,
      timeout: 5000
    };

    const socket = tls.connect(options, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        const authError = socket.authorizationError || null;
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        socket.destroy();

        if (!cert || !Object.keys(cert).length) {
          return resolve({ success: false, error: 'No certificate returned by remote server.' });
        }

        resolve({
          success: true,
          authorized,
          authorizationError: authError ? String(authError) : null,
          protocol,
          cipher: cipher ? `${cipher.name} (${cipher.version})` : 'Unknown',
          cert: {
            subject: cert.subject?.CN || 'Unknown',
            subjectFull: cert.subject,
            issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
            issuerOrg: cert.issuer?.O || '',
            issuerCN: cert.issuer?.CN || '',
            issuerFull: cert.issuer,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            fingerprint256: cert.fingerprint256,
            fingerprint: cert.fingerprint,
            serialNumber: cert.serialNumber,
            bits: cert.bits || null,
            asymmType: cert.asymmKeyType || (cert.bits ? 'RSA' : 'Unknown'),
            sigalg: cert.sigalg || 'SHA256withRSA',
            subjectaltname: cert.subjectaltname || ''
          }
        });
      } catch (err) {
        socket.destroy();
        resolve({ success: false, error: err.message });
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ success: false, error: 'TLS connection timed out after 5000ms.' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ success: false, error: err.message });
    });
  });
}

export async function runCertificateValidationPillar(host) {
  const findings = [];
  let score = 0; // 0 = perfect certificate security, 100 = critical TLS failure

  const tlsResult = await inspectTlsCertificate(host);

  if (!tlsResult.success || !tlsResult.cert) {
    findings.push({
      level: 'high',
      category: 'TLS Connection',
      title: 'Failed to establish TLS connection',
      detail: tlsResult.error || 'The remote origin does not serve a valid HTTPS certificate on port 443.',
      points: 40
    });
    return {
      pillar: 'Certificate Validation & CT Monitoring',
      score: 80,
      riskLevel: 'High',
      certificate: null,
      findings
    };
  }

  const { cert, authorized, authorizationError, protocol, cipher } = tlsResult;

  // 1. Trust Chain Validity
  if (!authorized) {
    findings.push({
      level: 'high',
      category: 'Chain Validity',
      title: 'Certificate is NOT trusted by standard root store',
      detail: `TLS handshake verification rejected: "${authorizationError || 'Untrusted root or self-signed'}". Modern browsers will display full-page security interstitials.`,
      points: 45
    });
    score += 45;
  } else {
    findings.push({
      level: 'good',
      category: 'Chain Validity',
      title: 'Publicly trusted certificate chain',
      detail: 'Certificate chain verified against trusted OS and browser CA trust stores.',
      points: 0
    });
  }

  // 2. Distrusted or Weak CA Flagging (including eMudhra)
  const fullIssuerStr = `${cert.issuerOrg} ${cert.issuerCN} ${cert.issuer}`.toLowerCase();
  let flaggedCa = null;

  for (const ca of DISTRUSTED_OR_SCRUTINIZED_CAS) {
    if (ca.pattern.test(fullIssuerStr)) {
      flaggedCa = ca;
      findings.push({
        level: ca.severity,
        category: 'Distrusted CA Flag',
        title: `FLAGGED CA: Issued by ${ca.name} (${ca.status})`,
        detail: ca.desc,
        points: ca.severity === 'high' ? 40 : 20
      });
      score += ca.severity === 'high' ? 40 : 20;
      break;
    }
  }

  if (!flaggedCa) {
    findings.push({
      level: 'good',
      category: 'CA Reputation',
      title: `Issued by reputable Certificate Authority (${cert.issuerOrg || cert.issuerCN || cert.issuer})`,
      detail: 'Issuer is an established, non-flagged public root authority in good standing.',
      points: 0
    });
  }

  // 3. Expiration Analysis
  const now = Date.now();
  const validFrom = new Date(cert.valid_from).getTime();
  const validTo = new Date(cert.valid_to).getTime();
  const daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

  if (now > validTo) {
    findings.push({
      level: 'high',
      category: 'Expiration',
      title: 'CRITICAL: Certificate has EXPIRED',
      detail: `Certificate expired on ${new Date(cert.valid_to).toLocaleDateString()} (${Math.abs(daysLeft)} days ago). All browser connections are broken.`,
      points: 50
    });
    score += 50;
  } else if (daysLeft <= 14) {
    findings.push({
      level: 'high',
      category: 'Expiration',
      title: `Certificate expires urgently in ${daysLeft} days`,
      detail: `Certificate expires on ${new Date(cert.valid_to).toLocaleDateString()}. Renewal must occur immediately to avoid outage.`,
      points: 25
    });
    score += 25;
  } else if (daysLeft <= 30) {
    findings.push({
      level: 'warning',
      category: 'Expiration',
      title: `Certificate expires soon in ${daysLeft} days`,
      detail: `Certificate expires on ${new Date(cert.valid_to).toLocaleDateString()}. Renewal recommended.`,
      points: 10
    });
    score += 10;
  } else {
    findings.push({
      level: 'good',
      category: 'Expiration',
      title: `Certificate is valid (${daysLeft} days remaining)`,
      detail: `Active period: ${new Date(cert.valid_from).toLocaleDateString()} to ${new Date(cert.valid_to).toLocaleDateString()}.`,
      points: 0
    });
  }

  // 4. Domain Matching & SANs
  const domainMatch = checkDomainMatch(host, cert);
  if (!domainMatch.match) {
    findings.push({
      level: 'high',
      category: 'Domain Match',
      title: 'Hostname mismatch (Mismatched SAN / CN)',
      detail: `Certificate Common Name and Subject Alternative Names do not cover "${host}". Browsers block connection with ERR_CERT_COMMON_NAME_INVALID.`,
      points: 40
    });
    score += 40;
  } else {
    findings.push({
      level: 'good',
      category: 'Domain Match',
      title: `Valid domain match (${domainMatch.matchedPattern})`,
      detail: `The requested host "${host}" matches certificate SAN pattern "${domainMatch.matchedPattern}".`,
      points: 0
    });
  }

  // 5. Key Size and Cryptographic Strength
  if (cert.bits && cert.bits < 2048) {
    findings.push({
      level: 'high',
      category: 'Key Strength',
      title: `Weak cryptographic key size (${cert.bits} bits)`,
      detail: `Key size is below standard 2048-bit minimum. Vulnerable to factoring attacks.`,
      points: 30
    });
    score += 30;
  } else {
    findings.push({
      level: 'good',
      category: 'Key Strength',
      title: `Strong key specifications (${cert.asymmType} ${cert.bits ? cert.bits + '-bit' : ''})`,
      detail: `Cryptographic strength meets current NIST & CA/Browser Forum requirements. Signature algorithm: ${cert.sigalg}.`,
      points: 0
    });
  }

  // 6. Modern Protocol Check
  if (protocol === 'TLSv1.3' || protocol === 'TLSv1.2') {
    findings.push({
      level: 'good',
      category: 'TLS Protocol',
      title: `Modern TLS protocol negotiated (${protocol})`,
      detail: `Cipher: ${cipher}. Obsolete protocols (SSLv3, TLS 1.0, TLS 1.1) are deprecated.`,
      points: 0
    });
  } else {
    findings.push({
      level: 'high',
      category: 'TLS Protocol',
      title: `Legacy or insecure protocol (${protocol})`,
      detail: `Connection negotiated using ${protocol}, which is deprecated and contains known cryptographic vulnerabilities.`,
      points: 25
    });
    score += 25;
  }

  // 7. Certificate Transparency (CT) Monitoring via crt.sh
  const ctData = await fetchCtLogs(host);
  if (ctData.logged) {
    findings.push({
      level: 'good',
      category: 'Certificate Transparency',
      title: `Logged in public CT logs (${ctData.count} certificates recorded)`,
      detail: `Domain has verifiable Certificate Transparency history recorded on crt.sh. Latest cert logged: ${new Date(ctData.latestLogged).toLocaleDateString()}.`,
      points: 0
    });
  } else {
    findings.push({
      level: 'warning',
      category: 'Certificate Transparency',
      title: 'Certificate Transparency record unverified',
      detail: `Could not verify recent CT log entries on crt.sh. All publicly trusted certificates must be submitted to CT logs to be accepted by Google Chrome and Apple.`,
      points: 10
    });
    score += 10;
  }

  const finalScore = Math.min(score, 100);

  return {
    pillar: 'Certificate Validation & CT Monitoring',
    score: finalScore,
    riskLevel: finalScore >= 45 ? 'High' : finalScore >= 20 ? 'Moderate' : 'Low',
    authorized,
    protocol,
    cipher,
    daysLeft,
    flaggedCa: flaggedCa?.name || null,
    ctLogs: ctData,
    certificate: {
      ...cert,
      daysLeft,
      domainMatch: domainMatch.match
    },
    findings
  };
}

