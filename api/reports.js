import { getReports, saveReport, voteReport, getCommunityBlocklist, exportBlocklist } from './storage.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;

    // Check if blocklist export requested
    if (pathname.includes('/export') || url.searchParams.has('export')) {
      const format = url.searchParams.get('format') || 'txt';
      const fileExport = await exportBlocklist(format);
      res.setHeader('Content-Type', fileExport.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${fileExport.filename}"`);
      return res.status(200).send(fileExport.content);
    }

    if (pathname.includes('/blocklist')) {
      const list = await getCommunityBlocklist();
      return res.status(200).json(list);
    }

    if (req.method === 'GET') {
      const data = await getReports();
      return res.status(200).json(data);
    }

    if (req.method === 'POST') {
      const action = req.body?.action || (url.searchParams.get('action'));

      // Voting action
      if (action === 'vote' || req.body?.reportId) {
        const reportId = req.body?.reportId;
        const voteType = req.body?.type || 'up';
        if (!reportId) return res.status(400).json({ error: 'Missing reportId for vote' });
        const updated = await voteReport(reportId, voteType);
        return res.status(200).json(updated);
      }

      // Submission action
      const domain = String(req.body?.domain || '').trim().toLowerCase();
      const category = String(req.body?.category || 'Phishing');
      const severity = String(req.body?.severity || 'High');
      const details = String(req.body?.details || '').trim();

      const validCategories = ['Phishing', 'Impersonation', 'Malicious redirect', 'Malware', 'Cryptocurrency Scam', 'Other'];
      if (!domain.includes('.') || details.length < 5) {
        return res.status(400).json({ error: 'Provide a valid domain name and at least 5 characters of description.' });
      }

      const created = await saveReport({ domain, category, severity, details });
      return res.status(201).json(created);
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('Reports API error:', err);
    return res.status(500).json({ error: err.message || 'Unable to process reports request.' });
  }
}
