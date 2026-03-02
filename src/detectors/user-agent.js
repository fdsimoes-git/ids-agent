const SCANNER_SIGNATURES = [
  'sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'gobuster',
  'wfuzz', 'nuclei', 'burpsuite', 'zaproxy', 'zap', 'w3af',
  'acunetix', 'nessus', 'openvas', 'arachni', 'skipfish',
  'havij', 'commix', 'hydra', 'medusa', 'paros', 'whatweb',
  'fierce', 'wpscan', 'joomscan', 'droopescan',
];

const SCANNER_RE = new RegExp(SCANNER_SIGNATURES.join('|'), 'i');

export function checkUserAgent(event, store) {
  if (event.source !== 'nginx') return null;
  if (!event.userAgent) return null;

  const match = event.userAgent.match(SCANNER_RE);
  if (match) {
    return {
      rule: 'suspicious-user-agent',
      severity: 'HIGH',
      ip: event.ip,
      timestamp: new Date().toISOString(),
      endpoint: event.path,
      details: `Scanner signature "${match[0]}" in User-Agent: "${event.userAgent.slice(0, 120)}"`,
      suggestedAction: 'Block IP — known scanning tool detected',
      count: 1,
    };
  }

  return null;
}
