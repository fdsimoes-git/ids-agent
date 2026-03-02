const SQLI_PATTERNS = [
  /(\bunion\b\s+\bselect\b)/i,
  /(\bselect\b\s+.+\bfrom\b\s+\binformation_schema\b)/i,
  /(\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i,
  /('(\s*)(or|and)(\s*)('|\d+\s*=\s*\d+))/i,
  /(;\s*(drop|delete|update|insert|alter|create|truncate)\b)/i,
  /(\bsleep\s*\(\s*\d+\s*\))/i,
  /(\bbenchmark\s*\(\s*\d+)/i,
  /(\bload_file\s*\()/i,
  /(\binto\s+(out|dump)file\b)/i,
  /(0x[0-9a-f]{8,})/i,
  /(\bexec(\s+|\s*\())/i,
  /(\bwaitfor\s+delay\b)/i,
];

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(error|load|click|mouseover|focus|blur|submit|change)\s*=/i,
  /(document\.(cookie|domain|write|location))/i,
  /\b(eval|alert|prompt|confirm)\s*\(/i,
  /<(iframe|object|embed|svg|img)\b[^>]*(on\w+|src\s*=\s*['"]?javascript)\s*/i,
  /%3[Cc]script/i,
  /\bString\.fromCharCode\s*\(/i,
  /\batob\s*\(/i,
];

export function checkPayload(event, store) {
  if (event.source !== 'nginx') return null;
  if (!event.path) return null;

  const decoded = decodeURISafe(event.path);

  for (const re of SQLI_PATTERNS) {
    if (re.test(decoded)) {
      return {
        rule: 'sqli-attempt',
        severity: 'CRITICAL',
        ip: event.ip,
        timestamp: new Date().toISOString(),
        endpoint: event.path.slice(0, 200),
        details: 'SQL injection pattern detected in request URL',
        suggestedAction: 'Block IP immediately — active injection attempt',
        count: 1,
      };
    }
  }

  for (const re of XSS_PATTERNS) {
    if (re.test(decoded)) {
      return {
        rule: 'xss-attempt',
        severity: 'HIGH',
        ip: event.ip,
        timestamp: new Date().toISOString(),
        endpoint: event.path.slice(0, 200),
        details: 'XSS pattern detected in request URL',
        suggestedAction: 'Block IP — cross-site scripting attempt',
        count: 1,
      };
    }
  }

  return null;
}

function decodeURISafe(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}
