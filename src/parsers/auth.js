import { sanitizeLine, sanitizeIp } from '../utils/sanitize.js';

const FAILED_RE = /sshd\[\d+\]: Failed (\w+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/;
const INVALID_USER_RE = /sshd\[\d+\]: Invalid user (\S+) from (\S+) port (\d+)/;
const ACCEPTED_RE = /sshd\[\d+\]: Accepted (\w+) for (\S+) from (\S+) port (\d+)/;

export function parseAuthLine(raw) {
  const line = sanitizeLine(raw);
  let m;

  if ((m = line.match(FAILED_RE))) {
    const ip = sanitizeIp(m[3]);
    if (!ip) return null;
    return {
      source: 'auth',
      action: 'failed_login',
      method: m[1],
      user: m[2],
      ip,
      port: parseInt(m[4], 10),
      timestamp: parseSyslogDate(line),
    };
  }

  if ((m = line.match(INVALID_USER_RE))) {
    const ip = sanitizeIp(m[2]);
    if (!ip) return null;
    return {
      source: 'auth',
      action: 'invalid_user',
      user: m[1],
      ip,
      port: parseInt(m[3], 10),
      timestamp: parseSyslogDate(line),
    };
  }

  if ((m = line.match(ACCEPTED_RE))) {
    const ip = sanitizeIp(m[3]);
    if (!ip) return null;
    return {
      source: 'auth',
      action: 'accepted',
      method: m[1],
      user: m[2],
      ip,
      port: parseInt(m[4], 10),
      timestamp: parseSyslogDate(line),
    };
  }

  return null;
}

function parseSyslogDate(line) {
  // Syslog format: "Mon DD HH:MM:SS" (first 15 chars)
  const dateStr = line.slice(0, 15).trim();
  const now = new Date();
  const parsed = new Date(`${dateStr} ${now.getFullYear()}`);
  return isNaN(parsed.getTime()) ? new Date() : parsed;
}
