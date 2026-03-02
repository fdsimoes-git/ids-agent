import { sanitizeLine, sanitizeIp } from '../utils/sanitize.js';

// Nginx combined-format: first field must be CF-Connecting-IP (configure Nginx accordingly)
// Expected log_format: '$http_cf_connecting_ip - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
const NGINX_RE = /^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d+) (\d+|-) "([^"]*)" "([^"]*)"/;

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

export function parseNginxLine(raw) {
  const line = sanitizeLine(raw);
  const m = line.match(NGINX_RE);
  if (!m) return null;

  const ip = sanitizeIp(m[1]);
  if (!ip) return null;

  return {
    source: 'nginx',
    ip,
    user: m[2] === '-' ? null : m[2],
    timestamp: parseNginxDate(m[3]),
    method: m[4],
    path: m[5],
    status: parseInt(m[6], 10),
    size: m[7] === '-' ? 0 : parseInt(m[7], 10),
    referer: m[8] === '-' ? null : m[8],
    userAgent: m[9],
  };
}

function parseNginxDate(str) {
  const m = str.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/);
  if (!m) return new Date();
  const [, d, mon, y, h, min, s, tz] = m;
  const month = MONTHS[mon];
  if (month === undefined) return new Date();
  const iso = `${y}-${String(month + 1).padStart(2, '0')}-${d}T${h}:${min}:${s}${tz.slice(0, 3)}:${tz.slice(3)}`;
  const date = new Date(iso);
  return isNaN(date.getTime()) ? new Date() : date;
}
