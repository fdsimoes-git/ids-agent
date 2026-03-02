import { sanitizeLine, sanitizeIp } from '../utils/sanitize.js';

const UFW_RE = /\[UFW (\w+)\]/;
const SRC_RE = /SRC=(\S+)/;
const DST_RE = /DST=(\S+)/;
const PROTO_RE = /PROTO=(\S+)/;
const SPT_RE = /SPT=(\d+)/;
const DPT_RE = /DPT=(\d+)/;

export function parseUfwLine(raw) {
  const line = sanitizeLine(raw);
  const actionMatch = line.match(UFW_RE);
  if (!actionMatch) return null;

  const srcMatch = line.match(SRC_RE);
  if (!srcMatch) return null;

  const ip = sanitizeIp(srcMatch[1]);
  if (!ip) return null;

  return {
    source: 'ufw',
    action: actionMatch[1],
    ip,
    dst: (line.match(DST_RE) || [])[1] || null,
    proto: (line.match(PROTO_RE) || [])[1] || null,
    spt: parseInt((line.match(SPT_RE) || [])[1], 10) || null,
    dpt: parseInt((line.match(DPT_RE) || [])[1], 10) || null,
    timestamp: parseSyslogDate(line),
  };
}

function parseSyslogDate(line) {
  const dateStr = line.slice(0, 15).trim();
  const now = new Date();
  const parsed = new Date(`${dateStr} ${now.getFullYear()}`);
  return isNaN(parsed.getTime()) ? new Date() : parsed;
}
