import { sanitizeLine, sanitizeIp } from '../utils/sanitize.js';

// fail2ban log format:
// 2024-01-01 12:00:00,000 fail2ban.actions [1234]: NOTICE  [sshd] Ban 1.2.3.4
const BAN_RE = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+.+\[(\w+)\]\s+(Ban|Unban|Restore Ban)\s+(\S+)/;

export function parseFail2banLine(raw) {
  const line = sanitizeLine(raw);
  const m = line.match(BAN_RE);
  if (!m) return null;

  const ip = sanitizeIp(m[4]);
  if (!ip) return null;

  const action = m[3].includes('Ban') ? 'ban' : 'unban';

  return {
    source: 'fail2ban',
    timestamp: new Date(m[1].replace(' ', 'T')),
    jail: m[2],
    action,
    ip,
  };
}
