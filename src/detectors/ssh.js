import config from '../../config.js';

const { count, windowSec } = config.thresholds.sshAbuse;
const windowMs = windowSec * 1000;

export function checkSsh(event, store) {
  if (event.source !== 'auth') return null;
  if (event.action !== 'failed_login' && event.action !== 'invalid_user') return null;

  const key = `ssh:${event.ip}`;
  store.push(key, { user: event.user, action: event.action });
  const hits = store.count(key, windowMs);

  if (hits >= count) {
    return {
      rule: 'ssh-abuse',
      severity: hits >= count * 3 ? 'CRITICAL' : 'HIGH',
      ip: event.ip,
      timestamp: new Date().toISOString(),
      endpoint: `SSH (user: ${event.user})`,
      details: `${hits} failed SSH attempts in ${windowSec}s`,
      suggestedAction: 'Block IP via fail2ban SSH jail',
      count: hits,
    };
  }

  return null;
}
