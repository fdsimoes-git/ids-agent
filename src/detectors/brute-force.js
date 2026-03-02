import config from '../../config.js';

const { count, windowSec } = config.thresholds.bruteForce;
const windowMs = windowSec * 1000;

export function checkBruteForce(event, store) {
  if (event.source !== 'nginx') return null;
  if (event.status !== 401 && event.status !== 403) return null;

  const key = `brute:${event.ip}`;
  store.push(key, { path: event.path });
  const hits = store.count(key, windowMs);

  if (hits >= count) {
    return {
      rule: 'brute-force',
      severity: hits >= count * 2 ? 'HIGH' : 'MEDIUM',
      ip: event.ip,
      timestamp: new Date().toISOString(),
      endpoint: event.path,
      details: `${hits} failed login attempts (401/403) in ${windowSec}s`,
      suggestedAction: 'Block IP via fail2ban',
      count: hits,
    };
  }

  return null;
}
