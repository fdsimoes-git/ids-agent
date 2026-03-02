import config from '../../config.js';

const { count, windowSec } = config.thresholds.httpFlood;
const windowMs = windowSec * 1000;

export function checkHttpFlood(event, store) {
  if (event.source !== 'nginx') return null;

  const key = `flood:${event.ip}`;
  store.push(key, { path: event.path });
  const hits = store.count(key, windowMs);

  if (hits >= count) {
    return {
      rule: 'http-flood',
      severity: hits >= count * 3 ? 'CRITICAL' : 'HIGH',
      ip: event.ip,
      timestamp: new Date().toISOString(),
      endpoint: event.path,
      details: `${hits} requests in ${windowSec}s`,
      suggestedAction: 'Rate-limit or block IP — possible DDoS',
      count: hits,
    };
  }

  return null;
}
