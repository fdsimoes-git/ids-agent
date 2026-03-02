import config from '../../config.js';

export function checkErrorSpike(event, store) {
  if (event.source !== 'nginx') return null;

  // 4xx spike detection
  if (event.status >= 400 && event.status < 500) {
    const key = '4xx:global';
    store.push(key, { ip: event.ip, path: event.path, status: event.status });
    const hits = store.count(key, config.thresholds.error4xx.windowSec * 1000);

    if (hits >= config.thresholds.error4xx.count) {
      return {
        rule: '4xx-spike',
        severity: 'MEDIUM',
        ip: event.ip,
        timestamp: new Date().toISOString(),
        endpoint: event.path,
        details: `${hits} client errors (4xx) in 1 minute (latest: ${event.status} from ${event.ip})`,
        suggestedAction: 'Review for misconfiguration or scanning activity',
        count: hits,
      };
    }
  }

  // 5xx spike detection
  if (event.status >= 500) {
    const key = '5xx:global';
    store.push(key, { ip: event.ip, path: event.path, status: event.status });
    const hits = store.count(key, config.thresholds.error5xx.windowSec * 1000);

    if (hits >= config.thresholds.error5xx.count) {
      return {
        rule: '5xx-spike',
        severity: 'HIGH',
        ip: event.ip,
        timestamp: new Date().toISOString(),
        endpoint: event.path,
        details: `${hits} server errors (5xx) in 1 minute (latest: ${event.status})`,
        suggestedAction: 'Check application health immediately',
        count: hits,
      };
    }
  }

  return null;
}
