import config from '../../config.js';
import logger from '../utils/logger.js';

let lookup = null;

try {
  const geoip = await import('geoip-lite');
  lookup = (geoip.default || geoip).lookup;
  logger.info('GeoIP detection enabled');
} catch {
  logger.warn('geoip-lite not available — geo-anomaly detection disabled');
}

export function checkGeo(event, store) {
  if (!lookup) return null;
  if (event.source !== 'nginx') return null;
  if (!event.ip) return null;

  const geo = lookup(event.ip);
  if (!geo || !geo.country) return null;

  if (!config.allowedCountries.includes(geo.country)) {
    // Only alert once per IP (use store to deduplicate)
    const key = `geo:${event.ip}`;
    const seen = store.count(key, 3600_000); // 1 hour window
    store.push(key, { country: geo.country });

    if (seen === 0) {
      return {
        rule: 'geo-anomaly',
        severity: 'LOW',
        ip: event.ip,
        timestamp: new Date().toISOString(),
        endpoint: event.path,
        details: `Request from ${geo.country} (${geo.city || 'unknown city'}) — allowed: ${config.allowedCountries.join(', ')}`,
        suggestedAction: 'Review — may be legitimate VPN/CDN traffic',
        count: 1,
        meta: { country: geo.country, region: geo.region, city: geo.city },
      };
    }
  }

  return null;
}
