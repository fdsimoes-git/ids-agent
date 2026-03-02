export function checkBannedIp(event, store) {
  // Track fail2ban ban/unban events
  if (event.source === 'fail2ban') {
    if (event.action === 'ban') {
      store.markBanned(event.ip, event.jail);
    } else if (event.action === 'unban') {
      store.markUnbanned(event.ip);
      store.push(`unbanned:${event.ip}`, { jail: event.jail });
    }
    return null;
  }

  // Flag nginx requests from recently-unbanned IPs
  if (event.source === 'nginx' && event.ip) {
    const unbans = store.entries(`unbanned:${event.ip}`, 3600_000); // 1 hour window
    if (unbans.length > 0) {
      // Only flag the first access (deduplicate via store)
      const key = `postban:${event.ip}`;
      const seen = store.count(key, 3600_000);
      store.push(key, {});

      if (seen === 0) {
        return {
          rule: 'post-ban-access',
          severity: 'MEDIUM',
          ip: event.ip,
          timestamp: new Date().toISOString(),
          endpoint: event.path,
          details: `Previously banned IP (jail: ${unbans[0].jail}) resumed access`,
          suggestedAction: 'Monitor closely — may resume attack pattern',
          count: 1,
        };
      }
    }
  }

  return null;
}
