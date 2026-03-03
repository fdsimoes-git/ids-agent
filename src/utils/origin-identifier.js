const KNOWN_ORIGINS = [
  // Monitoring services
  { pattern: /GoogleStackdriverMonitoring|Google-Cloud-Monitoring/i, name: 'Google Cloud Monitoring', type: 'monitoring' },
  { pattern: /UptimeRobot/i, name: 'UptimeRobot', type: 'monitoring' },
  { pattern: /Pingdom/i, name: 'Pingdom', type: 'monitoring' },
  { pattern: /Datadog/i, name: 'Datadog', type: 'monitoring' },
  { pattern: /NewRelicPinger|newrelic/i, name: 'New Relic', type: 'monitoring' },
  { pattern: /StatusCake/i, name: 'StatusCake', type: 'monitoring' },
  { pattern: /Site24x7/i, name: 'Site24x7', type: 'monitoring' },
  { pattern: /Better Uptime/i, name: 'Better Uptime', type: 'monitoring' },

  // Search engines
  { pattern: /Googlebot/i, name: 'Googlebot', type: 'search-engine' },
  { pattern: /bingbot/i, name: 'Bingbot', type: 'search-engine' },
  { pattern: /YandexBot/i, name: 'YandexBot', type: 'search-engine' },
  { pattern: /Baiduspider/i, name: 'Baiduspider', type: 'search-engine' },
  { pattern: /DuckDuckBot/i, name: 'DuckDuckBot', type: 'search-engine' },

  // Social / preview bots
  { pattern: /facebookexternalhit|facebot/i, name: 'Facebook', type: 'social-bot' },
  { pattern: /Twitterbot/i, name: 'Twitter', type: 'social-bot' },
  { pattern: /LinkedInBot/i, name: 'LinkedIn', type: 'social-bot' },
  { pattern: /Slackbot/i, name: 'Slack', type: 'social-bot' },
  { pattern: /WhatsApp/i, name: 'WhatsApp', type: 'social-bot' },
  { pattern: /TelegramBot/i, name: 'Telegram', type: 'social-bot' },

  // CDN / Infrastructure
  { pattern: /Cloudflare[-\s]?Health/i, name: 'Cloudflare Healthcheck', type: 'cdn' },
  { pattern: /Amazon-Route53-Health-Check/i, name: 'AWS Route 53', type: 'cdn' },
  { pattern: /ELB-HealthChecker/i, name: 'AWS ELB HealthChecker', type: 'cdn' },

  // Common tools
  { pattern: /\bcurl\b/i, name: 'curl', type: 'tool' },
  { pattern: /python-requests/i, name: 'python-requests', type: 'tool' },
  { pattern: /Go-http-client/i, name: 'Go-http-client', type: 'tool' },
  { pattern: /\bwget\b/i, name: 'wget', type: 'tool' },
  { pattern: /\baxios\b/i, name: 'axios', type: 'tool' },
];

export function identifyOrigin(userAgent) {
  if (!userAgent) return null;
  for (const { pattern, name, type } of KNOWN_ORIGINS) {
    if (pattern.test(userAgent)) return { name, type };
  }
  return null;
}

export const HTTP_STATUS_LABELS = {
  200: 'OK',
  201: 'Created',
  204: 'No Content',
  301: 'Moved',
  302: 'Redirect',
  304: 'Not Modified',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  408: 'Request Timeout',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
};

export function describeStatus(code) {
  return HTTP_STATUS_LABELS[code] || null;
}
