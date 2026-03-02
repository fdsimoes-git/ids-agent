// Strip null bytes, control characters, and limit length to prevent log injection
export function sanitizeLine(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/\0/g, '')           // null bytes
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F]/g, '') // control chars (keep \n \r \t)
    .slice(0, 4096);              // hard length cap
}

// Validate and normalize an IPv4/IPv6 address
export function sanitizeIp(ip) {
  if (typeof ip !== 'string') return null;
  const trimmed = ip.trim();
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
    const parts = trimmed.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) return trimmed;
  }
  // IPv6 (simplified check)
  if (/^[0-9a-fA-F:]+$/.test(trimmed) && trimmed.includes(':')) {
    return trimmed.toLowerCase();
  }
  return null;
}

// Escape special chars for safe Telegram MarkdownV2
export function escapeTelegram(text) {
  return String(text).replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, '\\$1');
}
