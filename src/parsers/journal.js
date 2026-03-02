import { sanitizeLine } from '../utils/sanitize.js';

// journalctl --output=short-iso format:
// 2024-01-01T12:00:00+0000 hostname unit[1234]: message
const JOURNAL_RE = /^(\S+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.+)$/;

export function parseJournalLine(raw) {
  const line = sanitizeLine(raw);
  const m = line.match(JOURNAL_RE);
  if (!m) {
    // Fallback: treat as a generic message if it doesn't match the structured format
    if (line.trim()) {
      return {
        source: 'journal',
        timestamp: new Date(),
        hostname: null,
        unit: null,
        pid: null,
        message: line.trim(),
      };
    }
    return null;
  }

  return {
    source: 'journal',
    timestamp: new Date(m[1]),
    hostname: m[2],
    unit: m[3],
    pid: parseInt(m[4], 10),
    message: m[5],
  };
}
