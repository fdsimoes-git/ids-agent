export class CooldownManager {
  constructor(cooldownMs) {
    this.cooldownMs = cooldownMs;
    this.entries = new Map(); // key: `${ip}:${ruleType}` → timestamp
  }

  shouldAlert(ip, ruleType) {
    const key = `${ip}:${ruleType}`;
    const now = Date.now();
    const last = this.entries.get(key);
    if (last && now - last < this.cooldownMs) return false;
    this.entries.set(key, now);
    return true;
  }

  cleanup() {
    const now = Date.now();
    for (const [key, ts] of this.entries) {
      if (now - ts > this.cooldownMs * 2) this.entries.delete(key);
    }
  }
}
