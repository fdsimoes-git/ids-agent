import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import config from '../../config.js';
import logger from '../utils/logger.js';

class ThreatMemory {
  constructor() {
    this.filePath = config.threatHistoryPath;
    this.history = [];
    this.dirty = false;
    this.saveTimer = null;
  }

  async load() {
    try {
      await mkdir(dirname(this.filePath), { recursive: true }).catch(() => {});
      const data = await readFile(this.filePath, 'utf8');
      this.history = JSON.parse(data);
      this.trimOld();
      logger.info(`Loaded ${this.history.length} threat history entries`);
    } catch {
      this.history = [];
      logger.info('Starting with empty threat history');
    }

    this.saveTimer = setInterval(() => {
      if (this.dirty) this.save().catch(() => {});
    }, 60_000);
  }

  addEvent(event) {
    this.history.push({
      ...event,
      recordedAt: new Date().toISOString(),
    });
    this.dirty = true;
    this.trimOld();
  }

  trimOld() {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    this.history = this.history.filter(
      e => new Date(e.recordedAt).getTime() > cutoff
    );
  }

  getLast24h() {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    return this.history.filter(
      e => new Date(e.recordedAt).getTime() > cutoff
    );
  }

  getLastWeek() {
    return [...this.history];
  }

  async save() {
    try {
      await mkdir(dirname(this.filePath), { recursive: true }).catch(() => {});
      await writeFile(this.filePath, JSON.stringify(this.history, null, 2));
      this.dirty = false;
    } catch (err) {
      logger.error('Failed to save threat history', { error: err.message });
    }
  }

  async stop() {
    if (this.saveTimer) clearInterval(this.saveTimer);
    if (this.dirty) await this.save();
  }
}

export default new ThreatMemory();
