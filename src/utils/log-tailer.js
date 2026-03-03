import { open, stat } from 'node:fs/promises';
import { watch } from 'node:fs';
import { spawn } from 'node:child_process';
import logger from './logger.js';

/**
 * Tail a log file from the end, emitting new lines via callback.
 * Handles log rotation (file truncation / inode change).
 */
export class LogTailer {
  constructor(filePath, onLine) {
    this.filePath = filePath;
    this.onLine = onLine;
    this.offset = 0;
    this.buffer = '';
    this.watcher = null;
    this.fd = null;
    this.stopped = false;
    this.reading = false;
    this.inode = null;
  }

  async start() {
    try {
      const st = await stat(this.filePath);
      this.offset = st.size; // start from end
      this.inode = st.ino;
      this.fd = await open(this.filePath, 'r');
    } catch (err) {
      logger.warn(`Cannot open ${this.filePath}: ${err.message} — will poll until it appears`);
      this.offset = 0;
    }

    // fs.watch crashes on non-existent files, so only watch if the file exists
    try {
      this.watcher = watch(this.filePath, { persistent: false }, () => {
        if (!this.stopped) this._readNew();
      });
      this.watcher.on('error', () => {}); // suppress watcher errors (e.g. file deleted)
    } catch {
      // File doesn't exist yet — polling will pick it up when it appears
    }

    // Poll every 2s as fallback (handles missing files and unreliable fs.watch)
    this.pollInterval = setInterval(() => {
      if (!this.stopped) this._readNew();
    }, 2000);

    logger.info(`Tailing ${this.filePath}`);
  }

  async _readNew() {
    if (this.reading || this.stopped) return;
    this.reading = true;

    try {
      const st = await stat(this.filePath);

      // First time seeing the file, or log rotation (file got smaller or different inode)
      if (!this.fd || st.size < this.offset || st.ino !== this.inode) {
        if (this.fd) {
          logger.info(`Log rotation detected for ${this.filePath}`);
          await this.fd.close().catch(() => {});
        } else {
          logger.info(`File appeared: ${this.filePath}`);
        }
        this.fd = await open(this.filePath, 'r');
        this.offset = this.inode ? 0 : st.size; // new file: start from end; rotation: read from start
        this.inode = st.ino;
        this.buffer = '';

        // Start watcher if we didn't have one
        if (!this.watcher) {
          try {
            this.watcher = watch(this.filePath, { persistent: false }, () => {
              if (!this.stopped) this._readNew();
            });
            this.watcher.on('error', () => {});
          } catch { /* polling is enough */ }
        }
      }

      if (st.size <= this.offset) {
        this.reading = false;
        return;
      }

      const readSize = st.size - this.offset;
      const buf = Buffer.alloc(Math.min(readSize, 65536));
      const { bytesRead } = await this.fd.read(buf, 0, buf.length, this.offset);
      this.offset += bytesRead;

      this.buffer += buf.toString('utf8', 0, bytesRead);
      const lines = this.buffer.split('\n');
      this.buffer = lines.pop(); // keep incomplete line in buffer

      for (const line of lines) {
        if (line.trim()) this.onLine(line);
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        // File removed during rotation, wait for it to reappear
        logger.debug(`${this.filePath} temporarily gone (rotation)`);
      } else {
        logger.error(`Error tailing ${this.filePath}: ${err.message}`);
      }
    }

    this.reading = false;
  }

  async stop() {
    this.stopped = true;
    if (this.watcher) this.watcher.close();
    if (this.pollInterval) clearInterval(this.pollInterval);
    if (this.fd) await this.fd.close().catch(() => {});
  }
}

/**
 * Tail a systemd journal for a specific service using journalctl.
 */
export class JournalTailer {
  constructor(serviceName, onLine) {
    this.serviceName = serviceName;
    this.onLine = onLine;
    this.proc = null;
    this.stopped = false;
  }

  start() {
    try {
      this.proc = spawn('journalctl', [
        '-f', '-u', this.serviceName,
        '--output=short-iso',
        '--no-pager',
        '-n', '0', // don't replay old entries
      ], { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      logger.warn(`journalctl not available: ${err.message}`);
      return;
    }

    this.proc.on('error', (err) => {
      logger.warn(`journalctl spawn error: ${err.message} — journal tailing disabled`);
      this.stopped = true;
    });

    let buffer = '';
    this.proc.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.trim()) this.onLine(line);
      }
    });

    this.proc.stderr.on('data', (chunk) => {
      logger.warn(`journalctl stderr: ${chunk.toString().trim()}`);
    });

    this.proc.on('close', (code) => {
      if (!this.stopped) {
        logger.warn(`journalctl exited with code ${code}, restarting in 5s`);
        setTimeout(() => { if (!this.stopped) this.start(); }, 5000);
      }
    });

    logger.info(`Tailing journal for service: ${this.serviceName}`);
  }

  stop() {
    this.stopped = true;
    if (this.proc) this.proc.kill('SIGTERM');
  }
}
