import { createServer } from 'node:http';
import config from '../../config.js';
import logger from '../utils/logger.js';

let httpServer = null;

export function startApiServer(store) {
  httpServer = createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    res.setHeader('Content-Type', 'application/json');

    if (url.pathname === '/health' && req.method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({
        status: 'ok',
        uptime: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
      }));
      return;
    }

    if (url.pathname === '/stats' && req.method === 'GET') {
      const auth = req.headers.authorization;
      if (!config.api.bearerToken || auth !== `Bearer ${config.api.bearerToken}`) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      res.writeHead(200);
      res.end(JSON.stringify(store.getStats()));
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not Found' }));
  });

  httpServer.listen(config.api.port, '127.0.0.1', () => {
    logger.info(`HTTP API listening on 127.0.0.1:${config.api.port}`);
  });

  httpServer.on('error', (err) => {
    logger.error('HTTP API server error', { error: err.message });
  });
}

export function stopApiServer() {
  return new Promise(resolve => {
    if (httpServer) httpServer.close(resolve);
    else resolve();
  });
}
