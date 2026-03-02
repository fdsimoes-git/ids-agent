import { checkBruteForce } from './brute-force.js';
import { checkPortScan } from './port-scan.js';
import { checkHttpFlood } from './http-flood.js';
import { checkErrorSpike } from './error-spike.js';
import { checkSsh } from './ssh.js';
import { checkUserAgent } from './user-agent.js';
import { checkGeo } from './geo.js';
import { checkPayload } from './payload.js';
import { checkBannedIp } from './banned-ip.js';

const detectors = [
  checkBannedIp,    // must run first to track ban/unban state
  checkBruteForce,
  checkPortScan,
  checkHttpFlood,
  checkErrorSpike,
  checkSsh,
  checkUserAgent,
  checkGeo,
  checkPayload,
];

export function runDetectors(event, store) {
  const threats = [];
  for (const check of detectors) {
    try {
      const threat = check(event, store);
      if (threat) threats.push(threat);
    } catch {
      // Individual detector failure should not break the pipeline
    }
  }
  return threats;
}
