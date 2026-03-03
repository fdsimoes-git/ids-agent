import { checkBruteForce } from './brute-force.js';
import { checkPortScan } from './port-scan.js';
import { checkHttpFlood } from './http-flood.js';
import { checkErrorSpike } from './error-spike.js';
import { checkSsh } from './ssh.js';
import { checkUserAgent } from './user-agent.js';
import { checkGeo } from './geo.js';
import { checkPayload } from './payload.js';
import { checkBannedIp } from './banned-ip.js';
import { identifyOrigin, describeStatus } from '../utils/origin-identifier.js';

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

const MAX_UA_LENGTH = 120;

function enrichThreat(threat, event) {
  switch (event.source) {
    case 'nginx': {
      threat.protocol = 'HTTP';
      if (event.method) threat.httpMethod = event.method;
      if (event.status) {
        threat.statusCode = event.status;
        const label = describeStatus(event.status);
        if (label) threat.statusLabel = label;
      }
      if (event.userAgent) {
        threat.userAgent = event.userAgent.length > MAX_UA_LENGTH
          ? event.userAgent.slice(0, MAX_UA_LENGTH) + '…'
          : event.userAgent;
        const origin = identifyOrigin(event.userAgent);
        if (origin) threat.origin = origin;
      }
      break;
    }
    case 'auth': {
      threat.protocol = 'SSH';
      if (event.method) threat.authMethod = event.method;
      break;
    }
    case 'ufw': {
      threat.protocol = event.proto ? `Firewall/${event.proto.toUpperCase()}` : 'Firewall';
      if (event.dpt) threat.destPort = event.dpt;
      break;
    }
    case 'fail2ban': {
      threat.protocol = 'Fail2ban';
      if (event.jail) threat.jail = event.jail;
      break;
    }
  }
}

export function runDetectors(event, store) {
  const threats = [];
  for (const check of detectors) {
    try {
      const threat = check(event, store);
      if (threat) {
        enrichThreat(threat, event);
        threats.push(threat);
      }
    } catch {
      // Individual detector failure should not break the pipeline
    }
  }
  return threats;
}
