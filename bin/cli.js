#!/usr/bin/env node

import { generateEd25519Key } from '../dist/crypto.js';
import { createAgentCard } from '../dist/agentCard.js';
import { issueCapabilityCredential, verifyCapabilityCredential } from '../dist/credentials.js';

const [,, command, ...args] = process.argv;

function printUsage() {
  console.log(`
TrustMesh A2A CLI - Agentic Web Discovery & Cryptographic Verification
Commands:
  keygen              Generate new Ed25519 DID key (did:key)
  card                Output compliant /.well-known/agent-card.json
  issue-cap           Issue sample W3C AgentCapabilityCredential
  verify <path>       Verify a Verifiable Credential file
  help                Display this assistance
  `);
}

switch (command) {
  case 'keygen': {
    const key = generateEd25519Key();
    console.log(JSON.stringify({
      did: key.did,
      publicKeyMultibase: key.did.replace('did:key:', '')
    }, null, 2));
    break;
  }
  case 'card': {
    const key = generateEd25519Key();
    const card = createAgentCard({
      did: key.did,
      name: 'TrustMesh Sentinel Node',
      description: 'Autonomous Agentic Web verification and capability discovery node',
      serviceEndpoint: 'https://agentic-web.github.io/trustmesh-sentinel',
      publicKeyMultibase: key.did.replace('did:key:', ''),
      skills: [
        { id: 'trust-mesh:verify-capability', name: 'Verify Capability Credential', description: 'Validates Ed25519 signatures and delegation bounds' },
        { id: 'trust-mesh:sla-settle', name: 'Deterministic SLA Settlement', description: 'Settles micro-escrows via sha256 preimages' }
      ]
    });
    console.log(JSON.stringify(card, null, 2));
    break;
  }
  case 'issue-cap': {
    const issuer = generateEd25519Key();
    const subject = generateEd25519Key();
    const cred = issueCapabilityCredential(issuer, {
      subjectDid: subject.did,
      allowedActions: ['web:fetch', 'crypto:sign', 'data:index'],
      maxBudgetSats: 500000,
      maxDelegationDepth: 2,
      validitySeconds: 3600
    });
    console.log(JSON.stringify(cred, null, 2));
    break;
  }
  default:
    printUsage();
    break;
}
