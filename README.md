# TrustMesh A2A 🛡️ — Discovery, Identity & SLA Escrow for the Open Agentic Web

[![Open Agentic Web](https://img.shields.io/badge/Protocol-Open%20Agentic%20Web-38bdf8.svg)](https://cognizant-agenticweb.devpost.com/)
[![Tests: 19 Passed](https://img.shields.io/badge/Vitest-19%2F19%20Passed-10b981.svg)](tests/trustmesh.test.ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**TrustMesh A2A** is a zero-dependency TypeScript protocol, CLI, and browser-native WebCrypto sandbox providing open capability discovery, attenuated W3C Ed25519 delegation chains, and hashlocked SLA micro-escrow for cross-domain web agents.

- **Live Browser Trust Sandbox**: [https://khanhtnq.github.io/trustmesh-a2a/](https://khanhtnq.github.io/trustmesh-a2a/)
- **Live Agentified Manifest (`/.well-known/agent-card.json`)**: [https://khanhtnq.github.io/trustmesh-a2a/.well-known/agent-card.json](https://khanhtnq.github.io/trustmesh-a2a/.well-known/agent-card.json)
- **Submission Overview**: [`SUBMISSION_DEVPOST_AND_T3.md`](SUBMISSION_DEVPOST_AND_T3.md)

---

## ✨ Core Primitives

1. **Zero-Friction Web Agent Discovery (`src/agentCard.ts`)**:
   - RFC-aligned `/.well-known/agent-card.json` generator & validator exposing agent skills, JSON schemas, `did:key` Ed25519 multibase public keys, and SLA latency contracts.
2. **W3C Ed25519 Attenuated Capability Credentials (`src/credentials.ts`, `src/crypto.ts`)**:
   - Cross-runtime Node `crypto` + browser `SubtleCrypto` Ed25519 signing over deterministic canonical JSON.
   - Enforces strictly monotonic scope, spend-limit, and TTL attenuation across multi-hop agent delegation chains.
3. **Deterministic SLA Micro-Escrow (`src/settlement.ts`)**:
   - SHA-256 hashlock commitments and signed latency receipts enforcing deterministic `PENDING -> SETTLED | SLASHED | REFUNDED` settlement.

---

## 🚀 Quick Start

```bash
# Run all 19 cryptographic & adversarial security tests
npm test

# Build TypeScript SDK & inspect CLI
npm run build
node bin/cli.js --help
```
