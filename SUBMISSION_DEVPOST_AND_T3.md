# TrustMesh A2A — Devpost & T3 Submission Details

## Devpost Form Metadata
- **Hackathon**: Cognizant Open Agentic Web Challenge (`https://cognizant-agenticweb.devpost.com/`, $13,000 / $10,000+ Cash Pool)
- **Project Name**: `TrustMesh A2A`
- **Elevator Pitch (165 chars)**: `Open Agentic Web protocol delivering RFC-compliant /.well-known/agent-card.json discovery, W3C Ed25519 attenuated delegation chains, and hashlocked SLA micro-escrow.`
- **Track / Prize Category**: `Discovery, Identity & Trust` / `Agentifying Websites & Reusable Open Agentic Web Infrastructure`
- **Built With**: `typescript`, `nodejs`, `webcrypto`, `ed25519`, `w3c-vc`, `did-key`, `a2a-protocol`, `json-schema`, `html5`, `vitest`
- **GitHub Repository URL**: `https://github.com/Khanhtnq/trustmesh-a2a`
- **Try It Out Links**:
  - `https://khanhtnq.github.io/trustmesh-a2a/`
  - `https://khanhtnq.github.io/trustmesh-a2a/.well-known/agent-card.json`
  - `https://github.com/Khanhtnq/trustmesh-a2a`
- **File Attachments**: None required (Live Agentic Browser Sandbox + Live `/.well-known/agent-card.json` Endpoint + Public MIT Repo + 1080p YouTube Video + 3 Gallery PNGs)
- **YouTube Title**: `TrustMesh A2A — Discovery, Ed25519 Capability Trust & SLA Escrow for the Open Agentic Web (1080p)`
- **YouTube Description**:
  ```text
  TrustMesh A2A — Official Open-Source Submission for the Cognizant Open Agentic Web Challenge.
  Cryptographic trust, discovery, and settlement infrastructure for independent browser & web agents:
  1. Zero-Friction Web Agent Discovery (/.well-known/agent-card.json manifest + capability indexing)
  2. W3C Ed25519 Attenuated Capability Credentials (did:key multibase + monotonic multi-hop delegation)
  3. Deterministic SLA Hashlock Micro-Escrow (SHA-256 preimage receipts + automatic latency slashing)

  Live Interactive Sandbox: https://khanhtnq.github.io/trustmesh-a2a/
  Live Agent Card Endpoint: https://khanhtnq.github.io/trustmesh-a2a/.well-known/agent-card.json
  Open-Source Repository (MIT): https://github.com/Khanhtnq/trustmesh-a2a
  ```

---

## About the Project (Markdown Story)

### Inspiration
For the **Open Agentic Web** to scale like the original World Wide Web, autonomous browser and service agents across independent domains must be able to **discover** each other's capabilities, **delegate** strictly scoped permissions without sharing root API keys, and **settle** service-level agreements (SLAs) without centralized gatekeepers.

Today, cross-site agent collaboration breaks down on three missing primitives:
1. Websites lack machine-verifiable capability manifests that browser agents can index natively.
2. Multi-hop agent delegation suffers from ambient authority—if Agent A hires Agent B, and Agent B subcontracts Agent C, permissions can be silently escalated or forged.
3. There is no lightweight cryptographic mechanism to hold sub-agents accountable to latency and quality SLAs.

We built **TrustMesh A2A**—a zero-dependency TypeScript SDK, CLI, and browser-native WebCrypto sandbox that brings open discovery, cryptographic capability attenuation, and deterministic SLA settlement to any static or dynamic website.

### What It Does
1. **Open Agentic Web Discovery (`/.well-known/agent-card.json`)**:
   - Turns any website or GitHub Pages deployment into an agent-ready node exposing declarative skill schemas, input/output JSON contracts, `did:key` multibase Ed25519 public keys, and verifiable SLA latency/uptime guarantees.
2. **W3C Ed25519 Capability Credentials & Monotonic Attenuation**:
   - Enables root users or orchestrator agents to sign W3C-aligned Capability Credentials using native WebCrypto / Node `crypto` Ed25519 keys.
   - Enforces **strictly monotonic attenuation** across multi-hop delegation chains (`User -> Orchestrator -> Specialist Agent`): child tokens can narrow action scopes (`read/write -> read`), lower spend caps, or shorten expiration windows, and any scope-expansion or signature-tampering attempt is deterministically rejected.
3. **Deterministic SLA Micro-Escrow & Hashlock Settlement**:
   - Locks micro-bounties behind SHA-256 hashlocks (`H(preimage)`) paired with strict execution deadlines.
   - Verifies signed execution receipts against actual wall-clock latency, transitioning deterministically from `PENDING` to `SETTLED` (on-time valid proof), `SLASHED` (SLA breach penalty), or `REFUNDED` (timeout).
4. **Interactive Browser Playground & CLI (`bin/cli.js`)**:
   - Live browser simulator (`docs/index.html`) running real WebCrypto Ed25519 key generation, live `/.well-known/agent-card.json` discovery, tampered delegation attack simulations, and SLA escrow settlement.

### How We Built It
- **Pure Standards & Zero Bloat**: Written in strict TypeScript (`ES2022`) using native W3C `SubtleCrypto` (`Ed25519` + `SHA-256`) and Node.js `node:crypto`—zero heavy blockchain RPC dependencies or proprietary cloud lock-in.
- **Deterministic Canonical JSON (RFC 8785 style)**: Recursive lexicographical key canonicalization ensuring byte-identical Ed25519 signatures across Chrome, Firefox, Safari, Edge, and Node.js runtimes.
- **did:key Multicodec (`0xed01`)**: Standard Base58btc multibase encoding for self-certifying decentralized agent identifiers.
- **Comprehensive Security Suite (`tests/trustmesh.test.ts`)**: `19/19` automated unit and adversarial security tests via Vitest verifying signature forgery rejection, privilege escalation blocking, replay protection, and SLA slash math.

### Challenges We Ran Into
- **Cross-Runtime Ed25519 Interoperability**: Bridging PKCS#8/SPKI DER key encodings in Node.js with browser `SubtleCrypto` raw 32-byte public keys required crafting clean DER prefix envelopes and Base58btc multicodec codecs (`src/crypto.ts`) without external npm crypto bloat.
- **Preventing Privilege Escalation in Multi-Hop Chains**: Designing the verifier (`src/credentials.ts`) to walk the entire parent-child cryptographic proof chain and verify subset inclusion on capability scopes, resource prefixes, and timestamps at every hop.

### Accomplishments That We're Proud Of
- Shipping a **live agentified website** (`https://khanhtnq.github.io/trustmesh-a2a/.well-known/agent-card.json`) alongside a full interactive browser trust mesh simulator and CLI tool under the open **MIT License**.
- Passing `19/19` adversarial cryptographic and SLA state-machine tests with zero runtime dependencies.

### What We Learned
- How lightweight W3C capability credentials (`did:key` + attenuated JSON proofs) solve cross-origin agent authorization far more cleanly than OAuth2 bearer tokens, which cannot be safely attenuated by intermediate browser agents.

### What's Next for TrustMesh A2A
- **WebMCP & MIT NANDA Index Connector**: Automatic one-command registration of `/.well-known/agent-card.json` endpoints into decentralized Open Agentic Web directories and Cognizant Neuro SAN orchestrators.
- **Browser Extension Trust Badge**: A lightweight Chromium extension displaying real-time green cryptographic trust badges whenever a visited site exposes a verified `agent-card.json`.
