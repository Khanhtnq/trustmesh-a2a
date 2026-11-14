# TrustMesh A2A — Open Agentic Web Protocol

## Hackathon Submissions
- **Cognizant Open Agentic Web Challenge** ($13,000 USD Cash Prize Pool)
- **DoraHacks Terminal 3 Build+Scale Agent Micro Grant** ($1,800 USD)

## Core Innovations
1. **Open Agentic Web Discovery (`/.well-known/agent-card.json`)**:
   - RFC-compliant schema enabling zero-friction agent-to-agent capability indexing.
   - Declarative skill registry, authentication multibase keys, and SLA policies.

2. **W3C Ed25519 Capability Credentials & Attenuation Engine**:
   - Native Node.js `crypto` & WebCrypto Ed25519 signing.
   - Deterministic canonical JSON serialization.
   - Multi-hop delegation chains with strictly monotonic depth limits and action scope attenuation.
   - Temporal validation (issuanceDate, expirationDate).

3. **Deterministic SLA Settlement & Micro-Escrow Hashlock**:
   - Performance-bonded execution receipts.
   - Latency-enforced escrow state transitions (`PENDING` -> `SETTLED` / `SLASHED` / `REFUNDED`).
   - Replay protection and SHA-256 preimage verification.

4. **SDK & Command Line Interface**:
   - `bin/cli.js`: Key generation, agent card creation, capability issuance, and verification.
   - Standalone live browser simulator: `docs/index.html`.

## Test Results
- 19 automated unit & security tests executed via Vitest with 100% pass rate.
- Covers cryptographic primitives, base58 multicodec, signature forgery detection, scope expansion rejection, and SLA slash penalties.
