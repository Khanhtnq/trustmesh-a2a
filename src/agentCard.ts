export interface AgentSkill {
  id: string;
  name: string;
  description: string;
  parametersSchema?: Record<string, any>;
  pricing?: {
    model: 'per_call' | 'subscription' | 'sla_hashlock';
    costSats?: number;
    escrowCategoryId?: string;
  };
}

export interface AgentCard {
  '@context': string[];
  id: string; // did:web or did:key
  type: string[];
  name: string;
  description: string;
  version: string;
  serviceEndpoint: string;
  skills: AgentSkill[];
  authentication: {
    type: string;
    publicKeyMultibase: string;
  };
  slaPolicy?: {
    maxLatencyMs: number;
    availabilitySlaPercent: number;
    challengeWindowBlocks: number;
    forfeitBondSats: number;
  };
}

export function createAgentCard(params: {
  did: string;
  name: string;
  description: string;
  serviceEndpoint: string;
  skills: AgentSkill[];
  publicKeyMultibase: string;
  slaPolicy?: AgentCard['slaPolicy'];
}): AgentCard {
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
      'https://agentic-web.org/ns/agent-card/v1'
    ],
    id: params.did,
    type: ['AgentProfile', 'AutonomousAgentNode'],
    name: params.name,
    description: params.description,
    version: '1.0.0',
    serviceEndpoint: params.serviceEndpoint,
    skills: params.skills,
    authentication: {
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: params.publicKeyMultibase
    },
    slaPolicy: params.slaPolicy || {
      maxLatencyMs: 1500,
      availabilitySlaPercent: 99.9,
      challengeWindowBlocks: 144,
      forfeitBondSats: 250000
    }
  };
}

export function validateAgentCard(card: AgentCard): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!card.id || (!card.id.startsWith('did:key:') && !card.id.startsWith('did:web:'))) {
    errors.push("Invalid 'id': must be a valid did:key or did:web identifier.");
  }
  if (!card.serviceEndpoint || !card.serviceEndpoint.startsWith('http')) {
    errors.push("Invalid 'serviceEndpoint': must be a valid HTTP/HTTPS endpoint.");
  }
  if (!Array.isArray(card.skills) || card.skills.length === 0) {
    errors.push("Agent card must publish at least one skill capability.");
  }
  if (!card.authentication?.publicKeyMultibase) {
    errors.push("Missing authentication public key multibase.");
  }
  return { valid: errors.length === 0, errors };
}
