import { describe, expect, it } from 'vitest'
import {
  BLANK_POLICY,
  generateCiliumNetworkPolicyYAML,
  ruleHasNoEffectiveSelector,
  ruleProducesNoOutput,
  type EgressRule,
  type IngressRule,
  type PolicyModel,
} from './policy'

function emptyIngressRule(overrides: Partial<IngressRule> = {}): IngressRule {
  return {
    id: 'ingress-1',
    fromEndpoints: [],
    fromCIDRs: [],
    fromEntities: [],
    toPorts: [],
    ...overrides,
  }
}

function emptyEgressRule(overrides: Partial<EgressRule> = {}): EgressRule {
  return {
    id: 'egress-1',
    toEndpoints: [],
    toCIDRs: [],
    toEntities: [],
    toPorts: [],
    ...overrides,
  }
}

describe('generateCiliumNetworkPolicyYAML', () => {
  it('emits an explicit ingressDeny for a policy with zero ingress/egress rules', () => {
    const yaml = generateCiliumNetworkPolicyYAML(BLANK_POLICY)
    expect(yaml).toContain('  ingressDeny:\n    - {}')
  })

  it('renders a fromEndpoints ingress rule with ports', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      ingressRules: [
        emptyIngressRule({
          fromEndpoints: [{ matchLabels: { app: 'frontend' } }],
          toPorts: [{ port: '8080', protocol: 'TCP' }],
        }),
      ],
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('  ingress:')
    expect(yaml).toContain('    - fromEndpoints:')
    expect(yaml).toContain('            app: "frontend"')
    expect(yaml).toContain('      toPorts:')
    expect(yaml).toContain('            - port: "8080"')
    expect(yaml).toContain('              protocol: TCP')
  })

  it('renders a fromCIDRs ingress rule', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      ingressRules: [emptyIngressRule({ fromCIDRs: ['10.0.0.0/8'] })],
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('    - fromCIDR:')
    expect(yaml).toContain('        - "10.0.0.0/8"')
  })

  it('renders a fromEntities ingress rule', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      ingressRules: [emptyIngressRule({ fromEntities: ['world'] })],
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('    - fromEntities:')
    expect(yaml).toContain('        - world')
  })

  it('renders a toEndpoints egress rule with ports', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      egressRules: [
        emptyEgressRule({
          toEndpoints: [{ matchLabels: { app: 'database' } }],
          toPorts: [{ port: '5432', protocol: 'TCP' }],
        }),
      ],
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('  egress:')
    expect(yaml).toContain('    - toEndpoints:')
    expect(yaml).toContain('            app: "database"')
    expect(yaml).toContain('      toPorts:')
    expect(yaml).toContain('            - port: "5432"')
  })

  it('renders a toCIDRs egress rule', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      egressRules: [emptyEgressRule({ toCIDRs: ['0.0.0.0/0'] })],
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('    - toCIDR:')
    expect(yaml).toContain('        - "0.0.0.0/0"')
  })

  it('renders a toEntities egress rule', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      egressRules: [emptyEgressRule({ toEntities: ['cluster'] })],
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('    - toEntities:')
    expect(yaml).toContain('        - cluster')
  })

  it('escapes a literal double quote in the description', () => {
    const model: PolicyModel = {
      ...BLANK_POLICY,
      description: 'Allows "trusted" traffic only',
    }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('  description: "Allows \\"trusted\\" traffic only"')
  })

  it('emits matchLabels: {} when the target has no labels', () => {
    const model: PolicyModel = { ...BLANK_POLICY, targetLabels: {} }
    const yaml = generateCiliumNetworkPolicyYAML(model)
    expect(yaml).toContain('    matchLabels: {}')
  })
})

describe('ruleHasNoEffectiveSelector', () => {
  it('is true when an endpoint has only an empty label key', () => {
    const rule = emptyIngressRule({ fromEndpoints: [{ matchLabels: { '': '' } }] })
    expect(ruleHasNoEffectiveSelector(rule)).toBe(true)
  })

  it('is false when an endpoint has a real label', () => {
    const rule = emptyIngressRule({ fromEndpoints: [{ matchLabels: { app: 'foo' } }] })
    expect(ruleHasNoEffectiveSelector(rule)).toBe(false)
  })

  it('is false for a rule using fromEntities/fromCIDRs instead of endpoints', () => {
    const rule = emptyIngressRule({ fromEntities: ['world'], fromCIDRs: ['1.2.3.0/24'] })
    expect(ruleHasNoEffectiveSelector(rule)).toBe(false)
  })
})

describe('ruleProducesNoOutput', () => {
  it('is true for a fully-empty rule', () => {
    expect(ruleProducesNoOutput(emptyIngressRule())).toBe(true)
  })

  it('is false once endpoints are set', () => {
    const rule = emptyIngressRule({ fromEndpoints: [{ matchLabels: { app: 'foo' } }] })
    expect(ruleProducesNoOutput(rule)).toBe(false)
  })

  it('is false once CIDRs are set', () => {
    expect(ruleProducesNoOutput(emptyIngressRule({ fromCIDRs: ['10.0.0.0/8'] }))).toBe(false)
  })

  it('is false once entities are set', () => {
    expect(ruleProducesNoOutput(emptyIngressRule({ fromEntities: ['host'] }))).toBe(false)
  })

  it('is false once ports are set', () => {
    expect(
      ruleProducesNoOutput(emptyIngressRule({ toPorts: [{ port: '80', protocol: 'TCP' }] })),
    ).toBe(false)
  })
})
