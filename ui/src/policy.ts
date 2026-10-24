// Data model, presets, and YAML generator for CiliumNetworkPolicy (cilium.io/v2).

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'ANY'

export interface PortRule {
  port: string
  protocol: Protocol
}

export interface EndpointSelectorRule {
  matchLabels: Record<string, string>
  namespace?: string
}

export interface IngressRule {
  id: string
  fromEndpoints: EndpointSelectorRule[]
  fromCIDRs: string[]
  fromEntities: string[] // "world" | "host" | "cluster"
  toPorts: PortRule[]
}

export interface EgressRule {
  id: string
  toEndpoints: EndpointSelectorRule[]
  toCIDRs: string[]
  toEntities: string[] // "world" | "host" | "cluster"
  toPorts: PortRule[]
}

export interface PolicyModel {
  name: string
  namespace: string
  description: string
  targetLabels: Record<string, string>
  ingressRules: IngressRule[]
  egressRules: EgressRule[]
}

// BLANK_POLICY is the editor's zero-state starting point — the one preset
// that's always available instantly (no fetch needed) as App.tsx's initial
// state and as the Policy Editor's "Blank Policy"/"Reset form" option. Every
// other preset (starting policies, and the per-rule "Web", "DNS", etc.
// buttons) is loaded over HTTP from the backend's /api/templates, which
// reads a directory of real CiliumNetworkPolicy YAML files rather than
// hardcoding them here — see shared/useTemplates.ts and templates.go.
export const BLANK_POLICY: PolicyModel = {
  name: 'custom-policy',
  namespace: 'default',
  description: 'Custom network policy',
  targetLabels: { app: 'my-service' },
  ingressRules: [],
  egressRules: [],
}

// Rule-level presets: common ingress/egress patterns (DNS, world HTTPS,
// cluster-internal, …) a user can drop into a rule list with one click
// instead of hand-assembling endpoints/entities/ports every time — distinct
// from the generic policy templates, which replace the whole policy model.
// "rule" has no "id": a fresh one is assigned wherever a preset is actually
// added to the canvas, since the same preset can be added more than once.
export interface IngressRulePreset {
  id: string
  name: string
  description: string
  rule: Omit<IngressRule, 'id'>
}

export interface EgressRulePreset {
  id: string
  name: string
  description: string
  rule: Omit<EgressRule, 'id'>
}

// A peer endpoint whose matchLabels have no non-empty key (e.g. the user
// cleared a label's key in the editor) isn't "no peer specified" — the
// generator below still emits a `- matchLabels:` list item for it, with
// nothing underneath, which Cilium reads as matching every endpoint. That's
// silently equivalent to "allow from/to anything" and needs a visible
// warning rather than looking like an ordinary scoped rule.
function endpointIsEffectivelyEmpty(ep: EndpointSelectorRule): boolean {
  return Object.entries(ep.matchLabels).filter(([k]) => k.trim()).length === 0
}

export function ruleHasNoEffectiveSelector(rule: IngressRule | EgressRule): boolean {
  const endpoints = 'fromEndpoints' in rule ? rule.fromEndpoints : rule.toEndpoints
  return endpoints.length > 0 && endpoints.some(endpointIsEffectivelyEmpty)
}

// True when a rule contributes zero lines to the generated YAML — every
// peer/CIDR/entity and every port has been cleared, so the rule is a no-op:
// still a node in the graph, but invisible to the actual generated policy.
export function ruleProducesNoOutput(rule: IngressRule | EgressRule): boolean {
  const endpoints = 'fromEndpoints' in rule ? rule.fromEndpoints : rule.toEndpoints
  const cidrs = 'fromCIDRs' in rule ? rule.fromCIDRs : rule.toCIDRs
  const entities = 'fromEntities' in rule ? rule.fromEntities : rule.toEntities
  return endpoints.length === 0 && cidrs.length === 0 && entities.length === 0 && rule.toPorts.length === 0
}

export function generateCiliumNetworkPolicyYAML(model: PolicyModel): string {
  const lines: string[] = []

  lines.push('apiVersion: cilium.io/v2')
  lines.push('kind: CiliumNetworkPolicy')
  lines.push('metadata:')
  lines.push(`  name: ${model.name || 'unnamed-policy'}`)
  if (model.namespace) {
    lines.push(`  namespace: ${model.namespace}`)
  }
  lines.push('spec:')
  if (model.description) {
    lines.push(`  description: "${model.description.replace(/"/g, '\\"')}"`)
  }

  // endpointSelector
  lines.push('  endpointSelector:')
  const targetLabelEntries = Object.entries(model.targetLabels).filter(([k]) => k.trim())
  if (targetLabelEntries.length > 0) {
    lines.push('    matchLabels:')
    for (const [k, v] of targetLabelEntries) {
      lines.push(`      ${k}: "${v}"`)
    }
  } else {
    lines.push('    matchLabels: {}')
  }

  // ingress
  if (model.ingressRules.length === 0) {
    // No allow rules yet doesn't mean "nothing to generate" — the rest of
    // this editor already labels a rule-less target "Ingress: Default Deny"
    // (see PolicyGraph.tsx's target node badge and its "+ Default Deny —
    // click to add a rule" node), but omitting the ingress key entirely
    // left that label false: Cilium leaves ingress fully open until some
    // key (Ingress/IngressDeny/Egress/EgressDeny) is actually present, and
    // Sanitize() rejects a spec with none of them at all. An explicit
    // empty-match ingressDeny rule is the one Cilium-valid way to write
    // "deny all ingress" (confirmed against the vendored policy engine —
    // see examples/postgres-default-deny.yaml's comment for the same
    // finding) — it's what makes this editor's own "Default Deny" promise
    // real instead of a decorative label on a no-op policy.
    lines.push('  ingressDeny:')
    lines.push('    - {}')
  } else {
    lines.push('  ingress:')
    for (const rule of model.ingressRules) {
      let emittedAny = false

      // fromEndpoints rule item
      if (rule.fromEndpoints.length > 0) {
        emittedAny = true
        lines.push('    - fromEndpoints:')
        for (const ep of rule.fromEndpoints) {
          lines.push('        - matchLabels:')
          const epEntries = Object.entries(ep.matchLabels).filter(([k]) => k.trim())
          if (epEntries.length > 0) {
            for (const [k, v] of epEntries) {
              lines.push(`            ${k}: "${v}"`)
            }
          }
          if (ep.namespace) {
            lines.push(`            io.kubernetes.pod.namespace: "${ep.namespace}"`)
          }
        }
        appendPortLines(lines, rule.toPorts, '      ')
      }

      // fromCIDR rule item (separate list entry)
      if (rule.fromCIDRs.length > 0) {
        emittedAny = true
        lines.push('    - fromCIDR:')
        for (const cidr of rule.fromCIDRs) {
          lines.push(`        - "${cidr}"`)
        }
        appendPortLines(lines, rule.toPorts, '      ')
      }

      // fromEntities rule item (separate list entry)
      if (rule.fromEntities.length > 0) {
        emittedAny = true
        lines.push('    - fromEntities:')
        for (const ent of rule.fromEntities) {
          lines.push(`        - ${ent}`)
        }
        appendPortLines(lines, rule.toPorts, '      ')
      }

      // If no endpoints/CIDRs/entities were specified, but ports were
      if (!emittedAny && rule.toPorts.length > 0) {
        lines.push('    - toPorts:')
        lines.push('        - ports:')
        for (const p of rule.toPorts) {
          lines.push(`            - port: "${p.port}"`)
          if (p.protocol && p.protocol !== 'ANY') {
            lines.push(`              protocol: ${p.protocol}`)
          }
        }
      }
    }
  }

  // egress
  if (model.egressRules.length > 0) {
    lines.push('  egress:')
    for (const rule of model.egressRules) {
      let emittedAny = false

      // toEndpoints rule item
      if (rule.toEndpoints.length > 0) {
        emittedAny = true
        lines.push('    - toEndpoints:')
        for (const ep of rule.toEndpoints) {
          lines.push('        - matchLabels:')
          const epEntries = Object.entries(ep.matchLabels).filter(([k]) => k.trim())
          if (epEntries.length > 0) {
            for (const [k, v] of epEntries) {
              lines.push(`            ${k}: "${v}"`)
            }
          }
          if (ep.namespace) {
            lines.push(`            io.kubernetes.pod.namespace: "${ep.namespace}"`)
          }
        }
        appendPortLines(lines, rule.toPorts, '      ')
      }

      // toCIDR rule item (separate list entry)
      if (rule.toCIDRs.length > 0) {
        emittedAny = true
        lines.push('    - toCIDR:')
        for (const cidr of rule.toCIDRs) {
          lines.push(`        - "${cidr}"`)
        }
        appendPortLines(lines, rule.toPorts, '      ')
      }

      // toEntities rule item (separate list entry)
      if (rule.toEntities.length > 0) {
        emittedAny = true
        lines.push('    - toEntities:')
        for (const ent of rule.toEntities) {
          lines.push(`        - ${ent}`)
        }
        appendPortLines(lines, rule.toPorts, '      ')
      }

      // If no endpoints/CIDRs/entities were specified, but ports were
      if (!emittedAny && rule.toPorts.length > 0) {
        lines.push('    - toPorts:')
        lines.push('        - ports:')
        for (const p of rule.toPorts) {
          lines.push(`            - port: "${p.port}"`)
          if (p.protocol && p.protocol !== 'ANY') {
            lines.push(`              protocol: ${p.protocol}`)
          }
        }
      }
    }
  }

  return lines.join('\n') + '\n'
}

function appendPortLines(lines: string[], ports: PortRule[], indent: string) {
  if (ports.length === 0) return
  lines.push(`${indent}toPorts:`)
  lines.push(`${indent}  - ports:`)
  for (const p of ports) {
    lines.push(`${indent}      - port: "${p.port}"`)
    if (p.protocol && p.protocol !== 'ANY') {
      lines.push(`${indent}        protocol: ${p.protocol}`)
    }
  }
}
