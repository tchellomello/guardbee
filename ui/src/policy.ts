// Data model, presets, and YAML generator for CiliumNetworkPolicy /
// CiliumClusterwideNetworkPolicy (cilium.io/v2).

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'ANY'

// A CiliumClusterwideNetworkPolicy has no metadata.namespace — PolicyModel's
// `namespace` field means something slightly different depending on `kind`
// (see generateCiliumNetworkPolicyYAML below): metadata.namespace for a CNP,
// or an explicit io.kubernetes.pod.namespace match label on the target
// selector for a CCNP. Reusing the one field keeps every namespace-aware
// bit of the editor (the live-pod picker, peer autocomplete) working
// unchanged for both kinds.
export type PolicyKind = 'CiliumNetworkPolicy' | 'CiliumClusterwideNetworkPolicy'

export interface PortRule {
  port: string
  protocol: Protocol
}

export interface EndpointSelectorRule {
  matchLabels: Record<string, string>
  namespace?: string
}

// K8sServiceRef is the simple (and by far the most common) form of Cilium's
// `Service` union — selecting one k8s Service by name/namespace rather than
// a whole set of Services via a label selector (api.K8sServiceSelectorNamespace,
// deferred: a v1 simplification, see generateCiliumNetworkPolicyYAML).
export interface K8sServiceRef {
  serviceName: string
  namespace: string
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
  // Cilium's ToServices — egress-only, no ingress equivalent exists in the
  // real API (FromServices isn't a thing: inbound traffic doesn't originate
  // "from" a Service). Scoped to the K8sService{name, namespace} form only;
  // selecting a whole set of Services by label (K8sServiceSelector) is
  // deferred — see generateCiliumNetworkPolicyYAML's toServices branch.
  //
  // FromRequires/ToRequires (Cilium's AND-style peer-narrowing constraint)
  // were deliberately NOT added alongside this: the exact Cilium version
  // this project pins (go.mod: v1.20.2) marks both Deprecated with
  // `+kubebuilder:validation:MaxItems=0` — a real cluster's CRD schema
  // rejects any non-empty value outright. An editor feature for it would
  // generate YAML that parses fine in this tool but gets rejected by the
  // real cluster on apply, which is exactly the kind of guessed-semantics
  // bug this project's embedded-real-engine principle exists to prevent.
  toServices: K8sServiceRef[]
  toPorts: PortRule[]
}

export interface PolicyModel {
  kind: PolicyKind
  name: string
  namespace: string
  description: string
  targetLabels: Record<string, string>
  ingressRules: IngressRule[]
  egressRules: EgressRule[]
  // True means "deliberately deny all egress" (spec.egressDeny), distinct
  // from egressRules being empty because it hasn't been configured yet
  // (spec.egress omitted entirely, which is default-allow — see the egress
  // branch of generateCiliumNetworkPolicyYAML below). Ingress needs no
  // equivalent flag: an empty ingressRules list already means default-deny
  // for ingress, both in this editor and in real Cilium semantics.
  egressDenyAll: boolean
}

// BLANK_POLICY is the editor's zero-state starting point — the one preset
// that's always available instantly (no fetch needed) as App.tsx's initial
// state and as the Policy Editor's "Blank Policy"/"Reset form" option. Every
// other preset (starting policies, and the per-rule "Web", "DNS", etc.
// buttons) is loaded over HTTP from the backend's /api/templates, which
// reads a directory of real CiliumNetworkPolicy YAML files rather than
// hardcoding them here — see shared/useTemplates.ts and templates.go.
export const BLANK_POLICY: PolicyModel = {
  kind: 'CiliumNetworkPolicy',
  name: 'custom-policy',
  namespace: 'default',
  description: 'Custom network policy',
  targetLabels: { app: 'my-service' },
  ingressRules: [],
  egressRules: [],
  egressDenyAll: false,
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
  const toServices = 'toServices' in rule ? rule.toServices : []
  return (
    endpoints.length === 0 &&
    cidrs.length === 0 &&
    entities.length === 0 &&
    toServices.length === 0 &&
    rule.toPorts.length === 0
  )
}


export function generateCiliumNetworkPolicyYAML(model: PolicyModel): string {
  const lines: string[] = []

  const isClusterwide = model.kind === 'CiliumClusterwideNetworkPolicy'

  lines.push('apiVersion: cilium.io/v2')
  lines.push(`kind: ${model.kind}`)
  lines.push('metadata:')
  lines.push(`  name: ${model.name || 'unnamed-policy'}`)
  // A CiliumClusterwideNetworkPolicy has no metadata.namespace — the
  // Namespace field's value goes into the endpointSelector instead, below.
  if (!isClusterwide && model.namespace) {
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
    if (isClusterwide && model.namespace) {
      lines.push(`      io.kubernetes.pod.namespace: "${model.namespace}"`)
    }
  } else if (isClusterwide && model.namespace) {
    lines.push('    matchLabels:')
    lines.push(`      io.kubernetes.pod.namespace: "${model.namespace}"`)
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
  if (model.egressDenyAll) {
    // The one Cilium-valid way to write "deny all egress" — a bare empty
    // `egress: []` doesn't work, Sanitize() rejects a rule with none of
    // Ingress/IngressDeny/Egress/EgressDeny at all (same finding as
    // ingress's own ingressDeny fallback above, confirmed against the
    // vendored policy engine — see examples/postgres-default-deny.yaml).
    lines.push('  egressDeny:')
    lines.push('    - {}')
  } else if (model.egressRules.length > 0) {
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

      // toServices rule item (separate list entry) — scoped to the simple
      // K8sService{name, namespace} form only (Cilium's api.Service also
      // supports K8sServiceSelector, selecting a whole set of Services by
      // label; deferred as a v1 simplification, same spirit as this
      // editor's existing toPorts/toCIDR scope decisions).
      if (rule.toServices.length > 0) {
        emittedAny = true
        lines.push('    - toServices:')
        for (const svc of rule.toServices) {
          lines.push('        - k8sService:')
          lines.push(`            serviceName: "${svc.serviceName}"`)
          if (svc.namespace) {
            lines.push(`            namespace: "${svc.namespace}"`)
          }
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
