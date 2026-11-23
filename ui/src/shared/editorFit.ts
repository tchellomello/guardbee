import type { PolicyParseResult } from '../api'

// Why a parsed candidate can't be opened in the Policy Editor, or null when
// it can. The editor holds one policy with port-level rules; anything it
// can't represent (the backend's lossy flag) would lose rules on the way.
export function editorRefusal(res: PolicyParseResult): string | null {
  if (!res.valid || !res.policy) return res.error ?? 'Not a valid policy'
  if ((res.documents ?? 1) > 1) {
    return `This candidate holds ${res.documents} policies; the Policy Editor edits one at a time. Keep editing it here.`
  }
  if (res.lossy) {
    return "The Policy Editor can't represent everything in this policy (L7 HTTP/DNS rules, toFQDNs, TLS/SNI, or scoped deny rules), so it would lose rules. Keep editing it here."
  }
  return null
}
