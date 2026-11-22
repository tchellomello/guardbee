import { describe, expect, it } from 'vitest'
import { flowsToCSV, flowsToText, l7Text, verdictRowsToCSV, verdictRowsToText } from './tableExport'
import type { Flow, VerdictRow } from '../api'

const flow = (over: Partial<Flow> = {}): Flow => ({
  time: '2026-11-10T11:44:44Z',
  verdict: 'DROPPED',
  source: 'testing/netshoot-mmello',
  destination: 'reserved:kube-apiserver',
  l4: 'TCP:443',
  dropReason: 'POLICY_DENIED',
  direction: 'EGRESS',
  decision: 'default-deny',
  decidedBy: 'default deny: no policy rule allows it',
  ...over,
})

describe('flowsToCSV', () => {
  it('writes a header and one CRLF-terminated row per flow', () => {
    expect(flowsToCSV([flow()])).toBe(
      'Time,Verdict,Direction,Source,Destination,L4,Decided By,Drop Reason\r\n' +
        '2026-11-10T11:44:44Z,DROPPED,EGRESS,testing/netshoot-mmello,reserved:kube-apiserver,TCP:443,default deny: no policy rule allows it,POLICY_DENIED\r\n'
    )
  })

  it('leaves a missing drop reason, direction and attribution empty', () => {
    const out = flowsToCSV([flow({ verdict: 'FORWARDED', dropReason: undefined, direction: undefined, decision: undefined, decidedBy: undefined })])
    expect(out).toContain('FORWARDED,,testing/netshoot-mmello')
    expect(out).toContain('TCP:443,,\r\n')
  })

  it('quotes commas, quotes and newlines', () => {
    const out = flowsToCSV([flow({ source: 'a,"b"\nc' })])
    expect(out).toContain('"a,""b""\nc"')
  })

  it('neutralises spreadsheet formulas', () => {
    const out = flowsToCSV([flow({ source: '=HYPERLINK("x")', destination: '@cmd' })])
    expect(out).toContain(`"'=HYPERLINK(""x"")"`)
    expect(out).toContain(",'@cmd,")
  })

  it('exports just the header for no flows', () => {
    expect(flowsToCSV([])).toBe('Time,Verdict,Direction,Source,Destination,L4,Decided By,Drop Reason\r\n')
  })
})

describe('flowsToText', () => {
  it('is tab-separated and flattens tabs/newlines inside values', () => {
    const out = flowsToText([flow({ source: 'a\tb\nc' })])
    expect(out.split('\n')[0]).toBe('Time\tVerdict\tDirection\tSource\tDestination\tL4\tDecided By\tDrop Reason')
    expect(out.split('\n')[1].split('\t')[3]).toBe('a b c')
  })
})

describe('verdict rows export', () => {
  const row = (over: Partial<VerdictRow> = {}): VerdictRow => ({
    change: 'NEWLY_DROPPED',
    source: 'testing/netshoot-mmello',
    destination: 'reserved:kube-apiserver',
    protocol: 'TCP',
    port: 443,
    count: 3,
    explanation: '(currently allowed; this candidate would start blocking it)',
    ...over,
  })

  it('writes the table columns with raw protocol, port and count', () => {
    expect(verdictRowsToCSV([row()])).toBe(
      'Change,Source,Destination,Protocol,Port,Seen,Why,L7\r\n' +
        'NEWLY_DROPPED,testing/netshoot-mmello,reserved:kube-apiserver,TCP,443,3,' +
        '(currently allowed; this candidate would start blocking it),\r\n'
    )
  })

  it('neutralises formulas and produces tab-separated text', () => {
    expect(verdictRowsToCSV([row({ source: '=cmd' })])).toContain(",'=cmd,")
    expect(verdictRowsToText([row()]).split('\n')[1].split('\t')).toHaveLength(8)
  })

  it('names the L7 rules: unchanged, changed, added and removed', () => {
    expect(l7Text(row())).toBe('')
    expect(l7Text(row({ l7Baseline: 'ingress: HTTP GET /healthz', l7Candidate: 'ingress: HTTP GET /healthz' }))).toBe('ingress: HTTP GET /healthz')
    expect(l7Text(row({ l7Baseline: 'ingress: HTTP GET /a', l7Candidate: 'ingress: HTTP GET /b' }))).toBe('ingress: HTTP GET /a → ingress: HTTP GET /b')
    expect(l7Text(row({ l7Candidate: 'egress: DNS *.example.com' }))).toBe('no L7 rules → egress: DNS *.example.com')
    expect(l7Text(row({ l7Baseline: 'egress: DNS *' }))).toBe('egress: DNS * → no L7 rules')
  })
})
