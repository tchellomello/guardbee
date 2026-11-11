import { describe, expect, it } from 'vitest'
import { flowsToCSV, flowsToText, verdictRowsToCSV, verdictRowsToText } from './tableExport'
import type { Flow, VerdictRow } from '../api'

const flow = (over: Partial<Flow> = {}): Flow => ({
  time: '2026-11-10T11:44:44Z',
  verdict: 'DROPPED',
  source: 'testing/netshoot-mmello',
  destination: 'reserved:kube-apiserver',
  l4: 'TCP:443',
  dropReason: 'POLICY_DENIED',
  ...over,
})

describe('flowsToCSV', () => {
  it('writes a header and one CRLF-terminated row per flow', () => {
    expect(flowsToCSV([flow()])).toBe(
      'Time,Verdict,Source,Destination,L4,Drop Reason\r\n' +
        '2026-11-10T11:44:44Z,DROPPED,testing/netshoot-mmello,reserved:kube-apiserver,TCP:443,POLICY_DENIED\r\n'
    )
  })

  it('leaves a missing drop reason empty', () => {
    expect(flowsToCSV([flow({ verdict: 'FORWARDED', dropReason: undefined })])).toContain('TCP:443,\r\n')
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
    expect(flowsToCSV([])).toBe('Time,Verdict,Source,Destination,L4,Drop Reason\r\n')
  })
})

describe('flowsToText', () => {
  it('is tab-separated and flattens tabs/newlines inside values', () => {
    const out = flowsToText([flow({ source: 'a\tb\nc' })])
    expect(out.split('\n')[0]).toBe('Time\tVerdict\tSource\tDestination\tL4\tDrop Reason')
    expect(out.split('\n')[1].split('\t')[2]).toBe('a b c')
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
      'Change,Source,Destination,Protocol,Port,Seen,Why\r\n' +
        'NEWLY_DROPPED,testing/netshoot-mmello,reserved:kube-apiserver,TCP,443,3,' +
        '(currently allowed; this candidate would start blocking it)\r\n'
    )
  })

  it('neutralises formulas and produces tab-separated text', () => {
    expect(verdictRowsToCSV([row({ source: '=cmd' })])).toContain(",'=cmd,")
    expect(verdictRowsToText([row()]).split('\n')[1].split('\t')).toHaveLength(7)
  })
})
