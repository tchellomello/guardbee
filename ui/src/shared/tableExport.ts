import type { Flow, VerdictRow } from '../api'

export const FLOW_COLUMNS = ['Time', 'Verdict', 'Source', 'Destination', 'L4', 'Drop Reason'] as const

// Raw ISO time rather than the on-screen toLocaleTimeString(): an export is
// read by other tools, and a time-of-day string loses the date and timezone.
function flowCells(f: Flow): string[] {
  return [f.time, f.verdict, f.source, f.destination, f.l4, f.dropReason ?? '']
}

// A cell that starts with = + - @ (or a control char) is executed as a
// formula by spreadsheets. Labels and names in these tables come from the
// cluster, so they are untrusted; a leading apostrophe makes the cell text.
function csvCell(v: string): string {
  const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}

function toCSV(header: readonly string[], body: string[][]): string {
  return [header, ...body].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n'
}

// Tab-separated, so it pastes straight into a spreadsheet and stays readable
// as plain text. Tabs/newlines inside a value would break the columns.
function toText(header: readonly string[], body: string[][]): string {
  const clean = (v: string) => v.replace(/[\t\r\n]+/g, ' ')
  return [header, ...body].map((r) => r.map(clean).join('\t')).join('\n') + '\n'
}

export const flowsToCSV = (flows: Flow[]) => toCSV(FLOW_COLUMNS, flows.map(flowCells))
export const flowsToText = (flows: Flow[]) => toText(FLOW_COLUMNS, flows.map(flowCells))

// Same columns/order as the Verdict results table, except Protocol and Port
// are split (filterable in a spreadsheet) and Seen is the raw count, not the
// on-screen "—"/"3×" display form.
export const VERDICT_COLUMNS = ['Change', 'Source', 'Destination', 'Protocol', 'Port', 'Seen', 'Why'] as const

function verdictCells(r: VerdictRow): string[] {
  return [r.change, r.source, r.destination, r.protocol, String(r.port), String(r.count), r.explanation]
}

export const verdictRowsToCSV = (rows: VerdictRow[]) => toCSV(VERDICT_COLUMNS, rows.map(verdictCells))
export const verdictRowsToText = (rows: VerdictRow[]) => toText(VERDICT_COLUMNS, rows.map(verdictCells))

export function downloadTextFile(filename: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
