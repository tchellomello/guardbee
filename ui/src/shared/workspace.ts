// The policy workspace: named, saved candidates the user is iterating on,
// plus auto-save of the Verdict form. Lives in localStorage, same reasoning
// as App.tsx's Policy Editor draft: per-browser scratch work, never synced
// to the backend or the cluster (GuardBee stays read-only there).

import type { PolicyModel } from '../policy'
import { EMPTY_DESTINATION_FILTER, type DestinationFilter } from './destinationFilter'

export interface SavedPolicy {
  id: string
  name: string
  savedAt: string // ISO timestamp
  // Where it was saved from. A Verdict candidate is raw YAML (possibly
  // several documents: candidate + Allow/Deny exceptions); an Editor draft
  // also keeps its model so it reopens in the editor exactly as it was.
  origin: 'verdict' | 'editor'
  candidateYAML: string
  namespace: string
  allNamespaces: boolean
  editorModel?: PolicyModel
}

export type NewSavedPolicy = Omit<SavedPolicy, 'id' | 'savedAt'>

export const WORKSPACE_STORAGE_KEY = 'guardbee.workspace.policies'
export const VERDICT_FORM_STORAGE_KEY = 'guardbee.verdict.form'

function isSavedPolicy(v: unknown): v is SavedPolicy {
  const p = v as SavedPolicy
  return (
    !!p &&
    typeof p.id === 'string' &&
    typeof p.name === 'string' &&
    typeof p.candidateYAML === 'string' &&
    typeof p.namespace === 'string' &&
    (p.origin === 'verdict' || p.origin === 'editor')
  )
}

export function loadSavedPolicies(): SavedPolicy[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(WORKSPACE_STORAGE_KEY) || '[]')
    // Entries from a future/older shape are dropped rather than fed into
    // the UI half-formed.
    return Array.isArray(parsed) ? parsed.filter(isSavedPolicy) : []
  } catch {
    return []
  }
}

export function persistSavedPolicies(list: SavedPolicy[]): void {
  try {
    localStorage.setItem(WORKSPACE_STORAGE_KEY, JSON.stringify(list))
  } catch {
    // Storage full/unavailable — the list still works for this page load.
  }
}

function newId(): string {
  return `p-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

// Saving under a name that already exists updates that entry in place (and
// moves it to the top) — re-saving as you iterate is the common case, and
// a pile of same-named entries would be the opposite of a workspace.
export function saveEntry(
  list: SavedPolicy[],
  entry: NewSavedPolicy,
  now = new Date()
): { list: SavedPolicy[]; updated: boolean } {
  const name = entry.name.trim()
  const existing = list.find((p) => p.name === name)
  const saved: SavedPolicy = { ...entry, name, id: existing?.id ?? newId(), savedAt: now.toISOString() }
  return { list: [saved, ...list.filter((p) => p.id !== saved.id)], updated: !!existing }
}

export function renameEntry(list: SavedPolicy[], id: string, name: string): SavedPolicy[] {
  const trimmed = name.trim()
  if (!trimmed || list.some((p) => p.id !== id && p.name === trimmed)) return list
  return list.map((p) => (p.id === id ? { ...p, name: trimmed } : p))
}

export function uniqueCopyName(list: SavedPolicy[], name: string): string {
  const names = new Set(list.map((p) => p.name))
  let candidate = `${name} (copy)`
  for (let i = 2; names.has(candidate); i++) candidate = `${name} (copy ${i})`
  return candidate
}

export function duplicateEntry(list: SavedPolicy[], id: string, now = new Date()): SavedPolicy[] {
  const src = list.find((p) => p.id === id)
  if (!src) return list
  const copy: SavedPolicy = { ...src, id: newId(), name: uniqueCopyName(list, src.name), savedAt: now.toISOString() }
  const at = list.indexOf(src)
  return [...list.slice(0, at + 1), copy, ...list.slice(at + 1)]
}

export function removeEntry(list: SavedPolicy[], id: string): SavedPolicy[] {
  return list.filter((p) => p.id !== id)
}

// Counts non-empty "---"-separated documents, so a candidate carrying
// Allow/Deny exceptions shows as "3 policies" rather than looking like one.
export function countDocuments(yaml: string): number {
  return yaml
    .split(/^---\s*$/m)
    .filter((doc) => doc.split('\n').some((l) => l.trim() && !l.trim().startsWith('#'))).length
}

// First metadata.name in the YAML — the default name offered when saving.
export function firstPolicyName(yaml: string): string | null {
  return yaml.match(/^metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+name:\s*["']?([^"'\s]+)/m)?.[1] ?? null
}

export interface VerdictFormState {
  namespace: string
  allNamespaces: boolean
  last: number
  showUnchanged: boolean
  candidateYAML: string
  // The workspace entry this form was loaded from / last saved as, so Save
  // offers to update it instead of asking for a name again.
  savedName: string
  filter: DestinationFilter
}

export const EMPTY_VERDICT_FORM: VerdictFormState = {
  namespace: '',
  allNamespaces: false,
  last: 50,
  showUnchanged: false,
  candidateYAML: '',
  savedName: '',
  filter: EMPTY_DESTINATION_FILTER,
}

export function loadVerdictForm(): VerdictFormState {
  try {
    const parsed = JSON.parse(localStorage.getItem(VERDICT_FORM_STORAGE_KEY) || 'null')
    if (parsed && typeof parsed === 'object' && typeof parsed.candidateYAML === 'string') {
      // filter merged separately so a form saved before it existed (or
      // missing a field) still gets every key.
      return { ...EMPTY_VERDICT_FORM, ...parsed, filter: { ...EMPTY_DESTINATION_FILTER, ...parsed.filter } }
    }
  } catch {
    // fall through
  }
  return EMPTY_VERDICT_FORM
}

export function persistVerdictForm(state: VerdictFormState): void {
  try {
    localStorage.setItem(VERDICT_FORM_STORAGE_KEY, JSON.stringify(state))
  } catch {
    // Storage full/unavailable — just not restored after a reload.
  }
}
