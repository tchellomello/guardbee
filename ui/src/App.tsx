import { useEffect, useState } from 'react'
import { CompatButton } from './components/CompatButton'
import { CompatModal } from './components/CompatModal'
import { FlowsPanel } from './components/FlowsPanel'
import { PoliciesPanel } from './components/PoliciesPanel'
import { PolicyEditorPanel } from './components/PolicyEditorPanel'
import { VerdictPanel, type VerdictLoad } from './components/VerdictPanel'
import { WorkspaceButton } from './components/WorkspaceButton'
import { WorkspaceModal } from './components/WorkspaceModal'
import { ThemeToggle } from './components/ThemeToggle'
import { HomepageLink } from './components/HomepageLink'
import { GitHubLink } from './components/GitHubLink'
import { VersionBanner } from './components/VersionBanner'
import { ThemeProvider } from './theme'
import type { EditablePolicyModel } from './api'
import { BLANK_POLICY, generateCiliumNetworkPolicyYAML, toPolicyModel, type EgressRule, type IngressRule, type PolicyModel } from './policy'
import {
  WORKSPACE_STORAGE_KEY,
  duplicateEntry,
  loadSavedPolicies,
  loadVerdictForm,
  persistSavedPolicies,
  removeEntry,
  renameEntry,
  saveEntry,
  type NewSavedPolicy,
  type SavedPolicy,
} from './shared/workspace'

type Tab = 'verdict' | 'flows' | 'policies' | 'editor'

// Draft persistence — the in-progress Policy Editor draft used to live only
// in React state, so switching browser tabs or an accidental reload threw
// away everything typed in. localStorage is per-browser, not shared with
// the backend or other viewers, which is exactly right for "my own
// in-progress scratch work," unlike anything synced from the cluster.
const DRAFT_STORAGE_KEY = 'guardbee.policyEditor.draft'

function loadStoredDraft(): PolicyModel {
  try {
    const raw = localStorage.getItem(DRAFT_STORAGE_KEY)
    if (!raw) return BLANK_POLICY
    const parsed = JSON.parse(raw)
    // Minimal shape check — a draft saved by an older version of this app
    // missing a field (e.g. before egressDenyAll/toServices existed) falls
    // back to blank rather than feeding a half-formed model into the editor.
    if (
      parsed &&
      typeof parsed === 'object' &&
      Array.isArray(parsed.ingressRules) &&
      Array.isArray(parsed.egressRules) &&
      typeof parsed.kind === 'string'
    ) {
      return parsed as PolicyModel
    }
  } catch {
    // Corrupt/unparseable stored draft — fall back to blank below.
  }
  return BLANK_POLICY
}

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  )
}

function AppContent() {
  const [tab, setTab] = useState<Tab>('flows')
  const [compatModalOpen, setCompatModalOpen] = useState(false)
  const [verdictLoad, setVerdictLoad] = useState<VerdictLoad | null>(null)
  const [workspaceOpen, setWorkspaceOpen] = useState(false)
  const [savedPolicies, setSavedPolicies] = useState<SavedPolicy[]>(loadSavedPolicies)

  // The in-progress policy draft lives here, not inside PolicyEditorPanel,
  // so the Verdict tab can append a rule to it directly (see
  // handleAppendRule) without the two tabs needing a shared
  // ancestor further down the tree.
  const [policyModel, setPolicyModel] = useState<PolicyModel>(loadStoredDraft)
  const [autoSelectNodeId, setAutoSelectNodeId] = useState<string | null>(null)
  // Snapshot of a live policy at the moment it was loaded via "Edit in
  // Policy Editor" — null whenever the draft isn't editing a live policy
  // (blank/preset/already-reset). Lets the editor show a real "what's
  // changed since this was loaded from the cluster" diff instead of only
  // ever comparing against nothing.
  const [originalLiveModel, setOriginalLiveModel] = useState<PolicyModel | null>(null)

  useEffect(() => {
    try {
      localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(policyModel))
    } catch {
      // Storage full/unavailable (private browsing, quota) — the draft
      // just won't survive a reload this time, not worth surfacing to the
      // user over.
    }
  }, [policyModel])

  useEffect(() => {
    persistSavedPolicies(savedPolicies)
  }, [savedPolicies])

  // Another GuardBee tab saving/deleting would otherwise be overwritten by
  // this tab's stale list on its next save. The storage event only fires in
  // the *other* tabs, so this can't loop.
  useEffect(() => {
    function handleStorage(e: StorageEvent) {
      if (e.key === WORKSPACE_STORAGE_KEY) setSavedPolicies(loadSavedPolicies())
    }
    window.addEventListener('storage', handleStorage)
    return () => window.removeEventListener('storage', handleStorage)
  }, [])

  function handleSendToVerdict(ns: string, yaml: string) {
    setVerdictLoad({ namespace: ns, candidateYAML: yaml, token: Date.now() })
    setTab('verdict')
  }

  // Computed against the current list (not inside a state updater) so the
  // caller learns synchronously whether it created or updated an entry.
  function handleSavePolicy(entry: NewSavedPolicy): boolean {
    const { list, updated } = saveEntry(savedPolicies, entry)
    setSavedPolicies(list)
    return updated
  }

  function handleSaveEditorDraft(name: string): boolean {
    return handleSavePolicy({
      name,
      origin: 'editor',
      candidateYAML: generateCiliumNetworkPolicyYAML(policyModel),
      namespace: policyModel.namespace,
      allNamespaces: policyModel.kind === 'CiliumClusterwideNetworkPolicy' && !policyModel.namespace,
      editorModel: policyModel,
    })
  }

  // Opening a saved entry replaces work in progress, so only ask when that
  // work isn't itself already saved somewhere in the workspace.
  function handleOpenInVerdict(p: SavedPolicy) {
    const current = loadVerdictForm().candidateYAML
    const unsaved = current.trim() && current !== p.candidateYAML && !savedPolicies.some((s) => s.candidateYAML === current)
    if (unsaved && !window.confirm('Replace the Verdict tab\'s current (unsaved) candidate with this saved policy?')) return
    setVerdictLoad({
      namespace: p.namespace,
      allNamespaces: p.allNamespaces,
      candidateYAML: p.candidateYAML,
      savedName: p.name,
      token: Date.now(),
    })
    setWorkspaceOpen(false)
    setTab('verdict')
  }

  function handleOpenInEditor(p: SavedPolicy) {
    if (!p.editorModel) return
    const current = JSON.stringify(policyModel)
    const unsaved =
      current !== JSON.stringify(BLANK_POLICY) && !savedPolicies.some((s) => JSON.stringify(s.editorModel) === current)
    if (unsaved && !window.confirm('Replace the current (unsaved) Policy Editor draft with this saved policy?')) return
    setPolicyModel(p.editorModel)
    setOriginalLiveModel(null)
    setWorkspaceOpen(false)
    setTab('editor')
  }

  // "Edit in Policy Editor" from the Policies tab — loads a live CNP/CCNP
  // straight into the draft, same destination handleAppendRule
  // already jumps to, and snapshots it as originalLiveModel so the editor
  // can show a diff against what's actually running.
  function handleEditLivePolicy(editable: EditablePolicyModel) {
    const model = toPolicyModel(editable)
    setPolicyModel(model)
    setOriginalLiveModel(model)
    setTab('editor')
  }

  // A row in the Verdict tab's results, or an observed flow in the Flows
  // tab, found something worth turning into policy — append it as a new
  // ingress/egress rule on the draft and jump to the Policy Editor with
  // that rule selected for immediate review/editing.
  function handleAppendRule(direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) {
    setPolicyModel((prev) =>
      direction === 'ingress'
        ? { ...prev, ingressRules: [...prev.ingressRules, rule as IngressRule] }
        : // egressDenyAll makes the generator emit only the catchall and ignore
          // egressRules, so a rule appended while it's on would silently do
          // nothing — appending one means the user wants egress managed again.
          { ...prev, egressDenyAll: false, egressRules: [...prev.egressRules, rule as EgressRule] }
    )
    setAutoSelectNodeId(`${direction}-${rule.id}`)
    setTab('editor')
  }

  // "New block policy" on a flow — replaces the whole draft with a generated
  // policy for that flow. The draft is the user's in-progress work, so a
  // non-pristine one needs an explicit OK before it's overwritten.
  function handleCreatePolicyFromFlow(model: PolicyModel, ruleNodeId: string) {
    const pristine = JSON.stringify(policyModel) === JSON.stringify(BLANK_POLICY)
    if (!pristine && !window.confirm('Replace the current Policy Editor draft with a new block policy for this flow?')) {
      return
    }
    setPolicyModel(model)
    setOriginalLiveModel(null)
    setAutoSelectNodeId(ruleNodeId)
    setTab('editor')
  }

  return (
    <div className="relative z-10 min-h-screen">
      <header className="border-b border-line bg-panel/70 backdrop-blur-sm">
        <div className="flex flex-wrap items-center justify-between gap-4 px-6 py-5 lg:px-10">
          <div className="rise-in">
            <div className="flex items-center gap-2.5">
              <img src="/guardbee-logo.svg" alt="GuardBee" className="h-14 w-14 shrink-0 rounded" />
              <h1 className="font-display text-lg font-bold tracking-[0.08em] text-ink uppercase">
                GuardBee
              </h1>
            </div>
            <p className="mt-1 sm:pl-16.5 text-xs text-ink-dim">
              which real flows on this cluster would a candidate policy break or newly allow?
            </p>
          </div>
          <div className="flex items-center gap-3">
            <nav className="flex gap-1 rounded-sm border border-line bg-void/60 p-1">
              <TabButton active={tab === 'verdict'} onClick={() => setTab('verdict')}>
                Verdict
              </TabButton>
              <TabButton active={tab === 'flows'} onClick={() => setTab('flows')}>
                Flows
              </TabButton>
              <TabButton active={tab === 'policies'} onClick={() => setTab('policies')}>
                Policies
              </TabButton>
              <TabButton active={tab === 'editor'} onClick={() => setTab('editor')}>
                Policy Editor
              </TabButton>
            </nav>
            <WorkspaceButton count={savedPolicies.length} onClick={() => setWorkspaceOpen(true)} />
            <CompatButton onClick={() => setCompatModalOpen(true)} />
            <HomepageLink />
            <GitHubLink />
            <ThemeToggle />
          </div>
        </div>
      </header>

      <CompatModal isOpen={compatModalOpen} onClose={() => setCompatModalOpen(false)} />
      <WorkspaceModal
        isOpen={workspaceOpen}
        onClose={() => setWorkspaceOpen(false)}
        policies={savedPolicies}
        onOpenInVerdict={handleOpenInVerdict}
        onOpenInEditor={handleOpenInEditor}
        onRename={(id, name) => setSavedPolicies((prev) => renameEntry(prev, id, name))}
        onDuplicate={(id) => setSavedPolicies((prev) => duplicateEntry(prev, id))}
        onDelete={(id) => setSavedPolicies((prev) => removeEntry(prev, id))}
      />

      <VersionBanner />

      <main className="px-6 py-8 lg:px-10">
        {/* All three panels stay mounted and are only hidden via CSS, not
            unmounted — switching tabs used to throw away in-progress work
            (a half-built policy in the editor, stacked verdict/flow runs)
            because each panel's state lives in local useState. */}
        <div className={tab === 'verdict' ? '' : 'hidden'}>
          <VerdictPanel
            load={verdictLoad}
            onSavePolicy={handleSavePolicy}
            policyNamespace={policyModel.namespace}
            onAppendRuleToPolicy={handleAppendRule}
          />
        </div>
        <div className={tab === 'flows' ? '' : 'hidden'}>
          <FlowsPanel
            policyNamespace={policyModel.namespace}
            onAppendRuleToPolicy={handleAppendRule}
            onCreatePolicy={handleCreatePolicyFromFlow}
          />
        </div>
        <div className={tab === 'policies' ? '' : 'hidden'}>
          <PoliciesPanel onEditPolicy={handleEditLivePolicy} />
        </div>
        <div className={tab === 'editor' ? '' : 'hidden'}>
          <PolicyEditorPanel
            model={policyModel}
            setModel={setPolicyModel}
            autoSelectNodeId={autoSelectNodeId}
            onConsumeAutoSelect={() => setAutoSelectNodeId(null)}
            onSendToVerdict={handleSendToVerdict}
            onSavePolicy={handleSaveEditorDraft}
            originalLiveModel={originalLiveModel}
            onClearOriginalLiveModel={() => setOriginalLiveModel(null)}
          />
        </div>
      </main>
    </div>
  )
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-sm px-4 py-1.5 font-display text-xs font-semibold tracking-wide uppercase transition-colors cursor-pointer ${
        active ? 'bg-signal text-void' : 'text-ink-dim hover:text-ink'
      }`}
    >
      {children}
    </button>
  )
}
