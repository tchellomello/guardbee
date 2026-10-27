import { useEffect, useState } from 'react'
import { CompatButton } from './components/CompatButton'
import { CompatModal } from './components/CompatModal'
import { FlowsPanel } from './components/FlowsPanel'
import { PoliciesPanel } from './components/PoliciesPanel'
import { PolicyEditorPanel } from './components/PolicyEditorPanel'
import { VerdictPanel } from './components/VerdictPanel'
import { ThemeToggle } from './components/ThemeToggle'
import { HomepageLink } from './components/HomepageLink'
import { GitHubLink } from './components/GitHubLink'
import { VersionBanner } from './components/VersionBanner'
import { ThemeProvider } from './theme'
import type { EditablePolicyModel } from './api'
import { BLANK_POLICY, toPolicyModel, type EgressRule, type IngressRule, type PolicyModel } from './policy'

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
  const [verdictNamespace, setVerdictNamespace] = useState('')
  const [verdictCandidateYAML, setVerdictCandidateYAML] = useState('')

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

  function handleSendToVerdict(ns: string, yaml: string) {
    setVerdictNamespace(ns)
    setVerdictCandidateYAML(yaml)
    setTab('verdict')
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
        : { ...prev, egressRules: [...prev.egressRules, rule as EgressRule] }
    )
    setAutoSelectNodeId(`${direction}-${rule.id}`)
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
            <CompatButton onClick={() => setCompatModalOpen(true)} />
            <HomepageLink />
            <GitHubLink />
            <ThemeToggle />
          </div>
        </div>
      </header>

      <CompatModal isOpen={compatModalOpen} onClose={() => setCompatModalOpen(false)} />

      <VersionBanner />

      <main className="px-6 py-8 lg:px-10">
        {/* All three panels stay mounted and are only hidden via CSS, not
            unmounted — switching tabs used to throw away in-progress work
            (a half-built policy in the editor, stacked verdict/flow runs)
            because each panel's state lives in local useState. */}
        <div className={tab === 'verdict' ? '' : 'hidden'}>
          <VerdictPanel
            initialNamespace={verdictNamespace}
            initialCandidateYAML={verdictCandidateYAML}
            policyNamespace={policyModel.namespace}
            onAppendRuleToPolicy={handleAppendRule}
          />
        </div>
        <div className={tab === 'flows' ? '' : 'hidden'}>
          <FlowsPanel policyNamespace={policyModel.namespace} onAppendRuleToPolicy={handleAppendRule} />
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
