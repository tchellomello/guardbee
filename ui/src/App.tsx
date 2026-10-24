import { useState } from 'react'
import { FlowsPanel } from './components/FlowsPanel'
import { PoliciesPanel } from './components/PoliciesPanel'
import { PolicyEditorPanel } from './components/PolicyEditorPanel'
import { VerdictPanel } from './components/VerdictPanel'
import { ThemeToggle } from './components/ThemeToggle'
import { HomepageLink } from './components/HomepageLink'
import { GitHubLink } from './components/GitHubLink'
import { ThemeProvider } from './theme'
import { BLANK_POLICY, type EgressRule, type IngressRule, type PolicyModel } from './policy'

type Tab = 'verdict' | 'flows' | 'policies' | 'editor'

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  )
}

function AppContent() {
  const [tab, setTab] = useState<Tab>('flows')
  const [verdictNamespace, setVerdictNamespace] = useState('')
  const [verdictCandidateYAML, setVerdictCandidateYAML] = useState('')

  // The in-progress policy draft lives here, not inside PolicyEditorPanel,
  // so the Verdict tab can append a rule to it directly (see
  // handleAppendRuleFromVerdict) without the two tabs needing a shared
  // ancestor further down the tree.
  const [policyModel, setPolicyModel] = useState<PolicyModel>(BLANK_POLICY)
  const [autoSelectNodeId, setAutoSelectNodeId] = useState<string | null>(null)

  function handleSendToVerdict(ns: string, yaml: string) {
    setVerdictNamespace(ns)
    setVerdictCandidateYAML(yaml)
    setTab('verdict')
  }

  // A row in the Verdict tab's results found a real break — append it as a
  // new ingress/egress rule on the draft policy and jump to the Policy
  // Editor with that rule selected for immediate review/editing.
  function handleAppendRuleFromVerdict(direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) {
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
            <HomepageLink />
            <GitHubLink />
            <ThemeToggle />
          </div>
        </div>
      </header>

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
            onAppendRuleToPolicy={handleAppendRuleFromVerdict}
          />
        </div>
        <div className={tab === 'flows' ? '' : 'hidden'}>
          <FlowsPanel />
        </div>
        <div className={tab === 'policies' ? '' : 'hidden'}>
          <PoliciesPanel />
        </div>
        <div className={tab === 'editor' ? '' : 'hidden'}>
          <PolicyEditorPanel
            model={policyModel}
            setModel={setPolicyModel}
            autoSelectNodeId={autoSelectNodeId}
            onConsumeAutoSelect={() => setAutoSelectNodeId(null)}
            onSendToVerdict={handleSendToVerdict}
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
