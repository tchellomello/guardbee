// Links out to the project's GitHub Pages site (docs/index.html) — the
// public-facing pitch/demo, not part of this app. Styled to match
// ThemeToggle's icon-button so the two sit together consistently in the header.
export function HomepageLink() {
  return (
    <a
      href="https://tchellomello.github.io/guardbee/"
      target="_blank"
      rel="noopener noreferrer"
      title="GuardBee homepage"
      aria-label="GuardBee homepage"
      className="flex h-8 w-8 items-center justify-center rounded-sm border border-line bg-void/60 text-ink-dim transition-colors hover:border-line-bright hover:text-ink"
    >
      <ExternalLinkIcon className="h-3.5 w-3.5 text-signal" />
    </a>
  )
}

function ExternalLinkIcon({ className = 'h-3.5 w-3.5' }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <path d="M15 3h6v6" />
      <path d="M10 14 21 3" />
    </svg>
  )
}
