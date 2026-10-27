// Opens the Compatibility modal (CompatModal.tsx). Styled to match
// GitHubLink/HomepageLink/ThemeToggle's icon-button so all four sit
// together consistently in the header.
export function CompatButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Version compatibility"
      aria-label="Version compatibility"
      className="flex h-8 w-8 items-center justify-center rounded-sm border border-line bg-void/60 text-ink-dim transition-colors hover:border-line-bright hover:text-ink cursor-pointer"
    >
      <CompatIcon className="h-4 w-4 text-signal" />
    </button>
  )
}

function CompatIcon({ className = 'h-4 w-4' }: { className?: string }) {
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
      <path d="M12 22c4.97-1.68 8-6 8-10.5V5l-8-3-8 3v6.5C4 16 7.03 20.32 12 22Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  )
}
