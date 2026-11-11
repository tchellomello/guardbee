// Opens the Saved policies modal (WorkspaceModal.tsx). Same icon-button
// styling as CompatButton/GitHubLink/ThemeToggle, plus a count badge so
// it's visible at a glance that saved work exists.
export function WorkspaceButton({ count, onClick }: { count: number; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Saved policies"
      aria-label={`Saved policies (${count})`}
      className="relative flex h-8 w-8 items-center justify-center rounded-sm border border-line bg-void/60 text-ink-dim transition-colors hover:border-line-bright hover:text-ink cursor-pointer"
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-4 w-4 text-signal"
      >
        <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z" />
        <path d="M17 21v-8H7v8" />
        <path d="M7 3v5h8" />
      </svg>
      {count > 0 && (
        <span className="absolute -right-1.5 -top-1.5 min-w-4 rounded-full bg-signal px-1 text-center text-[0.55rem] font-bold leading-4 text-void">
          {count}
        </span>
      )}
    </button>
  )
}
