import type { ProbeImage, ProbeProtocol } from '../api'

// Radio cards over the server's image catalog: the browser can only pick an
// entry the server was started with, never type an image. Each card shows
// what the image can test and whether it is digest-pinned.
export function ProbeImagePicker({ images, value, protocol, onChange }: {
  images: readonly ProbeImage[]; value: string; protocol: ProbeProtocol; onChange: (image: ProbeImage) => void
}) {
  return (
    <fieldset className="min-w-0">
      <legend className="mb-2 font-display text-[0.65rem] font-bold tracking-widest text-ink-dim uppercase">Probe image</legend>
      <div role="radiogroup" aria-label="Probe image" className="grid min-w-0 gap-2 sm:grid-cols-2">
        {images.map((image) => {
          const selected = image.id === value
          return (
            <label key={image.id} className={`flex min-w-0 cursor-pointer flex-col gap-1.5 rounded-sm border p-3 transition-colors ${selected ? 'border-signal bg-signal/10' : 'border-line hover:border-line-bright'}`}>
              <span className="flex min-w-0 items-center gap-2">
                <input type="radio" name="probe-image" value={image.id} checked={selected} onChange={() => onChange(image)} className="accent-signal" />
                <span className="min-w-0 truncate font-display text-sm font-bold text-ink">{image.name}</span>
                <span className="ml-auto flex shrink-0 gap-1">
                  {(['TCP', 'UDP'] as const).map((p) => (
                    <span key={p} className={`rounded-sm border px-1.5 font-mono text-[0.6rem] ${image.protocols.includes(p) ? (p === protocol && selected ? 'border-signal text-signal' : 'border-line text-ink-dim') : 'border-transparent text-ink-faint line-through'}`}>{p}</span>
                  ))}
                </span>
              </span>
              {image.description && <span className="text-xs text-ink-dim">{image.description}</span>}
              <span className="flex min-w-0 items-center gap-1.5 font-mono text-[0.6rem] text-ink-faint" title={image.image}>
                <span aria-hidden="true">{image.pinned ? '🔒' : '⚠'}</span>
                <span className="sr-only">{image.pinned ? 'Pinned by digest' : 'Tag only, re-pulled on every test'}</span>
                <span className="truncate">{image.image}</span>
              </span>
            </label>
          )
        })}
      </div>
    </fieldset>
  )
}
