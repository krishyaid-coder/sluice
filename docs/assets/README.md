# Sluice Brand Assets

Logo, favicon, social card, and the product demo video. Everything visual for the project lives here.

## Files

| File | Use |
|---|---|
| `logo.svg` | Primary mark, 128×128, ink + teal accent. Use on light backgrounds. |
| `logo-dark.svg` | Same mark tuned for dark backgrounds — near-white chevrons, brighter teal slit. |
| `logo-mono.svg` | Same mark, single-color via `currentColor`. Use inside HTML/CSS where you want to inherit color. |
| `logo-lockup.svg` | Horizontal mark + wordmark for light backgrounds. Use in README header, docs site header. |
| `logo-lockup-dark.svg` | Lockup tuned for dark backgrounds. Paired with `logo-lockup.svg` via `<picture>` in the README. |
| `favicon.svg` | Optimized for tiny sizes (thicker strokes, wider slit). Use as the browser tab / PyPI icon. |
| `social-card.svg` | 1280×640 GitHub social preview. Upload via repo Settings → Social preview. |
| `demo_new.mov` | ~30-second product demo. Embedded in README (secret block + taint leak). |

## Recording the demo

See [demo-recording.md](../demo-recording.md). Save as `demo_new.mov` or export **MP4** from Kap for widest browser support.

README embed:

```html
<video controls playsinline width="100%" src="docs/assets/demo_new.mov"></video>
```

## Palette

| Role | Hex | Notes |
|---|---|---|
| Ink (light bg) | `#0B1220` | Primary text and mark on light backgrounds. Deep near-black — easier on eyes than pure `#000`. |
| Ink (dark bg) | `#E8ECF1` | Primary text and mark on dark backgrounds. Warm near-white — avoids the aggressive contrast of pure `#FFF`. |
| Accent (light bg) | `#0F766E` | Teal-700. Watchpoint slit and links on light backgrounds. |
| Accent (dark bg) | `#2DD4BF` | Teal-400. Vibrant enough to carry across GitHub's dark theme without becoming neon. |
| Paper | `#FAFAF9` | Soft off-white for social cards and marketing surfaces. |
| Muted | `#4A5568` | Secondary text on paper backgrounds. |

## Typography

Wordmark uses a bold geometric sans-serif via the system stack:

```
-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif
```

At weight 700–800 with letter-spacing `-0.02em` to `-0.03em`. If you install a specific typeface later (Inter, Söhne, GT America), swap the `font-family` in `logo-lockup.svg` and `social-card.svg`.

Monospace anywhere code is shown: `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace`.

## Design intent

The mark is two facing chevrons (`>` `<`) with a vertical slit between them — a narrow aperture. The chevrons are the walls of the gate. The slit is the watchpoint: the value being seen and remembered.

Two readings on purpose:
1. **A gate on the wire.** The literal metaphor for the product.
2. **`>` and `<` — developer-friendly angle brackets.** A visual cue that this is a CLI-first tool for engineers.

The teal accent isolates the slit — the metaphor of the logo becomes visible.

## Usage rules

- Do not add gradients, shadows, or 3D effects to the mark. It is meant to read flat.
- Do not rotate the mark. Chevrons are directional; they only work vertical.
- Minimum size: 16×16 for `favicon.svg`, 24×24 for `logo.svg`. Below that, use text.
- Clear space around the mark: at least half the mark's height on all sides.
- Do not recolor the accent to red, orange, or any warning color. Sluice is precision, not alarm.

## When to update this doc

Only when a decision changes: new accent color, wordmark typeface swap, additional asset variants. Not for individual file edits.
