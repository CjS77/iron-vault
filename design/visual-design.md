# Visual design

This file describes the design system for Iron Vault, including the logo, lockup, wordmark, typefaces and CSS.

## Lockup

### Specification

The IronVault lockup is a red mark followed by the wordmark **IRONVAULT.**, set on one line in Michroma. It comes in a dark version and a
light version.

- **The mark reads as IV.** An inverted triangle forms the V, and the I inside it is drawn as a keyhole, which says "secure" before any
  words are read.
- **The wordmark is one word in two weights.** "IRON" is heavy and bright, and "VAULT" is light and grey. The change of weight and colour
  does the work of a space, so there is no space between them.
- **The red full stop ends it.** A round red dot gives a sense of finality (secure, done) and repeats the red of the mark.

All measurements below come from the master files `assets/ironvault-lockup-dark.svg`, `assets/ironvault-lockup-light.svg` and 
`assets/ironvault-mark.svg`. Use those files whenever possible. This spec is for redrawing, checking or extending them.

## The mark

### Symbolism

The logo is a superposition of the letters `I` and `V`, representing Iron Vault; and combined in a way to represent a lock with a keyhole.

Typically, the inverted triangle is rendered as a red steel alloy (representing Rust), with the keyhole stamped out of it.

### Specification

The mark is drawn on a 100 × 86.6 grid: an equilateral triangle pointing down, with a white keyhole centred on its vertical axis. It is two
filled shapes, with no strokes.

**Triangle**

| Property      | Value                            |
|---------------|----------------------------------|
| Shape         | Equilateral triangle, point down |
| Vertices      | (0, 0), (100, 0), (50, 86.6)     |
| Corner radius | 6 units on all three corners     |
| Fill          | Red `#B0282C`                    |

**Keyhole (the I)**

| Part          | x (units) | y (units)   | Size                                                  |
|---------------|-----------|-------------|-------------------------------------------------------|
| Whole keyhole | 39 – 61   | 8 – 54      | 22 wide × 46 tall                                     |
| Top cap       | 39 – 61   | 8 – 18.5    | 22 × 10.5, ends fully rounded (radius 5.25)           |
| Stem          | 45 – 55   | 18.5 – 43.5 | 10 wide; square inner corners where it meets the caps |
| Bottom cap    | 39 – 61   | 43.5 – 54   | Same as the top cap                                   |

The keyhole is filled white `#FFFFFF` on both dark and light backgrounds. It sits slightly above the triangle's centre: 8 units below the
top edge and about 32 units above the bottom point.

**SVG paths** (viewBox `0 0 100 86.6`)

```
Triangle: M10.39 0H89.61A6 6 0 0 1 94.8 9L55.2 77.6A6 6 0 0 1 44.8 77.6L5.2 9A6 6 0 0 1 10.39 0z
Keyhole:  M44.25 8H55.75A5.25 5.25 0 0 1 55.75 18.5H55V43.5H55.75A5.25 5.25 0 0 1 55.75 54H44.25A5.25 5.25 0 0 1 44.25 43.5H45V18.5H44.25A5.25 5.25 0 0 1 44.25 8z
```

## The wordmark

The wordmark is **IRONVAULT.** set in Michroma Regular (Google Fonts, SIL Open Font License), all capitals, with no space between the two
words. All em values below are relative to the type size.

| Element         | Setting                                                                                                           |
|-----------------|-------------------------------------------------------------------------------------------------------------------|
| Typeface        | Michroma Regular 400, the only weight it comes in                                                                 |
| Case            | All capitals throughout. Never mix in lowercase.                                                                  |
| Tracking        | +0.035em (35/1000) after every letter, including the last T                                                       |
| Kerning         | The font's own kerning, switched on                                                                               |
| "IRON" (heavy)  | Michroma Regular with a 0.035em outline stroke in the same colour (half of it outside the letter), mitred corners |
| "VAULT" (light) | Michroma Regular, no stroke                                                                                       |
| Join            | "IRON" runs straight into "VAULT" with no space. Only the normal tracking separates the N and the V.              |
| Full stop       | A red circle 0.2em across, sitting on the baseline, 0.04em after the T's tracking                                 |

**Why the heavy weight is built with a stroke.** Michroma has no bold. "IRON" gets its extra weight from a same-colour outline 0.035em wide,
which adds about 0.0175em to each side of every stroke. In the master SVGs this is already converted to outlines. When redrawing by hand,
you can also offset the paths outward by 0.0175em with mitred corners.

**Full stop.** The font's own full stop is not used. A drawn circle replaces it, larger than a normal full stop, so it reads clearly as a
deliberate ending.

## Colour

The mark and the full stop are always red with a white keyhole. Only the two words change between the dark and light versions.

| Element    | Dark version             | Light version                |
|------------|--------------------------|------------------------------|
| Background | Ink `#0E0F11`            | Paper `#F4F3F0`              |
| Triangle   | Red `#B0282C`            | Red `#B0282C`                |
| Keyhole    | White `#FFFFFF`          | White `#FFFFFF`              |
| IRON       | Paper `#F4F3F0` (17.3:1) | Ink `#0E0F11` (17.3:1)       |
| VAULT      | Steel `#8E949C` (6.3:1)  | Steel deep `#6B6F76` (4.6:1) |
| Full stop  | Red `#B0282C`            | Red `#B0282C`                |

Contrast ratios are against that version's background. Both versions also work on any background close to their own, such as near-black for
dark and white for light. The full palette and CSS tokens are in `ironvault.css`.

## Lockup

The mark sits to the left of the wordmark, and the capitals are centred vertically on the mark. Everything scales from the cap height (C) of
the wordmark. In the master file C = 45 px, at a type size of 60 px (C = 0.75em).

| Measurement        | In cap heights        | Master file (px) |
|--------------------|-----------------------|------------------|
| Cap height (C)     | 1 C                   | 45               |
| Type size          | 1.33 C                | 60               |
| Mark width         | 3.02 C                | 136              |
| Mark height        | 2.62 C                | 117.8            |
| Gap, mark to I     | 1.16 C                | 52               |
| Full stop diameter | 0.27 C                | 12               |
| Whole lockup       | about 15.8 C × 2.62 C | 713 × 118        |

- **Vertical alignment:** the middle of the capitals lines up with the middle of the mark's bounding box. With C = 45, the baseline is 81.4
  px from the top of the mark.
- **Height:** the mark is about 2.6 times the cap height, so it reads as the lead element and doesn't sit like an extra letter.
- **Clear space:** keep at least 1 C of empty space on every side of the lockup.

## Typography

Three faces, each with one job. All are on Google Fonts under the SIL Open Font License.

| Role    | Face                | Weights  | Use for                                                    | Fallback stack                               |
|---------|---------------------|----------|------------------------------------------------------------|----------------------------------------------|
| Display | Michroma            | 400      | The wordmark, section headings, small labels. Capitals only | Eurostile, Microgramma, sans-serif           |
| Body    | Geist               | 400–600  | Running text, buttons, navigation, card titles             | ui-sans-serif, system-ui, Segoe UI           |
| Code    | JetBrains Mono      | 400, 700 | Commands, config, log lines, version numbers               | ui-monospace, SFMono-Regular, Menlo, Consolas |

- **Michroma is a display face.** Use it in capitals for headings and labels, never for paragraphs. Headings take +0.02em tracking,
  and small labels +0.14em. A heading may end with the red full stop, as the wordmark does. Use it on section headings, not on every line.
- **Geist carries the reading.** Body text is 16px at a 1.6 line height, with lines kept to about 65 characters.
- **Code is always JetBrains Mono,** on a dark code surface in both themes, because the commands are what people copy.

Type scale (rem, ratio 1.25): 0.8 · 0.9 · 1 · 1.25 · 1.563 · 1.953 · 2.441.

## Theme and CSS

`assets/ironvault.css` is the single source of the theme. It loads the three faces, and defines:

| Group           | Tokens                                     | Notes                                                                                     |
|-----------------|--------------------------------------------|-------------------------------------------------------------------------------------------|
| Brand core      | `--iv-red`, `--iv-ink`, `--iv-paper`, `--iv-white`, `--iv-steel`, `--iv-steel-deep` | The colours in the [Colour](#colour) table                                  |
| Red scale       | `--iv-red-50` … `--iv-red-900`             | 500 is the brand red. Use 300 for red text on dark (6.6:1), 500 for red text on light (5.9:1) |
| Neutral scale   | `--iv-neutral-0` … `--iv-neutral-950`      | Cool steel greys from white to ink                                                        |
| Functional      | `--iv-success`, `--iv-warning`, `--iv-info`, `--iv-danger`, each with a `-dark` variant | Danger is the brand red                        |
| Semantic        | `--iv-bg`, `--iv-surface`, `--iv-border`, `--iv-text`, `--iv-text-muted`, `--iv-accent`, `--iv-focus`, … | Switch between light and dark themes |
| Type            | `--iv-font-display`, `--iv-font-body`, `--iv-font-mono`, `--iv-text-xs` … `--iv-text-3xl` |                                              |
| Wordmark        | `.iv-wordmark`, `.iv-heavy`, `.iv-light`, `.iv-dot` | Live-text wordmark. Prefer the SVG lockups where possible                       |

**Themes.** Light is the default. Dark applies when the system prefers it, unless the page sets `data-theme="light"`, and
`data-theme="dark"` forces it. Style components through the semantic tokens, never the raw scale, so both themes follow.

**Red is a signal, not a fill.** Use it for the mark, the full stop, the primary button and focus rings. Never use it for large areas of
background or for body text.

**The landing page** (`site/`) builds on this file. Its forge band (header, hero and footer) stays ink in both themes, so the dark lockup
and the forge banner always sit on dark. `site/build.sh` assembles it with the manual into `_site/`, and
`.github/workflows/pages.yml` publishes that to GitHub Pages.

## Rules

**Do**

- Use the master SVGs. Their lettering is converted to outlines, so they need no font installed.
- Keep the red triangle and the white keyhole the same on both dark and light backgrounds.
- Scale the whole lockup together, keeping every proportion above.

**Don't**

- Add a space between IRON and VAULT, or write it as "Iron Vault".
- Set the wordmark in lowercase or mixed case.
- Make "VAULT" heavy or "IRON" light, or swap their colours.
- Use a square full stop, the font's own full stop, or any colour but red for it.
- Change the keyhole to sharp or circular ends, or cut it out of the triangle.
- Put the lockup on a red background, or on a mid-tone background where the triangle loses contrast.

**Source files**

All files are in `../assets`

| File                         | Contents                                                                                   |
|------------------------------|--------------------------------------------------------------------------------------------|
| `ironvault-lockup-dark.svg`  | Full lockup for dark backgrounds, lettering converted to outlines, transparent background  |
| `ironvault-lockup-light.svg` | Full lockup for light backgrounds, lettering converted to outlines, transparent background |
| `ironvault-mark.svg`         | Mark only, 2 paths                                                                         |
| `ironvault.css`              | Colour palette, light and dark theme tokens, and the heavy and light wordmark styles       |
