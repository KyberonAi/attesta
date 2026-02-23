# Skill: Mintlify Documentation

When writing or updating documentation for Mintlify, follow these conventions. This is the Kyberon standard documentation style.

## Kyberon Doc Style

All Kyberon projects share the same Mintlify foundation:
- **Theme:** `maple`
- **Config file:** `docs.json` (not `mint.json`)
- **Fonts:** Space Grotesk 700 (headings), Inter 400 (body)
- **Layout:** `sidenav`
- **Codeblocks:** `github-light` / `github-dark-dimmed`
- **Custom CSS:** `style.css` with wider content area, card hover effects, transparent pagination/footer

### Attesta Brand

- **Primary color:** `#16A34A` (green)
- **Light color:** `#22C55E`
- **Dark color:** `#15803D`
- **Background dark:** `#1A1D1C`
- **Dark border:** `#2d3130`
- **Primary RGB:** `22, 163, 74`
- **Light RGB:** `34, 197, 94`
- **Icon:** `shield-check` (Lucide)
- **Logo SVG:** Lucide shield-check icon in primary color + "Attesta" in Space Grotesk 700

### Known Kyberon Project Colors

| Project | Primary | Light | Dark | Dark BG | Dark Border |
|---------|---------|-------|------|---------|-------------|
| Attesta | `#16A34A` | `#22C55E` | `#15803D` | `#1A1D1C` | `#2d3130` |
| Trailproof | `#0EA5E9` | `#38BDF8` | `#0284C7` | `#1A1A1F` | `#2d3033` |
| Memproof | `#7C3AED` | `#A78BFA` | `#6D28D9` | `#1A1A1F` | `#2d3033` |

## Project Structure

```
docs/
├── docs.json              # Site config (NOT mint.json -- Mintlify v4+ uses docs.json)
├── favicon.svg            # Shield-check icon in #16A34A
├── style.css              # Custom overrides (wider layout, card hover, pagination)
├── introduction.mdx       # Landing page
├── quickstart.mdx         # Getting started guide
├── logo/
│   ├── dark.svg           # Icon + "Attesta" in #22C55E on dark bg
│   └── light.svg          # Icon + "Attesta" in #16A34A on light bg
├── images/                # Static assets (diagrams, architecture SVGs)
├── concepts/              # Core concept pages
├── api/                   # API docs
├── guides/                # How-to guides
├── integrations/          # Framework integration guides
├── no-code/               # No-code platform guides
├── cli/                   # CLI reference
└── configuration/         # Config reference
```

## Navigation Pattern

Put Guides under the Documentation tab alongside Getting Started and Core Concepts. Only API Reference gets its own tab. This reduces clicks and keeps the learning flow linear.

```
Documentation tab:
  Getting Started  → introduction, quickstart
  Core Concepts    → concept pages
  Configuration    → config reference
  Guides           → how-to guides
  Integrations     → framework integrations
  No-Code          → no-code platform guides

API Reference tab:
  API Reference    → gate-decorator, attesta-class, action-context, etc.

CLI tab:
  CLI Reference    → overview, init, audit, trust, mcp-wrap
```

## MDX Page Format

Every MDX page starts with frontmatter:

```mdx
---
title: "Page Title"
description: "One-line description for SEO and navigation"
icon: "icon-name"
---
```

**Important:** Always include `icon` in frontmatter for sidebar navigation icons. Always quote string values in frontmatter.

### Code Blocks -- Dual SDK

For dual SDK docs, wrap Python and TypeScript in `<CodeGroup>` for tabbed views:

```mdx
<CodeGroup>
```python Python
# Python example
```

```typescript TypeScript
// TypeScript example
```
</CodeGroup>
```

Standalone blocks (bash, json, single-language) do NOT need CodeGroup.

### Callouts

```mdx
<Note>Informational note -- use for "good to know" context.</Note>
<Warning>Important warning -- use for gotchas or breaking changes.</Warning>
<Tip>Helpful tip -- use for best practices and recommendations.</Tip>
```

### Cards and Card Groups

Used for feature highlights and navigation. Always use `cols={2}` and include `color` prop:

```mdx
<CardGroup cols={2}>
  <Card title="Feature" icon="icon-name" color="#16A34A">
    Description of what this feature does.
  </Card>
  <Card title="Next Page" icon="rocket" color="#15803D" href="/page">
    Short description linking to another page.
  </Card>
</CardGroup>
```

### Images and Diagrams

Do NOT use `<Frame>` for SVG diagrams. Use a plain `<img>` with inline responsive styles:

```mdx
<img src="/images/diagram.svg" alt="Descriptive alt text" style={{ width: '100%', height: 'auto' }} />
```

## Page Patterns

### Introduction Page
1. Summary (2-3 sentences)
2. The Problem (bullet list)
3. How Attesta Solves This (code example)
4. Key Properties (`<CardGroup cols={2}>` with 4 feature cards)
5. Architecture at a Glance (text diagram or `<img>`)
6. Next Steps (`<CardGroup cols={2}>`)

### Quickstart Page
1. Installation (pip/npm)
2. Numbered steps with dual Python + TypeScript code
3. Callouts for important details
4. Next Steps card group

### Concept Pages
1. Frontmatter with title + description + icon
2. Overview paragraph
3. Main content with `##` sections
4. Code examples
5. Next Steps card group

### API Reference Pages
1. Method signature as code block
2. Parameter documentation inline
3. Return type documentation
4. Code examples for Python + TypeScript
5. Error cases

## Logo SVG Pattern

Both logos use:
- viewBox `0 0 180 32`
- Lucide icon SVG nested at `x="0" y="4"` with `width="24" height="24"`
- Brand text `<text>` at `x="32" y="22"`, Space Grotesk 700, font-size 18
- Light logo: icon stroke = `#16A34A`, text fill = `#16A34A`
- Dark logo: icon stroke = `#22C55E`, text fill = `#22C55E`

## Writing Style

- **Concise** -- one idea per paragraph, short sentences
- **Action-oriented** -- start guides with what the reader will accomplish
- **Code-first** -- show code before explaining it
- **Dual SDK** -- always show both Python and TypeScript examples
- **No jargon without definition** -- define terms on first use
- **Present tense** -- "creates" not "will create"
- **Em dashes** -- use `--` (double hyphen) in content, Mintlify renders them

## Local Development

```bash
# Requires Node.js LTS (22 or lower). Mintlify does NOT support Node 25+.
cd docs
npx mintlify dev
# Preview at http://localhost:3000
```

If you have Node 25+ as default, use nvm:
```bash
nvm use 22 && cd docs && npx mintlify dev
```

## Common Mistakes to Avoid

- Do NOT use `<Frame>` for SVG diagrams -- use `<img style={{ width: '100%', height: 'auto' }} />`
- Do NOT use `mint.json` -- Mintlify v4+ uses `docs.json`
- Do NOT skip frontmatter -- every page needs `title`, `description`, and `icon`
- Do NOT omit `color` prop on Cards
- Do NOT write walls of text -- break up with code examples and callouts
- Do NOT use relative links with .mdx extension -- use paths like `/quickstart`
- Do NOT use different fonts -- always Space Grotesk for headings, Inter for body
- DO use CodeGroup for dual SDK code blocks
- Do NOT use `[data-theme="dark"]` in CSS -- Mintlify maple uses `html.dark`
- Do NOT create separate Guides tab -- put Guides under Documentation tab
- Do NOT try Node 25+ with Mintlify CLI -- use Node LTS (22 or lower)
