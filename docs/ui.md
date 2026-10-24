# UI guide

The web app is plain ES modules and **one stylesheet**, `server/internal/web/static/app.css` (the extension reuses a generated copy). No framework, no build step, no web font, no external image. Light and dark follow the system; *Settings → Account* can force one (stored in `localStorage`, nothing sensitive).

## Look and feel

Graphite and steel with the blue glow and brass of the logo: same family as ClosedDoor (graphite + gold) and SkyNet. Blue (`--accent`) is for actions, gold only for brand details (the hairline under the top bar and on cards, administrator avatars, favorites, shared-space badges). Status colours (red, green, amber, blue) are separate, and every status also carries an icon or words, never colour alone.

## Rules (the CSP and the tests enforce them)

* No inline `<script>`, `style` attributes or `on*=` handlers; no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` (Trusted Types make them throw). Build DOM with `h()` (`js/app/dom.js`): strings become text nodes, hrefs are filtered, `style` and `on*` attributes throw.
* No external resources. Icons come from `static/icons.svg` via `icon('name')`.
* One `<h1>` per view, every input has a label, dialogs are `<dialog>`, lists are lists, tables have a scrollable `role="region"` wrapper. `tests/ui/run.mjs` runs axe (WCAG 2.2 AA + best practice) on every screen in light and dark.
* Add a colour pair to `tests/contrast.py` whenever you add a token pair.

## Tokens

All colours, radii and shadows are CSS variables at the top of `app.css` (`:root`, dark overrides under `prefers-color-scheme` and `[data-theme="dark"]`).

| Group | Tokens |
|---|---|
| Surfaces | `--bg`, `--surface`, `--surface-2`, `--surface-3` |
| Lines | `--line`, `--line-strong`, `--input-line` (3:1 for form controls) |
| Text | `--text`, `--muted` (4.5:1) |
| Action | `--accent`, `--accent-hover`, `--on-accent`, `--accent-soft`, `--accent-text`, `--ring` |
| Brand | `--gold`, `--gold-light`, `--gold-text` (gold that is safe as text) |
| Status | `--danger`, `--success`, `--warn`, `--info`, each with `-bg` and `-line` |
| Avatars | `--av-0..7-bg/fg` |
| Shape | `--radius-sm/--radius/--radius-lg`, `--shadow-sm/md/lg` |

## Layout

* **Auth pages** (`/login`, error, setup, unlock, recovery): centred card with the logo and a gold hairline.
* **App**: sticky top bar (logo, search, *New item*, lock, account menu), sidebar (vault, types, folders, spaces, tools, administration), and routed content. The vault view is a list pane plus a detail pane; below 48 rem the sidebar becomes a drawer and the list and detail show one at a time.
* Routes are hash-based (`#/all`, `#/type/login`, `#/space/<id>`, `#/all/item/<id>`, `#/new/<type>`, `#/edit/<id>`, `#/settings/<tab>`, `#/admin/<tab>`, `#/spaces`, `#/space-manage/<id>`, `#/health`, `#/generator`, `#/trash`): the fragment never reaches the server, so ids stay out of its logs.

## Components (classes in `app.css`)

`.btn` (+`-primary`, `-danger`, `-ghost`, `-sm`, `-icon`), `.field` > `.label` + `.input` (+`.hint`), `.card` (+`-head`, `-body`, `-foot`, `-danger`), `.alert` (+`-error|-success|-warn|-info`), `.badge`, `.avatar`, `.table` (+`.table-stack` for phones), `.tabs`, `.stats`, `.item-row`, `.fld` (detail rows), `.meter` (strength), `.ring` (TOTP), `.recovery`, `.fp` (fingerprints), `.menu`, dialogs, toasts, `.empty`.

## Branding

The logo is `docs/brand/thevault-logo.webp` (original). `python3 -I docs/brand/make-assets.py` (needs Pillow) generates the web files in `static/brand/` (login logo, top-bar wordmark, the vault-wheel mark, favicon, touch icon) and the extension icons in `extension/icons/`. Never edit the generated files by hand.

## Checking your changes

1. `python3 tests/contrast.py`.
2. `node tests/ui/run.mjs` (axe, CSP, Trusted Types, no horizontal scroll on phones, light/dark/phone screenshots in `tests/ui/out/`). **Open the screenshots**: automated checks do not catch ugly.


## Your apps

The compact Your apps rail uses only ClosedDoor's verified `apps` claim. It hides this application, entries without a valid HTTPS launch URL, and applications without a grant. Names are escaped; links load no external assets. The rail scrolls horizontally on narrow screens. Apps refresh with the normal SSO check; a provider outage retains the last verified list, while a successful check with no apps clears it. Older sessions start with no links until verification or sign-in.

The rail and a **Download Chrome extension** entry remain available before vault unlock. The download uses the existing authenticated `/download/extension.zip` route; it is an unpacked Chromium extension, not a Windows or Android installer. No master password or vault data is needed to list apps or download the package.

Real-provider verification (disposable installed ClosedDoor only): `CLOSEDDOOR_DIR=... tests/sso/run_closeddoor.sh`. This creates synthetic accounts and registrations, checks the rail and Chrome ZIP without creating/unlocking a vault, then checks grant and account revocation. It requires the embedded extension ZIP, PHP/MariaDB, Go, Node and Playwright.
