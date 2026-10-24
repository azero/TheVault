# The Chrome extension

Manifest V3, vanilla JavaScript, no dependencies, no build step (the package is the `extension/` folder; `core/` is a generated copy of the web app's crypto core: `npm run sync`, CI runs `npm run check:sync`).

## Install

* **One person**: *Settings → Browser extension* in the web app downloads `thevault-extension.zip` (embedded in the server image). Unzip, `chrome://extensions` → *Developer mode* → *Load unpacked* → the folder. Pin the icon. Click it, enter the vault address, *Sign in with ClosedDoor*, then the master password.
* **A fleet**: build and sign a CRX with your own key, force-install it with Chrome policy (`ExtensionInstallForcelist`), and set `VAULT_EXTENSION_IDS` to its id. The id in this repository (`gfnpigdeagehjmdcmkijcmgfadlpnlbl`) comes from the public `key` in `manifest.json`; it is a stable id for development and unpacked installs, not a secret.
* Requires Chrome 116+ (or another Chromium with MV3, `chrome.identity` and offscreen documents).

## Sign-in flow (the extension never talks to ClosedDoor)

```
popup ─▶ background: PKCE verifier/challenge ─▶ chrome.identity.launchWebAuthFlow(
            https://vault/ext/auth?redirect_uri=https://<id>.chromiumapp.org/cb&code_challenge=…&state=… )
vault ─▶ ClosedDoor (normal OIDC, silently if you are already signed in) ─▶ vault callback
vault ─▶ 302 https://<id>.chromiumapp.org/cb?code=<one-time, 60 s>&state=…        (no cookie is created)
background ─▶ POST /api/v1/ext/token {code, verifier, redirect_uri}  ─▶ bearer token (hash at rest, revocable)
```

* The vault accepts only `https://<id>.chromiumapp.org/…` for an id in `VAULT_EXTENSION_IDS` and answers CORS only for `chrome-extension://<id>`; it never redirects to an unvalidated address.
* ClosedDoor tokens last an hour and have no refresh. Unlocking needs a fresh one, so at unlock time the extension re-runs the flow **silently** (`prompt=none`) if needed and presents its old token, which keeps the unlock state; if ClosedDoor's own session has ended it opens the sign-in window.

## What is stored where

| Where | What |
|---|---|
| `chrome.storage.local` | vault address, bearer token, **encrypted** vault cache (tagged with the account it belongs to; a different account signing in on this browser drops it, together with the unlock key) (same ciphertext as the server holds), sealed private keys, KDF parameters (for offline unlock), preferences, "never save here" hosts, pinned sharer fingerprints |
| `chrome.storage.session` (memory only, cleared on browser close, not visible to content scripts) | the unlock key, "save this login?" prompts (120 s), last activity |
| Service worker memory | the decrypted index while the worker lives (Chrome discards it after ~30 s idle) |
| Nowhere | the master password, decrypted items on disk |

The browser test asserts that none of `chrome.storage.local` contains a password, username, item name or the master password.

## Autofill rules

1. **Only on an explicit action**: clicking *Fill* in the popup, the context menu, or `Ctrl+Shift+L` / `Cmd+Shift+L`. Nothing fills on page load. There is no inline icon on web pages.
2. **Exact match** of the saved website rules (`core/urlmatch.js`): *same host* (default), *host and subdomains* (the host you saved is the boundary; bare TLDs, IP addresses and shared suffixes such as `co.uk` or `github.io` never expand), *exact address (path prefix on a `/` boundary: `/app` covers `/app/x`, not `/apple`)*, or *never*. `paypal.com.evil.io`, `evilpaypal.com`, `paypal.com@evil.io`, other ports (an https rule never meets `:80`), other schemes and punycode look-alikes do not match (tested).
3. **https only** (plus `http://localhost`, `127.0.0.1`, `[::1]`). A saved `https://` rule never matches an `http://` page.
4. **Page and frame must both match.** The service worker enumerates the tab's frames and fills only frames whose own address matches *and* only when the top-level page matches too: a trusted login embedded in a hostile page, or a hostile frame inside a trusted page, gets nothing. The message goes to a specific `documentId`, so a navigation between the check and the fill cannot redirect it.
5. **Visible fields only**: not `display:none`, not `visibility:hidden`, not near-transparent, not pushed off-screen, not tiny, not disabled/read-only (honeypot test).
6. Framework-friendly: native value setter plus `input` and `change` events.
7. One-time codes are filled into `autocomplete=one-time-code`/OTP-named fields when the item has a TOTP secret.
8. If several logins match the shortcut asks you to choose in the popup; with none it says so.

## Saving logins

A passive listener notices submits (`submit` event, clicking a submit button, Enter) on forms with a password, and reports `{username, password}` to the service worker for that instant only. If the login is new, or the username exists with a different password, a prompt is stored (120 s) and a bar is shown in the page after the next load (or 1.2 s later for single-page apps): *Save* / *Not now* / *Never for this site*. Only a password the person typed counts: a value written by page script is never offered, and TheVault's own pages (unlock, dialogs, the editor) are never captured. The bar is built in a **closed shadow root** with inline `!important` styles, ignores synthetic (`isTrusted: false`) clicks, and ignores *real* clicks unless it is demonstrably visible (IntersectionObserver v2, computed opacity/transform/filter, under the pointer) and has been on screen for 700 ms, so a page cannot hide it and put a decoy button underneath. It needs the vault unlocked. It saves to the personal vault, encrypted with the user key, with the origin as a *same host* rule.

## Locking

Locks after the idle time set in *Settings* (default 15 min, also enforced by the server), when the screen locks, and when the browser closes (the key is in session storage). Locking removes the key, the decrypted index and any pending save prompt immediately. The idle check runs on every worker wake-up and before every use of the index, not only on the one-minute alarm (a restarted worker must not postpone it), and the index is only served while the key exists, so a server-side lock or a revoked session stops fills at once.

## Offline

With *Keep an encrypted offline copy* on (default), unlocking works with the server unreachable: the master password opens the cached sealed key locally. Filling works; saving needs the server. Offline unlocking is not throttled by the server (the same ciphertext is on disk anyway); use full-disk encryption.

## Permissions

| Permission | Why |
|---|---|
| content script on `https://*/*`, `http://localhost`, `127.0.0.1` | find login forms, fill when told, notice submits |
| `tabs`, `webNavigation` | read the active tab's address and its frames' addresses to match them |
| `storage`, `unlimitedStorage` | the encrypted cache (large vaults exceed 10 MB) |
| `identity` | the sign-in window |
| `alarms`, `idle` | auto-lock, keep-alive, clipboard clearing, lock on screen lock |
| `offscreen`, `clipboardWrite` | clearing the clipboard from a service worker |
| `contextMenus` | "Fill login", "Copy a generated password" |

No network permission is requested: calls to the vault work through CORS, which the vault grants only to this extension's id. Page scripts cannot message the extension (`externally_connectable` is not declared), and the service worker accepts privileged messages only from the extension's own pages.

## Testing

`node tests/ext/run.mjs` loads this exact folder into Chromium (headless=new) with the real server and a fake ClosedDoor and covers: the real sign-in window, unlock, fill, honeypots, other host, hostile frames both ways, the shortcut path (one/many/none), OTP and username-only pages, save bar (new, update, never), locking, ciphertext-only storage, offline unlock.
