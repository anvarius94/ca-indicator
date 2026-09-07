# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Chrome MV3 extension ("CA Indicator") that reads the TLS certificate chain of the top-level
navigation and classifies the issuing CA as trusted / interceptor / unknown, surfacing the result
as a toolbar badge, a toolbar icon, an in-page banner, and a popup. All UI strings are Russian.

## Commands

There is no `package.json`, no build step, and no bundler. The `.js` files at the repo root are
either extension sources (loaded directly by Chrome) or Node dev-time generators — never both.

```
node test_extension.js     # full test suite (see caveat below)
#   after editing build_root_store.js, rerun it and re-check trusted_roots.json counts
node build_root_store.js   # regenerate trusted_roots.json from Chrome Root Store + Mozilla NSS
node generate_icons.js     # regenerate all 20 PNGs in icons/ (zero deps, hand-rolled PNG encoder)
node bump_version.js 1.3.1  # bump the version in all three places it appears
```

`test_extension.js` is a single sequential script using `node:assert` — there is no runner and no
way to select an individual test; comment out sections to narrow it. Tests 1–2 are offline
(manifest shape, icon PNG signatures); test 3 opens real TLS sockets to google.com,
letsencrypt.org and github.com, so it fails without network. Test 4 only runs after test 3
completes, via the `completed === testDomains.length` callback.

### Loading and running the extension

`chrome://extensions` → Developer mode → Load unpacked → this folder. Requires Chrome ≥ 144.

**Nothing works without the flag.** Certificate data comes from
`chrome.webRequest.onHeadersReceived` with `extraInfoSpec: ['securityInfo', 'securityInfoRawDer']`,
which is gated behind `chrome://flags/#web-request-security-info` (or launching Chrome with
`--enable-features=WebRequestSecurityInfo`, what `start-chrome-with-flag.cmd` does). After
changing extension code, reload the extension *and* the page — the badge is only written from a
`main_frame` request.

## Architecture

### The `level` string is the spine of the whole extension

`analyzeSecurityInfo()` in [background.js](background.js) returns one object whose `level` field is
one of `trusted | danger | warning | insecure | flag_required`. Four places consume it, and adding
or renaming a level means touching all of them:

1. [background.js](background.js) `analyzeSecurityInfo` — produces `level`, `badge`, `badgeColor`,
   `iconTheme`, `title`, `riskDescription`.
2. [background.js](background.js) `updateBrowserAction` — maps `iconTheme` to `icons/icon-<theme>-<size>.png`.
3. [popup.js](popup.js) `renderStatus` — an if/else chain keyed on `level`.
4. [content.js](content.js) `displayIndicator` — danger renders a full-width banner, warning a
   persistent pill, trusted an auto-fading pill; `insecure`/`flag_required` render nothing in-page.

A new `iconTheme` also needs a matching entry in the `THEMES` map in
[generate_icons.js](generate_icons.js) and a rerun of that script, or `setIcon` silently fails.

### Classification is Certificate Transparency, not name lists

`GLOBAL_TRUSTED` and `KNOWN_INTERCEPTION` are **gone**. They decided verdicts by substring-matching
the issuer DN, which meant any CA absent from the hardcoded 72 names was reported as suspicious, and
two-letter signatures like `"WE"` matched by accident. Do not reintroduce a name list.

The verdict now comes from one bit: does the leaf carry embedded SCTs — X.509 extension OID
`1.3.6.1.4.1.11129.2.4.2`? `hasExtension()` walks the TBSCertificate's `[3]` context tag
(`0xA3`) → `SEQUENCE OF Extension` → each extension's leading OID.

- SCTs present → `trusted`. CT logs only accept certificates from publicly trusted CAs, so a
  locally installed root cannot obtain them.
- SCTs absent, issuer in `userWhitelist` → `trusted`. The legitimate no-CT case is a company's
  internal CA, so the popup offers the whitelist button on `danger`.
- SCTs absent → `danger`. Chrome only enforces CT for chains to *public* roots; chains to a locally
  installed root are exempt, which is exactly the carve-out antivirus and DPI interception relies on.
- DER unparseable → `warning`. This level no longer means "unknown CA".

**The check is presence-only.** SCT signatures are not verified — that needs the CT logs' public
keys and precert reconstruction. A forged certificate that copies an SCT extension verbatim would
pass. Closing that requires verifying the SCT signatures, not another list.

`trustedRootsMap` and the weekly Google root-store update still exist and still cannot fire (leaf
only, see above). They are kept for the day Chrome exposes the chain, not because they do work.

### Versioning and git

The version string lives in **three** places: `manifest.json` `version`, `manifest.json` `name`
(which embeds `v1.3.0`), and the `popup.html` footer. Never edit them by hand — run
`node bump_version.js <major.minor.patch>`, which updates all three and fails loudly if the footer
marker has drifted.

Commit each user-visible change with the version bump in the same commit, so `git log` doubles as
the version history and any released state can be checked out directly. `.backup/` and `.staged/`
are agent scratch directories and are gitignored.

Fingerprints are `AA:BB:...` uppercase hex with colons everywhere (`computeSha256`,
`build_root_store.js`, and the keys of `trusted_roots.json` must all agree on this format).

### The ASN.1 DER parser is duplicated three times

`readTLV` / `children` / `decodeOID` / `parseName` / `parseCertificate` exist in near-identical
copies in [background.js](background.js), [build_root_store.js](build_root_store.js) and
[test_extension.js](test_extension.js). They cannot share a module: the first runs in a service
worker with no imports configured, the other two are CommonJS. **Fix parser bugs in all three.**
The copies differ deliberately — `build_root_store.js` returns only `subject`, the extension copy
also returns `issuer` and `serial`.

### Root store data flow

`trusted_roots.json` is bundled and always read by `initRootStore()`; anything in
`chrome.storage.local.customRoots` is then merged **on top of** it. `customRoots` holds only what
`UPDATE_ROOT_STORE_FROM_GOOGLE` downloaded, and that handler is driven both by a popup button and
by a weekly `chrome.alarms` alarm (`ca-indicator-root-store-update`).

`build_root_store.js` fetches ~100 roots from Google and ~145 from `tls.rootCertificates`, then
merges Mozilla first and Google second so overlapping hashes accumulate a combined `source`
string. The counts collapse to 145 because every Chrome Root Store hash is also in NSS — that is
expected, not a failed fetch.

### Chrome hands over the leaf certificate only

This is the single most important constraint in the codebase. In
`extensions/browser/api/web_request/web_request_event_details.cc`, `SetSecurityInfo()` builds one
`leaf_cert` and does `certificates.Append(std::move(leaf_cert))` — the array **always has exactly
one element**, the server certificate. No intermediates, no root.

Verified exhaustively: every `extraInfoSpec` enum in `extensions/common/api/web_request.json` was
enumerated, `securityInfo`/`securityInfoRawDer` exist only on `OnHeadersReceived`, and the schema
contains no `certificateChain` option of any kind. The root genuinely cannot be reached this way —
real chains run 3 to 5 certificates deep, and the extension receives element `[0]`.

Two escape hatches exist, both rejected:

- `chrome.debugger` + CDP gives `Network.getCertificate` (experimental, returns DER strings) and
  `Network.responseReceived`'s `securityDetails` with `signedCertificateTimestampList` and
  `certificateTransparencyCompliance`. It also pins a "Chrome is being debugged by an extension"
  infobar to every tab, which is incompatible with a passive indicator.
- AIA chasing — fetching the issuer from the leaf's `caIssuers` URL — rebuilds the chain but needs a
  network request per issuer and breaks the offline guarantee.

Consequences to keep in mind: the loop over `si.certificates` always runs exactly once, and
`trustedRootsMap[fp]` compares a **leaf** fingerprint against **root** hashes, so it never matches.

### State and messaging

Per-tab analysis lives in the in-memory `tabStatusMap` **and** is mirrored into
`chrome.storage.session` under `tab_<id>` by `saveTabStatus()`; `loadTabStatus()` reads through to
it. Without that mirror the service worker's ~30 s suspension wipes the map, the popup sees a null
status, and it used to render that as "enable the flag" — which was the extension's most visible
bug. Anything new that writes per-tab state must go through `saveTabStatus`, not `tabStatusMap.set`.

Persistent state is `chrome.storage.local`: `userWhitelist`, `flagConfirmed`, `customRoots`,
`rootStoreUpdatedAt` (background) and `bannerMode`, `bannerPosition` (content + popup). Background
and content both mirror these into module-level variables via `chrome.storage.onChanged`, so write
through `storage.local.set` and let the listener update the variable rather than assigning both.

Messages, all `chrome.runtime.sendMessage` with a `type` field: `GET_TAB_STATUS`,
`UPDATE_ROOT_STORE_FROM_GOOGLE`, `ADD_WHITELIST`, `REMOVE_WHITELIST` (popup/content → background),
and `CA_STATUS_UPDATE` pushed background → content via `chrome.tabs.sendMessage`.
`GET_TAB_STATUS` responds asynchronously — it must keep its `return true`.

### Detecting whether the flag is on

`securityInfo` is gated behind `chrome://flags/#web-request-security-info`
(`extensions_features::kWebRequestSecurityInfo`). **When the feature is off, `addListener` does not
throw** — `web_request_api.cc` calls `AddMessageToConsoleForListener` and returns, so the listener
is silently never registered. A `try`/`catch` around `addListener` cannot detect this; the catch in
`registerWebRequestListener` only fires on Chrome < 144, where the enum values are unknown.

Detection is therefore a runtime probe. A second listener is registered with **no** `extraInfoSpec`,
so it always survives the feature gate. It counts https `main_frame` responses in
`httpsResponsesSeen`, while the real listener counts deliveries in `securityInfoDeliveries`. From
those two counters:

- `flagMissing` = never confirmed **and** at least two https responses already seen. An empty status
  cache alone is never treated as a missing flag.
- If `flagConfirmed` is set but three https responses arrive with zero deliveries, the flag was
  turned off after the fact and `flagConfirmed` is reset.

`flagConfirmed` is latched in `chrome.storage.local` the first time real `securityInfo` arrives.

## Known gaps

These exist in the source and are not wired up — do not assume they work:

- `badge-hash-verified` now reflects `hasSct`, not the root-store hash.
- The `GET_TAB_STATUS` response still carries `isSecurityInfoSupported` and `securityInfoError`
  that the popup does not surface anywhere.
- `content.js` never receives a `flag_required` push, so a page whose flag is off shows no in-page
  hint at all — only the toolbar badge and the popup say anything.
- Chrome blocks extensions entirely on `chromewebstore.google.com`, so no listener ever fires there.
  The popup detects this host explicitly; the background has no status to give and must not be
  "fixed" to produce one.

## Conventions

- Zero runtime and dev dependencies — keep it that way; `generate_icons.js` hand-rolls a PNG
  encoder on `zlib` rather than pulling in a library.
- Privacy is a stated product claim: the only outbound request in the entire extension is the
  user-triggered root-store update to `chromium.googlesource.com`. Do not add telemetry, analytics,
  or reputation lookups.
- [content.js](content.js) renders inside a Shadow DOM on a `<ca-indicator-root>` host with
  `all:initial`; all styles are injected into the shadow root, and `content.css` only styles the
  host element. Any cert-derived string interpolated into `innerHTML` must go through `escapeHtml`.
