---
name: consent-audit
description: How to audit a web site's consent banner and detect server-side device fingerprinting using the consent-audit CLI in this repo. Trigger whenever the user wants to audit cookies/storage/trackers across noaction/accept/reject states, test for cross-context identifier persistence (server-side fingerprinting), check PECR/GDPR/ePrivacy compliance of a banner, add a new site to the audit set, or interpret a report this tool produced. Trigger even if the user only says "audit this site", "check what fires before consent", "see if reject actually rejects", or names a tracker (GA4, Meta Pixel, Bing UET, Tealium, FullStory, Segment, etc.) in the context of cookie/consent work.
---

# consent-audit

A two-experiment privacy auditor built on Playwright. Use it when the question is *what does a site actually do to the user under each consent choice, and can it re-identify them after they decline?*

## The two experiments

### 1. Three-state audit (`consent-audit audit`)

Captures browser state under three independent visits to the same URL:

- **noaction** — load the page, wait, capture. Nothing clicked.
- **accept** — load, click the Accept-all button, wait, capture.
- **reject** — load, click the Reject-all (or "essential only" / "save preferences") button, wait, capture.

Each visit uses a **fresh, fully isolated browser context** — no shared cookies, storage, cache, or in-memory state between states. For each state the tool records cookies, `localStorage` keys, `sessionStorage` keys, and the set of unique third-party hosts contacted (via `performance.getEntriesByType('resource')`).

Use this experiment to answer:
- Does the site contact analytics/ad hosts *before* the user makes any choice?
- Does reject actually reject — i.e., are non-essential cookies still set?
- Does the site mask third parties behind first-party subdomains (e.g. `sst.example.com` as a GTM server-side endpoint, `id.example.com` as an identity proxy)?

### 2. Fingerprint persistence test (`consent-audit fingerprint`)

Opens **N independent browser contexts** (default 3) against the same URL. Each context optionally clicks a pre-specified selector (typically the reject button) before capture. The tool then compares one or more "identity cookies" across the N contexts.

The core logic: isolated contexts share no client-side state. If a cookie value — or a parseable persistent component of a cookie value — is **byte-identical across N contexts**, that identifier did not come from the client. It came from a server-side process that re-identified the visitor, which is almost always device fingerprinting (canvas, fonts, audio, WebGL, header entropy, IP, TLS fingerprint, etc.).

Use this experiment when the three-state audit surfaced a suspicious identity cookie that survived reject, or when you suspect an unfamiliar cookie is a fingerprint match rather than a random session ID.

## When to reach for which

| Question | Experiment |
|---|---|
| "What fires before the user clicks anything?" | Three-state |
| "Does the reject button do what it says?" | Three-state |
| "Is this cookie a real per-session ID or is it a fingerprint match?" | Fingerprint persistence |
| "Does this site re-identify across its sister brands?" | Fingerprint persistence — point at one brand, then another, with the same identity-cookie list |

## Setup (first run)

The plugin ships the Python source under `${CLAUDE_PLUGIN_ROOT}`. Install it once into a
persistent per-plugin venv (lives in `${CLAUDE_PLUGIN_DATA}`, survives plugin updates):

```bash
python3 -m venv "${CLAUDE_PLUGIN_DATA}/venv"
"${CLAUDE_PLUGIN_DATA}/venv/bin/pip" install -e "${CLAUDE_PLUGIN_ROOT}"
"${CLAUDE_PLUGIN_DATA}/venv/bin/playwright" install chromium   # ~150MB browser, one-time
```

The console script is installed inside that venv, not on the global `PATH`. The full path is
`${CLAUDE_PLUGIN_DATA}/venv/bin/consent-audit` — the rest of this skill abbreviates it as `$CA`.
Set `CA` at the start of **each** command (shell state does not persist between separate
command runs), or just inline the full path:

```bash
CA="${CLAUDE_PLUGIN_DATA}/venv/bin/consent-audit"; "$CA" --help
```

If a later run reports the command is missing, the venv was wiped (e.g. a major plugin update) —
re-run the three setup lines above. Reports are written to `reports/` under the current working
directory (the user's project), not the plugin dir.

## Adding a new site

Three-state audits read a per-site YAML config. Bundled examples live in
`${CLAUDE_PLUGIN_ROOT}/sites/`; write new configs anywhere convenient (e.g. a `sites/` dir in
the user's project) and pass the path to `$CA audit`. The schema:

```yaml
url: https://example.com
accept_selector: "<CSS selector of the Accept-all button>"
reject_selector: "<CSS selector of the Reject-all / essential-only button>"
consent_cookie: "<name of the cookie that records the choice, optional>"
identity_cookies:                         # optional, used by some downstream tooling
  - <cookie name>
settle_seconds: 4.0                       # wait after click for trackers to fire
```

### Finding the selectors

There is no auto-detection. Get the selectors manually:

1. Open the site in a real browser.
2. Open DevTools → Elements, find the banner.
3. Right-click the Accept-all button → Copy → Copy selector. Trim it to the shortest stable form (`#button-accept-all`, `[data-testid="accept-all"]`, `button[aria-label="Accept all cookies"]`).
4. Do the same for the Reject-all button. **Be careful**: many banners only offer "Manage preferences" or "Essential only" in the first layer. If the only first-layer button is "Manage", you have to follow the path the user would follow and capture the selector of the *final* button that submits a reject-equivalent choice. Note this asymmetry in the report — it is itself a finding.
5. If the consent banner is in a shadow DOM or an iframe, Playwright's default selectors won't reach it. For a shadow DOM you may need `>>` piercing selectors; for an iframe you'll need to extend `${CLAUDE_PLUGIN_ROOT}/consent_audit/browser.py` to enter the frame before clicking. Flag this to the user before silently giving up.

### `settle_seconds`

The default 4.0 is usually fine. Increase to 6–8 for sites with lazy-loaded GTM containers, server-side tag managers, or A/B-test bootstraps that delay tag firing. Symptom of "too short": the accept state shows fewer hosts than expected.

## Running

```bash
# three-state audit, writes reports/<stem>.{json,md}
"$CA" audit "${CLAUDE_PLUGIN_ROOT}/sites/example.com.yaml"

# fingerprint persistence, writes reports/<host>.fingerprint.{json,md}
"$CA" fingerprint https://www.example.com \
  -c <cookie_name_1> -c <cookie_name_2> \
  --contexts 3 \
  --pre-click '#reject-button'
```

The fingerprint test takes `--contexts N` (default 3) — three is the floor for evidence; two contexts could collide by chance for a short ID, three with byte-identical values is hard to explain away.

## Picking identity cookies to track

Three-state audit output lists every cookie set in each state. For the fingerprint test, focus on cookies that:

1. Persist after reject (visible in the audit's `Cookies post-Reject` section).
2. Look like opaque identifiers — long random-looking strings, UUIDs, base64-ish blobs.
3. Come from a host that doesn't look like the first party — but is set as a first-party cookie (a strong signal of CNAME-cloaked or server-side identity).
4. Are named in a way that suggests identity: `*_id`, `*_uid`, `*device*`, `*visitor*`, `*fp*`, `_ga`, `_fbp`, `_uetvid`, vendor-prefixed IDs.

Also include any GA4 cookies (`_ga`, `_ga_<MID>`) for comparison — these *should* differ across isolated contexts. If `_ga` is identical across contexts, something is broken (or the test is rigged, e.g., the same fingerprint-restored client_id is being injected server-side).

## Interpreting findings

Findings are tagged with the ICO PECR Reg 6 obligation they relate to, so each can be mapped directly back to the rule. The report also produces an **ICO PECR Reg 6 self-audit** table and per-state **cookie inventory** tables — these are the artefacts a DPO would attach to a Reg 6 self-assessment.

### Three-state audit — tag reference

- **[R1] Pre-consent activity.** Two distinct signals: third-party tracker *host* contacted in `noaction`, and non-essential *cookies* set in `noaction`. The ICO is explicit that non-essential cookies on the homepage before consent is a violation. CMPs themselves (Quantcast Choice, Sourcepoint, OneTrust, Didomi, TrustArc) loading their own infrastructure pre-consent is generally accepted — flag it but don't lead with it. Identifier-like localStorage/sessionStorage keys pre-consent count under [R13] but are semantically the same problem.
- **[R4] Reject mechanism reachability.** If the configured reject selector did not match an element on the page, the tool reports it as a finding. Freely-given consent requires that refusal be at least as reachable as acceptance; a missing or buried reject button is itself the violation.
- **[R6] Non-essential cookies after reject.** GA4 (`_ga*`), Google Ads conversion linker (`_gcl_au`, `_gcl_aw`), Meta Pixel (`_fbp`), Bing UET (`_uetsid`, `_uetvid`), Microsoft Clarity (`_clck`, `_clsk`), FullStory (`fs_uid`, `fs_lua`), Segment (`ajs_anonymous_id`) all surviving reject is a violation unless the site successfully argues "strictly necessary" — which for analytics, ads, and session replay, it cannot. The classifier captures the full known list in `NON_ESSENTIAL_COOKIE_PATTERNS`.
- **[R10] Long-lived cookies.** Non-essential cookies with lifetime > 365 days after reject. The ICO checklist asks the site to confirm "duration is appropriate" — 1 year is the CNIL/EDPB working norm and the practical ceiling implied. The tool surfaces these so the site can either justify the duration or shorten it.
- **[R11] Third-party and first-party-masked cookies.** Two related signals: (a) cookies whose domain is on a different eTLD+1 to the site (true third party), and (b) cookies whose domain is a subdomain of the site but looks like a vendor proxy (`sst.<site>` / `cs.<site>` / `tags.<site>` are typically GTM server-side endpoints; `id.<site>` / `identity.<site>` are identity proxies; `analytics.<site>` / `telemetry.<site>` / `events.<site>` are behavioural analytics). Masked subdomains are third parties dressed as first parties to bypass tracker-blocking browser policies; treat the underlying vendor, not the subdomain, as the actor.
- **[R13] Similar technologies.** Reg 6 covers any method of storage or access — not just cookies. The tool flags session-replay vendors (FullStory, Quantum Metric, Microsoft Clarity, Hotjar, Mouseflow, Smartlook) on accept, and identifier-like localStorage/sessionStorage keys (`*id*`, `*uid*`, `*uuid*`, `*anon*`, `*device*`, `*fp*`, `*visitor*`, `*client*`) set in noaction. Fingerprinting itself (covered by the separate `fingerprint` command) falls under [R13] too.

### ICO PECR Reg 6 self-audit table

Each report ends with a checklist mapping observed behaviour to the obligation. Markers:

- **✓** — observed behaviour is consistent with the obligation.
- **✗** — observed behaviour contradicts the obligation; this is what a complaint would lead with.
- **n/a** — documentation/review items the tool cannot verify automatically (the site must produce these themselves).

Do not present a row of ✓s as a clean bill of health. The tool measures what fires; the obligations have legal nuance (strictly-necessary scope, what counts as "appropriate" duration for a given purpose) that requires human judgement.

### Per-cookie classification

Every cookie in the inventory tables is classified as:

- **non-essential** — clearly requires consent under Reg 6. Triggered by: (a) known tracker host, (b) first-party-masked vendor subdomain, (c) known non-essential cookie name pattern, or (d) third-party cookie domain.
- **essential** — matches a narrow allow-list of cookies whose purpose falls directly under a Reg 6(4) exemption the ICO explicitly names. Includes: load-balancing (`ARRAffinity`, `AWSALB`), strictly-necessary security / bot management (`__cf_bm`, `_cfuvid`, `_abck`, `bm_sz`, `cf_clearance`), CSRF tokens (`XSRF-TOKEN`, `csrftoken`), and generic app-server session cookies (`JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`). The reason text cites the exemption category. Anything contested (PerimeterX, marketing-attached "session" cookies) deliberately remains `unknown`.
- **unknown** — first-party cookie of unstated purpose. The classifier defaults to `unknown` rather than guessing essential; only the site can declare a cookie strictly necessary by reference to a user-requested service. Unknown cookies are the site's homework — they must be justified or consented.

### Audit-quality warning

When neither the accept nor the reject selector matches an element on the page, the captured state may be a bot-challenge interstitial (Cloudflare, PerimeterX) or an unrendered CMP rather than the real site. Without the warning, every R1/R6/R10/R11/R13 check would render ✓ trivially (nothing was loaded → nothing to flag), producing a misleading green report.

The audit prepends an `[AUDIT]` finding in that case and the ICO checklist includes a top row showing whether both buttons clicked. If the audit row is ✗ but the rest is ✓, do not present it as a clean bill of health — re-run with `headless=False` or a longer `settle_seconds`, or investigate whether the egress IP is being challenged.

### Fingerprint persistence test

The output table shows, per tracked cookie, whether the persistent component is identical across N contexts. Read this carefully:

- **Whole-cookie equality.** If the entire cookie value matches, that's the simplest case — but check that the cookie isn't something benign like a hard-coded site config blob.
- **Inner-ID equality.** Many identity cookies have a structure like `session=<rotating>:id=<persistent>` or `s_<rotating>.<persistent>`. The tool's parsers extract known formats (GA4, and a generic device-cookie pattern). For an unknown vendor, you may need to add a parser to `${CLAUDE_PLUGIN_ROOT}/consent_audit/parse.py` — model it after the existing examples, return an `IdentityField` with `persistent_id` set to the stable component.
- **Confidence score.** Some vendors helpfully include a self-reported match-confidence field in the cookie (`confidenceScore`, `match_score`, `prob`). When present, it's prima facie evidence that the value is a fingerprint match, not a session ID. Surface it.
- **What it does *not* tell you.** A persistent ID across N contexts proves *re-identification*. It does not prove what entropy sources were used, whether IP alone was sufficient, or whether the user can be linked across days (the test runs in one sitting). For cross-session persistence, repeat the test after a wait — different day, different IP if possible.

## Common pitfalls

- **`networkidle` never fires.** Sites with long-poll trackers or pinned WebSocket connections will hang. `browser.py` falls back to `domcontentloaded` after 30s — but you may still wait the full timeout. If a run is hanging, drop the timeout or change `wait_until` to `"load"`.
- **Headless detection.** Some banners render differently or trigger bot-management challenges (PerimeterX, Cloudflare, DataDome) under headless Chromium. If you see *zero* identity cookies and an unusually short host list, the site has detected the headless browser. Try `headless=False` in `with_fresh_context` — it requires a display, but it's the simplest fix.
- **Geo-gated banners.** A UK-based banner may not appear from a US IP and vice versa. The browser is configured `en-GB` / `Europe/London` by default — that's a locale hint, not a network egress. If banners are missing entirely, the egress IP is wrong for the regime being tested. Document the egress location with the finding.
- **Symmetric reject UX is rare.** Many banners offer a one-click "Accept all" but bury reject behind two or three clicks of "Manage preferences" → toggle each category off → "Save preferences". Make sure the configured `reject_selector` points at the *final* reject-equivalent button, not the first preferences menu.
- **Don't trust banner copy.** "Essential only" sometimes still allows analytics under a "Legitimate Interest" toggle that the user has to find separately. The audit measures *what fires*, not what the banner *claims*. Trust the cookie set, not the label.

## Where to extend

Source paths below are relative to `${CLAUDE_PLUGIN_ROOT}/consent_audit/`. Note that the
installed plugin copy is replaced on update — durable changes belong in a clone of the repo
(then `pip install -e` it / push upstream), not in the installed copy.

- **New cookie parser**: add a function to `parse.py` returning `IdentityField`; wire it into `run_fingerprint_persistence_test` in `audit.py` so the inner `persistent_id` is extracted for that cookie name.
- **New known tracker**: add a host suffix to `KNOWN_TRACKERS` in `parse.py`. The tuple is `(category, vendor)`.
- **First-party-masked detection**: add suspicious subdomain prefixes to `is_first_party_masked` in `parse.py`.
- **Shadow DOM / iframe banners**: extend `click_if_present` in `browser.py` to accept a frame or shadow-root traversal step.

## Output

Reports land in `reports/`:

- `<host>.json` / `<host>.md` — three-state audit.
- `<host>.fingerprint.json` / `<host>.fingerprint.md` — fingerprint persistence.

Markdown is what to show the user or paste into a writeup; JSON is what to diff between runs or feed downstream tooling.
