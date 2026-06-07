# consent-audit

Audit web consent banners and detect server-side device-fingerprint re-identification across fully isolated browser contexts.

The tool runs two distinct experiments per site:

1. **Three-state audit** — `noaction` / `accept` / `reject`. Captures cookies, storage, and unique hosts contacted in each state. Surfaces non-essential trackers that fire pre-consent or persist after the user clicks reject.
2. **Fingerprint persistence test** — N fully isolated browser contexts visit the same URL. Any identifier that is byte-identical across all N can only come from server-side fingerprinting (the contexts share no cookies, storage, or in-memory state).

## How the fingerprint test works

Some server-side identity services issue a device cookie whose value nests a rotating
session token around a stable, fingerprint-derived identifier — for example:

```
refresh=<ms>&id=<session_uuid>:id=<persistent_id>&cacheExpiry=<s>&requestId=<...>&confidenceScore=<n>
```

The outer `session_uuid` rotates per visit; the inner `persistent_id` does not. Because each
test runs in a fresh, fully isolated `BrowserContext` (no shared cookies, storage, or in-memory
state), a `persistent_id` that is **byte-identical across N independent contexts** cannot have
come from the client — it was re-derived server-side, the signature of device fingerprinting.
When the cookie also carries a self-reported match `confidenceScore`, that is prima facie
evidence the value is a fingerprint match rather than a session ID.

This is the behaviour UK PECR Regulation 6, the ICO's 2019 storage guidance, and the EDPB 2024
device-fingerprinting guidelines were written to constrain. A synthetic fixture demonstrating
the parser and the cross-context match check is in `tests/fixtures/device_id_evidence.json`
(fabricated values — not captured from any real site).

## Install

```bash
git clone <this repo>
cd consent-audit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
playwright install chromium
```

## Use as a Claude Code plugin

This repo is also a self-contained Claude Code plugin (and its own single-plugin marketplace).
Installing it gives Claude the `consent-audit` skill, which knows when to run each experiment and
how to read the output:

```text
/plugin marketplace add Thihal/consent-audit
/plugin install consent-audit@consent-audit
```

To develop or test locally without a GitHub remote, point the marketplace at the working tree:

```text
/plugin marketplace add ./
/plugin install consent-audit@consent-audit
```

On first use the skill builds a persistent venv from the bundled source (in the plugin's data
dir) and runs `playwright install chromium` — no system-wide install. After that, just ask
Claude to "audit example.com" or "check if reject actually rejects on <site>".

## Run

Three-state audit:

```bash
consent-audit audit sites/example.com.yaml
# → reports/example.com.{json,md}
```

Fingerprint persistence test (three isolated contexts, click the reject button before capture):

```bash
consent-audit fingerprint https://www.example.com \
  -c device_id -c _ga \
  --contexts 3 \
  --pre-click '#reject-all-cookies'
# → reports/www.example.com.fingerprint.{json,md}
```

## Adding a site

Create `sites/<host>.yaml`:

```yaml
url: https://example.com
accept_selector: "#accept"        # CSS selector of the Accept-all button
reject_selector: "#reject"        # CSS selector of the Reject-all (or equivalent) button
consent_cookie: "CookieConsent"   # name of the cookie that records the user's choice
identity_cookies:
  - _ga
  - device_id
settle_seconds: 4.0
```

## Tests

```bash
pytest -v
```

The unit tests exercise the parsers against synthetic fixtures and fail if the persistent_id parsing or the cross-context identity-match check ever regresses.

## What the audit surfaces

A typical three-state audit distinguishes, per consent state:

- **Pre-consent activity** — analytics/ad hosts contacted or non-essential cookies set in `noaction`, before the user chooses anything ([R1]).
- **Reject that doesn't reject** — GA4, Google Ads conversion linker, Meta Pixel, Bing UET, session-replay, or CDP cookies that survive a reject-equivalent click ([R6]).
- **First-party masking** — vendor endpoints disguised as first-party subdomains (`sst.`, `id.`, behavioural-analytics proxies) to evade tracker-blocking ([R11]).
- **Similar technologies** — session-replay vendors and identifier-like storage keys that fall under Reg 6 even though they are not classic cookies ([R13]).

The fingerprint test then answers the harder question: of the identifiers that survive reject, which are genuine per-session IDs and which are server-side fingerprint matches that no client-side action defeats.

## Limitations

- Banner-button selectors are configured manually per site. There is no LLM-driven auto-detection yet; adding it is the obvious next iteration.
- Playwright Chromium fingerprints differently from a real user (`HeadlessChrome` substring in UA absent in headed mode, default screen size, etc.). Re-identification confidence on a hardened anti-fingerprint browser like Brave or Tor would differ.
- The tool measures what fires *during a single visit*. Cross-session correlation (returning days later) requires additional infrastructure.
- "Confidence the device is fingerprinted" depends on the cookie format being parseable. A nested `:id=<persistent>` with an explicit `confidenceScore` field makes detection trivial; other vendors hide the persistent component inside an opaque blob.
