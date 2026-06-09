"""Auto-detect consent-banner Accept-all / Reject-all buttons.

The three-state audit needs a CSS selector for the Accept-all and Reject-all (or
"essential only") buttons. Hand-configuring these per site is the main barrier to
running the tool against an arbitrary URL. This module recovers them automatically so
`consent-audit audit https://example.com` works with no YAML.

Two strategies, in order of reliability:

1. **Known-CMP signatures.** The major consent platforms render stable, documented
   button IDs/attributes. If a documented button is in the DOM the CMP is identified and
   its selectors used directly — high confidence, reproducible, and (unlike the generic
   path) not gated on visibility, so a reject button present-but-hidden-until-animated is
   still recovered.
2. **Generic text matching.** When no known CMP is present, enumerate the page's clickable
   controls and match their accessible label against an accept/reject vocabulary using
   **word-boundary** matching — never substring, so "ok" does not match "co-ok-ie policy".

Auto-mode deliberately handles only **single-click reject-all**. Multi-layer banners
(Manage preferences -> toggle each category off -> Save) are an action *sequence*, not a
selector; auto-mode reports them as `not_found` rather than guessing, and the user is
directed to the manual-YAML path. Detecting the wrong reject button would manufacture a
false "reject doesn't reject" finding, which is the one error that destroys credibility.

iframe-hosted CMPs (Sourcepoint/Quantcast Choice, TrustArc) render their buttons in a
nested cross-origin iframe Playwright's default selector engine does not pierce; they are
detected as *present* (-> inconclusive, "use manual YAML") rather than mis-matched.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import TypedDict

from playwright.async_api import Page


class _Candidate(TypedDict):
    label: str
    selector: str
    visible: bool


class Provenance(enum.StrEnum):
    """How a selector was obtained — drives how analyse() treats the result.

    The distinction between NOT_FOUND and INCONCLUSIVE is load-bearing: the first is a
    finding *against the site* (a banner was readable and offered no one-click reject),
    the second is a *tool limitation* (the banner could not be read at all) and must not
    be presented as either compliance or non-compliance.
    """

    CMP_SIGNATURE = "cmp_signature"  # matched a known CMP's documented button — high confidence
    GENERIC_TEXT = "generic_text"    # matched generic accept/reject text — medium confidence
    NOT_FOUND = "not_found"          # banner was readable but this button is absent (site finding)
    INCONCLUSIVE = "inconclusive"    # no banner readable (iframe/shadow/none) — tool limitation
    MANUAL = "manual"                # selector supplied by hand-written YAML, not detected


@dataclass
class Detection:
    cmp: str | None = None
    accept_selector: str | None = None
    reject_selector: str | None = None
    accept_provenance: Provenance = Provenance.INCONCLUSIVE
    reject_provenance: Provenance = Provenance.INCONCLUSIVE
    notes: list[str] = field(default_factory=list)


# (name, signature_selector, accept_selector, reject_selector). The CMP is considered
# present if the signature OR any documented accept/reject candidate is in the DOM — the
# container element sometimes lazy-renders after the buttons, so keying only on it misses
# live banners. Comma-separated candidates are tried in order. Playwright's CSS engine
# pierces open shadow DOM, so the Usercentrics data-testid selectors resolve unaided.
KNOWN_CMPS: list[tuple[str, str, str, str]] = [
    (
        "OneTrust",
        "#onetrust-banner-sdk, #onetrust-consent-sdk",
        "#onetrust-accept-btn-handler",
        "#onetrust-reject-all-handler",
    ),
    (
        "Cookiebot",
        "#CybotCookiebotDialog",
        "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll, #CybotCookiebotDialogBodyButtonAccept",
        "#CybotCookiebotDialogBodyButtonDecline",
    ),
    (
        "Didomi",
        "#didomi-host, #didomi-notice",
        "#didomi-notice-agree-button",
        "#didomi-notice-disagree-button",
    ),
    (
        "Usercentrics",
        "#usercentrics-root",
        "[data-testid='uc-accept-all-button']",
        "[data-testid='uc-deny-all-button']",
    ),
    (
        "Osano",
        ".osano-cm-window, .osano-cm-dialog",
        ".osano-cm-accept-all",
        ".osano-cm-denyAll, .osano-cm-deny",
    ),
    (
        "CookieYes",
        ".cky-consent-container, .cky-consent-bar",
        ".cky-btn-accept",
        ".cky-btn-reject",
    ),
    (
        "Complianz",
        ".cmplz-cookiebanner",
        ".cmplz-accept",
        ".cmplz-deny",
    ),
]

# iframe-hosted CMPs: detected so the report can say "CMP present but not auto-readable"
# rather than silently falling through to a misleading generic match.
IFRAME_CMPS: list[tuple[str, str]] = [
    ("Quantcast/Sourcepoint", "iframe[src*='consent'], iframe[id*='sp_message'], .qc-cmp2-container"),
    ("TrustArc", "#truste-consent-track, iframe[src*='trustarc'], iframe[src*='truste']"),
]

# Accessible-label vocabularies for the generic fallback, longest/most-specific first so a
# "reject all cookies" button outscores a bare "reject". Reject patterns include the common
# reject-equivalent labels ("essential/necessary only") but NOT "manage"/"preferences"/
# "settings" — those open a second layer (multi-step) we do not auto-traverse.
ACCEPT_TEXTS = [
    "accept all cookies", "allow all cookies", "accept all", "allow all",
    "i accept", "i agree", "accept cookies", "accept & close", "accept and close",
    "yes i agree", "accept", "agree", "allow", "got it",
]
REJECT_TEXTS = [
    "reject all cookies", "decline all cookies", "reject all", "decline all", "deny all",
    "refuse all", "use necessary cookies only", "only necessary cookies",
    "essential cookies only", "essential only", "only essential", "necessary only",
    "only necessary", "continue without accepting", "do not accept",
    "reject", "decline", "deny", "refuse", "disagree",
]

# One pass over every clickable control, returning a stable selector + accessible label for
# each. Plain <a> links are excluded unless role=button — they are almost always "cookie
# policy" / "learn more", the classic false-positive source. querySelectorAll does not
# pierce shadow roots; shadow-DOM CMPs are handled by the signature path above.
_CANDIDATES_JS = r"""
() => {
  const cssEscape = (s) => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  const sel = 'button, [role="button"], input[type="submit"], input[type="button"], a[role="button"]';
  const out = [];
  for (const el of document.querySelectorAll(sel)) {
    const label = (el.getAttribute('aria-label') || el.value || el.textContent || '').trim().replace(/\s+/g, ' ');
    if (!label || label.length > 60) continue;
    const rect = el.getBoundingClientRect();
    const cs = window.getComputedStyle(el);
    // offsetParent is null for position:fixed elements — which cookie banners almost always
    // are — so it cannot be used to judge banner-button visibility. Use computed style + box.
    const visible = cs.visibility !== 'hidden' && cs.display !== 'none'
      && parseFloat(cs.opacity || '1') > 0 && rect.width > 0 && rect.height > 0;
    const a = (n) => el.getAttribute(n);
    const q = (s) => String(s).replace(/'/g, "\\'");
    const tag = el.tagName.toLowerCase();
    let selector;
    if (el.id) selector = '#' + cssEscape(el.id);
    else if (a('data-testid')) selector = "[data-testid='" + q(a('data-testid')) + "']";
    else if (a('aria-label')) selector = "[aria-label='" + q(a('aria-label')) + "']";
    else if (a('name')) selector = tag + "[name='" + q(a('name')) + "']";
    else selector = tag + ':has-text("' + label.replace(/"/g, '\\"') + '")';
    out.push({ label, selector, visible });
  }
  return out;
}
"""


async def _present(page: Page, selector: str) -> bool:
    """True if any matching element exists (visibility not required — banners can be
    off-screen until animated in; existence in the DOM is enough to identify the CMP)."""
    try:
        return await page.query_selector(selector) is not None
    except Exception:
        return False


async def _first_present(page: Page, comma_selectors: str) -> str | None:
    for candidate in [s.strip() for s in comma_selectors.split(",")]:
        if candidate and await _present(page, candidate):
            return candidate
    return None


def _score(label: str, phrase: str) -> int:
    """Word-boundary match score (0 = no match). Exact label beats whole-phrase-contained;
    longer phrases beat shorter. Word boundaries prevent 'ok' matching 'cookie'."""
    norm = label.lower().strip().rstrip(".!").strip()
    if norm == phrase:
        return 200 + len(phrase)
    if re.search(r"\b" + re.escape(phrase) + r"\b", norm):
        return 100 + len(phrase)
    return 0


def _best_match(candidates: list[_Candidate], vocab: list[str]) -> str | None:
    """Pick the highest-scoring candidate selector for a vocabulary. Visible controls are
    preferred over hidden ones at equal text score (banner buttons are visible; hidden
    same-text controls are usually footer/duplicate elements)."""
    best_sel, best_key = None, (0, 0)
    for c in candidates:
        score = max((_score(c["label"], p) for p in vocab), default=0)
        if score == 0:
            continue
        key = (score, 1 if c.get("visible") else 0)
        if key > best_key:
            best_key, best_sel = key, c["selector"]
    return best_sel


async def detect_consent(page: Page) -> Detection:
    """Detect Accept-all and Reject-all selectors on an already-navigated page.

    The page must already be loaded (and given time to render its banner). Detection does
    not click anything; it only reads the DOM so the same selectors can be reused across
    the three independent audit contexts.
    """
    det = Detection()

    # 1. Known CMP signatures (high confidence). Present if the container OR a documented
    # button is in the DOM.
    for name, signature, accept_sel, reject_sel in KNOWN_CMPS:
        accept_found = await _first_present(page, accept_sel)
        reject_found = await _first_present(page, reject_sel)
        if not (await _present(page, signature) or accept_found or reject_found):
            continue
        det.cmp = name
        if accept_found:
            det.accept_selector = accept_found
            det.accept_provenance = Provenance.CMP_SIGNATURE
        if reject_found:
            det.reject_selector = reject_found
            det.reject_provenance = Provenance.CMP_SIGNATURE
        else:
            det.reject_provenance = Provenance.NOT_FOUND
            det.notes.append(
                f"{name} detected but no one-click reject button present; reject is likely "
                "behind a 'Manage preferences' layer — use manual YAML to capture it."
            )
        return det

    # 2. iframe-hosted CMPs we cannot auto-read in v1.
    for name, signature in IFRAME_CMPS:
        if await _present(page, signature):
            det.cmp = name
            det.accept_provenance = Provenance.INCONCLUSIVE
            det.reject_provenance = Provenance.INCONCLUSIVE
            det.notes.append(
                f"{name} renders its buttons in a nested iframe Playwright does not pierce "
                "by default; auto-detection cannot read them. Use manual YAML."
            )
            return det

    # 3. Generic accessible-label fallback (medium confidence).
    try:
        candidates: list[_Candidate] = await page.evaluate(_CANDIDATES_JS)
    except Exception:
        candidates = []
    accept = _best_match(candidates, ACCEPT_TEXTS)
    reject = _best_match(candidates, REJECT_TEXTS)
    if accept:
        det.accept_selector = accept
        det.accept_provenance = Provenance.GENERIC_TEXT
    if reject:
        det.reject_selector = reject
        det.reject_provenance = Provenance.GENERIC_TEXT

    if accept and not reject:
        # Banner with an accept control but no readable one-click refusal: a site finding
        # (no symmetric reject), not a tool limitation.
        det.reject_provenance = Provenance.NOT_FOUND
        det.notes.append(
            "Accept control found but no one-click reject/essential-only control matched; "
            "either reject is behind a preferences layer (multi-step) or absent."
        )
    elif not accept and not reject:
        det.notes.append(
            "No known CMP and no accept/reject control matched — the page may have no "
            "consent banner, or it renders in an iframe/shadow root not auto-readable."
        )

    return det


__all__ = ["Provenance", "Detection", "detect_consent", "KNOWN_CMPS"]
