"""Unit tests for SiteAudit.analyse() reject-outcome routing.

This is the credibility-critical path: a non-essential cookie present in the reject state
must be reported as "[R6] survives reject" ONLY when reject was actually clicked. If the
reject button was never found/clicked, the same cookie is a pre-consent ([R1]) artefact —
calling it [R6] would accuse a site of ignoring a refusal that the experiment never made.
"""

from __future__ import annotations

from consent_audit.audit import SiteAudit, StateSnapshot
from consent_audit.detect import Detection, Provenance

SITE = "example.com"
URL = "https://example.com"


def _cookie(name: str, domain: str = ".example.com") -> dict:
    return {
        "name": name, "value": "x", "domain": domain, "path": "/",
        "expires": -1.0, "secure": True, "httpOnly": False, "sameSite": "Lax",
    }


def _snap(state: str, *, cookies: list[dict], button_clicked) -> StateSnapshot:
    raw = {
        "cookies": {c["name"]: c["value"] for c in cookies},
        "cookie_records": cookies,
        "localStorage_lengths": {},
        "sessionStorage_lengths": {},
        "unique_hosts": [],
    }
    return StateSnapshot.from_raw(state, raw, site_host=SITE, button_clicked=button_clicked)


def _audit(*, reject_clicked, detection: Detection | None) -> SiteAudit:
    # Non-essential _ga present in every state (the site sets it on load).
    cookies = [_cookie("_ga")]
    audit = SiteAudit(
        site=SITE, url=URL,
        noaction=_snap("noaction", cookies=cookies, button_clicked=None),
        accept=_snap("accept", cookies=cookies, button_clicked=True),
        reject=_snap("reject", cookies=cookies, button_clicked=reject_clicked),
        detection=detection,
    )
    audit.analyse()
    return audit


def _tags(audit: SiteAudit, tag: str) -> bool:
    return any(f.startswith(tag) for f in audit.findings)


def test_reject_clicked_reports_r6():
    audit = _audit(reject_clicked=True, detection=Detection(
        reject_selector="#r", reject_provenance=Provenance.CMP_SIGNATURE))
    assert _tags(audit, "[R6]")


def test_not_found_reports_r4_not_r6():
    # Banner readable, no one-click reject: [R4] fires, [R6] must NOT (reject never ran).
    audit = _audit(reject_clicked=False, detection=Detection(
        cmp="OneTrust", reject_provenance=Provenance.NOT_FOUND,
        notes=["no one-click reject"]))
    assert _tags(audit, "[R4]")
    assert not _tags(audit, "[R6]")


def test_inconclusive_reports_audit_not_r6_not_r4():
    # Banner unreadable (iframe/shadow/none): inconclusive [AUDIT], no [R4] accusation,
    # no [R6] — the experiment did not run, so it is neither pass nor fail.
    audit = _audit(reject_clicked=False, detection=Detection(
        cmp="Quantcast/Sourcepoint", reject_provenance=Provenance.INCONCLUSIVE,
        notes=["iframe CMP"]))
    assert _tags(audit, "[AUDIT]")
    assert not _tags(audit, "[R6]")
    assert not _tags(audit, "[R4]")


def test_manual_failed_reject_reports_r4():
    # Hand-written YAML whose reject selector no longer matches: still a [R4] signal,
    # but not [R6] (no real reject click happened).
    audit = _audit(reject_clicked=False, detection=None)
    assert _tags(audit, "[R4]")
    assert not _tags(audit, "[R6]")
