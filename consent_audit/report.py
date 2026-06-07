"""Render audits as JSON and Markdown."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime

from .audit import FingerprintAudit, SiteAudit, StateSnapshot


def audit_to_json(audit: SiteAudit) -> str:
    return json.dumps(asdict(audit) | {"generated_at": datetime.now(UTC).isoformat()}, indent=2)


def fingerprint_to_json(audit: FingerprintAudit) -> str:
    return json.dumps(asdict(audit) | {"generated_at": datetime.now(UTC).isoformat()}, indent=2)


def _state_row(label: str, snap: StateSnapshot) -> str:
    return (
        f"| {label} | {snap.cookie_count} | {len(snap.localStorage_keys)} | "
        f"{len(snap.sessionStorage_keys)} | {snap.host_count} |"
    )


def _lifetime_str(days: float | None) -> str:
    if days is None:
        return "session"
    if days < 1:
        return f"{days * 24:.1f}h"
    if days < 30:
        return f"{days:.1f}d"
    if days < 365:
        return f"{days / 30:.1f}mo"
    return f"{days / 365:.1f}y"


def _cookie_inventory_table(snapshot: StateSnapshot) -> list[str]:
    """Per-cookie table aligned to the ICO Reg 6 audit checklist.

    Columns map to the checklist items: name, domain (third party transparency),
    party, session vs persistent, lifetime, classification with reason. This is the
    artifact a DPO would attach to a Reg 6 self-assessment.
    """
    rows = [
        "| Cookie | Domain | Party | Persistence | Lifetime | Classification | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    if not snapshot.cookie_records:
        rows.append("| _(none)_ | | | | | | |")
        return rows
    # Sort order: non-essential first (most concerning), then unknown, then essential
    # (least concerning); within each group, third-party before first-party so vendor
    # cookies surface above platform cookies; then alphabetical.
    class_order = {"non-essential": 0, "unknown": 1, "essential": 2}
    sorted_records = sorted(
        snapshot.cookie_records,
        key=lambda c: (class_order.get(c.classification, 3), not c.is_third_party, c.name),
    )
    for c in sorted_records:
        party = "third" if c.is_third_party else "first"
        persistence = "session" if c.is_session else "persistent"
        rows.append(
            f"| `{c.name}` | {c.domain} | {party} | {persistence} | "
            f"{_lifetime_str(c.lifetime_days)} | {c.classification} | {c.classification_reason} |"
        )
    return rows


def _ico_checklist(audit: SiteAudit) -> list[str]:
    """Render an ICO PECR Reg 6 self-audit checklist for the captured states.

    Each row is what the ICO checklist asks the organisation to confirm; the ✓ / ✗ /
    ? marker is *what the tool can observe*, not a legal judgement. Items the tool
    cannot verify automatically (documentation, review cadence) are marked accordingly.
    """
    from urllib.parse import urlparse

    from .parse import classify_host, is_first_party_masked

    reject = audit.reject
    noaction = audit.noaction
    accept = audit.accept
    site_host = urlparse(audit.url).hostname or ""

    pre_consent_tracker_hosts = [
        h for h in noaction.unique_hosts
        if classify_host(h) is not None or is_first_party_masked(h, site_host)
    ]

    # Counts are by unique cookie name throughout, matching the finding text. The
    # inventory table separately shows each (name, domain) record so the user can see
    # cases like device_id appearing on both a vendor domain and the first party.
    third_party_post_reject = len({c.name for c in reject.third_party_cookies})
    non_essential_pre_consent = len({c.name for c in noaction.non_essential_cookies})
    non_essential_post_reject = len({c.name for c in reject.non_essential_cookies})
    long_lived_post_reject = len({
        c.name for c in reject.long_lived_cookies
        if c.classification == "non-essential"
    })
    accept_button_worked = accept.button_clicked is True
    reject_button_worked = reject.button_clicked is True
    banner_exercised = accept_button_worked and reject_button_worked

    suspicious_storage_count = len(noaction.suspicious_storage_keys)

    def mark(ok: bool, *, na: bool = False) -> str:
        if na:
            return "n/a"
        return "✓" if ok else "✗"

    return [
        "## ICO PECR Reg 6 self-audit",
        "",
        "Mapping captured behaviour to the ICO cookies-and-similar-technologies checklist.",
        "Markers indicate what the audit observed, not a legal conclusion. Counts are by "
        "unique cookie name; the inventory table below shows each (name, domain) record.",
        "",
        "| Reg 6 obligation | Status | Observed |",
        "|---|---|---|",
        f"| [AUDIT] Audit exercised the consent banner (both buttons clicked) | "
        f"{mark(banner_exercised)} | "
        f"accept_selector {'matched' if accept_button_worked else 'did not match'}; "
        f"reject_selector {'matched' if reject_button_worked else 'did not match'} |",
        f"| [R1] Non-essential cookies absent before consent | "
        f"{mark(non_essential_pre_consent == 0)} | "
        f"{non_essential_pre_consent} unique non-essential cookies in noaction state |",
        f"| [R1] No third-party tracker hosts contacted before consent | "
        f"{mark(len(pre_consent_tracker_hosts) == 0)} | "
        f"{noaction.host_count} unique hosts; "
        f"{len(pre_consent_tracker_hosts)} known-tracker / first-party-masked hosts |",
        f"| [R4] Reject mechanism reachable in one click | {mark(reject_button_worked)} | "
        f"reject_selector {'matched' if reject_button_worked else 'did not match'} an element |",
        f"| [R6] Only strictly-necessary cookies after Reject | "
        f"{mark(non_essential_post_reject == 0)} | "
        f"{non_essential_post_reject} unique non-essential cookies still present after Reject |",
        f"| [R10] Cookie lifetimes appropriate (≤1 year for non-essential) | "
        f"{mark(long_lived_post_reject == 0)} | "
        f"{long_lived_post_reject} unique non-essential cookies exceed 1 year after Reject |",
        f"| [R11] Third-party cookie use disclosed and minimised | "
        f"{mark(third_party_post_reject == 0)} | "
        f"{third_party_post_reject} unique third-party cookies after Reject |",
        f"| [R13] No identifier-like storage set before consent | "
        f"{mark(suspicious_storage_count == 0)} | "
        f"{suspicious_storage_count} identifier-like keys "
        f"(of {len(noaction.localStorage_keys)} localStorage / "
        f"{len(noaction.sessionStorage_keys)} sessionStorage total) |",
        f"| Documentation of every cookie's purpose and duration | {mark(False, na=True)} | "
        f"site responsibility — tool produces the inventory below for review |",
        f"| Appropriate review period for cookie usage | {mark(False, na=True)} | "
        f"site responsibility |",
        "",
    ]


def audit_to_markdown(audit: SiteAudit) -> str:
    lines = [
        f"# Consent audit — {audit.site}",
        "",
        f"**URL:** {audit.url}",
        f"**Generated:** {datetime.now(UTC).isoformat(timespec='seconds')}",
        "",
        "## State summary",
        "",
        "| State | Cookies | localStorage keys | sessionStorage keys | Unique hosts |",
        "|---|---:|---:|---:|---:|",
        _state_row("No action", audit.noaction),
        _state_row("Reject", audit.reject),
        _state_row("Accept", audit.accept),
        "",
    ]

    if audit.findings:
        lines.append("## Findings")
        lines.append("")
        for f in audit.findings:
            lines.append(f"- {f}")
        lines.append("")

    lines.extend(_ico_checklist(audit))

    lines.append("## Cookie inventory — post-Reject")
    lines.append("")
    lines.append(
        "Per the ICO checklist, every cookie must have a documented purpose, party, "
        "persistence and lifetime. The classifier marks each as `non-essential` (clearly "
        "requires consent) or `unknown` (first-party of unstated purpose — site must "
        "justify as strictly necessary or seek consent)."
    )
    lines.append("")
    lines.extend(_cookie_inventory_table(audit.reject))
    lines.append("")

    lines.append("## Cookie inventory — pre-consent (noaction)")
    lines.append("")
    lines.extend(_cookie_inventory_table(audit.noaction))
    lines.append("")

    return "\n".join(lines)


def fingerprint_to_markdown(audit: FingerprintAudit) -> str:
    lines = [
        f"# Fingerprint persistence — {audit.url}",
        "",
        f"**Isolated contexts tested:** {audit.contexts}",
        f"**Generated:** {datetime.now(UTC).isoformat(timespec='seconds')}",
        "",
        "Two or more fully isolated browser contexts share no cookies, storage, or",
        "in-memory state. A persistent identifier that repeats across them can only",
        "come from server-side device fingerprinting.",
        "",
        "## Findings",
        "",
        "| Cookie | Persistent across contexts? | Distinct IDs observed | Confidence scores |",
        "|---|---|---|---|",
    ]
    for f in audit.findings:
        ids = "; ".join(sorted({i for i in f.persistent_ids if i})) or "_(empty)_"
        confs = "; ".join(f"{c:.2f}" if c is not None else "—" for c in f.confidence_scores)
        verdict = "✓ FINGERPRINTED" if f.is_persistent_across_contexts else "no"
        lines.append(f"| `{f.cookie}` | {verdict} | {ids} | {confs} |")
    lines.append("")
    return "\n".join(lines)
