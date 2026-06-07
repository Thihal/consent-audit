"""Orchestrate three-state consent audits and fingerprint-persistence tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from .browser import capture_state, click_if_present, with_fresh_context
from .parse import (
    classify_cookie,
    classify_host,
    cookie_lifetime_days,
    is_first_party_cookie,
    is_first_party_masked,
    looks_identifier_like,
    parse_consentmgr,
    parse_device_id_cookie,
    parse_ga4,
)

# A cookie persisting > LONG_LIFETIME_DAYS for non-essential purposes is flagged under
# the ICO Reg 6 checklist item "established how long our cookies last and that this
# duration is appropriate". The 365-day threshold is the CNIL/EDPB working norm and
# the practical ceiling implied by the ICO's "appropriate duration" wording.
LONG_LIFETIME_DAYS = 365.0


class SiteConfig(BaseModel):
    url: str
    accept_selector: str
    reject_selector: str
    consent_cookie: str | None = None
    identity_cookies: list[str] = Field(default_factory=list)
    settle_seconds: float = 4.0

    @classmethod
    def load(cls, path: Path) -> SiteConfig:
        return cls.model_validate(yaml.safe_load(path.read_text()))


@dataclass
class CookieRecord:
    """Per-cookie metadata captured via Playwright's context.cookies().

    The fields below are exactly what the ICO PECR Reg 6 audit checklist requires for
    each cookie: name, party (first/third), persistence (session/persistent), lifetime,
    and a classification of whether consent is required.
    """
    name: str
    value: str
    domain: str
    path: str
    expires: float  # unix seconds; -1.0 for session cookies (Playwright convention)
    is_session: bool
    lifetime_days: float | None
    is_first_party: bool
    is_third_party: bool
    secure: bool
    http_only: bool
    same_site: str | None
    classification: str  # "non-essential" | "unknown"
    classification_reason: str

    @classmethod
    def from_raw(cls, raw: dict[str, Any], site_host: str) -> CookieRecord:
        expires = float(raw.get("expires", -1.0))
        is_session = expires < 0
        is_first_party = is_first_party_cookie(raw.get("domain", ""), site_host)
        classification, reason = classify_cookie(
            raw["name"], raw.get("domain", ""), site_host
        )
        return cls(
            name=raw["name"],
            value=raw.get("value", ""),
            domain=raw.get("domain", ""),
            path=raw.get("path", "/"),
            expires=expires,
            is_session=is_session,
            lifetime_days=cookie_lifetime_days(expires),
            is_first_party=is_first_party,
            is_third_party=not is_first_party,
            secure=bool(raw.get("secure", False)),
            http_only=bool(raw.get("httpOnly", False)),
            same_site=raw.get("sameSite"),
            classification=classification,
            classification_reason=reason,
        )


@dataclass
class StateSnapshot:
    state: str  # "noaction" | "accept" | "reject"
    cookies: dict[str, str]
    cookie_count: int
    cookie_records: list[CookieRecord]
    localStorage_keys: list[str]
    sessionStorage_keys: list[str]
    unique_hosts: list[str]
    host_count: int
    button_clicked: bool | None = None  # None for noaction; True/False for accept/reject

    @classmethod
    def from_raw(
        cls,
        state: str,
        raw: dict[str, Any],
        site_host: str,
        button_clicked: bool | None = None,
    ) -> StateSnapshot:
        records = [
            CookieRecord.from_raw(c, site_host) for c in raw.get("cookie_records", [])
        ]
        return cls(
            state=state,
            cookies=raw["cookies"],
            cookie_count=len(raw["cookies"]),
            cookie_records=records,
            localStorage_keys=sorted(raw["localStorage_lengths"].keys()),
            sessionStorage_keys=sorted(raw["sessionStorage_lengths"].keys()),
            unique_hosts=raw["unique_hosts"],
            host_count=len(raw["unique_hosts"]),
            button_clicked=button_clicked,
        )

    @property
    def non_essential_cookies(self) -> list[CookieRecord]:
        return [c for c in self.cookie_records if c.classification == "non-essential"]

    @property
    def essential_cookies(self) -> list[CookieRecord]:
        return [c for c in self.cookie_records if c.classification == "essential"]

    @property
    def third_party_cookies(self) -> list[CookieRecord]:
        return [c for c in self.cookie_records if c.is_third_party]

    @property
    def persistent_cookies(self) -> list[CookieRecord]:
        return [c for c in self.cookie_records if not c.is_session]

    @property
    def long_lived_cookies(self) -> list[CookieRecord]:
        return [
            c for c in self.cookie_records
            if c.lifetime_days is not None and c.lifetime_days > LONG_LIFETIME_DAYS
        ]

    @property
    def suspicious_storage_keys(self) -> list[str]:
        """localStorage and sessionStorage keys whose tokens match identifier keywords."""
        return sorted({
            k for k in (self.localStorage_keys + self.sessionStorage_keys)
            if looks_identifier_like(k)
        })


@dataclass
class SiteAudit:
    site: str
    url: str
    noaction: StateSnapshot
    accept: StateSnapshot
    reject: StateSnapshot
    findings: list[str] = field(default_factory=list)

    def analyse(self) -> None:
        """Generate human-readable findings based on the three captured states.

        Findings are tagged with the relevant ICO PECR Reg 6 obligation so a reader can
        map each finding back to the underlying rule. Tags used:
          [AUDIT] audit-quality warnings (page may not have loaded normally)
          [R1] non-essential cookies / trackers before consent
          [R4] consent UX: accept and reject mechanism reachability
          [R6] non-essential cookies surviving reject (not exempt under Reg 6(4))
          [R10] cookie lifetime appropriateness
          [R11] third-party cookies and first-party-masked vendor subdomains
          [R13] similar technologies (session replay, localStorage identifiers)

        Counts are reported by unique cookie name throughout — the same cookie name set
        on multiple domains (e.g., `device_id` on both a vendor domain and the first
        party) is one entry in the finding text but a distinct row in the inventory
        table, so the user can see the domain split.
        """
        site_host = urlparse(self.url).hostname or ""
        accept_failed = self.accept.button_clicked is False
        reject_failed = self.reject.button_clicked is False

        # [AUDIT] Page-didn't-load-normally warning. When neither consent button matched,
        # the captured state may be a bot challenge / Cloudflare interstitial / unrendered
        # CMP rather than the real site — and the rest of the findings will look ✓ by
        # default. Prepend this so the reader sees the caveat before the green markers.
        if accept_failed and reject_failed:
            self.findings.append(
                "[AUDIT] Neither accept_selector nor reject_selector matched any element "
                "— the captured state may reflect a bot-challenge page or an unrendered "
                f"consent banner rather than the real site (accept state: "
                f"{self.accept.cookie_count} cookies, {self.accept.host_count} hosts). "
                "Treat ✓ markers below with caution."
            )

        # [R1] Pre-consent third-party tracker host contact.
        pre_consent_third_party = [
            h for h in self.noaction.unique_hosts
            if (classify_host(h) is not None) or is_first_party_masked(h, site_host)
        ]
        if pre_consent_third_party:
            self.findings.append(
                f"[R1] Pre-consent tracker contact ({len(pre_consent_third_party)} hosts): "
                + ", ".join(pre_consent_third_party[:8])
                + ("…" if len(pre_consent_third_party) > 8 else "")
            )

        # [R1] Non-essential cookies present in noaction (before any user action). The
        # ICO is explicit: "you cannot set non-essential cookies on your website's
        # homepage before the user has consented to them."
        noaction_non_essential_names = sorted({
            c.name for c in self.noaction.non_essential_cookies
        })
        if noaction_non_essential_names:
            self.findings.append(
                f"[R1] Non-essential cookies set before any user action "
                f"({len(noaction_non_essential_names)}): "
                + ", ".join(noaction_non_essential_names)
            )

        # [R4] Accept and reject button reachability. Either failing-to-match is a
        # finding: accept failing means the page may not be in the expected state for
        # the accept-state comparison; reject failing is a direct consent-UX problem.
        if accept_failed:
            self.findings.append(
                "[R4] Configured accept selector did not match an element on the page — "
                "the accept-state capture may not reflect a real consent decision"
            )
        if reject_failed:
            self.findings.append(
                "[R4] Configured reject selector did not match an element on the page — "
                "verify the banner provides a clearly-labelled reject mechanism reachable "
                "in the same layer as Accept"
            )

        # [R6] Non-essential cookies surviving the reject click. Reg 6 exemptions are
        # narrow: communication transmission, or strictly-necessary for a user-requested
        # service. Analytics, ads, behavioural tracking, session replay never qualify.
        post_reject_non_essential_names = sorted({
            c.name for c in self.reject.non_essential_cookies
        })
        if post_reject_non_essential_names:
            self.findings.append(
                f"[R6] Non-essential cookies still set after Reject "
                f"({len(post_reject_non_essential_names)}): "
                + ", ".join(post_reject_non_essential_names)
            )

        # [R10] Long-lived cookies. Surface anything > 1 year, especially non-essential.
        # Cookies with the same name on multiple domains are distinct records; include
        # `@domain` in the display so the reader can see they are separate items.
        long_lived_non_essential = [
            c for c in self.reject.long_lived_cookies
            if c.classification == "non-essential"
        ]
        if long_lived_non_essential:
            sorted_records = sorted(
                long_lived_non_essential, key=lambda c: -(c.lifetime_days or 0)
            )
            details = ", ".join(
                f"{c.name}@{c.domain} ({c.lifetime_days:.0f}d)"
                for c in sorted_records[:8]
            )
            self.findings.append(
                f"[R10] Non-essential cookies persist > {LONG_LIFETIME_DAYS:.0f} days "
                f"after reject ({len(long_lived_non_essential)}): {details}"
                + ("…" if len(long_lived_non_essential) > 8 else "")
            )

        # [R11] First-party-masked subdomains in the host list (any state).
        masked = [
            h for h in self.accept.unique_hosts
            if is_first_party_masked(h, site_host)
        ]
        if masked:
            self.findings.append(
                f"[R11] First-party-masked tracker subdomains observed: {', '.join(masked)}"
            )

        # [R11] Third-party cookie count after reject — independent signal from name-based
        # classification, catches vendors not in our pattern list.
        third_party_after_reject_names = sorted({
            c.name for c in self.reject.third_party_cookies
        })
        if third_party_after_reject_names:
            self.findings.append(
                f"[R11] Third-party cookies remain after Reject "
                f"({len(third_party_after_reject_names)}): "
                + ", ".join(third_party_after_reject_names[:10])
                + ("…" if len(third_party_after_reject_names) > 10 else "")
            )

        # [R13] Session-replay vendors — Reg 6 covers any technology that stores or
        # accesses information on the device, and session replay records keystrokes,
        # mouse movement and DOM mutations.
        replay_vendors = {
            "fullstory.com", "quantummetric.com", "clarity.ms",
            "hotjar.com", "mouseflow.com", "smartlook.com",
        }
        replay_present = sorted({
            classify_host(h)[1]  # vendor name
            for h in self.accept.unique_hosts
            if any(h.endswith("." + v) or h == v for v in replay_vendors)
            and classify_host(h)
        })
        if replay_present:
            self.findings.append(
                f"[R13] Session replay vendors on accept: {', '.join(replay_present)}"
            )

        # [R13] Identifier-like localStorage / sessionStorage keys present in noaction.
        # PECR applies to *any* method of storage or access on the device; storage keys
        # with identity-related tokens set pre-consent are equivalent to a pre-consent
        # cookie under the regulation. Token-based matching avoids false positives from
        # benign substrings (e.g., `video` does not match `id`).
        suspicious_storage = self.noaction.suspicious_storage_keys
        if suspicious_storage:
            self.findings.append(
                f"[R13] Identifier-like storage keys present before consent "
                f"({len(suspicious_storage)}): "
                + ", ".join(suspicious_storage[:8])
                + ("…" if len(suspicious_storage) > 8 else "")
            )


@dataclass
class FingerprintFinding:
    cookie: str
    persistent_ids: list[str]  # one per context
    confidence_scores: list[float | None]
    is_persistent_across_contexts: bool


@dataclass
class FingerprintAudit:
    url: str
    contexts: int
    raw_values: list[str]  # raw cookie values, one per context
    findings: list[FingerprintFinding]


# ---------- Three-state audit ----------

async def _capture_with_button(
    cfg: SiteConfig, selector: str | None, site_host: str
) -> StateSnapshot:
    """Open a fresh context, optionally click a selector, return snapshot.

    Records whether the click actually matched an element (button_clicked); this is the
    [R4] signal that the reject mechanism is reachable as configured.
    """
    click_result: dict[str, bool] = {"clicked": False}

    async def cb(page):  # type: ignore[no-untyped-def]
        if selector:
            click_result["clicked"] = await click_if_present(
                page, selector, settle_seconds=cfg.settle_seconds
            )
        else:
            await asyncio.sleep(cfg.settle_seconds)
        return await capture_state(page)

    raw = await with_fresh_context(callback=cb, url=cfg.url)
    state = "noaction" if selector is None else (
        "accept" if selector == cfg.accept_selector else "reject"
    )
    button_clicked = None if selector is None else click_result["clicked"]
    return StateSnapshot.from_raw(state, raw, site_host=site_host, button_clicked=button_clicked)


async def run_three_state_audit(cfg: SiteConfig) -> SiteAudit:
    site_host = urlparse(cfg.url).hostname or ""
    noaction = await _capture_with_button(cfg, selector=None, site_host=site_host)
    accept = await _capture_with_button(cfg, selector=cfg.accept_selector, site_host=site_host)
    reject = await _capture_with_button(cfg, selector=cfg.reject_selector, site_host=site_host)

    audit = SiteAudit(
        site=site_host, url=cfg.url,
        noaction=noaction, accept=accept, reject=reject,
    )
    audit.analyse()
    return audit


# ---------- Fingerprint persistence test ----------

async def run_fingerprint_persistence_test(
    url: str,
    identity_cookies: list[str],
    *,
    contexts: int = 3,
    pre_click_selector: str | None = None,
) -> FingerprintAudit:
    """
    Open N fully isolated browser contexts, optionally click a reject button,
    capture identity cookie values, and report whether any persistent identifier
    repeats across contexts (only possible via server-side fingerprinting).
    """
    cookies_per_context: list[dict[str, str]] = []

    for _ in range(contexts):
        async def cb(page):  # type: ignore[no-untyped-def]
            if pre_click_selector:
                await click_if_present(page, pre_click_selector)
            else:
                await asyncio.sleep(4.0)
            return await capture_state(page)

        raw = await with_fresh_context(callback=cb, url=url)
        cookies_per_context.append(raw["cookies"])

    findings: list[FingerprintFinding] = []
    raw_values: list[str] = []
    for cookie_name in identity_cookies:
        values = [cs.get(cookie_name, "") for cs in cookies_per_context]
        raw_values.extend(values)

        persistent_ids: list[str] = []
        confidences: list[float | None] = []
        for v in values:
            if cookie_name == "device_id":
                p = parse_device_id_cookie(v) if v else None
                persistent_ids.append(p.persistent_id or "" if p else "")
                confidences.append(p.confidence_score if p else None)
            elif cookie_name == "_ga" or cookie_name.startswith("_ga_"):
                p = parse_ga4(cookie_name, v) if v else None
                persistent_ids.append(p.persistent_id or "" if p else "")
                confidences.append(None)
            else:
                persistent_ids.append(v)
                confidences.append(None)

        unique_ids = {pid for pid in persistent_ids if pid}
        is_persistent = len(unique_ids) == 1 and len(persistent_ids) > 1 and all(persistent_ids)

        findings.append(FingerprintFinding(
            cookie=cookie_name,
            persistent_ids=persistent_ids,
            confidence_scores=confidences,
            is_persistent_across_contexts=is_persistent,
        ))

    return FingerprintAudit(
        url=url, contexts=contexts, raw_values=raw_values, findings=findings,
    )


__all__ = [
    "SiteConfig",
    "StateSnapshot",
    "SiteAudit",
    "FingerprintFinding",
    "FingerprintAudit",
    "run_three_state_audit",
    "run_fingerprint_persistence_test",
    "parse_consentmgr",
]
