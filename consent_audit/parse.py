"""Parsers for known identity-cookie formats and tracker host classification."""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityField:
    name: str
    value: str
    parsed: dict[str, str | float | None]
    persistent_id: str | None
    confidence_score: float | None


def parse_device_id_cookie(value: str) -> IdentityField:
    """
    Server-side device-id cookie (generic vendor format):
        refresh=<ms>&id=<session_uuid>:id=<persistent_id>&cacheExpiry=<s>&requestId=<...>&confidenceScore=<n>

    The persistent_id after the inner ':id=' is the fingerprint-matched identifier
    that survives across isolated browser contexts. confidenceScore is the server's
    self-reported fingerprint match confidence.
    """
    parsed: dict[str, str | float | None] = {}
    persistent_id: str | None = None
    confidence: float | None = None

    inner = re.search(r":id=([A-Za-z0-9]+)", value)
    if inner:
        persistent_id = inner.group(1)

    for part in value.split("&"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k == "confidenceScore":
            with contextlib.suppress(ValueError):
                confidence = float(v)
            parsed[k] = confidence
        else:
            parsed[k] = v

    return IdentityField(
        name="device_id",
        value=value,
        parsed=parsed,
        persistent_id=persistent_id,
        confidence_score=confidence,
    )


def parse_ga4(name: str, value: str) -> IdentityField:
    """
    GA4 cookies:
      _ga          → GA1.1.<cid>.<ts>      where <cid> is the client ID
      _ga_<MID>    → GS2.1.s<sid>.<...>    session state for property MID
    """
    persistent_id: str | None = None
    parsed: dict[str, str | float | None] = {}

    if name == "_ga":
        m = re.match(r"GA\d+\.\d+\.(\d+)\.(\d+)", value)
        if m:
            persistent_id = m.group(1)
            parsed["client_id"] = m.group(1)
            parsed["first_seen_ts"] = m.group(2)
    elif name.startswith("_ga_"):
        parsed["property_id"] = name.removeprefix("_ga_")
        m = re.search(r"s(\d+)", value)
        if m:
            parsed["session_start_ts"] = m.group(1)

    return IdentityField(
        name=name,
        value=value,
        parsed=parsed,
        persistent_id=persistent_id,
        confidence_score=None,
    )


def parse_consentmgr(value: str) -> dict[str, bool | int]:
    """Tealium ConsentMgr: c1:1%7Cc2:0%7Cc3:0%7Cc4:0%7Cc5:0%7Cts:...%7Cconsent:true"""
    out: dict[str, bool | int] = {}
    for chunk in value.replace("%7C", "|").split("|"):
        if ":" not in chunk:
            continue
        k, v = chunk.split(":", 1)
        if k.startswith("c") and v in ("0", "1"):
            out[k] = v == "1"
        elif k == "consent":
            out[k] = v.lower() == "true"
        elif k == "ts":
            with contextlib.suppress(ValueError):
                out[k] = int(v)
    return out


# Known tracker categorisation. Keys are host suffixes (right-anchored).
KNOWN_TRACKERS: dict[str, tuple[str, str]] = {
    # (category, vendor)
    "google-analytics.com": ("analytics", "Google Analytics"),
    "googletagmanager.com": ("tag-manager", "Google Tag Manager"),
    "doubleclick.net": ("advertising", "Google Ads / DoubleClick"),
    "googlesyndication.com": ("advertising", "Google Ads"),
    "google.com": ("advertising-or-search", "Google"),
    "facebook.net": ("advertising", "Meta / Facebook Pixel"),
    "facebook.com": ("advertising", "Meta / Facebook Pixel"),
    "bat.bing.com": ("advertising", "Microsoft Bing UET"),
    "bat.bing.net": ("advertising", "Microsoft Bing UET"),
    "clarity.ms": ("session-replay", "Microsoft Clarity"),
    "fullstory.com": ("session-replay", "FullStory"),
    "quantummetric.com": ("session-replay", "Quantum Metric"),
    "optimizely.com": ("experimentation", "Optimizely"),
    "split.io": ("experimentation", "Split.io"),
    "dynatrace.com": ("rum", "Dynatrace RUM"),
    "px-cloud.net": ("bot-management", "HUMAN / PerimeterX"),
    "cloudflareinsights.com": ("rum", "Cloudflare Web Analytics"),
    "adalyser.com": ("attribution", "Adalyser"),
    "amazon-adsystem.com": ("advertising", "Amazon Ads"),
    "tiqcdn.com": ("tag-manager", "Tealium IQ"),
    "celebrus.com": ("behavioral-analytics", "Celebrus / D4t4"),
    "segment.com": ("customer-analytics", "Segment"),
    "segment.io": ("customer-analytics", "Segment"),
    "trustpilot.com": ("widget", "Trustpilot"),
    "sentry.io": ("error-tracking", "Sentry"),
    "builder.io": ("cms", "Builder.io"),
}


def classify_host(host: str) -> tuple[str, str] | None:
    """Return (category, vendor) for a known tracker host, or None."""
    h = host.lower()
    for suffix, label in KNOWN_TRACKERS.items():
        if h == suffix or h.endswith("." + suffix):
            return label
    return None


# Multi-segment public suffixes relevant to the UK / sites this tool typically targets.
# Not a full Public Suffix List — sufficient for first-vs-third-party classification of
# .co.uk-family domains without pulling in a heavyweight dependency.
_MULTI_SEGMENT_SUFFIXES = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ac.jp", "go.jp",
    "co.za", "org.za", "gov.za",
    "com.br", "com.mx", "com.sg",
}


def registrable_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) for the given host.

    Uses a small hard-coded multi-segment suffix list to handle .co.uk-family TLDs
    correctly. Hosts already at or below the registrable level are returned unchanged.
    """
    h = host.lstrip(".").lower()
    parts = h.split(".")
    if len(parts) < 2:
        return h
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SEGMENT_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_first_party_cookie(cookie_domain: str, site_host: str) -> bool:
    """Cookie is first-party if its domain shares an eTLD+1 with the site host."""
    if not cookie_domain or not site_host:
        return False
    return registrable_domain(cookie_domain) == registrable_domain(site_host)


# Cookie-name patterns that are non-essential under PECR Reg 6. Exact-match names plus
# prefix patterns (with trailing `*` meaning startswith).
NON_ESSENTIAL_COOKIE_PATTERNS: set[str] = {
    # Google Analytics / Ads
    "_ga", "_gid", "_gat", "_ga_*", "_gat_*",
    "_gcl_au", "_gcl_aw", "_gcl_dc", "_gcl_gb", "_gcl_gf", "_gcl_ha",
    # Meta / Facebook
    "_fbp", "_fbc",
    # Microsoft Bing / Clarity
    "_uetsid", "_uetvid", "_uetmsclkid", "MUID",
    "_clck", "_clsk", "CLID", "ANONCHK", "SM",
    # Session-replay vendors
    "fs_lua", "fs_uid", "fs_session",
    "_hjSession", "_hjSession_*", "_hjSessionUser", "_hjSessionUser_*",
    "_hjid", "_hjFirstSeen", "_hjAbsoluteSessionInProgress",
    # Attribution / adtech
    "__adal_id", "__adal_ses", "__adal_ca", "__adal_cw",
    "_pin_unauth", "_ttp",
    "IDE", "NID", "DSID", "FLC", "AID", "TAID",
    # Customer analytics / CDP
    "ajs_anonymous_id", "ajs_user_id",
    "mp_*", "amp_*",
    # Server-side device identity
    "device_id",
    # Visitor IDs / experiment tooling
    "_vid_t", "_vis_opt_s", "_vis_opt_test_cookie",
    "optimizelyEndUserId", "optimizelyBuckets",
    # LinkedIn / X / Pinterest / TikTok
    "li_sugr", "bcookie", "bscookie", "UserMatchHistory", "lidc",
    "personalization_id", "guest_id",
}


def _matches_pattern(name: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


# Narrow allow-list of cookies whose purpose maps directly onto the Reg 6 exemptions the
# ICO names: communication-transmission, strictly-necessary security for a user-requested
# service, and load-balancing. The (pattern, category, vendor) triple lets the report cite
# *which* ICO exemption a given cookie relies on. Tracker / analytics / ads / fingerprint
# cookies are deliberately excluded — those never qualify regardless of vendor framing.
ESSENTIAL_COOKIE_PATTERNS: list[tuple[str, str, str]] = [
    # Cloudflare bot management / DDoS protection — security exemption.
    ("__cf_bm", "security", "Cloudflare bot management"),
    ("_cfuvid", "security", "Cloudflare bot management"),
    ("cf_clearance", "security", "Cloudflare challenge clearance"),
    # AWS Application Load Balancer — load-balancing exemption.
    ("AWSALB", "load-balancing", "AWS ALB stickiness"),
    ("AWSALBCORS", "load-balancing", "AWS ALB stickiness (CORS)"),
    # Azure App Service / Application Request Routing — load-balancing exemption.
    ("ARRAffinity", "load-balancing", "Azure ARR affinity"),
    ("ARRAffinitySameSite", "load-balancing", "Azure ARR affinity"),
    # Akamai bot manager / Imperva — security exemption.
    ("_abck", "security", "Akamai bot manager"),
    ("bm_sz", "security", "Akamai bot manager"),
    ("ak_bmsc", "security", "Akamai bot manager"),
    ("bm_sv", "security", "Akamai bot manager"),
    ("incap_ses_*", "security", "Imperva session"),
    ("visid_incap_*", "security", "Imperva session"),
    # CSRF tokens — security exemption.
    ("XSRF-TOKEN", "security", "CSRF token"),
    ("csrf_token", "security", "CSRF token"),
    ("csrftoken", "security", "CSRF token"),
    # Generic app-server session cookies — user-requested service exemption.
    ("JSESSIONID", "session", "Java app server session"),
    ("PHPSESSID", "session", "PHP session"),
    ("ASP.NET_SessionId", "session", "ASP.NET session"),
]


def classify_cookie(
    name: str, cookie_domain: str, site_host: str
) -> tuple[str, str]:
    """Classify a cookie against ICO PECR Reg 6 categories.

    Returns (classification, reason) where classification is:
      - "essential": the cookie matches a narrow allow-list of cookies whose purpose
        falls directly under a Reg 6(4) exemption the ICO explicitly names
        (load-balancing, strictly-necessary security, transmission). The reason cites
        the exemption category and the vendor.
      - "non-essential": the cookie clearly requires consent under PECR. It is either
        set by a known tracker host, masked as first-party but vendor-linked, set on a
        third-party domain, or matches a well-known analytics/ads/replay name pattern.
      - "unknown": a first-party cookie whose purpose cannot be inferred from name or
        domain. Per the ICO checklist the site is responsible for justifying these as
        "strictly necessary" or seeking consent.

    The allow-list is deliberately narrow — only cookies whose purpose is universally
    recognised by privacy regulators map to "essential". Anything contested
    (e.g. PerimeterX, marketing-attached "session" cookies) remains "unknown".
    """
    domain_clean = cookie_domain.lstrip(".")

    for pat, category, vendor in ESSENTIAL_COOKIE_PATTERNS:
        if _matches_pattern(name, pat):
            return ("essential", f"{category} ({vendor}) — Reg 6(4) exemption")

    tracker = classify_host(domain_clean)
    if tracker:
        return ("non-essential", f"set by known tracker host: {tracker[1]} ({tracker[0]})")

    if is_first_party_masked(domain_clean, site_host):
        return ("non-essential", f"first-party-masked subdomain: {cookie_domain}")

    for pat in NON_ESSENTIAL_COOKIE_PATTERNS:
        if _matches_pattern(name, pat):
            return ("non-essential", f"matches non-essential cookie pattern: {pat}")

    if not is_first_party_cookie(cookie_domain, site_host):
        return ("non-essential", f"third-party cookie domain: {cookie_domain}")

    return ("unknown", "first-party cookie of unstated purpose")


# Tokens that suggest a storage/cookie key is an identifier. Matched against the tokens
# extracted from a key by tokenize_key — substring matching would over-trigger on
# benign keys like "video" or "valid_until".
ID_KEYWORD_TOKENS: set[str] = {
    "id", "uid", "guid", "uuid",
    "anon", "device", "fp", "fingerprint",
    "visitor", "client", "session", "sid",
}


_TOKEN_SEPARATOR_RE = re.compile(r"[_\-.\s]+")
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z])([A-Z])")


def tokenize_key(key: str) -> set[str]:
    """Split a storage / cookie key into lowercase tokens at common separators.

    Splits on `_`, `-`, `.`, whitespace, and at lowercase→uppercase transitions.
    Used for word-boundary matching of identifier keywords so that `video` does not
    match `id` and `valid_until` does not match `id`.
    """
    spaced = _TOKEN_SEPARATOR_RE.sub(" ", key)
    spaced = _CAMEL_BOUNDARY_RE.sub(r"\1 \2", spaced)
    return {t.lower() for t in spaced.split() if t}


def looks_identifier_like(key: str) -> bool:
    """True if any token in the key matches an identifier keyword."""
    return bool(tokenize_key(key) & ID_KEYWORD_TOKENS)


def cookie_lifetime_days(expires: float) -> float | None:
    """Convert a Playwright cookie `expires` field (unix seconds, -1 for session) to days.

    Session cookies return None. Persistent cookies return the remaining lifetime from
    capture time; sites set these as absolute expiry, so this is a snapshot.
    """
    if expires is None or expires < 0:
        return None
    import time
    return max(0.0, (expires - time.time()) / 86400)


def is_first_party_masked(host: str, site_host: str) -> bool:
    """
    Detect subdomain disguises of third-party trackers as first-party.

    e.g. sst.example.com (GTM Server-Side), id.example.com (identity proxy),
    analytics.example.com (behavioural analytics).
    """
    base = site_host.removeprefix("www.")
    if not (host == base or host.endswith("." + base)):
        return False
    label = host.removesuffix("." + base)
    if label == base:
        return False
    suspicious_prefixes = {
        "sst", "stape", "cs",                          # GTM SS
        "fusion-id", "fusion-events", "id",            # identity proxies
        "celebrus", "chronicle", "events", "telemetry",
        "analytics", "metric", "stats",
    }
    return label in suspicious_prefixes or any(label.startswith(p + "-") for p in suspicious_prefixes)
