"""Unit tests for parsers, with fixtures from real captured data."""

from __future__ import annotations

import json
from pathlib import Path

from consent_audit.parse import (
    KNOWN_TRACKERS,
    classify_cookie,
    classify_host,
    is_first_party_cookie,
    is_first_party_masked,
    looks_identifier_like,
    parse_consentmgr,
    parse_device_id_cookie,
    parse_ga4,
    registrable_domain,
    tokenize_key,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_device_persistent_id_is_byte_identical_across_three_contexts() -> None:
    """The core signal: persistent_id repeats across fully isolated contexts."""
    data = json.loads((FIXTURES / "device_id_evidence.json").read_text())
    parsed = [parse_device_id_cookie(c["cookie_value"]) for c in data["captures"]]

    persistent_ids = {p.persistent_id for p in parsed}
    assert len(persistent_ids) == 1, (
        f"Expected one persistent_id across 3 contexts, got {persistent_ids}"
    )
    assert "Zx7Qp2Lm9Kd4Rt1Vb8N" in persistent_ids


def test_device_confidence_score_extracted() -> None:
    data = json.loads((FIXTURES / "device_id_evidence.json").read_text())
    for capture in data["captures"]:
        parsed = parse_device_id_cookie(capture["cookie_value"])
        assert parsed.confidence_score == capture["expected_confidence"]


def test_device_session_id_differs_per_context() -> None:
    """The outer session UUID rotates per visit — only the inner persistent_id stays the same."""
    data = json.loads((FIXTURES / "device_id_evidence.json").read_text())
    session_ids = {parse_device_id_cookie(c["cookie_value"]).parsed.get("id") for c in data["captures"]}
    assert len(session_ids) == 3, "Session UUID should differ per context"


def test_parse_ga4_client_id() -> None:
    parsed = parse_ga4("_ga", "GA1.1.853868626.1779288170")
    assert parsed.persistent_id == "853868626"
    assert parsed.parsed["first_seen_ts"] == "1779288170"


def test_parse_ga4_session_property() -> None:
    parsed = parse_ga4("_ga_RTPL2GQWBY", "GS2.1.s1779288169$o1$g0$t1779288170$j59$l0$h0")
    assert parsed.parsed["property_id"] == "RTPL2GQWBY"
    assert parsed.parsed["session_start_ts"] == "1779288169"


def test_parse_consentmgr_essential_only() -> None:
    parsed = parse_consentmgr("c1:1%7Cc2:0%7Cc3:0%7Cc4:0%7Cc5:0%7Cts:1779291208628%7Cconsent:true")
    assert parsed == {"c1": True, "c2": False, "c3": False, "c4": False, "c5": False,
                      "ts": 1779291208628, "consent": True}


def test_known_trackers_classify() -> None:
    assert classify_host("region1.google-analytics.com") == KNOWN_TRACKERS["google-analytics.com"]
    assert classify_host("www.googletagmanager.com") == KNOWN_TRACKERS["googletagmanager.com"]
    assert classify_host("connect.facebook.net") == KNOWN_TRACKERS["facebook.net"]
    assert classify_host("cdn.segment.com") == KNOWN_TRACKERS["segment.com"]
    assert classify_host("not-a-tracker.example.com") is None


def test_registrable_domain_handles_co_uk() -> None:
    """eTLD+1 must handle .co.uk-family TLDs correctly — common for UK sites."""
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("id.example.co.uk") == "example.co.uk"
    assert registrable_domain(".example.com") == "example.com"
    assert registrable_domain("sub.example.co.jp") == "example.co.jp"
    assert registrable_domain("example.com") == "example.com"


def test_is_first_party_cookie() -> None:
    assert is_first_party_cookie(".example.com", "www.example.com")
    assert is_first_party_cookie("api.example.com", "www.example.com")
    assert not is_first_party_cookie("doubleclick.net", "www.example.com")
    # Cross-brand: a vendor's own eTLD+1 cookie on a different site is third-party.
    assert not is_first_party_cookie(".vendor.co.uk", "www.example.com")


def test_classify_cookie_known_tracker_domain() -> None:
    classification, reason = classify_cookie("_ga", ".google-analytics.com", "www.example.com")
    assert classification == "non-essential"
    assert "Google Analytics" in reason


def test_classify_cookie_first_party_masked() -> None:
    classification, reason = classify_cookie(
        "device_id", "id.example.com", "www.example.com"
    )
    assert classification == "non-essential"
    assert "first-party-masked" in reason


def test_classify_cookie_known_name_pattern() -> None:
    classification, _ = classify_cookie("_ga_RTPL2GQWBY", ".example.com", "www.example.com")
    assert classification == "non-essential"
    classification, _ = classify_cookie("_fbp", ".example.com", "www.example.com")
    assert classification == "non-essential"


def test_classify_cookie_third_party_domain() -> None:
    classification, reason = classify_cookie("opaque_id", "tracker.com", "www.example.com")
    assert classification == "non-essential"
    assert "third-party" in reason


def test_classify_cookie_unknown_first_party() -> None:
    """A plausibly-essential first-party cookie is classified 'unknown' — only the site
    can declare it strictly necessary unless it matches the narrow allow-list."""
    classification, _ = classify_cookie("session_token", ".example.com", "www.example.com")
    assert classification == "unknown"


def test_classify_cookie_essential_cloudflare() -> None:
    """Cloudflare's __cf_bm is universally recognised security infrastructure under
    the ICO Reg 6(4) security exemption."""
    classification, reason = classify_cookie("__cf_bm", ".example.com", "www.example.com")
    assert classification == "essential"
    assert "Cloudflare" in reason
    assert "Reg 6(4)" in reason


def test_classify_cookie_essential_load_balancer() -> None:
    """Azure ARRAffinity falls under the load-balancing exemption named by the ICO."""
    classification, reason = classify_cookie(
        "ARRAffinity", ".example.com", "www.example.com"
    )
    assert classification == "essential"
    assert "load-balancing" in reason


def test_classify_cookie_essential_takes_precedence_over_third_party() -> None:
    """A Cloudflare cookie on a third-party domain (CF as CDN) is still essential —
    the allow-list must be checked before the third-party-domain rule."""
    classification, _ = classify_cookie("__cf_bm", "cf-edge.cdn.net", "www.example.com")
    assert classification == "essential"


def test_tokenize_key_snake_camel_kebab() -> None:
    assert tokenize_key("client_uid") == {"client", "uid"}
    assert tokenize_key("clientUid") == {"client", "uid"}
    assert tokenize_key("client-uid") == {"client", "uid"}
    assert tokenize_key("device.id") == {"device", "id"}
    assert tokenize_key("pxsid") == {"pxsid"}


def test_looks_identifier_like_avoids_false_positives() -> None:
    """The whole point of tokenisation: bare `id` substring must not match `valid_until`
    or `video_meta`. Identifier-like tokens at proper boundaries must still match."""
    # True positives: identifier tokens at word boundaries.
    assert looks_identifier_like("client_uid")
    assert looks_identifier_like("clientUid")
    assert looks_identifier_like("device_id")
    assert looks_identifier_like("anon_user")
    assert looks_identifier_like("visitor.guid")
    # False positives that the old substring matcher would have flagged.
    assert not looks_identifier_like("video_meta")
    assert not looks_identifier_like("valid_until")
    assert not looks_identifier_like("considered")
    assert not looks_identifier_like("solid")


def test_first_party_masking_detection() -> None:
    # An `sst` subdomain is GTM Server-Side disguised as first-party
    assert is_first_party_masked("sst.example.com", "www.example.com")
    assert is_first_party_masked("fusion-id.example.com", "www.example.com")
    assert is_first_party_masked("fusion-events.example.com", "www.example.com")
    assert is_first_party_masked("celebrus.example.com", "www.example.com")
    # Normal first-party paths are not masking
    assert not is_first_party_masked("www.example.com", "www.example.com")
    assert not is_first_party_masked("static.example.com", "www.example.com")
