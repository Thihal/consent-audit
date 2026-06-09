"""Unit tests for consent-button auto-detection scoring.

The live browser paths (CMP signatures, generic enumeration) are exercised manually
against real sites; these tests pin the pure label-matching logic, whose failure mode is
the one that destroys credibility — a footer "Cookie policy" link mis-detected as Accept
because "ok" is a substring of "cookie".
"""

from __future__ import annotations

from consent_audit.detect import ACCEPT_TEXTS, REJECT_TEXTS, _best_match, _score


def test_word_boundary_blocks_substring_false_positive():
    # "ok" is in ACCEPT_TEXTS and is a substring of "cookie" — must NOT match.
    assert _score("Cookie policy", "ok") == 0
    assert _score("Manage cookie settings", "ok") == 0


def test_exact_label_outscores_contained_phrase():
    assert _score("Accept all", "accept all") > _score("Accept all cookies", "accept all")


def test_longer_phrase_scores_higher():
    # A button reading "Reject all cookies" should prefer the specific phrase.
    specific = _score("Reject all cookies", "reject all cookies")
    generic = _score("Reject all cookies", "reject")
    assert specific > generic > 0


def test_best_match_prefers_visible_at_equal_text_score():
    candidates = [
        {"label": "Accept all", "selector": "#hidden", "visible": False},
        {"label": "Accept all", "selector": "#visible", "visible": True},
    ]
    assert _best_match(candidates, ACCEPT_TEXTS) == "#visible"


def test_best_match_ignores_cookie_policy_link():
    # The comparethemarket failure: only a policy link present -> no accept match.
    candidates = [{"label": "Cookie policy", "selector": 'a:has-text("Cookie policy")', "visible": True}]
    assert _best_match(candidates, ACCEPT_TEXTS) is None


def test_essential_only_matches_reject_vocabulary():
    candidates = [{"label": "Essential only", "selector": "#button-essential-only", "visible": True}]
    assert _best_match(candidates, REJECT_TEXTS) == "#button-essential-only"


def test_manage_preferences_is_not_a_reject():
    # Multi-layer entry points must not be treated as one-click reject.
    candidates = [{"label": "Manage preferences", "selector": "#manage", "visible": True}]
    assert _best_match(candidates, REJECT_TEXTS) is None
