"""Playwright helpers for capturing browser state under different consent flows."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, async_playwright

if TYPE_CHECKING:
    from .detect import Detection

STATE_CAPTURE_JS = """
() => {
  const ls = {};
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    ls[k] = (localStorage.getItem(k) || '').length;
  }
  const ss = {};
  for (let i = 0; i < sessionStorage.length; i++) {
    const k = sessionStorage.key(i);
    ss[k] = (sessionStorage.getItem(k) || '').length;
  }
  const hosts = Array.from(new Set(
    performance.getEntriesByType('resource')
      .map(e => { try { return new URL(e.name).host; } catch { return null; } })
      .filter(Boolean)
  )).sort();
  return {
    url: location.href,
    localStorage_lengths: ls,
    sessionStorage_lengths: ss,
    unique_hosts: hosts,
  };
}
"""


async def capture_state(page: Page) -> dict[str, Any]:
    """Capture browser state. Cookies come from Playwright's context.cookies() so we get
    domain, expires, httpOnly, secure, sameSite — required for ICO PECR Reg 6 classification
    (session vs persistent, first vs third party). document.cookie omits HttpOnly cookies and
    exposes only the JS-accessible key=value view, which is insufficient for compliance work.
    """
    raw: dict[str, Any] = await page.evaluate(STATE_CAPTURE_JS)
    raw["host"] = urlparse(raw["url"]).hostname or ""
    pw_cookies = await page.context.cookies()
    raw["cookie_records"] = pw_cookies
    raw["cookies"] = {c["name"]: c["value"] for c in pw_cookies}
    return raw


async def click_if_present(page: Page, selector: str, settle_seconds: float = 4.0) -> bool:
    """Click the consent button if a clickable match exists; return whether it was clicked.

    Robust by design: a detected selector can match a hidden duplicate (banners often ship
    a template copy) or an element Playwright deems not-yet-visible. We pick the first
    *visible* match, bound the click so a stuck element fails in seconds rather than the
    30s default, and swallow click failures into a False return — an unbounded raising
    click would crash a single audit and abort an entire batch scan on one bad site.
    """
    loc = page.locator(selector)
    try:
        n = await loc.count()
    except Exception:
        return False
    if n == 0:
        return False
    target = loc.first
    for i in range(min(n, 10)):
        cand = loc.nth(i)
        try:
            if await cand.is_visible():
                target = cand
                break
        except Exception:
            continue
    with contextlib.suppress(Exception):
        await target.scroll_into_view_if_needed(timeout=2_000)
    try:
        await target.click(timeout=6_000)
    except Exception:
        return False
    await asyncio.sleep(settle_seconds)
    return True


async def detect_for_url(url: str, *, settle_seconds: float = 4.0) -> Detection:
    """Open one fresh context, let the banner render, and return a Detection.

    Separate from with_fresh_context's dict contract because detection returns a
    dataclass, not a state dict. The detected selectors are stable strings reused across
    the three independent audit contexts that follow.
    """
    from .detect import Provenance, detect_consent  # local import avoids a browser<->detect cycle

    def _weak(d: Detection) -> bool:
        # Worth a retry: nothing found at all, or a consent control but no readable reject.
        return d.accept_selector is None or (
            d.cmp is None and d.reject_selector is None
        )

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(locale="en-GB", timezone_id="Europe/London")
        page = await context.new_page()
        try:
            await page.goto(url, timeout=30_000, wait_until="networkidle")
        except Exception:
            await page.goto(url, timeout=30_000, wait_until="domcontentloaded")
        await asyncio.sleep(settle_seconds)
        detection = await detect_consent(page)
        # Some CMPs (notably OneTrust) inject the banner a beat after the page settles;
        # a first snapshot can miss it. Retry once after a short wait and keep the stronger
        # result so a lazy banner is not mis-reported as "no reject offered".
        if _weak(detection):
            await asyncio.sleep(3.0)
            retry = await detect_consent(page)
            if not _weak(retry) or (
                retry.reject_provenance == Provenance.CMP_SIGNATURE
                and detection.reject_provenance != Provenance.CMP_SIGNATURE
            ):
                detection = retry
        await context.close()
        await browser.close()
        return detection


async def await_device_identity(page: Page, cookie_names: list[str], *, max_wait: float = 8.0) -> None:
    """Poll until a tracked device-id-shaped cookie carries its inner ':id=<persistent>'
    component, or max_wait elapses.

    Server-side identity is written asynchronously: vendors set a plain session id on load
    and *upgrade* it to the fingerprint-matched value a few seconds later, once the matching
    service responds. Capturing on a fixed short settle races that upgrade and produces a
    false negative — the cookie looks like a rotating session id and the fingerprint is
    missed. Waiting for the persistent shape to appear closes that race; if it never appears
    (genuinely no match), we wait the cap and capture the honest negative.
    """
    waited = 0.0
    step = 1.0
    while waited < max_wait:
        cookies = {c["name"]: c["value"] for c in await page.context.cookies()}
        if any(":id=" in cookies.get(n, "") for n in cookie_names):
            return
        await asyncio.sleep(step)
        waited += step


async def with_fresh_context(
    *,
    headless: bool = True,
    user_agent: str | None = None,
    locale: str = "en-GB",
    timezone: str = "Europe/London",
    callback: Callable[[Page], Awaitable[dict[str, Any]]],
    url: str,
    nav_timeout_ms: int = 30_000,
) -> dict[str, Any]:
    """Open a fully isolated browser context, navigate, run callback, close. Returns callback result."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        ctx_args: dict[str, Any] = {"locale": locale, "timezone_id": timezone}
        if user_agent:
            ctx_args["user_agent"] = user_agent
        context: BrowserContext = await browser.new_context(**ctx_args)
        page = await context.new_page()
        try:
            await page.goto(url, timeout=nav_timeout_ms, wait_until="networkidle")
        except Exception:
            # Some sites never reach networkidle thanks to long-poll trackers; fall back
            await page.goto(url, timeout=nav_timeout_ms, wait_until="domcontentloaded")
        result = await callback(page)
        await context.close()
        await browser.close()
        return result
