"""Playwright helpers for capturing browser state under different consent flows."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, async_playwright

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
    el = await page.query_selector(selector)
    if not el:
        return False
    await el.click()
    await asyncio.sleep(settle_seconds)
    return True


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
