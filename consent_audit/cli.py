"""CLI entry point."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console

from .audit import SiteConfig, run_fingerprint_persistence_test, run_three_state_audit
from .report import audit_to_json, audit_to_markdown, fingerprint_to_json, fingerprint_to_markdown

console = Console()


@click.group()
def main() -> None:
    """Audit web consent banners and detect fingerprint-based re-identification."""


@main.command()
@click.argument("site_config", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out-dir", default="reports", type=click.Path(file_okay=False, path_type=Path))
def audit(site_config: Path, out_dir: Path) -> None:
    """Run the three-state (noaction / accept / reject) audit on one site."""
    cfg = SiteConfig.load(site_config)
    console.log(f"Auditing {cfg.url}")
    result = asyncio.run(run_three_state_audit(cfg))

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = site_config.stem
    (out_dir / f"{stem}.json").write_text(audit_to_json(result))
    (out_dir / f"{stem}.md").write_text(audit_to_markdown(result))
    console.print(f"[green]Wrote {out_dir}/{stem}.json and {stem}.md[/green]")
    for finding in result.findings:
        console.print(f"  · {finding}")


@main.command()
@click.argument("url")
@click.option("--cookie", "-c", "identity_cookies", multiple=True, required=True,
              help="Identity cookie name to track; pass multiple times")
@click.option("--contexts", default=3, show_default=True, type=int)
@click.option("--pre-click", default=None, help="CSS selector to click after navigation (e.g. reject button)")
@click.option("--out-dir", default="reports", type=click.Path(file_okay=False, path_type=Path))
def fingerprint(
    url: str,
    identity_cookies: tuple[str, ...],
    contexts: int,
    pre_click: str | None,
    out_dir: Path,
) -> None:
    """
    Open N isolated browser contexts on URL, capture identity cookies,
    and detect server-side fingerprinting based on cross-context ID persistence.
    """
    console.log(f"Fingerprint test: {url} × {contexts} contexts; tracking {list(identity_cookies)}")
    result = asyncio.run(run_fingerprint_persistence_test(
        url, list(identity_cookies), contexts=contexts, pre_click_selector=pre_click,
    ))

    out_dir.mkdir(parents=True, exist_ok=True)
    host = url.split("//", 1)[-1].split("/", 1)[0]
    (out_dir / f"{host}.fingerprint.json").write_text(fingerprint_to_json(result))
    (out_dir / f"{host}.fingerprint.md").write_text(fingerprint_to_markdown(result))
    console.print(f"[green]Wrote {out_dir}/{host}.fingerprint.{'json,md'}[/green]")
    for f in result.findings:
        if f.is_persistent_across_contexts:
            console.print(f"  [red]{f.cookie}[/red] → persistent across {contexts} contexts")
        else:
            console.print(f"  [dim]{f.cookie}[/dim] → not persistent (good)")


if __name__ == "__main__":
    main()
