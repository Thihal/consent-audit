"""CLI entry point."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console

from .audit import (
    SiteConfig,
    audit_url,
    fingerprint_url,
    run_fingerprint_persistence_test,
    run_three_state_audit,
)
from .report import (
    audit_to_json,
    audit_to_markdown,
    fingerprint_to_json,
    fingerprint_to_markdown,
    scan_summary_to_json,
    scan_summary_to_markdown,
)

console = Console()


def _stem_for(target: str) -> str:
    """Report filename stem: hostname for a URL, file stem for a YAML path."""
    if target.startswith(("http://", "https://")):
        return target.split("//", 1)[-1].split("/", 1)[0]
    return Path(target).stem


@click.group()
def main() -> None:
    """Audit web consent banners and detect fingerprint-based re-identification."""


@main.command()
@click.argument("target")
@click.option("--out-dir", default="reports", type=click.Path(file_okay=False, path_type=Path))
@click.option("--settle", default=4.0, show_default=True, type=float,
              help="Seconds to wait for the banner / trackers to render before capture")
def audit(target: str, out_dir: Path, settle: float) -> None:
    """Run the three-state (noaction / accept / reject) audit on one site.

    TARGET may be a URL (https://example.com) — consent buttons are auto-detected — or a
    path to a hand-written site YAML for banners auto-detection cannot reach (iframe /
    multi-layer reject).
    """
    if target.startswith(("http://", "https://")):
        console.log(f"Auditing {target} (auto-detecting consent buttons)")
        result = asyncio.run(audit_url(target, settle_seconds=settle))
        if result.detection and result.detection.cmp:
            console.log(f"Detected CMP: {result.detection.cmp}")
    else:
        cfg = SiteConfig.load(Path(target))
        console.log(f"Auditing {cfg.url} (manual config)")
        result = asyncio.run(run_three_state_audit(cfg))

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = _stem_for(target)
    (out_dir / f"{stem}.json").write_text(audit_to_json(result))
    (out_dir / f"{stem}.md").write_text(audit_to_markdown(result))
    console.print(f"[green]Wrote {out_dir}/{stem}.json and {stem}.md[/green]")
    for finding in result.findings:
        console.print(f"  · {finding}")


@main.command()
@click.argument("targets", nargs=-1)
@click.option("--from-file", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Read URLs (one per line, # comments ok) instead of / in addition to args")
@click.option("--out-dir", default="reports", type=click.Path(file_okay=False, path_type=Path))
@click.option("--settle", default=4.0, show_default=True, type=float)
def scan(targets: tuple[str, ...], from_file: Path | None, out_dir: Path, settle: float) -> None:
    """Batch-audit many URLs with auto-detection; write per-site reports plus a summary.

    consent-audit scan https://a.com https://b.com
    consent-audit scan --from-file sites.txt
    """
    urls = list(targets)
    if from_file:
        urls += [
            ln.strip() for ln in from_file.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    if not urls:
        raise click.UsageError("Pass at least one URL or --from-file.")

    out_dir.mkdir(parents=True, exist_ok=True)
    audits = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        console.log(f"Scanning {url}")
        try:
            result = asyncio.run(audit_url(url, settle_seconds=settle))
        except Exception as e:  # one bad site shouldn't abort the batch
            console.print(f"  [red]failed: {e}[/red]")
            continue
        stem = url.split("//", 1)[-1].split("/", 1)[0]
        (out_dir / f"{stem}.json").write_text(audit_to_json(result))
        (out_dir / f"{stem}.md").write_text(audit_to_markdown(result))
        audits.append(result)
        cmp = result.detection.cmp if result.detection else None
        console.print(f"  · {stem}: {len(result.findings)} findings"
                      + (f" (CMP: {cmp})" if cmp else ""))

    if audits:
        (out_dir / "scan-summary.md").write_text(scan_summary_to_markdown(audits))
        (out_dir / "scan-summary.json").write_text(scan_summary_to_json(audits))
        console.print(f"[green]Wrote {out_dir}/scan-summary.md ({len(audits)} sites)[/green]")


@main.command()
@click.argument("url")
@click.option("--cookie", "-c", "identity_cookies", multiple=True,
              help="Identity cookie name to track; pass multiple times. "
                   "Omit to auto-discover surviving identifier cookies.")
@click.option("--contexts", default=3, show_default=True, type=int)
@click.option("--pre-click", default=None,
              help="CSS selector to click after navigation (e.g. reject button). "
                   "Omit to auto-detect the reject button.")
@click.option("--settle", default=4.0, show_default=True, type=float)
@click.option("--out-dir", default="reports", type=click.Path(file_okay=False, path_type=Path))
def fingerprint(
    url: str,
    identity_cookies: tuple[str, ...],
    contexts: int,
    pre_click: str | None,
    settle: float,
    out_dir: Path,
) -> None:
    """
    Open N isolated browser contexts on URL, capture identity cookies, and detect
    server-side fingerprinting based on cross-context ID persistence.

    Zero-config by default: the reject button and the identity cookies to track are
    auto-detected. Pass --pre-click and/or -c to override either.
    """
    if identity_cookies and pre_click is not None:
        console.log(f"Fingerprint test: {url} × {contexts} contexts; tracking {list(identity_cookies)}")
        result = asyncio.run(run_fingerprint_persistence_test(
            url, list(identity_cookies), contexts=contexts,
            pre_click_selector=pre_click, settle_seconds=settle,
        ))
    else:
        console.log(f"Fingerprint test: {url} × {contexts} contexts (auto-detecting reject + cookies)")
        result = asyncio.run(fingerprint_url(
            url, contexts=contexts, settle_seconds=settle,
            identity_cookies=list(identity_cookies) or None, pre_click_selector=pre_click,
        ))
        if result.pre_click_selector:
            console.log(f"Reject button: {result.pre_click_selector} ({result.pre_click_provenance})")
        else:
            console.log("No reject button auto-detected — captured without clicking reject")
        console.log(f"Tracking {len(result.findings)} cookies: {[f.cookie for f in result.findings]}")

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
