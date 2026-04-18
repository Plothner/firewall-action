"""Qryptera Crypto Debt Firewall — GitHub Action entrypoint."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

_RULES_IN_IMAGE = Path("/rules")


def run_semgrep(target: Path, rules_dir: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["semgrep", "scan", "--config", str(rules_dir), "--json", str(target)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed (rc={result.returncode}): {result.stderr[:500]}")
    try:
        return dict(json.loads(result.stdout or "{}"))
    except json.JSONDecodeError:
        return {"results": []}


def build_scan_request(
    *,
    semgrep_output: dict[str, Any],
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    commit_sha: str,
) -> dict[str, Any]:
    findings = []
    for r in semgrep_output.get("results", []):
        findings.append(
            {
                "rule_id": r.get("check_id", "unknown"),
                "file": r.get("path", "?"),
                "line": (r.get("start") or {}).get("line", 0),
                "code": (r.get("extra") or {}).get("lines", "")[:500],
            }
        )
    return {
        "repo_owner": repo_owner,
        "repo_name": repo_name,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "semgrep_findings": findings,
    }


def format_pr_comment(
    *,
    scan_resp: dict[str, Any],
    audit_resp: dict[str, Any],
    semgrep: dict[str, Any],
) -> str:
    lines = ["## 🔐 Qryptera Crypto Debt Firewall", ""]
    results = semgrep.get("results", [])
    findings = audit_resp.get("findings", [])
    lines.append(f"**{len(results)} deterministic · {len(findings)} auditor** findings")
    lines.append("")
    if results:
        lines.append("### 🟥 Deterministic (Semgrep)")
        for r in results[:15]:
            lines.append(
                f"- **`{r.get('path', '?')}:{(r.get('start') or {}).get('line', '?')}`** — "
                f"`{r.get('check_id', '?')}`"
            )
        lines.append("")
    if findings:
        lines.append("### 🟨 Continuous Crypto Auditor (LLM)")
        for f in findings:
            lines.append(
                f"- **`{f['file']}:{f['line_hint']}`** [confidence {f['confidence']:.2f}, "
                f"category: {f['category']}] {f['text']}"
            )
            lines.append("  👍 helpful · 👎 not helpful")
        lines.append("")
    if audit_resp.get("rate_limited"):
        lines.append("> ⚠️ Auditor rate-limited for this repo — free tier is 100 audits / month.")
        lines.append("> [Upgrade](https://qryptera.com/upgrade) for unlimited scans.")
        lines.append("")
    lines.append("---")
    lines.append(
        f"_Free tier · {scan_resp.get('rate_limit_remaining', '?')} of 100 monthly "
        f"audits remaining · [Upgrade](https://qryptera.com/upgrade)_"
    )
    return "\n".join(lines)


def main() -> int:
    backend = os.environ.get("INPUT_BACKEND_URL", "https://qryptera-api.plothner.com").rstrip("/")
    api_key = os.environ.get("INPUT_API_KEY", "")
    github_token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    repo_full = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo_full:
        print("No GITHUB_REPOSITORY env; nothing to do.", file=sys.stderr)
        return 0
    repo_owner, repo_name = repo_full.split("/", 1)
    pr_number = int(os.environ.get("GITHUB_PR_NUMBER") or os.environ.get("PR_NUMBER") or 0)
    commit_sha = os.environ.get("GITHUB_SHA", "")
    semgrep = run_semgrep(target=Path("."), rules_dir=_RULES_IN_IMAGE)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    with httpx.Client(timeout=30.0, headers=headers) as client:
        scan_resp = client.post(
            f"{backend}/api/v1/firewall/scan",
            json=build_scan_request(
                semgrep_output=semgrep,
                repo_owner=repo_owner,
                repo_name=repo_name,
                pr_number=pr_number,
                commit_sha=commit_sha,
            ),
        ).json()
        diff = subprocess.run(
            ["git", "diff", f"{commit_sha}^..{commit_sha}"],
            capture_output=True,
            text=True,
        ).stdout
        audit_resp = client.post(
            f"{backend}/api/v1/firewall/audit",
            json={
                "repo_owner": repo_owner,
                "repo_name": repo_name,
                "pr_number": pr_number,
                "unified_diff": diff,
            },
        ).json()
    body = format_pr_comment(scan_resp=scan_resp, audit_resp=audit_resp, semgrep=semgrep)
    if pr_number and github_token:
        url = f"https://api.github.com/repos/{repo_full}/issues/{pr_number}/comments"
        with httpx.Client(timeout=10.0) as gh:
            gh.post(
                url,
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/vnd.github+json",
                },
                json={"body": body},
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
