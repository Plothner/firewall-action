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
    # rc=0: no findings, rc=1: findings found, rc=2: some rules errored
    # (e.g. language parser missing). All produce valid JSON in stdout.
    if result.returncode not in (0, 1, 2):
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


def _get_pr_number() -> int:
    """Extract PR number from GitHub Actions event payload.
    GitHub doesn't set a PR_NUMBER env var — it's in the event JSON."""
    # Try explicit env first (for testing)
    explicit = os.environ.get("GITHUB_PR_NUMBER") or os.environ.get("PR_NUMBER")
    if explicit:
        return int(explicit)
    # Read from event payload (the real GitHub Actions way)
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_path and Path(event_path).exists():
        try:
            with open(event_path) as f:
                event = json.load(f)
            pr = event.get("pull_request") or event.get("number")
            if isinstance(pr, dict):
                return int(pr.get("number", 0))
            if isinstance(pr, int):
                return pr
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    return 0


def main() -> int:
    log = lambda msg: print(f"[qryptera] {msg}", file=sys.stderr)  # noqa: E731

    backend = os.environ.get("INPUT_BACKEND_URL", "https://qryptera-api.plothner.com").rstrip("/")
    api_key = os.environ.get("INPUT_API_KEY", "")
    github_token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN", "")

    repo_full = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo_full:
        log("No GITHUB_REPOSITORY env; nothing to do.")
        return 0
    repo_owner, repo_name = repo_full.split("/", 1)
    pr_number = _get_pr_number()
    commit_sha = os.environ.get("GITHUB_SHA", "")
    log(f"repo={repo_full} pr={pr_number} sha={commit_sha[:12]}")

    # Docker containers need safe.directory for the mounted workspace
    subprocess.run(
        ["git", "config", "--global", "--add", "safe.directory", "/github/workspace"],
        capture_output=True,
    )

    # 1. Semgrep
    try:
        log("running semgrep...")
        semgrep = run_semgrep(target=Path("."), rules_dir=_RULES_IN_IMAGE)
        log(f"semgrep: {len(semgrep.get('results', []))} findings")
    except Exception as e:
        log(f"semgrep error (non-fatal): {e}")
        semgrep = {"results": []}

    # 2. Scan → backend
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        log(f"POST {backend}/api/v1/firewall/scan")
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
        log(f"scan: {scan_resp.get('cbom_assets_added', '?')} assets added")
    except Exception as e:
        log(f"scan error: {e}")
        scan_resp = {"cbom_assets_added": 0, "rate_limit_remaining": "?"}

    # 3. Audit → backend
    try:
        # For pull_request events, diff between base and head branches.
        # GITHUB_SHA is the merge commit; GITHUB_BASE_REF is the target branch.
        base_ref = os.environ.get("GITHUB_BASE_REF", "")
        head_ref = os.environ.get("GITHUB_HEAD_REF", "")
        if base_ref and head_ref:
            diff_cmd = ["git", "diff", f"origin/{base_ref}...origin/{head_ref}"]
        elif base_ref:
            diff_cmd = ["git", "diff", f"origin/{base_ref}...{commit_sha}"]
        else:
            diff_cmd = ["git", "diff", f"{commit_sha}^..{commit_sha}"]
        log(f"diff cmd: {' '.join(diff_cmd)}")
        diff_result = subprocess.run(diff_cmd, capture_output=True, text=True)
        diff = diff_result.stdout
        if not diff and diff_result.stderr:
            log(f"diff stderr: {diff_result.stderr[:200]}")
        log(f"git diff: {len(diff)} chars")

        log(f"POST {backend}/api/v1/firewall/audit")
        with httpx.Client(timeout=60.0, headers=headers) as client:
            audit_resp = client.post(
                f"{backend}/api/v1/firewall/audit",
                json={
                    "repo_owner": repo_owner,
                    "repo_name": repo_name,
                    "pr_number": pr_number,
                    "unified_diff": diff,
                },
            ).json()
        log(f"audit: {len(audit_resp.get('findings', []))} findings, rate_limited={audit_resp.get('rate_limited')}")
    except Exception as e:
        log(f"audit error: {e}")
        audit_resp = {"findings": [], "rate_limited": False}

    # 4. Format + post comment
    body = format_pr_comment(scan_resp=scan_resp, audit_resp=audit_resp, semgrep=semgrep)
    if pr_number and github_token:
        try:
            url = f"https://api.github.com/repos/{repo_full}/issues/{pr_number}/comments"
            log(f"POST comment to {url}")
            with httpx.Client(timeout=10.0) as gh:
                resp = gh.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {github_token}",
                        "Accept": "application/vnd.github+json",
                    },
                    json={"body": body},
                )
                log(f"comment response: {resp.status_code}")
        except Exception as e:
            log(f"comment post error: {e}")
    else:
        log(f"skipping comment: pr_number={pr_number}, token={'set' if github_token else 'missing'}")

    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
