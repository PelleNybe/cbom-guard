"""GitHub Pull Request inline review comment engine with hybrid-PQC remediation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx

from cbom_guard.models import Finding, RiskLevel, ScanResult

_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
_MARKER_RE = re.compile(r"<!--\s*cbom-guard:rule=([^:\s]+):line=(\d+)\s*-->")


def parse_diff_added_lines(patch: str) -> set[int]:
    """Parse a unified diff patch and return 1-based line numbers present on the RIGHT side."""
    added_lines: set[int] = set()
    current_new_line: int | None = None

    for raw_line in patch.splitlines():
        hunk_match = _HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            current_new_line = int(hunk_match.group(1))
            continue

        if current_new_line is None:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added_lines.add(current_new_line)
            current_new_line += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            continue
        else:
            # Context line
            added_lines.add(current_new_line)
            current_new_line += 1

    return added_lines


def format_pr_comment_body(finding: Finding) -> str:
    """Format a structured Markdown inline review comment with hybrid-PQC guidance."""
    marker = f"<!-- cbom-guard:rule={finding.rule_id}:line={finding.start_line} -->"
    severity_label = (
        "CRITICAL — Shor's Algorithm Vulnerable"
        if finding.risk_level == RiskLevel.CRITICAL
        else "WARNING — Grover's Algorithm / Legacy Crypto"
    )

    lines = [
        marker,
        f"### 🔐 `cbom-guard` [{finding.rule_id}] {finding.rule_name}",
        "",
        f"- **Severity:** `{severity_label}`",
        f"- **Algorithm:** `{finding.algorithm}` | **CWE:** `{finding.cwe}` | **NIST PQC Status:** `{finding.nist_pqc_status}`",
        f"- **Hybrid-PQC Migration Target:** `{finding.remediation.hybrid_pqc_target}`",
        "",
        f"{finding.remediation.summary}",
    ]

    if finding.remediation.code_example.strip():
        lines.extend(
            [
                "",
                "**Recommended PQC / Hybrid Migration:**",
                "```text",
                finding.remediation.code_example.strip(),
                "```",
            ]
        )

    return "\n".join(lines)


def _normalize_repo_path(file_path: str, repo_root: Path | None) -> str:
    p = Path(file_path)
    if repo_root is not None:
        try:
            return p.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            pass
    return p.as_posix().lstrip("./")


def post_pr_review_comments(
    scan_result: ScanResult,
    repo: str,
    pr_number: int,
    token: str,
    *,
    api_url: str = "https://api.github.com",
    repo_root: Path | None = None,
    dry_run: bool = False,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Post deduplicated inline PR review comments for PQC findings on changed diff lines.

    Returns a summary dictionary including `posted_count`, `skipped_duplicates`, and `payload`.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    owns_client = client is None
    http = client or httpx.Client(base_url=api_url, headers=headers, timeout=30.0)

    try:
        pr_resp = http.get(f"/repos/{repo}/pulls/{pr_number}", headers=headers)
        pr_resp.raise_for_status()
        commit_sha: str = pr_resp.json()["head"]["sha"]

        files_resp = http.get(f"/repos/{repo}/pulls/{pr_number}/files?per_page=100", headers=headers)
        files_resp.raise_for_status()
        changed_lines_by_file: dict[str, set[int]] = {}
        for f_entry in files_resp.json():
            fname = str(f_entry.get("filename", ""))
            patch = f_entry.get("patch")
            if fname and isinstance(patch, str):
                changed_lines_by_file[fname] = parse_diff_added_lines(patch)

        existing_resp = http.get(
            f"/repos/{repo}/pulls/{pr_number}/comments?per_page=100", headers=headers
        )
        existing_resp.raise_for_status()
        existing_markers: set[tuple[str, str, int]] = set()
        for comment in existing_resp.json():
            c_path = str(comment.get("path", ""))
            c_body = str(comment.get("body", ""))
            for match in _MARKER_RE.finditer(c_body):
                existing_markers.add((c_path, match.group(1), int(match.group(2))))

        review_comments: list[dict[str, Any]] = []
        skipped_duplicates = 0

        for finding in scan_result.findings:
            if finding.risk_level == RiskLevel.INFO:
                continue

            rel_path = _normalize_repo_path(finding.file_path, repo_root)
            if rel_path not in changed_lines_by_file:
                continue
            if finding.start_line not in changed_lines_by_file[rel_path]:
                continue

            dedup_key = (rel_path, finding.rule_id, finding.start_line)
            if dedup_key in existing_markers:
                skipped_duplicates += 1
                continue

            existing_markers.add(dedup_key)
            review_comments.append(
                {
                    "path": rel_path,
                    "line": finding.start_line,
                    "side": "RIGHT",
                    "body": format_pr_comment_body(finding),
                }
            )

        payload: dict[str, Any] = {
            "commit_id": commit_sha,
            "event": "COMMENT",
            "body": (
                f"**cbom-guard** Post-Quantum Cryptography Scan: "
                f"{scan_result.critical_count} Critical (Shor), "
                f"{scan_result.warning_count} Warning (Grover)."
            ),
            "comments": review_comments,
        }

        if not dry_run and review_comments:
            post_resp = http.post(
                f"/repos/{repo}/pulls/{pr_number}/reviews",
                headers=headers,
                json=payload,
            )
            post_resp.raise_for_status()

        return {
            "posted_count": len(review_comments) if not dry_run else 0,
            "pending_count": len(review_comments),
            "skipped_duplicates": skipped_duplicates,
            "payload": payload,
        }
    finally:
        if owns_client:
            http.close()
