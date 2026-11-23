"""Phase 3 tests for GitHub PR inline review commenting engine."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from cbom_guard.reporters.github_pr import (
    format_pr_comment_body,
    parse_diff_added_lines,
    post_pr_review_comments,
)
from cbom_guard.scanner.workspace import scan_path

FIXTURES = Path(__file__).parent / "fixtures" / "python"


def test_parse_diff_added_lines() -> None:
    patch = (
        "@@ -10,2 +16,5 @@ def generate_keys() -> None:\n"
        "     pass\n"
        "+    _rsa_key = cg_rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "+    _weak_rsa = cg_rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        " \n"
    )
    lines = parse_diff_added_lines(patch)
    assert 17 in lines
    assert 18 in lines


def test_post_pr_review_comments_with_dedup() -> None:
    vuln_file = FIXTURES / "vulnerable_crypto.py"
    scan_result = scan_path(vuln_file)
    repo_root = vuln_file.parent.parent.parent.parent  # repo root
    rel_path = vuln_file.relative_to(repo_root).as_posix()

    posted_payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/pulls/42"):
            return httpx.Response(200, json={"head": {"sha": "deadbeef1234"}})
        if request.method == "GET" and request.url.path.endswith("/pulls/42/files"):
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": rel_path,
                        "patch": "@@ -15,0 +16,10 @@\n"
                        + "\n".join(f"+line {i}" for i in range(16, 26)),
                    }
                ],
            )
        if request.method == "GET" and request.url.path.endswith("/pulls/42/comments"):
            # Simulate PY-CRYPTO-001 already commented on line 18
            return httpx.Response(
                200,
                json=[
                    {
                        "path": rel_path,
                        "body": "<!-- cbom-guard:rule=PY-CRYPTO-001:line=18 -->\nExisting",
                    }
                ],
            )
        if request.method == "POST" and request.url.path.endswith("/pulls/42/reviews"):
            posted_payloads.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(200, json={"id": 999})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    with httpx.Client(base_url="https://api.github.com", transport=transport) as client:
        summary = post_pr_review_comments(
            scan_result=scan_result,
            repo="CoraxCoLAB/cbom-guard",
            pr_number=42,
            token="ghp_test",
            repo_root=repo_root,
            client=client,
        )

    assert summary["skipped_duplicates"] == 1
    assert summary["posted_count"] >= 1
    assert len(posted_payloads) == 1
    assert posted_payloads[0]["commit_id"] == "deadbeef1234"


def test_format_pr_comment_body_contains_marker_and_pqc_target() -> None:
    scan_result = scan_path(FIXTURES / "vulnerable_crypto.py")
    finding = scan_result.findings[0]
    body = format_pr_comment_body(finding)
    assert f"<!-- cbom-guard:rule={finding.rule_id}:line={finding.start_line} -->" in body
    assert finding.remediation.hybrid_pqc_target in body
