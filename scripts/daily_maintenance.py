#!/usr/bin/env python3
"""Daily lightweight maintenance updater for multiple repositories.

Safety goals:
- only updates .md/.txt documentation-style files
- no dependency/config/business-logic changes
- at most one commit per run
- deterministic repo rotation to avoid same repo two days in a row when possible
"""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable


DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=True,
    )


def load_config(path: Path) -> dict:
    # Accept UTF-8 files with or without BOM to avoid editor/OS variance.
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def choose_repo(candidates: list[str], run_date: dt.date) -> list[str]:
    if not candidates:
        return []
    days_since_epoch = (run_date - dt.date(1970, 1, 1)).days
    start = days_since_epoch % len(candidates)
    return candidates[start:] + candidates[:start]


def infer_default_branch(repo_dir: Path) -> str:
    cp = run(["git", "symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo_dir)
    return cp.stdout.strip().split("/")[-1]


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def pick_doc_file(repo_dir: Path, preferred_files: Iterable[str]) -> Path:
    for rel in preferred_files:
        candidate = repo_dir / rel
        if candidate.exists() and candidate.suffix.lower() in {".md", ".txt"}:
            return candidate

    for rel in preferred_files:
        candidate = repo_dir / rel
        if Path(rel).suffix.lower() in {".md", ".txt"}:
            return candidate

    return repo_dir / "daily-log.md"


def append_daily_entry(path: Path, owner_repo: str, run_date: dt.date, now_utc: dt.datetime) -> bool:
    existing = read_text(path)
    for match in DATE_RE.finditer(existing):
        if match.group(1) == run_date.isoformat():
            return False

    stamp = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    if path.suffix.lower() == ".txt":
        new_line = f"{stamp} | automated maintenance check-in for {owner_repo}."
        updated = (existing.rstrip() + "\n" + new_line + "\n") if existing else (new_line + "\n")
    else:
        heading = "## Daily Maintenance Log"
        entry = f"- {stamp}: automated maintenance check-in for `{owner_repo}`."
        if not existing:
            updated = f"# Daily Log\n\n{heading}\n\n{entry}\n"
        elif heading in existing:
            updated = existing.rstrip() + "\n" + entry + "\n"
        else:
            updated = existing.rstrip() + f"\n\n{heading}\n\n{entry}\n"

    if updated == existing:
        return False

    write_text(path, updated)
    return True


def stage_commit_push(repo_dir: Path, message: str, bot_name: str, bot_email: str, branch: str) -> bool:
    run(["git", "config", "user.name", bot_name], cwd=repo_dir)
    run(["git", "config", "user.email", bot_email], cwd=repo_dir)
    run(["git", "add", "."], cwd=repo_dir)

    status = run(["git", "status", "--porcelain"], cwd=repo_dir)
    if not status.stdout.strip():
        return False

    run(["git", "commit", "-m", message], cwd=repo_dir)
    run(["git", "push", "origin", branch], cwd=repo_dir)
    return True


def clone_repo(owner: str, repo: str, token: str, destination: Path) -> None:
    encoded = urllib.parse.quote(token, safe="")
    # Username can be any non-empty value for PAT over HTTPS.
    url = f"https://github-actions:{encoded}@github.com/{owner}/{repo}.git"
    run(["git", "clone", "--depth", "1", url, str(destination)])


def has_push_permission(owner: str, repo: str, token: str) -> tuple[bool, str]:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "daily-maintenance-bot",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return False, f"GitHub API error {exc.code}"
    except Exception as exc:  # pragma: no cover - defensive logging path
        return False, f"GitHub API error: {exc}"

    permissions = payload.get("permissions", {})
    can_push = bool(permissions.get("push"))
    reason = "push allowed" if can_push else "no push permission"
    return can_push, reason


def main() -> int:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
    config_path = Path(os.environ.get("MAINTENANCE_CONFIG", workspace / "automation" / "maintenance-config.json"))
    token = os.environ.get("MAINTENANCE_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("MAINTENANCE_TOKEN or GITHUB_TOKEN is required.", file=sys.stderr)
        return 2

    config = load_config(config_path)
    owner = config["owner"]
    target_repos = config.get("target_repos", [])
    skip_repos = set(config.get("skip_repos", []))
    preferred_files = config.get("preferred_files", ["daily-log.md", "maintenance-log.txt"])
    commit_messages = config.get("commit_messages", ["chore: daily maintenance update"])
    bot_name = config.get("bot_name", "repo-maintenance-bot")
    bot_email = config.get("bot_email", "repo-maintenance-bot@users.noreply.github.com")

    now_utc = dt.datetime.now(dt.timezone.utc)
    run_date = now_utc.date()

    candidates = [r for r in target_repos if r not in skip_repos]
    if not candidates:
        print("No candidate repositories after applying skip list.")
        return 0

    current_repo = os.environ.get("GITHUB_REPOSITORY", "")
    using_default_token = bool(os.environ.get("GITHUB_TOKEN")) and not bool(os.environ.get("MAINTENANCE_TOKEN"))
    if using_default_token:
        cross_repo_targets = [r for r in candidates if f"{owner}/{r}" != current_repo]
        if cross_repo_targets:
            print(
                "Warning: using default GITHUB_TOKEN with cross-repo targets. "
                "Set MAINTENANCE_PAT with push access for all target repositories."
            )

    ordered_repos = choose_repo(candidates, run_date)
    msg_idx = (run_date - dt.date(1970, 1, 1)).days % len(commit_messages)
    commit_message = commit_messages[msg_idx]

    print(f"Run date (UTC): {run_date.isoformat()}")
    print(f"Candidate order: {ordered_repos}")

    for repo in ordered_repos:
        owner_repo = f"{owner}/{repo}"
        print(f"Attempting repository: {owner_repo}")

        can_push, reason = has_push_permission(owner, repo, token)
        if not can_push:
            print(f"Skipping {owner_repo}: token cannot push ({reason}).")
            continue

        tmp = Path(tempfile.mkdtemp(prefix=f"daily-maintenance-{repo}-"))

        try:
            clone_repo(owner, repo, token, tmp)
            branch = infer_default_branch(tmp)
            target_file = pick_doc_file(tmp, preferred_files)
            changed = append_daily_entry(target_file, owner_repo, run_date, now_utc)
            if not changed:
                print(f"No change required in {owner_repo} ({target_file.name} already has date {run_date}).")
                continue

            committed = stage_commit_push(tmp, commit_message, bot_name, bot_email, branch)
            if committed:
                print(f"Committed and pushed maintenance update to {owner_repo}:{branch}")
                return 0

            print(f"Nothing staged for {owner_repo}; trying next repository.")
        except subprocess.CalledProcessError as exc:
            print(f"Failed for {owner_repo}: {exc.cmd}\n{exc.stderr}", file=sys.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("Completed run without creating a commit.")
    return 0


if __name__ == "__main__":
    random.seed(0)
    raise SystemExit(main())
