# Daily Repository Maintenance Automation

This automation creates at most one small documentation-only commit per run and rotates across repositories.

## What It Does

- Runs once per day from GitHub Actions.
- Selects one repository from `target_repos` using deterministic date-based rotation.
- Skips repositories in `skip_repos`.
- Updates only markdown or text documentation files from a safe list.
- Creates one lightweight commit with a meaningful message, then pushes.
- If no safe change is possible, it exits without forcing risky edits.

## Files Included

- `.github/workflows/daily-repository-maintenance.yml`
- `scripts/daily_maintenance.py`
- `automation/maintenance-config.json`

## Configure Target Repositories

Edit `automation/maintenance-config.json`:

- `owner`: GitHub user or org that owns target repos.
- `target_repos`: repositories to rotate through.
- `skip_repos`: repositories that must remain untouched.
- `preferred_files`: safe text files the script may update or create.
- `commit_messages`: rotating commit messages.
- `bot_name` and `bot_email`: commit author identity.

## Token and Secret Setup

### Same repository only

If you only target the repository that hosts this workflow, the built-in token is enough.

- Required: workflow permission `contents: write`.
- No personal token required.

### Cross-repository updates

If the workflow updates other repositories, add a Personal Access Token secret:

1. Create a PAT with repo write access for target repositories.
2. In the automation repository, open `Settings -> Secrets and variables -> Actions`.
3. Create secret `MAINTENANCE_PAT`.
4. Keep `permissions: contents: write` in the workflow.

The workflow automatically uses:

- `MAINTENANCE_PAT` when present.
- `github.token` as fallback.

## Safety Rules

- No dependency, package, config, database, or business-logic changes.
- Only `.md` and `.txt` files are modified.
- Intended for low-risk updates like logs/notes/readme entries.
- One commit maximum per workflow run.

## Rotation Logic

The script computes an index from the current UTC date and rotates the repository list.

- With 2 or more candidate repositories, this naturally avoids choosing the same repository on consecutive days.
- If a repository cannot be updated safely, the script attempts the next one.

## Run and Validation

- Automatic: daily schedule (`cron: 20 7 * * *`).
- Manual: `Run workflow` from the Actions tab.
- Check workflow logs for selected repo, changed file, and push result.

## Optional Hardening

- Add branch protection allowing this bot to push only docs updates.
- Keep `target_repos` focused on repositories with markdown/docs content.
- Add a dedicated machine user token if you want isolated audit trails.
