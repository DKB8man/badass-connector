# PyPI Release Process

This document describes how to publish a new version of `badass-runner` to PyPI.

---

## One-Time Setup

### 1. Create a PyPI account
- Register at [pypi.org/account/register](https://pypi.org/account/register)
- Verify your email

### 2. Generate a PyPI API token
- Go to **Account Settings → API tokens → Add API token**
- Scope: **Entire account** (or restrict to `badass-runner` after first publish)
- Copy the token — you only see it once

### 3. Add the token to GitHub
- Go to your repo → **Settings → Secrets and variables → Actions**
- Click **New repository secret**
- Name: `PYPI_API_TOKEN`
- Value: paste your PyPI token
- Click **Add secret**

### 4. GitHub Actions workflow
The publish workflow lives at `.github/workflows/publish.yml`.
It triggers automatically when a `v*` tag is pushed to the repo.
No further configuration is needed after the secret is added.

---

## Every Release

### Step 1 — Update the version
Edit `pyproject.toml`:
```toml
version = "X.Y.Z"
```

### Step 2 — Update the changelog
Add a new entry at the top of `CHANGELOG.md`:
```markdown
## [X.Y.Z] — YYYY-MM-DD

### Added / Changed / Fixed
- Description of changes
```

### Step 3 — Commit and push to a branch
```bash
git add pyproject.toml CHANGELOG.md
git commit -m "Release vX.Y.Z"
git push origin your-branch
```

### Step 4 — Open a pull request and merge to `main`
- Go to GitHub and open a PR from your branch → `main`
- Review and merge

### Step 5 — Tag the release
```bash
git checkout main
git pull origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

Pushing the tag triggers the GitHub Actions publish workflow automatically.

### Step 6 — Verify on PyPI
- Visit `https://pypi.org/project/badass-runner/`
- Confirm the new version appears
- Click **Download files** to view SHA256 hashes

---

## Verifying Package Integrity

PyPI provides SHA256 hashes for every release under **Download files → view hashes**.

To download and verify locally (avoids browser auto-decompression on macOS):
```bash
curl -L -o badass_runner-X.Y.Z.tar.gz \
  <URL from PyPI Download files page>

shasum -a 256 badass_runner-X.Y.Z.tar.gz
```

The output should match the SHA256 shown on PyPI exactly.

To install with hash verification:
```bash
pip install badass-runner==X.Y.Z \
  --require-hashes \
  --hash=sha256:<hash from PyPI>
```

---

## Troubleshooting

### Push rejected (non-fast-forward)
The remote branch has commits your local copy does not. Run:
```bash
git pull origin <branch> --rebase
git push origin <branch>
```

### PyPI upload returns 400 Bad Request
The version being uploaded already exists on PyPI. You cannot overwrite a published version.
- Check that `pyproject.toml` has the correct new version number
- Delete the tag, bump the version, and re-tag:
```bash
git tag -d vX.Y.Z
git push origin --delete vX.Y.Z
# update version in pyproject.toml, commit, then:
git tag vX.Y.Z
git push origin vX.Y.Z
```

### Workflow not triggering
The publish workflow only runs on `v*` tags — not on branch pushes or PRs.
Make sure the tag starts with `v` (e.g. `v0.3.1`, not `0.3.1`).

### PyPI description not showing
The `readme = "README.md"` field must be present in `pyproject.toml` before the package is built.
If it was missing, publish a new patch version with the field added.
