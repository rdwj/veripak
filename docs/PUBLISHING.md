# Publishing to PyPI with GitHub Trusted Publishing

This document explains how to publish `veripak` to PyPI using GitHub Actions and trusted publishing (OIDC).

## Overview

We use **GitHub's trusted publishing** feature, which eliminates the need for API tokens. GitHub authenticates directly with PyPI using OpenID Connect (OIDC).

## One-Time Setup Steps

### 1. Configure PyPI Trusted Publishing

1. **Go to PyPI** (create account if needed): https://pypi.org/account/register/

2. **Navigate to Publishing Settings**:
   - Go to https://pypi.org/manage/account/publishing/
   - Or: Account → Publishing → Add a new pending publisher

3. **Add GitHub as Trusted Publisher**:
   - **PyPI Project Name**: `veripak`
   - **Owner**: `rdwj`
   - **Repository name**: `veripak`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`

   Click "Add"

**Important**: You must configure trusted publishing BEFORE creating your first release. PyPI will create the project automatically on first publish.

### 2. Create GitHub Environment (Optional but Recommended)

This adds an extra approval step before publishing:

1. Go to your repository: https://github.com/rdwj/veripak
2. Navigate to **Settings → Environments**
3. Click **New environment**
4. Name it: `pypi`
5. Configure protection rules:
   - **Required reviewers**: Add yourself
   - **Deployment branches**: Only `main` branch

## Publishing a New Release

### Using the Release Script (Recommended)

```bash
# From project root
./scripts/release.sh 0.2.0 "Add new feature X"
```

The script will:
1. Update version in `src/veripak/version.py` and `pyproject.toml`
2. Commit the version bump
3. Push to main
4. Create and push a git tag

GitHub Actions will then automatically:
1. Run tests
2. Create a GitHub Release
3. Build distribution packages
4. Publish to PyPI

### Monitor the Release

- **Actions**: https://github.com/rdwj/veripak/actions
- **Release**: https://github.com/rdwj/veripak/releases

## Verification

After the workflow completes:

1. **Check PyPI**: https://pypi.org/project/veripak/
2. **Test installation**:
   ```bash
   pipx install veripak
   veripak --version
   ```

## Troubleshooting

### "Trusted publishing authentication error"

Verify settings at https://pypi.org/manage/account/publishing/:
- Owner: `rdwj`
- Repository: `veripak`
- Workflow: `release.yml`
- Environment: `pypi`

### "Environment protection rules"

Go to Actions → Workflow run → "Review deployments" → Approve.

### "Package already exists"

You cannot re-publish the same version. Increment the version number.

### Manual Upload (Emergency Fallback)

```bash
python -m build
pip install twine
twine upload dist/*
```

Use `__token__` as username and your PyPI API token as password.

## Security Notes

- No API tokens stored in the repository
- GitHub authenticates directly with PyPI via OIDC
- Workflow runs in isolated environment
- Environment protection rules add an approval step
- Only maintainers can create releases
