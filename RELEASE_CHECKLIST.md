# Release Checklist - After Merging to Main Branch

This checklist outlines the steps needed after merging the Rust extension migration to the main branch.

## 1. GitHub Actions Configuration

### 1.1 Set up PyPI Environment
- [ ] Go to GitHub repository → Settings → Environments
- [ ] Create a new environment named `pypi` (if not exists)
- [ ] Add the following secrets to the environment:
  - `PYPI_API_TOKEN`: Your PyPI API token (if using token-based auth)
  - Note: The workflow uses `pypa/gh-action-pypi-publish@release/v1` which supports both token and trusted publishing

### 1.2 Verify Workflow Files
- [ ] Confirm `.github/workflows/release.yml` exists and is correct
- [ ] Check if `src/icp_candid/ic_candid_parser/.github/workflows/CI.yml` conflicts with root workflow
  - If both exist, decide which one to use or merge them appropriately
  - The root `.github/workflows/release.yml` is for the main package release
  - The subdirectory CI.yml might be for Rust extension only

## 2. Update Documentation

### 2.1 Update README.md
- [ ] Remove or update the line about `antlr4-python3-runtime==4.9.3` dependency
  - Current line 37: `> If you use the Candid parser, we pin antlr4-python3-runtime==4.9.3.`
  - Should be updated to reflect that Rust extension is now used instead
- [ ] Add note about Rust extension being included (no Rust compiler needed for users)

### 2.2 Update Installation Instructions
- [ ] Verify installation instructions are accurate
- [ ] Add note that binary wheels are provided for all platforms (no Rust needed)

## 3. Version Management

### 3.1 Update Version Number
- [ ] Review `pyproject.toml` version (currently `2.0.0`)
- [ ] Consider if this migration warrants a version bump
- [ ] Update version if needed before first release

### 3.2 Update CHANGELOG.md
- [ ] Add entry documenting:
  - Migration from ANTLR to Rust-based Candid parser
  - Removal of `antlr4-python3-runtime` and `leb128` dependencies
  - Addition of Rust extension with binary wheels
  - Stable ABI (abi3) support for Python 3.8+

## 4. Testing & Verification

### 4.1 Local Testing
- [ ] Run the verification script: `./scripts/verify_clean_install.sh`
- [ ] Ensure Docker is installed and running
- [ ] Verify the script completes successfully

### 4.2 Test Wheel Building
- [ ] Test building wheels locally:
  ```bash
  cd src/icp_candid/ic_candid_parser
  maturin build --release --out dist
  ```
- [ ] Verify `.whl` files are generated correctly

### 4.3 Test Installation
- [ ] In a clean Python environment, test installing the built wheel:
  ```bash
  pip install dist/*.whl
  python -c "from icp_candid import _ic_candid_core; print('Success')"
  ```

## 5. Pre-Release Steps

### 5.1 Create Release Tag
- [ ] When ready to release, create a git tag:
  ```bash
  git tag v2.0.0  # or appropriate version
  git push origin v2.0.0
  ```
- [ ] This will trigger the `.github/workflows/release.yml` workflow

### 5.2 Monitor GitHub Actions
- [ ] Check GitHub Actions tab to ensure workflow runs successfully
- [ ] Verify wheels are built for all platforms (Linux, Windows, macOS)
- [ ] Confirm source distribution (sdist) is built
- [ ] Verify PyPI upload completes without errors

## 6. Post-Release Verification

### 6.1 Test PyPI Installation
- [ ] Wait for PyPI to process the upload (usually a few minutes)
- [ ] Test installation from PyPI in a clean environment:
  ```bash
  pip install --upgrade icp-py-core
  python -c "from icp_candid import _ic_candid_core; print('Success')"
  ```

### 6.2 Verify Dependencies
- [ ] Confirm `antlr4-python3-runtime` is not installed:
  ```bash
  pip list | grep antlr4  # Should return nothing
  ```
- [ ] Confirm `leb128` is not installed:
  ```bash
  pip list | grep leb128  # Should return nothing
  ```

## 7. Cleanup (Optional)

### 7.1 Remove Old Workflow Files
- [ ] If `src/icp_candid/ic_candid_parser/.github/workflows/CI.yml` is no longer needed, consider removing it
- [ ] Ensure there's no conflict between workflows

### 7.2 Update Git Configuration
- [ ] Verify `.gitignore` includes build artifacts (`dist/`, `target/`, etc.)

## Notes

- The Rust extension uses **Stable ABI (abi3-py38)**, meaning one build supports Python 3.8+
- Binary wheels are automatically built for Windows, macOS, and Linux
- Users do **not** need Rust compiler installed - wheels are pre-built
- The extension module is `icp_candid._ic_candid_core` (imported automatically)
