# Contributing to keyveil

Thanks for helping. keyveil handles API keys, so changes are reviewed with security in mind:
small, focused pull requests with tests are the easiest to merge.

## Run the checks locally

```bash
uv sync                                          # dev environment (uv fetches Python 3.11+)
uv run ruff check && uv run ruff format --check  # lint
uv run python -m unittest discover -s tests -v   # tests (offline; no keys, YubiKey or network)
./scripts/smoke-install.sh                       # build the wheel, install it, run the command
```

`uv run ruff format` fixes formatting. The sandbox tests need `bubblewrap`
(`sudo apt install bubblewrap`) and skip themselves if it can't run; CI makes sure they run.

## Pull request titles decide the version

Pull requests are **squash-merged**, and the PR title becomes the commit on `main`. Use the
[Conventional Commits](https://www.conventionalcommits.org/) format; a check enforces it.

| Title starts with | Example | Release |
|---|---|---|
| `feat:` | `feat: add idle shutdown` | minor (0.2.0 → 0.3.0) |
| `fix:` / `perf:` | `fix: reject empty routes file` | patch (0.2.0 → 0.2.1) |
| `docs:` `test:` `ci:` `build:` `chore:` `refactor:` `style:` `revert:` | `docs: clarify sandbox rules` | no release |
| `feat!:` / `fix!:` (breaking) | `feat!: rename config keys` | minor while below 1.0, then major |

## What happens on merge

`.github/workflows/release.yml` runs on every push to `main`:

1. **checks**: lint, tests on Python 3.11/3.12/3.13, install smoke test.
2. **release**: python-semantic-release reads the commits since the last tag. If any of them
   release, it bumps `pyproject.toml` and `uv.lock`, updates `CHANGELOG.md`, commits `chore(release): vX.Y.Z`,
   tags `vX.Y.Z` and creates the GitHub Release. Otherwise everything after this step is skipped.
3. **build**: builds the sdist and wheel from the tag once, checks their contents
   (`scripts/check-dist.py`), smoke-tests the wheel. Later jobs publish these exact files.
4. **github-release-assets**: attaches the files to the GitHub Release.
5. **deploy-testpypi**: publishes to TestPyPI and installs it back to check it works.
6. **deploy-pypi**: waits for a maintainer to approve the `pypi` environment, then publishes.

Publishing uses PyPI **trusted publishing** (OpenID Connect): there is no PyPI token stored in
the repository or anywhere else. All third-party actions are pinned to full commit SHAs.

## One-time repository setup (maintainers)

1. **Starting tag, pushed before `main`.** Pushing `main` starts the release workflow, so the
   starting tag has to be on GitHub first; without it the release job stops with an error
   (rather than inventing a first release from the whole history):
   `git tag v0.2.0 && git push origin v0.2.0 && git push origin main`.
2. **Merging.** Settings → General → Pull Requests: allow only *squash merging*, default commit
   message *Pull request title*.
3. **Branch rules.** Settings → Rules → new ruleset for `main`: require a pull request and the
   status checks `lint`, `test (3.11)`, `test (3.12)`, `test (3.13)`, `smoke` and
   `conventional-title`; block force pushes.
   The release job must be able to push its release commit and tag to `main`:
   - if your ruleset lets you add **GitHub Actions** to its bypass list, do that (not possible
     for a repository under a personal account: GitHub rejects it); or
   - create a fine-grained token (or a GitHub App token) limited to this repository with
     *Contents: read and write*, allowed to bypass the ruleset, and save it as the repository
     secret `RELEASE_TOKEN`. The workflow uses it automatically when it exists.
4. **Environments.** Settings → Environments: create `testpypi` (no protection) and `pypi`
   with **Required reviewers** (yourself) and deployment branches limited to `main`.
5. **PyPI and TestPyPI.** On each site (account with 2FA), add a *pending trusted publisher*:
   project `keyveil`, this repository's owner and name, workflow `release.yml`, environment
   `pypi` (on pypi.org) or `testpypi` (on test.pypi.org).

## Security issues

Please don't open a public issue for a vulnerability; see [SECURITY.md](SECURITY.md).
