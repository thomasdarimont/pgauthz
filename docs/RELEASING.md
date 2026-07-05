# Releasing

How to cut a pgauthz release, and a checklist so nothing is missed. Versioning
is [SemVer](https://semver.org/); pre-1.0, **minor** bumps may include breaking
changes. Tooling: `scripts/bump-version.sh` (bump refs + roll CHANGELOG) and
`scripts/release.sh` (preflight + annotated tag).

> **Golden rules**
> 1. **Never tag a red commit** — push, wait for CI green, *then* tag.
> 2. **Fill the CHANGELOG notes** before committing the bump (the bump only
>    creates an empty section).
> 3. **Push `main` AND the tag** — `git push origin vX.Y.Z` publishes only the
>    tag, not the branch.

## The flow

```bash
# 1. Land the work (feature/fix commits) and push; confirm CI is green.
# 2. Bump + write notes:
./scripts/bump-version.sh 0.1.4        # edits version refs + adds an empty CHANGELOG section
$EDITOR CHANGELOG.md                    # WRITE the [0.1.4] notes (see step below)
git diff                                # review
git commit -am "Bump version to 0.1.4"
git push                                # push the bump commit
# 3. Wait for CI green on the bump commit (all jobs).
# 4. Tag + publish:
./scripts/release.sh 0.1.4              # preflight + annotated tag (local)
git push origin v0.1.4                  # publish the tag  (or use release.sh --push)
```

### Unattended: `release.sh --auto`

`--auto` collapses steps 3–4: it **waits for the GitHub CI run on HEAD to pass,
then tags and pushes** — and treats an empty CHANGELOG section as a hard error
(not a warning). Use it after you've pushed the bump commit:

```bash
./scripts/bump-version.sh 0.1.4 && $EDITOR CHANGELOG.md
git commit -am "Bump version to 0.1.4" && git push
./scripts/release.sh 0.1.4 --auto      # blocks on CI, then tags + pushes v0.1.4
```

`--auto` = `--wait-ci` + `--push` + `--strict-changelog`, which are also usable
on their own:

| Flag | Effect |
|---|---|
| `--wait-ci` | Block until the CI run for HEAD passes before tagging; refuse to tag a red commit. HEAD must be pushed. Needs the [`gh`](https://cli.github.com/) CLI. |
| `--strict-changelog` | Fail (instead of warn) when the `## [X.Y.Z]` notes are empty. |
| `--push` | `git push origin vX.Y.Z` after tagging. |

It still runs every preflight check first (on `main`, clean tree, tag absent,
Chart version matches), so a misconfigured release fails *before* the CI wait.

## Pre-release checklist

Copy this into the release PR/notes and tick every box.

### Before bumping
- [ ] **`./scripts/pre-release.sh` passes locally** — Go build+vet, diagram
      renders fresh (regenerates and fails on drift), and the full local test
      run (`init.sh` + `test-all.sh`) — i.e. CI's main job *before* you push
      and wait on CI. `--skip-stack` runs just the fast checks. (The stack
      step resets the keycloak/playground opa overrides; the script prints
      the re-apply command.)
- [ ] All intended changes are **committed and pushed** to `main`.
- [ ] **CI is green** on the commit you're about to release — *all* jobs:
      `test`, `upgrade-test`, `replication-test`, `scaling-test`
      (`gh run list --branch main --limit 1`).
- [ ] Working tree is **clean** and you're on **`main`** (`git status`).
- [ ] Decide the version per SemVer: **patch** (fixes), **minor** (features /
      pre-1.0 breaking changes). Check `git log --oneline vPREV..HEAD` for scope.

### Bump (`./scripts/bump-version.sh X.Y.Z`)
Sweeps every pinned version reference — confirm each:
- [ ] `deploy/helm/pgauthz/Chart.yaml` — `version` **and** `appVersion`.
- [ ] `deploy/helm/pgauthz/values.yaml` — image tags (`migrations`,
      `authzenDirect`, `authzenOpa`).
- [ ] `deploy/helm/pgauthz/start.sh` — `IMAGE_TAG` default (also feeds the Go
      apps' `-version` via the `VERSION` build-arg).
- [ ] `CHANGELOG.md` — a new `## [X.Y.Z] - <date>` section + compare links.
- [ ] No stray old version left:
      `grep -rn "<old>" deploy/helm/pgauthz/{Chart.yaml,values.yaml,start.sh}`.

### CHANGELOG (the easy one to forget)
- [ ] The `## [X.Y.Z]` section is **NOT empty** — write Added / Changed / Fixed
      bullets. Base them on `git log --oneline vPREV..HEAD`.
- [ ] Compare links at the bottom point `[Unreleased] → vX.Y.Z...HEAD` and add
      `[X.Y.Z] → vPREV...vX.Y.Z`.

### Commit, verify, tag
- [ ] Commit the bump: `git commit -am "Bump version to X.Y.Z"`.
- [ ] `git push` the bump commit.
- [ ] **Tag once CI is green.** Either wait manually then
      `./scripts/release.sh X.Y.Z` (preflight: on `main`, clean tree, tag absent
      local+origin, `Chart.yaml` == X.Y.Z, CHANGELOG section present) + `--push`,
      **or** run `./scripts/release.sh X.Y.Z --auto` to wait for CI, tag, and
      push in one shot (also fails on empty CHANGELOG notes).

### Post-release
- [ ] Tag is on origin: `git ls-remote --tags origin vX.Y.Z`.
- [ ] Tag points at the bump commit: `git show -s vX.Y.Z`.
- [ ] `main` is pushed and not ahead of origin (tag push ≠ branch push).
- [ ] (Optional) GitHub release: `gh release create vX.Y.Z --notes-file -`
      with the CHANGELOG section.
- [ ] (Optional) Built + smoke-tested the release images
      (`IMAGE_TAG=X.Y.Z ./deploy/helm/pgauthz/start.sh`; check
      `pgauthzd -version` reports X.Y.Z).

## Gotchas we've hit
- **Empty CHANGELOG section.** The bump creates the heading but not the notes.
  `release.sh` **warns** (it doesn't block) when the `## [X.Y.Z]` section has no
  body — heed it and fill the notes before publishing the tag.
- **Tag pushed, branch not.** `git push origin vX` advances no branch. Push
  `main` separately, or `main` will lag behind the tag.
- **Tagging a red commit.** CI runs per-push; tag only after the bump commit is
  green, so `vX.Y.Z` always names a passing commit.
- **`0001_baseline.sql` is frozen** as of v0.1.0 — structural changes are new
  `db/migrations/NNNN_*.sql` files, never edits to the baseline (ADR 0001).
- **Undo a local tag** (pre-push): `git tag -d vX.Y.Z`. After push, retagging is
  disruptive (`git push origin :refs/tags/vX.Y.Z`) — avoid it; fix forward
  (e.g. backfill CHANGELOG on `main`) instead.
