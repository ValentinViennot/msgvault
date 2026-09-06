# Downstream build

This repository is a downstream build of
[kenn-io/msgvault](https://github.com/kenn-io/msgvault). It exists so that
features can be deployed before, or independently of, their acceptance
upstream, without ever diverging from upstream in a way that cannot be undone.

## Branch model

- `main` is the build branch. It is `upstream/main` plus merged feature
  branches plus the small set of downstream-only commits listed below. It is
  published, so it is only ever moved forward: upstream is brought in with
  `git merge upstream/main`, never by rebasing.
- Feature work happens on branches cut from `upstream/main`, so each one can be
  opened as an upstream pull request unchanged. A feature branch is merged into
  `main` with `git merge --no-ff <branch>`; when upstream merges the same
  branch, the next `git merge upstream/main` resolves to the upstream commits.
- Deployable builds are tagged `v<upstream version>-usl.<n>`; the Docker
  publish workflow pushes `ghcr.io/unstaticlabs/msgvault` for every push to
  `main` and every `v*` tag. Deployments pin the image digest.

## Downstream-only commits

Keep this list short; every entry is a permanent merge burden.

| Change | Why |
|---|---|
| `internal/update/update.go`: release owner `unstaticlabs` | `msgvault update` and the TUI's background check must look at this repository's releases, not upstream's, or they would replace a downstream binary with an upstream one. |
| `.github/workflows/ci-pr.yml`: reusable workflow reference | Pull requests here must run this repository's `ci.yml`. |
| this file | — |

## Keeping up with upstream

```bash
git fetch upstream
git checkout main
git merge upstream/main
go build ./... && make test
git push usl main
```

A conflict in one of the downstream-only files is expected occasionally and is
resolved by re-applying the row above; a conflict anywhere else means a feature
branch and upstream disagree, and the feature branch is where it is fixed.
