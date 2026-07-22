#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'release preflight: %s\n' "$*" >&2
  exit 1
}

require_env() {
  local name=$1
  [[ -n "${!name:-}" ]] || die "$name is required"
}

require_env GITHUB_REPOSITORY
require_env GITHUB_REF_TYPE
require_env GITHUB_REF_NAME
require_env GITHUB_SHA
[[ "$GITHUB_REPOSITORY" == "Gentleman-Programming/gentle-ai" ]] || die "unexpected repository $GITHUB_REPOSITORY"
[[ "$GITHUB_REF_TYPE" == "tag" ]] || die "release must run from a tag push"

tag=$GITHUB_REF_NAME
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die "tag must be exact stable semver (vMAJOR.MINOR.PATCH)"
if ! canonical_public_keys=$(./scripts/canonicalize-release-public-keys.sh); then
  die "MINISIGN_PUBLIC_KEYS is not canonical"
fi
[[ "$canonical_public_keys" == "$MINISIGN_PUBLIC_KEYS" ]] || die "public-key canonicalization changed the configured value"

[[ "$(git cat-file -t "refs/tags/$tag")" == "tag" ]] || die "release tag must be annotated"
head_sha=$(git rev-parse 'HEAD^{commit}')
event_sha=$(git rev-parse "$GITHUB_SHA^{commit}")
tag_sha=$(git rev-parse "refs/tags/$tag^{commit}")
[[ "$head_sha" == "$event_sha" && "$head_sha" == "$tag_sha" ]] || die "checkout, event, and tag do not resolve to one commit"

git fetch --no-tags origin '+refs/heads/main:refs/remotes/origin/main'
main_sha=$(git rev-parse 'refs/remotes/origin/main^{commit}')
[[ "$head_sha" == "$main_sha" ]] || die "tagged commit is not exact current origin/main"

remote_tag_sha=$(git ls-remote origin "refs/tags/$tag^{}" | awk 'NR == 1 { print $1 }')
[[ -n "$remote_tag_sha" && "$remote_tag_sha" == "$head_sha" ]] || die "remote annotated tag does not peel to the checkout"

[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || die "release checkout is dirty"
go mod tidy -diff
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || die "preflight mutated the checkout"

printf 'release preflight: exact tag %s on main %s verified\n' "$tag" "$head_sha"
