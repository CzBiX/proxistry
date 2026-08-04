
default:
  just --list

bump part="patch":
  #!/usr/bin/env bash
  set -eu

  git fetch origin
  local_sha=$(git rev-parse HEAD)
  remote_sha=$(git rev-parse origin/main)
  if [ "$local_sha" != "$remote_sha" ]; then
    echo "local main and origin/main have diverged — sync before bumping (git pull/push)" >&2
    exit 1
  fi

  cargo set-version --bump {{ part }}

  version=$(cargo pkgid | sed 's/.*#//')

  git add Cargo.toml Cargo.lock
  git commit -m "Bump version to $version"
  git tag -a "v$version" -m "v$version"

  echo "You can now push the changes and the tag with:"
  echo "  git push --follow-tags"

lint:
  cargo clippy --fix --allow-dirty
  cargo fmt