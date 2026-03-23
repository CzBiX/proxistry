
default:
  just --list

bump part="patch":
  #!/usr/bin/env bash
  set -eu
  cargo set-version --bump {{ part }}

  version=$(cargo pkgid | sed 's/.*#//')

  git add Cargo.toml Cargo.lock
  git commit -m "Bump version to $version"
  git tag "v$version"

  echo "You can now push the changes and the tag with:"
  echo "  git push --follow-tags"

lint:
  cargo clippy --fix --allow-dirty
  cargo fmt