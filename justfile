# List all just recipes
@list:
    just --list

# Generate README.md from library docs
readme:
    cargo readme --no-title --no-indent-headings > README.md

binstall crate bin="":
    #!/usr/bin/env bash
    set -euo pipefail

    BIN="{{ bin }}"
    if [ -z "$BIN" ]; then
        BIN="{{ crate }}"
    fi
    which "$BIN" 1>/dev/null || cargo binstall -y "{{ crate }}"

# Publish to crates.io
publish: (binstall 'toml-cli') test readme
    #!/usr/bin/env bash
    set -euo pipefail

    cargo publish --dry-run
    printf "Ready to publish? "
    read confirm
    if [ "$confirm" != "Y" ]; then
        echo "Cancelled."
        exit 0
    fi
    VERSION=$(toml get -r Cargo.toml package.version)
    git tag "v$VERSION"
    git push --tag
    cargo publish

# Run tests
test:
    cargo test
