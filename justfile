# List all just recipes
@list:
    just --list

# Generate README.md from library docs
readme:
    cargo readme --no-title --no-indent-headings > README.md

# Publish to crates.io
publish: test readme
    cargo publish --dry-run
    printf "Ready to publish? "
    read confirm
    if [ "$confirm" != "Y" ]; then echo "Cancelled."; exit 0; fi
    cargo publish

# Run tests
test:
    cargo test
