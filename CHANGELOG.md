# Changelog


## [0.9.0] - 2026-01-07

### Fixed

- Now depends on `web-time` crate instead of `std::time` so that it works in WASM (`wasm32-unknown-unknown`). Pretty useless if it doesn't work in WASM. See httsps://crates.io/crates/web-time

## [0.8.0] - 2026-01-05

### Added

- `fn decode_claims(bytes: &[u8]) -> Result<CLAIMS, Error>` to decode only the `CLAIMS` without verification
- `fn decode(bytes: &[u8]) -> Result<TokenData<CLAIMS>, Error>` to decode the `CLAIMS` and expiry without verification

### Changed

- **BREAKING**: Renamed old `fn decode(token: &str) -> Result<TokenData<CLAIMS>, Error>` to `decode_str`

## [0.7.0] - 2025-09-09

### Added

- Exposed `SignedToken` and `Token` structs as public

## [0.6.2] - 2025-09-09

- Initial fork
