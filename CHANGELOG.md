# Changelog

All notable changes to this project are documented here.

## [0.0.47]

### Added
- SECURITY.md with vulnerability reporting guidance.
- In-memory request record cap in netlog to bound session memory.
- Additional integration tests for manifest validation.

### Changed
- netlog no longer unwraps a poisoned mutex; lock failure is tolerated.
- CI runs `cargo fmt --check` after clippy.
- Migrated from `serde_yaml` to `serde_yaml_ng`.

### Pending
- Split large `deploy.rs`/`detect.rs`/`manifest.rs` into pipeline-stage modules.
- Integration tests for deploy rollback and cancellation.
