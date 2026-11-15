# Changelog

All notable changes to this project are documented here.

## [0.0.48]

### Added
- Detection: a repo with `index.html`, `public/` or `site/` deploys as the
  `static` profile instead of failing with "no supported stack markers found".

### Changed
- Preflight no longer requires `systemd-nspawn` (nothing in the deploy path uses
  it; it is a separate package on Debian/Ubuntu) and now checks cgroup v2 plus a
  `loginctl enable-linger` hint.

### Removed
- `demo-test` TUI prototype (`src/tui_v2`, `src/bin/demo_test.rs`): it shipped
  no `__serve-static`/`__egress-shim` workers, so services deployed from it
  crash-looped, and its deploy screen pointed at a missing Add Service view.

### Fixed
- Units no longer embed `current_exe()`: `paths::self_exe()` resolves
  `GHOSTPROVIDER_SELF` -> own binary -> `~/.local/bin` -> `PATH`, so a deploy
  started from `cargo run`, a copy or a stale binary writes a working
  `ExecStart`.
- The post-deploy non-loopback warning no longer fires on the sandbox's own
  `__egress-shim`/`__serve-static` listeners (`ss` parsing is owner-aware).
- Egress screen lists deployed units, not only library entries; the policy of a
  URL deploy is read from its unit file (`PrivateNetwork=`, `IPAddressAllow=`).

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
