//! demo-ghostprovider — local-first demo hosting panel (Rust rewrite).
//!
//! Deploys three curated services (VERT, SearXNG, Memos) as hardened
//! systemd user services. No telemetry: every outbound network contact is
//! allowlisted at compile time and logged locally (see [`netlog`]).
//!
//! Unsafe code is forbidden crate-wide by default. The handful of modules
//! that must issue raw syscalls (libc resource limits, PDEATHSIG process
//! groups) opt back in explicitly at file scope with a justification; the
//! rest of the crate cannot gain `unsafe` without a deliberate review point.

#![deny(unsafe_code)]

pub mod analyzer;
pub mod atomic;
pub mod crashlog;
pub mod flags;
pub mod hoster;
pub mod netlog;
pub mod netstatus;
pub mod output;
pub mod paths;
pub mod selftest;
pub mod serve;
pub mod state;
pub mod tui;
pub mod tui_v2;
pub mod verify;
