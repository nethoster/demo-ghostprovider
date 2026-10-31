//! Opt-in public sharing via Cloudflare Quick Tunnel.
//!
//! The deployed service stays loopback-only; a supervised `cloudflared`
//! subprocess publishes it while the panel is running.

pub mod cloudflare;
pub mod registry;
pub mod supervisor;
