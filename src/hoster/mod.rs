//! Deployment engine: curated recipes → hardened systemd user services.

pub mod cancel;
pub mod deploy;
pub mod egress;
pub mod gitclone;
pub mod github;
pub mod goenv;
pub mod httpclient;
pub mod journal;
pub mod lock;
pub mod models;
pub mod port;
pub mod prefetch;
pub mod preflight;
pub mod rawfetch;
pub mod recipes;
pub mod resolver;
pub mod sandbox;
pub mod secrets;
pub mod toolbox;
pub mod toolcheck;
pub mod units;
pub mod validate;
