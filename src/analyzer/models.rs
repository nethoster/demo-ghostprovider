//! Analyzer data model.

/// A TCP port found listening on the machine.
///
/// No owner attribution here: process names are only ever shown for ports
/// assigned to services deployed via this panel (see `tui::workers`), which
/// resolves them from local state.json, never from `ss`.
#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: String,
    pub netmask: String,
    pub status: String,
}

/// Full result of the local system analysis.
///
/// Deliberately privacy-minimal: prerequisite tool checks plus a bare map
/// of occupied ports. No owner probing, no VPN detection and no HTTP
/// fingerprinting of local services — this report must stay useless to
/// anyone but the operator.
#[derive(Debug, Default)]
pub struct AnalysisResult {
    pub systemd: bool,
    pub systemd_nspawn: bool,
    pub git: bool,
    pub python3: bool,
    pub node: bool,
    pub localhost: bool,
    pub network: bool,
    /// Boolean presence of the `tailscale` binary only — no login state, no
    /// status: the scan report must stay useless to attackers.
    pub tailscale: bool,
    pub cloudflared: bool,
    pub interfaces: Vec<InterfaceInfo>,
    pub listening_ports: Vec<ListeningPort>,
    pub gateway: String,
    pub dns: Vec<String>,
    pub errors: Vec<String>,
}
