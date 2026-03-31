use anyhow::{anyhow, Result};
use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
enum HostRule {
    Exact(String),
    Glob(GlobMatcher),
    Cidr(IpNet),
}

impl HostRule {
    fn matches(&self, host: &str, host_ip: Option<IpAddr>) -> bool {
        match self {
            HostRule::Exact(s) => s == host,
            HostRule::Glob(g) => g.is_match(host),
            HostRule::Cidr(net) => host_ip.map(|ip| net.contains(&ip)).unwrap_or(false),
        }
    }
}

/// Parses host allowlist entries.
///
/// Supported forms:
/// - Exact host: `example.com`
/// - Glob host: `*.example.com`
/// - CIDR: `10.0.0.0/8` or `2001:db8::/32` (only matches when `host` is an IP literal)
pub fn ensure_host_allowed(host: &str, allowed_hosts: &[String]) -> Result<()> {
    if allowed_hosts.is_empty() {
        return Err(anyhow!(
            "credential has no allowed_hosts; refusing to connect"
        ));
    }

    let host_ip = host.parse::<IpAddr>().ok();

    let mut rules = Vec::with_capacity(allowed_hosts.len());
    for raw in allowed_hosts {
        // CIDR?
        if let Ok(net) = raw.parse::<IpNet>() {
            rules.push(HostRule::Cidr(net));
            continue;
        }

        // Glob?
        if looks_like_glob(raw) {
            let g = Glob::new(raw)
                .map_err(|e| anyhow!("invalid glob in allowed_hosts '{raw}': {e}"))?
                .compile_matcher();
            rules.push(HostRule::Glob(g));
            continue;
        }

        // Exact
        rules.push(HostRule::Exact(raw.clone()));
    }

    if rules.iter().any(|r| r.matches(host, host_ip)) {
        Ok(())
    } else {
        Err(anyhow!("host not allowed by credential policy"))
    }
}

fn looks_like_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}
