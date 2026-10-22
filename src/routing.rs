use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, ensure};
use ipnet::IpNet;
use rama::net::address::Domain;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Proxy,
    Direct,
    Reject,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub default: Action,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub action: Action,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<IpNet>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

pub fn normalize_domain(value: &str) -> Option<String> {
    let name = normalized_name(value)?;
    Domain::try_from(name.as_str()).ok()?;
    Some(name)
}

pub(crate) fn normalized_host(value: &str) -> Option<Domain> {
    Domain::try_from(normalized_name(value)?).ok()
}

fn normalized_name(value: &str) -> Option<String> {
    let name = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if name.contains('*') || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name)
}

pub(crate) fn matches_domain(name: &str, domains: &[String]) -> bool {
    domains.iter().any(|domain| domain == name)
}

pub(crate) fn matches_domain_suffix(name: &str, suffixes: &[String]) -> bool {
    suffixes.iter().any(|suffix| {
        name == suffix
            || name
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

impl Routing {
    /// Decide without an address only when no earlier matching rule needs one.
    pub fn select_before_dns(&self, domain: &str, port: u16) -> Option<Action> {
        for rule in &self.rules {
            if !rule.ports.is_empty() && !rule.ports.contains(&port) {
                continue;
            }
            if !rule.domain.is_empty() && !matches_domain(domain, &rule.domain) {
                continue;
            }
            if !rule.domain_suffix.is_empty() && !matches_domain_suffix(domain, &rule.domain_suffix)
            {
                continue;
            }
            return rule.ip_cidr.is_empty().then_some(rule.action);
        }
        Some(self.default)
    }
    /// Compile domain conditions once, before accepting connections.
    pub fn prepare(&mut self) -> Result<()> {
        for rule in &mut self.rules {
            ensure!(
                !rule.domain.is_empty()
                    || !rule.domain_suffix.is_empty()
                    || !rule.ip_cidr.is_empty()
                    || !rule.ports.is_empty(),
                "routing rules need a condition; use routing.default for the fallback"
            );
            ensure!(!rule.ports.contains(&0), "routing ports must be nonzero");
            for domain in rule.domain.iter_mut().chain(&mut rule.domain_suffix) {
                *domain = normalize_domain(domain)
                    .ok_or_else(|| anyhow::anyhow!("invalid routing domain"))?;
            }
        }
        Ok(())
    }

    /// Different condition types are ANDed; values within a condition are ORed.
    pub fn select(&self, destination: SocketAddr, domain: Option<&str>) -> (Action, Option<usize>) {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, rule)| {
                (rule.domain.is_empty()
                    || domain.is_some_and(|name| matches_domain(name, &rule.domain)))
                    && (rule.domain_suffix.is_empty()
                        || domain
                            .is_some_and(|name| matches_domain_suffix(name, &rule.domain_suffix)))
                    && (rule.ip_cidr.is_empty()
                        || rule
                            .ip_cidr
                            .iter()
                            .any(|net| net.contains(&destination.ip())))
                    && (rule.ports.is_empty() || rule.ports.contains(&destination.port()))
            })
            .map_or((self.default, None), |(index, rule)| {
                (rule.action, Some(index))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_dns_rejection_preserves_ip_rule_precedence() {
        let mut routing: Routing = toml::from_str(
            "default = 'proxy'\n[[rules]]\ndomain = ['blocked.example']\naction = 'reject'",
        )
        .unwrap();
        routing.prepare().unwrap();
        let name = normalize_domain("Blocked.Example.").unwrap();
        assert_eq!(routing.select_before_dns(&name, 443), Some(Action::Reject));

        let mut routing: Routing = toml::from_str(
            "default = 'proxy'\n[[rules]]\nip_cidr = ['10.0.0.0/8']\naction = 'direct'\n[[rules]]\ndomain = ['blocked.example']\naction = 'reject'",
        )
        .unwrap();
        routing.prepare().unwrap();
        assert_eq!(routing.select_before_dns(&name, 443), None);
        assert_eq!(routing.select_before_dns("other.example", 443), None);
    }

    #[test]
    fn ordered_conditions_and_domain_boundaries() {
        let mut routing: Routing = toml::from_str(
            r#"
            default = "proxy"
            [[rules]]
            domain = ["Blocked.Example.COM."]
            action = "reject"
            [[rules]]
            domain_suffix = ["EXAMPLE.com"]
            ports = [443, 8443]
            action = "direct"
            [[rules]]
            ip_cidr = ["10.0.0.0/8", "2001:db8::/32"]
            action = "reject"
        "#,
        )
        .unwrap();
        routing.prepare().unwrap();
        let dst = "203.0.113.1:443".parse().unwrap();
        assert_eq!(
            routing.select(dst, Some("blocked.example.com")),
            (Action::Reject, Some(0))
        );
        for name in ["example.com", "a.example.com"] {
            assert_eq!(routing.select(dst, Some(name)), (Action::Direct, Some(1)));
        }
        for name in [None, Some("notexample.com"), Some("example.com.evil")] {
            assert_eq!(routing.select(dst, name), (Action::Proxy, None));
        }
        assert_eq!(
            routing
                .select("203.0.113.1:80".parse().unwrap(), Some("example.com"))
                .0,
            Action::Proxy
        );
        for ip in ["10.1.2.3:80", "[2001:db8::1]:443"] {
            assert_eq!(
                routing.select(ip.parse().unwrap(), None),
                (Action::Reject, Some(2))
            );
        }
    }

    #[test]
    fn domain_conditions_are_combined_before_and_after_dns() {
        let mut routing: Routing = toml::from_str(
            r#"
            default = "proxy"
            [[rules]]
            domain = ["Allowed.Example.COM.", "other.test"]
            domain_suffix = ["Example.COM."]
            action = "direct"
            "#,
        )
        .unwrap();
        routing.prepare().unwrap();
        let destination = "203.0.113.1:443".parse().unwrap();
        for (name, expected) in [
            (Some("allowed.example.com"), (Action::Direct, Some(0))),
            (Some("other.test"), (Action::Proxy, None)),
            (Some("www.example.com"), (Action::Proxy, None)),
            (None, (Action::Proxy, None)),
        ] {
            assert_eq!(routing.select(destination, name), expected);
            if let Some(name) = name {
                assert_eq!(routing.select_before_dns(name, 443), Some(expected.0));
            }
        }
    }

    #[test]
    fn rejects_invalid_conditions() {
        for source in [
            "[[rules]]\naction = 'direct'",
            "[[rules]]\naction = 'direct'\nports = [0]",
            "[[rules]]\naction = 'direct'\ndomain = ['*.example.com']",
        ] {
            assert!(
                toml::from_str::<Routing>(source)
                    .unwrap()
                    .prepare()
                    .is_err()
            );
        }
        assert!(
            toml::from_str::<Routing>("[[rules]]\naction = 'direct'\nip_cidr = ['10.0.0.0/99']")
                .is_err()
        );
    }
}
