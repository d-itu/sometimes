use sometimes::{
    config::{Config, Upstream},
    naive::client::Client,
};

fn upstream(host: &str, port: Option<u16>, name: Option<&str>) -> Upstream {
    let mut config = format!("host = {host:?}\nusername = \"user\"\npassword = \"pass\"\n");
    if let Some(port) = port {
        config.push_str(&format!("port = {port}\n"));
    }
    if let Some(name) = name {
        config.push_str(&format!("server_name = {name:?}\n"));
    }
    toml::from_str(&config).unwrap()
}

#[test]
fn hostname_and_ip_default_to_https_port() {
    for host in ["proxy.example.com", "192.0.2.1", "2001:db8::1"] {
        let config = upstream(host, None, None);
        assert!(config.server_name.is_none());
        assert_eq!(config.host, host);
        assert_eq!(config.port, 443);
        Client::new(config, None).unwrap();
        let config = upstream(host, Some(8443), Some("proxy.example.com"));
        assert_eq!(config.port, 8443);
        Client::new(config, None).unwrap();
    }
}

#[test]
fn invalid_host_port_and_tls_name_are_rejected_without_resolution() {
    for host in [
        "",
        "proxy.example.com:443",
        "192.0.2.1:443",
        "[2001:db8::1]",
        "https://proxy.example.com",
        "host/path",
    ] {
        assert!(
            Client::new(upstream(host, None, None), None).is_err(),
            "accepted {host}"
        );
        assert!(Client::new(upstream(host, None, Some("proxy.example.com")), None).is_err());
    }
    assert!(Client::new(upstream("proxy.example.com", Some(0), None), None).is_err());
    assert!(Client::new(upstream("proxy.example.com", None, Some("")), None).is_err());
}

#[test]
fn invalid_port_types_and_legacy_address_are_rejected() {
    let base = "host = \"proxy.example.com\"\nusername = \"user\"\npassword = \"pass\"\n";
    for port in ["65536", "-1", "\"443\""] {
        assert!(toml::from_str::<Upstream>(&format!("{base}port = {port}\n")).is_err());
    }
    assert!(
        toml::from_str::<Upstream>(&format!("{base}address = \"proxy.example.com:443\"\n"))
            .is_err()
    );
    assert!(toml::from_str::<Upstream>(&format!("{base}socket_mark = 21327\n")).is_err());
}

#[test]
fn outbound_mark_is_optional_without_tproxy_and_required_with_it() {
    let base = r#"
        listeners = [{ host = "127.0.0.1", port = 8080, protocol = "http" }]
        [upstream]
        host = "proxy.example.com"
        username = "user"
        password = "pass"
    "#;
    let config: Config = toml::from_str(base).unwrap();
    assert_eq!(config.outbound_mark, None);
    config.validate().unwrap();

    for (listener, mark, valid) in [
        ("http", "outbound_mark = 21327", true),
        ("http", "outbound_mark = 0", false),
        ("tproxy", "", false),
        ("tproxy", "outbound_mark = 0", false),
        ("tproxy", "outbound_mark = 21327", true),
    ] {
        let source = format!(
            "listeners = [{{ host = \"127.0.0.1\", port = 8080, protocol = \"{listener}\" }}]\n{mark}\n[upstream]\nhost = \"proxy.example.com\"\nusername = \"user\"\npassword = \"pass\"\n"
        );
        let config: Config = toml::from_str(&source).unwrap();
        assert_eq!(config.validate().is_ok(), valid, "{listener}: {mark}");
    }
}
