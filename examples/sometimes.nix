{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.sometimes;
  nft = "${pkgs.nftables}/bin/nft";
  ip = "${pkgs.iproute2}/bin/ip";
  rules = pkgs.writeText "sometimes-rules.nft" (
    builtins.readFile ./tproxy.nft + "\n" + builtins.readFile ./dns-redirect.nft
  );
  networkUp = pkgs.writeShellScript "sometimes-network-up" ''
    set -e
    active=0
    route4=0
    route6=0
    rule4=0
    rule6=0
    rollback() {
      trap - ERR
      if (( active )); then
        ${nft} delete table inet sometimes_dns || true
        ${nft} delete table inet sometimes || true
      fi
      if (( rule6 )); then ${ip} -6 rule del priority 100 fwmark 0x5354 lookup 100 || true; fi
      if (( rule4 )); then ${ip} -4 rule del priority 100 fwmark 0x5354 lookup 100 || true; fi
      if (( route6 )); then ${ip} -6 route del local ::/0 dev lo table 100 || true; fi
      if (( route4 )); then ${ip} -4 route del local 0.0.0.0/0 dev lo table 100 || true; fi
    }
    trap rollback ERR
    if ${nft} list table inet sometimes >/dev/null 2>&1 || ${nft} list table inet sometimes_dns >/dev/null 2>&1; then
      echo "sometimes nftables tables already exist" >&2
      exit 1
    fi
    if ${ip} -4 rule show | ${pkgs.gnugrep}/bin/grep -q '^100:' || ${ip} -6 rule show | ${pkgs.gnugrep}/bin/grep -q '^100:'; then
      echo "policy rule priority 100 is already in use" >&2
      exit 1
    fi
    if [[ -n "$(${ip} -4 route show table 100)" || -n "$(${ip} -6 route show table 100)" ]]; then
      echo "policy route table 100 is already in use" >&2
      exit 1
    fi
    ${ip} -4 route add local 0.0.0.0/0 dev lo table 100
    route4=1
    ${ip} -6 route add local ::/0 dev lo table 100
    route6=1
    ${ip} -4 rule add priority 100 fwmark 0x5354 lookup 100
    rule4=1
    ${ip} -6 rule add priority 100 fwmark 0x5354 lookup 100
    rule6=1
    active=1
    ${nft} -f ${rules}
    ${pkgs.coreutils}/bin/touch /run/sometimes-network-active
    trap - ERR
  '';
  networkDown = pkgs.writeShellScript "sometimes-network-down" ''
    if [[ ! -e /run/sometimes-network-active ]]; then exit 0; fi
    ${pkgs.coreutils}/bin/rm -f /run/sometimes-network-active
    ${nft} delete table inet sometimes_dns || true
    ${nft} delete table inet sometimes || true
    ${ip} -6 rule del priority 100 fwmark 0x5354 lookup 100 || true
    ${ip} -4 rule del priority 100 fwmark 0x5354 lookup 100 || true
    ${ip} -6 route del local ::/0 dev lo table 100 || true
    ${ip} -4 route del local 0.0.0.0/0 dev lo table 100 || true
  '';
in
{
  options.services.sometimes = {
    enable = lib.mkEnableOption "host-local TCP TPROXY and DNS interception";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.sometimes;
      description = "The packaged sometimes executable.";
    };
    configFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/sometimes/sometimes.toml";
      description = "Absolute path to the private TOML configuration outside the Nix store.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.hasPrefix "/" cfg.configFile && !(lib.hasPrefix "/nix/store/" cfg.configFile);
        message = "services.sometimes.configFile must be an absolute path outside the Nix store";
      }
    ];
    users.groups.sometimes = { };
    users.users.sometimes = {
      isSystemUser = true;
      group = "sometimes";
    };

    systemd.services.sometimes = {
      description = "Sometimes TPROXY client";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        User = "sometimes";
        Group = "sometimes";
        ExecStart = "${cfg.package}/bin/sometimes run --config ${cfg.configFile}";
        ExecStartPre = "${cfg.package}/bin/sometimes check --config ${cfg.configFile}";
        ExecStartPost = "+${networkUp}";
        ExecStop = "+${networkDown}";
        ExecStopPost = "+${networkDown}";
        AmbientCapabilities = "CAP_NET_ADMIN";
        CapabilityBoundingSet = "CAP_NET_ADMIN";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        UMask = "0077";
        Restart = "on-failure";
        RestartSec = "3s";
      };
    };
  };
}
