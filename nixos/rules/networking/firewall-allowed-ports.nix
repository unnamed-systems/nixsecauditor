{
  options,
  lib,
  ...
}:
{
  config.security.nixsecauditor.rules.firewall-allowed-ports = {
    name = "Allowed firewall ports";
    description = ''
      Collects all allowed TCP/UDP ports and port ranges from
      `config.networking.firewall.*` and reports them as informational findings.
    '';

    severity = "info";
    action = "log";

    matches =
      let
        formatItem = item:
          if builtins.isAttrs item
          then "${toString item.from}-${toString item.to}"
          else toString item;

        fn =
          field:
          builtins.concatMap (
            { file, value }:
            map (item: {
              id = "${field}_${formatItem item}";
              location = file;
              evidence = "config.networking.firewall.${field} = ${
                lib.generators.toPretty { multiline = false; } [ item ]
              }";
              confidence = "high";
            }) value
          ) options.networking.firewall.${field}.definitionsWithLocations;
      in
      builtins.concatMap fn [
        "allowedUDPPorts"
        "allowedUDPPortRanges"
        "allowedTCPPorts"
        "allowedTCPPortRanges"
      ];

    tests = {

      no-ports = {
        forbidden = [ ".*" ];
      };

      empty-allowedTCPPorts = {
        module = {
          networking.firewall.allowedTCPPorts = [ ];
        };
        forbidden = [ ".*" ];
      };

      empty-allowedUDPPorts = {
        module = {
          networking.firewall.allowedUDPPorts = [ ];
        };
        forbidden = [ ".*" ];
      };

      empty-allowedTCPPortRanges = {
        module = {
          networking.firewall.allowedTCPPortRanges = [ ];
        };
        forbidden = [ ".*" ];
      };

      empty-allowedUDPPortRanges = {
        module = {
          networking.firewall.allowedUDPPortRanges = [ ];
        };
        forbidden = [ ".*" ];
      };

      allowedTCPPorts = {
        module = {
          networking.firewall.allowedTCPPorts = [ 22 80 443 ];
        };
        expected = [
          "allowedTCPPorts_22"
          "allowedTCPPorts_80"
          "allowedTCPPorts_443"
        ];
        forbidden = [
          "allowedUDPPorts_.*"
          "allowedTCPPortRanges_.*"
          "allowedUDPPortRanges_.*"
        ];
      };

      allowedUDPPorts = {
        module = {
          networking.firewall.allowedUDPPorts = [ 53 ];
        };
        expected = [ "allowedUDPPorts_53" ];
        forbidden = [
          "allowedTCPPorts_.*"
          "allowedTCPPortRanges_.*"
          "allowedUDPPortRanges_.*"
        ];
      };

      allowedTCPPortRanges = {
        module = {
          networking.firewall.allowedTCPPortRanges = [
            { from = 8000; to = 8100; }
          ];
        };
        expected = [ "allowedTCPPortRanges_8000-8100" ];
        forbidden = [
          "allowedTCPPorts_.*"
          "allowedUDPPorts_.*"
          "allowedUDPPortRanges_.*"
        ];
      };

      allowedUDPPortRanges = {
        module = {
          networking.firewall.allowedUDPPortRanges = [
            { from = 60000; to = 61000; }
          ];
        };
        expected = [ "allowedUDPPortRanges_60000-61000" ];
        forbidden = [
          "allowedTCPPorts_.*"
          "allowedUDPPorts_.*"
          "allowedTCPPortRanges_.*"
        ];
      };

      multiple-ports-in-one-list = {
        module = {
          networking.firewall.allowedTCPPorts = [ 22 80 ];
        };
        expected = [
          "allowedTCPPorts_22"
          "allowedTCPPorts_80"
        ];
      };

      multiple-ranges-in-one-list = {
        module = {
          networking.firewall.allowedTCPPortRanges = [
            { from = 8000; to = 8100; }
            { from = 9000; to = 9100; }
          ];
        };
        expected = [
          "allowedTCPPortRanges_8000-8100"
          "allowedTCPPortRanges_9000-9100"
        ];
      };

      firewall-disabled = {
        module = {
          networking.firewall.enable = false;
          networking.firewall.allowedTCPPorts = [ 22 ];
        };
        expected = [ "allowedTCPPorts_22" ];
      };

      complex = {
        module = {
          networking.firewall.allowedTCPPorts = [ 22 80 443 ];
          networking.firewall.allowedUDPPorts = [ 53 ];
          networking.firewall.allowedTCPPortRanges = [
            { from = 8000; to = 8100; }
          ];
          networking.firewall.allowedUDPPortRanges = [
            { from = 60000; to = 61000; }
          ];
        };
        expected = [
          "allowedTCPPorts_22"
          "allowedTCPPorts_80"
          "allowedTCPPorts_443"
          "allowedUDPPorts_53"
          "allowedTCPPortRanges_8000-8100"
          "allowedUDPPortRanges_60000-61000"
        ];
      };

    };
  };
}