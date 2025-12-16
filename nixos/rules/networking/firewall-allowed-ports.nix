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
        fn =
          field:
          builtins.concatMap (
            { file, value }:
            lib.optional (value != [ ]) {
              location = file;
              evidence = "config.networking.firewall.${field} = ${
                lib.generators.toPretty { multiline = false; } value
              }";
              confidence = "high";
            }
          ) options.networking.firewall.${field}.definitionsWithLocations;
      in
      builtins.concatMap fn [
        "allowedUDPPorts"
        "allowedUDPPortRanges"
        "allowedTCPPorts"
        "allowedTCPPortRanges"
      ];
  };
}
