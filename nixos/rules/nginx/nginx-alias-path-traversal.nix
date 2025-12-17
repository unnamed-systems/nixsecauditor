{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.nginx-alias-path-traversal = {
    name = "NGINX alias path traversal due to unsafe location modifier and missing trailing slash";
    description = ''
      Detects NGINX configurations where the `alias` directive is used in a location block
      without a trailing slash. This can allow path traversal attacks, letting an attacker
      access files outside the intended directory.

      The rule checks location modifiers because:
      - `=` means an exact match and is safe.
      - `~` and `~*` mean regular expression matches and are not handled by this rule.
      - Locations without any modifier or with the `^~` modifier (prefix match stop) are not safe.

      Ensuring a trailing slash or using an exact match mitigates this risk.
    '';
    urls = [
      "https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md"
    ];

    severity = "high";
    action = "throw";

    matches =
      let
        forEachVirtualHost = fn: lib.mapAttrsToList fn options.services.nginx.virtualHosts.valueMeta.attrs;
        forEachLocation =
          fn:
          forEachVirtualHost (
            virtualHostName: virtualHost:
            lib.mapAttrsToList (fn virtualHostName virtualHost) virtualHost.configuration.options.locations.valueMeta.attrs
          );
      in
      lib.optionals config.services.nginx.enable (
        lib.concatLists (
          lib.concatLists (
            forEachLocation (
              virtualHostName: virtualHost: locationName: location:
              lib.optionals
                (
                  !lib.hasSuffix "/" locationName
                  && !lib.hasPrefix "=" locationName
                  && !lib.hasPrefix "~" locationName
                  && !lib.hasPrefix "~*" locationName
                )
                (
                  builtins.concatMap (
                    { file, value }:
                    lib.optional (value != null) {
                      location = file;
                      evidence =
                        "config.services.nginx.virtualHosts.${lib.strings.escapeNixIdentifier virtualHostName}"
                        + ".locations.${lib.strings.escapeNixIdentifier locationName}"
                        + ".alias = ${lib.generators.toPretty { } value}";
                      confidence = "high";
                      recommendation = ''
                        Add a trailing slash to the location path to prevent alias path traversal:
                        `${
                          "config.services.nginx.virtualHosts.${lib.strings.escapeNixIdentifier virtualHostName}"
                          + ".locations.${lib.strings.escapeNixIdentifier "${locationName}/"}"
                          + ".alias = ${lib.generators.toPretty { } value}"
                        }`
                        Alternatively, use an exact match modifier (`=`) for the location path if you want it to match the request path precisely:
                        `${
                          "config.services.nginx.virtualHosts.${lib.strings.escapeNixIdentifier virtualHostName}"
                          + ".locations.${lib.strings.escapeNixIdentifier "=${locationName}"}"
                          + ".alias = ${lib.generators.toPretty { } value}"
                        }`
                      '';
                    }
                  ) location.configuration.options.alias.definitionsWithLocations
                )
            )
          )
        )
      );
  };
}
