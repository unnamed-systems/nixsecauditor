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
              virtualHostName: _virtualHost: locationName: location:
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
                      id = "${virtualHostName}_${locationName}";
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

    tests = {

      nginx-disabled = {
        module = {
          services.nginx.enable = false;
          services.nginx.virtualHosts.example.locations."/foo".alias = "/var/www";
        };
        forbidden = [ ".*" ];
      };

      no-virtual-hosts = {
        module = {
          services.nginx.enable = true;
        };
        forbidden = [ ".*" ];
      };

      no-locations = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.serverName = "example.com";
        };
        forbidden = [ ".*" ];
      };

      no-alias = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."/foo".proxyPass = "http://localhost:8080";
        };
        forbidden = [ ".*" ];
      };

      alias-at-root = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."/".alias = "/var/www/";
        };
        forbidden = [ ".*" ];
      };

      alias-with-trailing-slash = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."/foo/".alias = "/var/www/";
        };
        forbidden = [ ".*" ];
      };

      alias-with-exact-match = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."=/foo".alias = "/var/www";
        };
        forbidden = [ ".*" ];
      };

      alias-with-regex-match = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."~/foo".alias = "/var/www";
        };
        forbidden = [ ".*" ];
      };

      alias-with-regex-case-insensitive-match = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."~*/foo".alias = "/var/www";
        };
        forbidden = [ ".*" ];
      };

      alias-without-trailing-slash = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."/foo".alias = "/var/www";
        };
        expected = [ "example_/foo" ];
      };

      alias-with-prefix-match-modifier = {
        module = {
          services.nginx.enable = true;
          services.nginx.virtualHosts.example.locations."^~/foo".alias = "/var/www";
        };
        expected = [ "example_\\^~/foo" ];
      };

      complex = {
        module = {
          services.nginx.enable = true;

          services.nginx.virtualHosts.example.locations."/safe/".alias = "/var/www/safe";
          services.nginx.virtualHosts.example.locations."=/exact".alias = "/var/www/exact";
          services.nginx.virtualHosts.example.locations."~/regex".alias = "/var/www/regex";
          services.nginx.virtualHosts.example.locations."~*/regex-ci".alias = "/var/www/regex-ci";
          services.nginx.virtualHosts.example.locations."/unsafe".alias = "/var/www/unsafe";
          services.nginx.virtualHosts.example.locations."^~/unsafe2".alias = "/var/www/unsafe2";

          services.nginx.virtualHosts.other.locations."/unsafe3".alias = "/var/www/unsafe3";
          services.nginx.virtualHosts.other.locations."/safe2/".alias = "/var/www/safe2";
        };
        expected = [
          "example_/unsafe"
          "example_\\^~/unsafe2"
          "other_/unsafe3"
        ];
        forbidden = [
          "example_/safe/"
          "example_=/exact"
          "example_~/regex"
          "example_~*/regex-ci"
          "other_/safe2/"
        ];
      };

    };
  };
}