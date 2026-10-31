{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.openssh-permit-root-login = {
    name = "Root login is permitted in OpenSSH";
    description = ''
      Detects when OpenSSH is configured to permit root login via
      `config.services.openssh.settings.PermitRootLogin`.
      Allowing direct root login increases the risk of unauthorized access.
    '';

    severity = "high";
    action = "warn";

    matches =
      if config.services.openssh.settings.PermitRootLogin == "yes" then
        [
          {
            id = "yes";
            location =
              (lib.findFirst ({ file, value }: value == "yes") { }
                options.services.openssh.settings.valueMeta.configuration.options.PermitRootLogin.definitionsWithLocations
              ).file or null;
            evidence = "config.services.openssh.settings.PermitRootLogin = \"yes\"";
            confidence = "high";
            recommendation = ''
              The safest option is to prevent direct root login entirely:
              `config.services.openssh.settings.PermitRootLogin = "no"`

              Alternatively, you can disallow password authentication for root while still
              permitting key-based login (less secure):
              `config.services.openssh.settings.PermitRootLogin = "prohibit-password"`
            '';
          }
        ]
      else if
        config.services.openssh.settings.PermitRootLogin == "prohibit-password"
        || config.services.openssh.settings.PermitRootLogin == "without-password"
      then
        [
          {
            id = "prohibit-password";
            location =
              (lib.findFirst ({ file, value }: value == config.services.openssh.settings.PermitRootLogin) { }
                options.services.openssh.settings.valueMeta.configuration.options.PermitRootLogin.definitionsWithLocations
              ).file or null;
            evidence = "config.services.openssh.settings.PermitRootLogin = \"${config.services.openssh.settings.PermitRootLogin}\"";
            confidence = "high";
            severity = "low";
            action = "log";
            recommendation = ''
              Preventing direct root login entirely is more secure:
              `config.services.openssh.settings.PermitRootLogin = "no"`
            '';
          }
        ]
      else
        [ ];

    tests = {

      permit-root-login-no = {
        module = {
          services.openssh.settings.PermitRootLogin = "no";
        };
        forbidden = [ ".*" ];
      };

      permit-root-login-forced-commands-only = {
        module = {
          services.openssh.settings.PermitRootLogin = "forced-commands-only";
        };
        forbidden = [ ".*" ];
      };

      permit-root-login-yes = {
        module = {
          services.openssh.settings.PermitRootLogin = "yes";
        };
        expected = [ "yes" ];
        forbidden = [ "prohibit-password" ];
      };

      permit-root-login-prohibit-password = {
        module = {
          services.openssh.settings.PermitRootLogin = "prohibit-password";
        };
        expected = [ "prohibit-password" ];
        forbidden = [ "yes" ];
      };

      permit-root-login-without-password = {
        module = {
          services.openssh.settings.PermitRootLogin = "without-password";
        };
        expected = [ "prohibit-password" ];
        forbidden = [ "yes" ];
      };

      ssh-disabled-permit-root-login-yes = {
        module = {
          services.openssh.enable = false;
          services.openssh.settings.PermitRootLogin = "yes";
        };
        expected = [ "yes" ];
      };

    };
  };
}
