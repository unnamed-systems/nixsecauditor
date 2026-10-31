{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.openssh-permit-empty-passwords = {
    name = "Empty passwords are permitted in OpenSSH";
    description = ''
      Detects when OpenSSH is configured to permit empty passwords via
      `config.services.openssh.settings.PermitEmptyPasswords`.
      Allowing empty passwords is highly insecure, because it permits login
      to users that have no password set.
    '';

    severity = "critical";
    action = "throw";

    matches =
      # "no" is the default value in OpenSSH
      if config.services.openssh.settings.PermitEmptyPasswords or "no" == "yes" then
        [
          {
            location =
              (lib.findFirst (
                { file, value }: value.PermitEmptyPasswords or "no" == "yes"
              ) { } options.services.openssh.settings.definitionsWithLocations).file or null;
            evidence = "config.services.openssh.settings.PermitEmptyPasswords = \"yes\"";
            confidence = "high";
            recommendation = ''
              Disallow empty passwords by setting:
              `config.services.openssh.settings.PermitEmptyPasswords = "no"`
            '';
          }
        ]
      else
        [ ];

    tests = {

      no-module = {
        forbidden = [ ".*" ];
      };

      permit-empty-passwords-no = {
        module = {
          services.openssh.settings.PermitEmptyPasswords = "no";
        };
        forbidden = [ ".*" ];
      };

      permit-empty-passwords-yes = {
        module = {
          services.openssh.settings.PermitEmptyPasswords = "yes";
        };
        expected = [ "match" ];
      };

      ssh-enabled-permit-empty-passwords-no = {
        module = {
          services.openssh.enable = true;
          services.openssh.settings.PermitEmptyPasswords = "no";
        };
        forbidden = [ ".*" ];
      };

      ssh-enabled-permit-empty-passwords-yes = {
        module = {
          services.openssh.enable = true;
          services.openssh.settings.PermitEmptyPasswords = "yes";
        };
        expected = [ "match" ];
      };

      ssh-disabled-permit-empty-passwords-yes = {
        module = {
          services.openssh.enable = false;
          services.openssh.settings.PermitEmptyPasswords = "yes";
        };
        expected = [ "match" ];
      };

    };
  };
}