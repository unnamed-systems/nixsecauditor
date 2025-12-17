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
  };
}
