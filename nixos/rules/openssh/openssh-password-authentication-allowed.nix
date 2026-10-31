{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.openssh-password-authentication-allowed = {
    name = "Password authentication in OpenSSH is allowed";
    description = ''
      Detects when OpenSSH password authentication is enabled via
      `config.services.openssh.settings.PasswordAuthentication` and
      OpenSSH is active (`config.services.openssh.enable = true`).
      Enabling password-based logins increases the attack surface,
      making brute-force and credential-stuffing attacks more feasible.
      Key-based authentication is recommended for improved security.
    '';

    severity = "high";
    action = "warn";

    matches =
      lib.optional
        (config.services.openssh.enable && config.services.openssh.settings.PasswordAuthentication == true)
        {
          location =
            (lib.findFirst ({ file, value }: value == true) { }
              options.services.openssh.settings.valueMeta.configuration.options.PasswordAuthentication.definitionsWithLocations
            ).file or null;
          evidence = "config.services.openssh.settings.PasswordAuthentication = true";
          confidence = "high";
          recommendation = ''
            Disable password authentication and use key-based authentication:
            `config.services.openssh.settings.PasswordAuthentication = false`
          '';
        };

    tests = {

      ssh-disabled = {
        forbidden = [ ".*" ];
      };

      ssh-disabled-password-authentication-enabled = {
        module = {
          services.openssh.enable = false;
          services.openssh.settings.PasswordAuthentication = true;
        };
        forbidden = [ ".*" ];
      };

      ssh-enabled-password-authentication-default = {
        module = {
          services.openssh.enable = true;
        };
        expected = [ "match" ];
      };

      ssh-enabled-password-authentication-enabled = {
        module = {
          services.openssh.enable = true;
          services.openssh.settings.PasswordAuthentication = true;
        };
        expected = [ "match" ];
      };

      ssh-enabled-password-authentication-disabled = {
        module = {
          services.openssh.enable = true;
          services.openssh.settings.PasswordAuthentication = false;
        };
        forbidden = [ ".*" ];
      };

      ssh-enabled-password-authentication-null = {
        module = {
          services.openssh.enable = true;
          services.openssh.settings.PasswordAuthentication = null;
        };
        forbidden = [ ".*" ];
      };

    };
  };
}