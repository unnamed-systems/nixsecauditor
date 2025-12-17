{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.cleartext-user-password = {
    name = "Usage of cleartext user password instead of a hashed password";
    description = ''
      Detects users whose configuration sets a password in
      `config.users.users.<name>.password` or `config.users.users.<name>.initialPassword`.
      Storing or distributing cleartext passwords in configuration files
      increases the risk of credential leakage and accidental disclosure,
      as such files are often shared, reviewed, or cached.
    '';
    databases.cwe = [ "CWE-260" ];

    severity = "high";
    action = "warn";

    matches = builtins.concatMap (
      { file, value }:
      builtins.concatLists (
        lib.mapAttrsToList (
          username: user:
          if user ? password && user.password != null then
            [
              {
                location = file;
                evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.password = \"…\"";
                confidence = "high";
                urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password" ];
                recommendation = ''
                  Replace the cleartext password with a hashed password option:
                  `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPassword`
                  or `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPasswordFile`.
                '';
              }
            ]
          else if user ? initialPassword && user.initialPassword != null then
            [
              {
                location = file;
                evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.initialPassword = \"…\"";
                confidence = "high";
                urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.users._name_.initialPassword" ];
                recommendation = ''
                  Replace the cleartext password with a hashed initial password option:
                  `config.users.users.${lib.strings.escapeNixIdentifier username}.initialHashedPassword`
                '';
              }
            ]
          else
            [ ]
        ) value
      )
    ) options.users.users.definitionsWithLocations;
  };
}
