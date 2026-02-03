{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.hashed-user-password = {
    name = "Usage of hashed user password";
    description = ''
      Detects users whose configuration sets a password in
      `config.users.users.<name>.hashedPassword`, `config.users.users.<name>.hashedPasswordFile`,
      or "initialHashedPassword".
    '';

    severity = "info";
    action = "log";

    matches = builtins.concatMap (
      { file, value }:
      builtins.concatLists (
        lib.mapAttrsToList (
          username: user:
          builtins.concatMap
            (
              field:
              (lib.optional (user.${field} or null != null) {
                location = file;
                evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.${field} = \"…\"";
                confidence = "high";
              })
            )
            [
              "hashedPassword"
              "hashedPasswordFile"
              "initialHashedPassword"
            ]
        ) value
      )
    ) options.users.users.definitionsWithLocations;
  };
}
