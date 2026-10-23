{
  options,
  lib,
  ...
}:
{
  config.security.nixsecauditor.rules.empty-user-password = {
    name = "Usage of empty user password";
    description = ''
      Detects users whose configuration sets an empty password in
      `config.users.users.<name>.password`, `config.users.users.<name>.initialPassword`,
      `config.users.users.<name>.hashedPassword`, or `config.users.users.<name>.initialHashedPassword`.
      Empty passwords allow passwordless login and are a common misconfiguration or
      deployment mistake that can expose a system to unauthorized access.
      This rule does not detect empty passwords configured via
      `config.users.users.<name>.hashedPasswordFile`.
    '';

    severity = "critical";
    action = "throw";

    matches = builtins.concatMap (
      { file, value }:
      builtins.concatLists (
        lib.mapAttrsToList (
          username: user:
          builtins.concatMap
            (
              field:
              lib.optional
                (
                  let
                    v = user.${field} or null;
                  in
                  builtins.isString v && v == ""
                )
                {
                  location = file;
                  evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.${field} = \"\"";
                  confidence = "high";
                  recommendation = ''
                    Remove the empty password and either set a strong password or disable password authentication for this account:
                    `config.users.users.${lib.strings.escapeNixIdentifier username}.${field} = null`
                    and prefer SSH keys or another strong authentication method instead.
                  '';
                }
            )
            [
              "password"
              "initialPassword"
              "hashedPassword"
              "initialHashedPassword"
            ]
        ) value
      )
    ) options.users.users.definitionsWithLocations;
  };

  # tests = {
  #   positive = map (lib.recursiveUpdate { users.users.alice.isNormalUser = true; }) [
  #     { users.users.alice.password = ""; }
  #     { users.users.alice.initialPassword = ""; }
  #     { users.users.alice.hashedPassword = ""; }
  #     { users.users.alice.initialHashedPassword = ""; }
  #   ];
  #   negative = [
  #     { }
  #   ]
  #   ++ map (lib.recursiveUpdate { users.users.alice.isNormalUser = true; }) [
  #     { }
  #     { users.users.alice.password = "a"; }
  #     { users.users.alice.initialPassword = "a"; }
  #     { users.users.alice.hashedPassword = "a"; }
  #     { users.users.alice.initialHashedPassword = "a"; }
  #     { users.users.alice.initialHashedPassword = "a"; }
  #     { users.users.alice.hashedPasswordFile = builtins.toFile "empty" ""; }
  #   ];
  # };
}
