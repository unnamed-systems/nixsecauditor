{
  options,
  lib,
  ...
}:
{
  config.security.nixsecauditor.rules.empty-user-password = {
    name = "Usage of empty user password";
    description = ''
      Detects users for which any of the following options under
      `config.users.users.<name>` is explicitly set to the empty string:
      `password`, `initialPassword`, `hashedPassword`, or
      `initialHashedPassword`.

      An empty password value is a strong indicator of a misconfiguration or a
      deployment mistake and may allow passwordless login. Note that this rule
      reports only the presence of an empty value in these specific options. It
      does not by itself prove that passwordless authentication is possible,
      since the effective login behavior also depends on:
      - other password-related options (e.g. `passwordFile`, `hashedPasswordFile`);
      - `config.users.mutableUsers` (when `true`, passwords can be changed at runtime);
      - the authentication stack of the services exposed on the host (e.g. whether
        SSH password authentication is enabled).

      This rule does not inspect empty values configured via
      `config.users.users.<name>.hashedPasswordFile`.
    '';

    severity = "critical";
    action = "warn";

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
                  id = "${username}_${field}";
                  location = file;
                  evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.${field} = \"\"";
                  confidence = "high";
                  recommendation = ''
                    Remove the empty value from
                    `config.users.users.${lib.strings.escapeNixIdentifier username}.${field}`
                    and provide real password via
                    `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPasswordFile`.

                    Prefer SSH keys or another strong authentication method over passwords.
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
