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

    tests = {

      empty-password = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "";
        };
        expected = [ "alice_password" ];
      };

      empty-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialPassword = "";
        };
        expected = [ "alice_initialPassword" ];
      };

      empty-hashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = "";
        };
        expected = [ "alice_hashedPassword" ];
      };

      empty-initialHashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialHashedPassword = "";
        };
        expected = [ "alice_initialHashedPassword" ];
      };

      no-user = {
        forbidden = [ ".*" ];
      };

      no-password = {
        module = {
          users.users.alice.isNormalUser = true;
        };
        forbidden = [ ".*" ];
      };

      non-empty-password = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "a";
        };
        forbidden = [ ".*" ];
      };

      non-empty-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialPassword = "a";
        };
        forbidden = [ ".*" ];
      };

      non-empty-hashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = "a";
        };
        forbidden = [ ".*" ];
      };

      non-empty-initialHashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialHashedPassword = "a";
        };
        forbidden = [ ".*" ];
      };

      empty-hashedPasswordFile = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPasswordFile = builtins.toFile "empty" "a";
        };
        forbidden = [ ".*" ];
      };

      complex = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "";

          users.users.bob.isNormalUser = true;
          users.users.bob.password = "a";
        };
        expected = [ "alice_password" ];
        forbidden = [ "bob_password" ];
      };

    };
  };
}
