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
                id = "${username}_${field}";
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

    tests = {

      non-empty-hashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";
        };
        expected = [ "alice_hashedPassword" ];
      };

      empty-hashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = "";
        };
        expected = [ "alice_hashedPassword" ];
      };

      non-empty-hashedPasswordFile = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPasswordFile = builtins.toFile "hash" "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";
        };
        expected = [ "alice_hashedPasswordFile" ];
      };

      empty-hashedPasswordFile = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPasswordFile = builtins.toFile "empty" "";
        };
        expected = [ "alice_hashedPasswordFile" ];
      };

      non-empty-initialHashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialHashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";
        };
        expected = [ "alice_initialHashedPassword" ];
      };

      empty-initialHashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialHashedPassword = "";
        };
        expected = [ "alice_initialHashedPassword" ];
      };

      null-hashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = null;
        };
        forbidden = [ ".*" ];
      };

      null-hashedPasswordFile = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPasswordFile = null;
        };
        forbidden = [ ".*" ];
      };

      null-initialHashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialHashedPassword = null;
        };
        forbidden = [ ".*" ];
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

      cleartext-password = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "a";
        };
        forbidden = [ ".*" ];
      };

      cleartext-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialPassword = "a";
        };
        forbidden = [ ".*" ];
      };

      complex = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";

          users.users.bob.isNormalUser = true;
          users.users.bob.initialHashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";

          users.users.carol.isNormalUser = true;
          users.users.carol.hashedPasswordFile = builtins.toFile "hash" "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";

          users.users.eve.isNormalUser = true;
          users.users.eve.password = "a";
        };
        expected = [
          "alice_hashedPassword"
          "bob_initialHashedPassword"
          "carol_hashedPasswordFile"
        ];
        forbidden = [
          "alice_hashedPasswordFile"
          "alice_initialHashedPassword"
          "bob_hashedPassword"
          "bob_hashedPasswordFile"
          "carol_hashedPassword"
          "carol_initialHashedPassword"
          "eve_hashedPassword"
          "eve_hashedPasswordFile"
          "eve_initialHashedPassword"
        ];
      };

    };
  };
}
