{
  options,
  lib,
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
          lib.optional (user ? password && user.password != null) {
            id = "${username}_password";
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
          ++ lib.optional (user ? initialPassword && user.initialPassword != null) {
            id = "${username}_initialPassword";
            location = file;
            evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.initialPassword = \"…\"";
            confidence = "high";
            urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.users._name_.initialPassword" ];
            recommendation = ''
              Replace the cleartext password with a hashed initial password option:
              `config.users.users.${lib.strings.escapeNixIdentifier username}.initialHashedPassword`
            '';
          }
        ) value
      )
    ) options.users.users.definitionsWithLocations;

    tests = {

      non-empty-password = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "a";
        };
        expected = [ "alice_password" ];
      };

      empty-password = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "";
        };
        expected = [ "alice_password" ];
      };

      non-empty-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialPassword = "a";
        };
        expected = [ "alice_initialPassword" ];
      };

      empty-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialPassword = "";
        };
        expected = [ "alice_initialPassword" ];
      };

      null-password = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = null;
        };
        forbidden = [ ".*" ];
      };

      null-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialPassword = null;
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

      hashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";
        };
        forbidden = [ ".*" ];
      };

      initialHashedPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.initialHashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D";
        };
        forbidden = [ ".*" ];
      };

      hashedPasswordFile = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.hashedPasswordFile = builtins.toFile "hash" "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D.";
        };
        forbidden = [ ".*" ];
      };

      both-password-and-initialPassword = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "a";
          users.users.alice.initialPassword = "b";
        };
        expected = [ "alice_password" "alice_initialPassword" ];
      };

      complex = {
        module = {
          users.users.alice.isNormalUser = true;
          users.users.alice.password = "";

          users.users.bob.isNormalUser = true;
          users.users.bob.initialPassword = "b";

          users.users.eve.isNormalUser = true;
          users.users.eve.hashedPassword = "$y$j9T$p6gkCE7t.nOXtx.KToev91$i0MNI5lhjJGvhtW8yVO85mdBuRFb43.61JwQGjlaN.D.";
        };
        expected = [
          "alice_password"
          "bob_initialPassword"
        ];
        forbidden = [
          "alice_initialPassword"
          "bob_password"
          "eve_password"
          "eve_initialPassword"
        ];
      };

    };
  };
}
