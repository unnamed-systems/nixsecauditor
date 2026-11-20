{
  config,
  lib,
  ...
}:
{
  config.security.nixsecauditor.rules.nixsecauditor-ignored = {
    name = "NixSecAuditor's `ignored` option";
    description = ''
      Ensures that `security.nixsecauditor.findings` forcibly sets the action for
      ignored matches to `"log"`.
    '';

    enable = false;
    matches = map (f: { id = "${f.match_id}-${f.action}"; }) config.security.nixsecauditor.findings;

    tests =
      let
        mk =
          module:
          lib.mkMerge [
            module
            {
              security.nixsecauditor.rules.test.matches = [
                {
                  id = "foo";
                  action = "log";
                }
                {
                  id = "hoge";
                  action = "log";
                }
                {
                  id = "bar";
                  action = "warn";
                }
                {
                  id = "fuga";
                  action = "warn";
                }
                {
                  id = "baz";
                  action = "throw";
                }
                {
                  id = "piyo";
                  action = "throw";
                }
              ];
            }
          ];
      in
      {

        first = {
          module = mk {
            security.nixsecauditor.ignored = [
              "test:foo"
              "test:fuga"
              "test:baz"
            ];
          };
          expected = [
            "foo-log"
            "hoge-log"
            "bar-warn"
            "fuga-log"
            "baz-log"
            "piyo-throw"
          ];
          forbidden = [
            "fuga-warn"
            "baz-throw"
          ];
        };

      };
  };
}
