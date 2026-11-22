{ config, lib, ... }: {
  config.security.nixsecauditor.rules.nixsecauditor-disabled-rules = {
    name = "NixSecAuditor's disabled rules";
    description = ''
      Ensures that findings from disabled rules are not included in
      `security.nixsecauditor.findings`.
    '';

    enable = false;
    matches = map (f: { id = f.uid; }) config.security.nixsecauditor.findings;

    tests =
      let
        mk =
          enableDisabledRule:
          lib.mkMerge [
            {
              security.nixsecauditor.rules.test-enabled = {
                enable = true;
                matches = [
                  {
                    id = "foo";
                    action = "log";
                  }
                  {
                    id = "baz";
                    action = "log";
                  }
                ];
              };

              security.nixsecauditor.rules.test-disabled = {
                enable = enableDisabledRule;
                matches = [
                  {
                    id = "bar";
                    action = "log";
                  }
                  {
                    id = "baz";
                    action = "log";
                  }
                ];
              };
            }
          ];
      in
      {
        disabled = {
          module = mk false;
          expected = [
            "test-enabled:foo"
            "test-enabled:baz"
          ];
          forbidden = [
            "test-disabled:bar"
            "test-disabled:baz"
          ];
        };

        enabled = {
          module = mk true;
          expected = [
            "test-enabled:foo"
            "test-enabled:baz"
            "test-disabled:bar"
            "test-disabled:baz"
          ];
        };
      };
  };
}
