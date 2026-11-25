{ config, lib, ... }:
let
  esc = builtins.fromJSON ''"\u001b"'';

  stripAnsi =
    s:
    builtins.concatStringsSep "" (
      builtins.filter builtins.isString (builtins.split "${esc}\\[[0-9;]*m" s)
    );

  isNsa = s: lib.hasInfix "\nNixSecAuditor Finding\n" (stripAnsi s);

  field =
    k: clean:
    let
      ms = builtins.filter (x: x != null) (
        map (builtins.match "${k} *: (.*)") (lib.splitString "\n" clean)
      );
    in
    if ms == [ ] then null else builtins.head (builtins.head ms);

  parseMsg =
    s:
    let
      clean = stripAnsi s;
    in
    {
      name = field "Name" clean;
      uid = field "UID" clean;
      severity = field "Severity" clean;
      confidence = field "Confidence" clean;
      action = field "Action" clean;
    };

  warnings = map parseMsg (builtins.filter isNsa config.warnings);
  assertions = map parseMsg (
    map (a: a.message) (builtins.filter (a: !a.assertion && isNsa a.message) config.assertions)
  );
in
{
  config.security.nixsecauditor.rules.nixsecauditor-evaluation-time-report = {
    name = "NixSecAuditor's evaluation-time reporting corresponds to findings";
    description = ''
      Ensures that evaluation-time reports (warnings + assertions) emitted by
      `security.nixsecauditor.report.evaluation-time` correspond exactly to
      findings whose action is `warn` or `throw`.

      Findings whose action is `log` and ignored ones must NOT be reported.
    '';

    enable = false;
    matches =
      map (m: { id = "warning;${m.uid};${m.action};${m.severity};${m.confidence};${m.name}"; }) warnings
      ++ map (m: {
        id = "assertion;${m.uid};${m.action};${m.severity};${m.confidence};${m.name}";
      }) assertions;

    tests =
      let
        mk =
          module:
          lib.mkMerge [
            module
            {
              security.nixsecauditor.rules.test = {
                name = "test rule";
                severity = "info";

                matches = [
                  {
                    id = "foo";
                    action = "log";
                  }
                  {
                    id = "bar";
                    action = "warn";
                    confidence = "medium";
                    severity = "high";
                  }
                  {
                    id = "barbar";
                    action = "warn";
                  }
                  {
                    id = "baz";
                    action = "throw";
                  }
                  {
                    id = "bazbaz";
                    action = "log";
                  }
                ];

              };
            }
          ];

      in
      {
        mixed = {
          module = mk { };
          expected = [
            "warning;test:bar;warn;high;medium;test rule"
            "warning;test:barbar;warn;info;.+"
            "assertion;test:baz;throw;.+"
          ];
          forbidden = [
            "[^;];test:foo;log;.+"
            "[^;];test:bazbaz;log;.+"
          ];
        };

        only-reported = {
          module = mk {
            security.nixsecauditor.rules.test.matches = lib.mkForce [
              {
                id = "foo";
                action = "warn";
              }
              {
                id = "bar";
                action = "throw";
              }
            ];
          };
          expected = [
            "warning;test:foo;warn;.+"
            "assertion;test:bar;throw;.+"
          ];
        };

        only-silent = {
          module = mk {
            security.nixsecauditor = {
              rules.test.matches = lib.mkForce [
                {
                  id = "foo";
                  action = "log";
                }
                {
                  id = "bar";
                  action = "warn";
                }
                {
                  id = "baz";
                  action = "throw";
                }
              ];
              ignored = [
                "test:bar"
                "test:baz"
              ];
            };
          };
          expected = [ ];
          forbidden = [
            "[^;];test:foo;log;.+"
            "[^;];test:bar;log;.+"
            "[^;];test:baz;log;.+"
          ];
        };

        empty = {
          module = mk { security.nixsecauditor.rules.test.matches = lib.mkForce [ ]; };
          expected = [ ];
        };

        complex-name =
          let
            name = "abcdef ABCDEF 1234567890 !@#$%^&*()-+=?!+\\|/[]{};':\"><., abcdef";
          in
          {
            module = mk {
              security.nixsecauditor.rules.test = {
                name = lib.mkForce name;
                matches = lib.mkForce [
                  {
                    id = "test";
                    action = "throw";
                  }
                ];
              };
            };
            expected = [ "throw;test:test;[^;]*;[^;]*;[^;]*;${lib.escapeRegex name}" ];
          };
      };

  };
}
