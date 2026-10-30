{
  lib,
  self,
  ...
}:
{
  checkTests =
    {
      system,
      modules ? [ ],
      configuration ? (
        lib.nixosSystem {
          modules = modules ++ [
            self.nixosModules.default
            { disabledModules = lib.optional disableBuiltinRules (self.nixosModules.default + "/rules"); }
            { nixpkgs.hostPlatform = system; }
          ];
        }
      ),
      allowMissingTests ? false,
      disableBuiltinRules ? true,
    }:
    let
      rules = configuration.config.security.nixsecauditor.rules;

      missingTests = lib.attrNames (lib.filterAttrs (_: rule: rule.tests == { }) rules);

      matchesAny = regexes: match_id: builtins.any (regex: builtins.match regex match_id != null) regexes;
      matchedByAny =
        match_ids: regex: builtins.any (match_id: builtins.match regex match_id != null) match_ids;

      evalTest =
        rule_name: rule: test_name: test:
        let
          matches =
            map (m: m.id)
              ((configuration.extendModules { modules = [ test.module ]; })
                .config.security.nixsecauditor.rules.${rule_name}
              ).matches;

          kind =
            id:
            if matchesAny test.forbidden id then
              "forbidden"
            else if matchesAny test.expected id then
              "expected"
            else
              "unexpected";

          byKind = lib.groupBy kind matches;
          valid = byKind.expected or [ ];
        in
        {
          name = "${rule_name}.tests.${test_name}";
          inherit matches;
          unexpected = byKind.unexpected or [ ];
          forbidden = byKind.forbidden or [ ];
          missing = builtins.filter (regex: !matchedByAny valid regex) test.expected;
        };

      failedTests = builtins.filter (t: t.missing != [ ] || t.unexpected != [ ] || t.forbidden != [ ]) (
        builtins.concatLists (
          lib.mapAttrsToList (
            rule_name: rule:
            lib.mapAttrsToList (test_name: test: evalTest rule_name rule test_name test) rule.tests
          ) rules
        )
      );

      ansi = {
        name = s: "[90m${s}[0m";
        passed = s: "[32m${s}[0m";
        forbidden = s: "[31m${s}[0m";
        forbidden_bold = s: "[1;31m${s}[0m";
        unexpected = s: "[38;5;214m${s}[0m";
        unexpected_bold = s: "[1;38;5;214m${s}[0m";
        missing = s: "[38;5;248m${s}[0m";
        missing_bold = s: "[1;38;5;248m${s}[0m";
      };

      list = xs: if xs == [ ] then "[ ]" else "[ ${builtins.concatStringsSep ", " xs} ]";

      formatFailure =
        test:
        let
          coloredMatch =
            id:
            if builtins.elem id test.forbidden then
              ansi.forbidden id
            else if builtins.elem id test.unexpected then
              ansi.unexpected id
            else
              ansi.passed id;

          problem =
            symbol: type: pad:
            lib.optional (
              test.${type} != [ ]
            ) "${ansi."${type}_bold" symbol} ${ansi.${type} type} ${pad}${list test.${type}}";

          body = [
            "  matches    ${list (map coloredMatch test.matches)}"
          ]
          ++ problem "?" "missing" "   "
          ++ problem "!" "unexpected" ""
          ++ problem "x" "forbidden" " ";
        in
        "${ansi.name "${test.name}:"}\n${builtins.concatStringsSep "\n" body}";

      problems =
        lib.optionals (!allowMissingTests) (map (t: "${ansi.name "${t}:"} no tests") missingTests)
        ++ map formatFailure failedTests;
    in
    {
      type = "derivation";
      name =
        if problems == [ ] then
          "passed"
        else
          throw ''
            The following NixSecAuditor rule tests failed:
            ${builtins.concatStringsSep "\n" problems}
          '';

      inherit failedTests missingTests;
    };
}
