{ inputs, ... }: {
  imports = [ inputs.nixsecauditor.flakeModules.tests ];

  nixsecauditor.tests = {
    nixsecauditor-rule-tests = {
      modules = [ ];
      allowMissingTests = false;
      disableBuiltinRules = false;
    };
  };
}
