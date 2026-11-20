{ inputs, ... }: {
  imports = [ inputs.nixsecauditor.flakeModules.tests ];

  nixsecauditor.tests = {
    nixsecauditor-rule-tests = {
      modules = [ ];
      allowMissingTests = false;
      disableBuiltinRules = false;
    };

    nixsecauditor-integration-tests = {
      modules = [ inputs.nixsecauditor.nixosModules.integrationTestRules ];
      allowMissingTests = false;
      disableBuiltinRules = true;
    };
  };
}
