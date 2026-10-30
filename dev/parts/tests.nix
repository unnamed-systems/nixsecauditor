{ inputs, ... }: {
  imports = [ inputs.nixsecauditor.flakeModules.tests ];

  nixsecauditor.tests = {
    modules = [ inputs.nixsecauditor.nixosModules.default ];
    allowMissingTests = false;
    disableBuiltinRules = false;
  };
}
