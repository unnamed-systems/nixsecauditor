{ self, ... }: { lib, config, ... }: {
  options = {

    nixsecauditor.tests = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
      default = { };
      example = lib.literalExpression ''
        {
          nixsecauditor-rule-tests = {
            modules = [ self.nixosModules.nixsecauditor-rules ]; 
          };
        }
      '';
      description = ''
        An attribute set where each key becomes an attribute in
        `perSystem.checks.<key>`, and its value is passed as arguments to
        `nixsecauditor.lib.checkTests`. The `system` from the current
        `perSystem` is added to those arguments automatically.
      '';
    };

  };

  config = {

    perSystem = { system, ... }: {
      checks = lib.mapAttrs (
        _name: args: self.lib.checkTests ({ inherit system; } // args)
      ) config.nixsecauditor.tests;
    };

  };
}
