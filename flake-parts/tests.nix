{ self, ... }: { lib, config, ... }: {
  options = {

    nixsecauditor.tests = lib.mkOption {
      type = lib.types.submodule {
        freeformType = lib.types.attrsOf lib.types.anything;

        options.checkName = lib.mkOption {
          type = lib.types.str;
          default = "nixsecauditor-rules-tests";
          description = ''
            Used as the attribute name in `perSystem.checks.<checkName>`. The check is
            built by `nix flake check`.
          '';
        };
      };
      default = { };
      example = lib.literalExpression ''
        {
          modules = [ self.nixosModules.nixsecauditor-rules ]; 
        }
      '';
      description = ''
        Arguments that are passed into the `nixsecauditor.lib.checkTests`. The
        `checkName` option is removed before the call, and `system` is added from the
        current `perSystem`.
      '';
    };

  };

  config = {

    perSystem = { system, ... }: {
      checks.${config.nixsecauditor.tests.checkName} = self.lib.checkTests (
        (removeAttrs config.nixsecauditor.tests [ "checkName" ]) // { inherit system; }
      );
    };

  };
}
