{ self, inputs, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    {
      packages.nixsecauditor-options = pkgs.callPackage (
        {
          lib,
          runCommand,
          nixosOptionsDoc,
          ...
        }:
        let
          eval = inputs.nixpkgs.lib.nixosSystem {
            modules = [
              self.nixosModules.default
              {
                _module.check = false;
                nixpkgs.hostPlatform = system;
                system.stateVersion = "26.05";
                disabledModules = [
                  (self.nixosModules.default + "/rules")
                ];
              }
            ];
          };

          root = toString ../..;

          transformDeclaration =
            decl:
            let
              declStr = toString (lib.filesystem.resolveDefaultNix decl);
              subpath = lib.removePrefix "/" (lib.removePrefix root declStr);
            in
            assert lib.hasPrefix root declStr;
            {
              url = "https://github.com/unnamed-systems/nixsecauditor/blob/master/${toString subpath}";
              name = subpath;
            };

          optionsDoc = nixosOptionsDoc {
            options.security.nixsecauditor = eval.options.security.nixsecauditor;
            documentType = "none";
            transformOptions = opt: opt // { declarations = map transformDeclaration opt.declarations; };
            #warningsAreErrors = false;
          };
        in
        runCommand "nixsecauditor-options.md" { } ''
          cat ${optionsDoc.optionsCommonMark} >> $out
        ''
      ) { };
    };
}
