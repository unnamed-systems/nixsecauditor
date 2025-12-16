{
  description = "Extensible rule-based static auditor for NixOS configuration code with multiple reporting outputs.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
    flake-compat = {
      url = "github:NixOS/flake-compat";
      flake = false;
    };
    git-hooks-nix.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    {
      flake-parts,
      systems,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import systems;

      imports = [
        inputs.git-hooks-nix.flakeModule
        ./pkgs/nixsecauditor-options
      ];

      flake = {
        nixosModules = {
          default = ./nixos/default.nix;
        };
      };

      perSystem =
        {
          system,
          pkgs,
          config,
          ...
        }:
        {
          pre-commit.settings = {
            src = ./.;
            hooks = {
              nixfmt-rfc-style.enable = true;

              nixsecauditor-generate-options = {
                enable = true;
                name = "NixSecAuditor generate options documentation";
                files = ".*";
                language = "system";
                entry =
                  (pkgs.writeShellScript "nixsecauditor-generate-options.sh" ''
                    cat $(nix build .#packages.${system}.nixsecauditor-options --print-out-paths --no-link) > ./options.md
                  '').outPath;
                stages = [ "pre-commit" ];
              };
            };
          };

          devShells = {
            default = config.pre-commit.devShell;
          };
        };
    };
}
