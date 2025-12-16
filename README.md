# NixSecAuditor

Extensible, rule-based static auditor for NixOS configuration code, with multiple reporting outputs (JSON, Markdown, evaluation-time warnings and assertions).

## Usage

For a full list of available NixOS module options, see [./options.md](./options.md).

## Installation

### With Flakes

Add `nixsecauditor` as a flake input and include the NixOS module in your system configuration:

```nix
{
  inputs.nixsecauditor.url = "github:yunfachi/NixSecAuditor";

  outputs = { nixpkgs, nixsecauditor, ... }:
    {
      nixosConfigurations.nixos = nixpkgs.lib.nixosSystem {
        modules = [
          # Other modules...
          nixsecauditor.nixosModules.default
        ];
      };
    };
}
```

Then, enable NixSecAuditor in your NixOS configuration:

```nix
{
  security.nixsecauditor.enable = true;
}
```

### Without Flakes

Import the module directly from the Git repository:

```nix
{ pkgs, lib, ... }:
let
  nixsecauditor = import (builtins.fetchGit {
    url = "https://github.com/yunfachi/NixSecAuditor";
  });
in 
{
  imports = [ nixsecauditor.nixosModules.default ];

  security.nixsecauditor.enable = true;
}
```

## License

This project is licensed under the [MIT License](./LICENSE).
