{ lib, ... }:
{
  imports = [
    ./report
    ./rules
    ./findings.nix
    ./rules.nix
  ];
}
