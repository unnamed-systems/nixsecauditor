{ lib, ... }:
{
  imports = [
    ./report
    ./rules
    ./findings.nix
    ./rules.nix
  ];

  options.security.nixsecauditor.enable = lib.mkEnableOption "the impact of NixSecAuditor on evaluating a NixOS configuration";
}
