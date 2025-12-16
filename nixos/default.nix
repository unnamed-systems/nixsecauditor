{ lib, ... }:
{
  imports = [
    ./findings.nix
    ./rules.nix
  ]
  ++ lib.fileset.toList ./report
  ++ lib.fileset.toList ./rules;
}
