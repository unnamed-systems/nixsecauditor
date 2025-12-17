{ lib, ... }:
{
  imports = builtins.filter (path: path != ./default.nix) (lib.fileset.toList ./.);
}
