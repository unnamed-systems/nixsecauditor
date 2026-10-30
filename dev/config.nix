{ lib, ... }: {
  debug = true;

  systems = lib.systems.flakeExposed;

  imports = [
    ./parts/tests.nix
    ./parts/treefmt.nix
  ];
}
