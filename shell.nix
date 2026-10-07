# Development shell: nix-shell --run 'make check'.
{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  packages = [ pkgs.python3 ];
}
