{pkgs, config, ...}: {
  name = "slib";
  compiler-nix-name = "ghc982"; # Version of GHC to use

  modules = [
# -fwrite-ide-info
# -hiedir .hiefiles
# -hidir .hifiles
  ];

  # Tools to include in the development shell
  shell.tools.cabal = "latest";
  shell.tools.hlint = "latest";
  shell.tools.haskell-language-server = "latest";
  shell.tools.hoogle = "latest";
  shell.tools.fourmolu = "latest";
  shell.withHoogle = true;
  shell.packages = ps: builtins.attrValues (pkgs.haskell-nix.haskellLib.selectProjectPackages ps);
  shell.nativeBuildInputs = [
    pkgs.buildPackages.cabalWrapped
    pkgs.ghciwatch
    pkgs.awscli2
    pkgs.postgresql_16
  ];
}
