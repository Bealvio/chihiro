let
  cfg = {};
  getName = pkg: (builtins.parseDrvName (pkg.name or pkg.pname or "")).name;
in cfg // {
  allowUnfreePredicate =
    if cfg.allowUnfree or false then
      (_: true)
    else if (cfg.permittedUnfreePackages or []) != [] then
      (pkg: builtins.elem (getName pkg) (cfg.permittedUnfreePackages or []))
    else
      (_: false);
}