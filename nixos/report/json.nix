{ lib, config, ... }:
let
  cfg = config.security.nixsecauditor;
in
{
  options.security.nixsecauditor.report.outPackages.json = lib.mkOption {
    type = lib.types.package;
    default = builtins.toFile "report.json" (builtins.toJSON cfg.findings);
    defaultText = lib.literalExpression "builtins.toFile \"report.json\" (builtins.toJSON config.security.nixsecauditor.findings)";
    readOnly = true;
    description = ''
      Machine-readable JSON report generated from `config.security.nixsecauditor.findings`, the aggregated list of matches from all enabled rules.
    '';
  };
}
