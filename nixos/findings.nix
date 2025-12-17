{ lib, config, ... }:
let
  cfg = config.security.nixsecauditor;
in
{
  options.security.nixsecauditor.findings = lib.mkOption {
    type = lib.types.listOf lib.types.anything;
    default = builtins.concatMap (
      rule:
      lib.optionals rule.enable (
        map (match: {
          inherit (rule)
            id
            name
            description
            ;
          inherit (match)
            location
            evidence
            confidence
            recommendation
            severity
            action
            ;
          databases = lib.mergeAttrsConcatenateValues rule.databases match.databases;
          urls = rule.urls ++ match.urls;
        }) rule.matches
      )
    ) (builtins.attrValues cfg.rules);
    readOnly = true;
    description = ''
      Aggregated list of findings from all matches of enabled rules.
    '';
  };
}
