{ lib, config, ... }:
let
  cfg = config.security.nixsecauditor;
in
{
  options.security.nixsecauditor = {
    ignored = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "empty-user-password:alice"
        "empty-user-password:nixos"
      ];
      description = ''
        List of unique finding IDs whose action should be forcibly set to "log".
      '';
    };

    findings = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = builtins.concatMap (
        rule:
        lib.optionals rule.enable (
          map (match: {
            inherit (rule)
              name
              description
              ;
            rule_id = rule.id;
            inherit (match)
              location
              evidence
              confidence
              recommendation
              severity
              ;
            match_id = match;
            uid = "${rule.id}:${match.id}";
            action = if builtins.elem cfg.ignored "${rule.id}:${match.id}" then "log" else match.action;
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
  };
}
