{ lib, config, ... }:
let
  cfg = config.security.nixsecauditor;
in
{
  options.security.nixsecauditor.report.outPackages.markdown = lib.mkOption {
    type = lib.types.package;
    default = builtins.toFile "report.md" (
      let
        renderDatabases =
          databases:
          lib.concatStringsSep "\n" (
            lib.concatMap (
              k:
              let
                v = databases.${k};
              in
              lib.optional (v != [ ]) "- **${k}**: ${lib.concatStringsSep ", " v}"
            ) (builtins.attrNames databases)
          );

        renderUrls =
          urls: if urls == [ ] then "" else lib.concatMapStringsSep "\n" (u: "- [${u}](${u})") urls;

        renderFinding =
          x:
          ''
            ## ${x.name} (`${x.id}`)

            **Severity:** ${x.severity}  
            **Confidence:** ${x.confidence}  
            **Action:** ${x.action}

            **Location:**  
            `${x.location}`

            **Evidence:**  
            `${x.evidence}`

            **Description:**  
            ${x.description}

            **Recommendation:**  
            ${x.recommendation}
          ''
          + lib.optionalString (
            renderDatabases x.databases != ""
          ) "**Associated vulnerability databases:**\n${renderDatabases x.databases}\n"
          + lib.optionalString (x.urls != [ ]) "**References:**\n${renderUrls x.urls}\n";

        body = lib.concatMapStringsSep "\n---\n\n" renderFinding cfg.findings;
      in
      ''
        # NixSecAuditor Report

        Total findings: ${toString (builtins.length cfg.findings)}

        ${if body == "" then "_No findings detected._" else body}
      ''
    );
    defaultText = lib.literalExpression "builtins.toFile \"report.md\" …";
    readOnly = true;
    description = ''
      Human-readable Markdown report generated from `config.security.nixsecauditor.findings`, the aggregated list of matches from all enabled rules.
    '';

  };
}
