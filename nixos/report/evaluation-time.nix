{ lib, config, ... }:
let
  cfg = config.security.nixsecauditor;
in
{
  options.security.nixsecauditor.report.evaluation-time.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    example = false;
    description = ''
      Enable or disable evaluation-time reporting of NixSecAuditor findings.

      When enabled:
        - `warn` findings produce NixOS evaluation warnings;
        - `throw` findings fail evaluation via assertions;
        - `log` findings are ignored during evaluation.

      When disabled, no warnings or errors are emitted, but all findings are still
      collected for full audit reports or external processing (e.g., CI pipelines).  
    '';
  };

  config =
    let
      formatFinding =
        finding:
        let
          indent =
            n: text:
            let
              pad = builtins.concatStringsSep "" (builtins.genList (_: " ") n);
            in
            builtins.concatStringsSep "\n" (map (line: pad + line) (lib.strings.splitString "\n" text));

          bold = s: "[1m${s}[0m";
          red = s: "[31m${s}[0m";
          green = s: "[32m${s}[0m";
          yellow = s: "[33m${s}[0m";
          blue = s: "[34m${s}[0m";
          magenta = s: "[35m${s}[0m";
          cyan = s: "[36m${s}[0m";
          gray = s: "[90m${s}[0m";

          colorSeverity =
            s:
            if s == "critical" then
              bold (red s)
            else if s == "high" then
              red s
            else if s == "medium" then
              yellow s
            else if s == "low" then
              green s
            else if s == "info" then
              blue s
            else
              gray s;

          colorConfidence =
            c:
            if c == "high" then
              red c
            else if c == "medium" then
              yellow c
            else if c == "low" then
              green c
            else
              gray c;

          colorAction =
            a:
            if a == "throw" then
              red a
            else if a == "warn" then
              yellow a
            else if a == "log" then
              blue a
            else
              gray a;
        in
        ''

          ${gray "──────────────────────────────────────────────────────────────"}
          ${bold "NixSecAuditor Finding"}

          ${bold "Name"}        : ${bold (cyan finding.name)}
          ${bold "Rule ID"}     : ${gray finding.id}
          ${bold "Severity"}    : ${colorSeverity finding.severity}
          ${bold "Confidence"}  : ${colorConfidence finding.confidence}
          ${bold "Action"}      : ${colorAction finding.action}

          ${bold "Location:"}
          ${indent 2 (bold (magenta finding.location))}

          ${bold "Evidence:"}
          ${indent 2 (finding.evidence)}

          ${bold "Description:"}
          ${indent 2 (finding.description)}

          ${bold "Recommendation:"}
          ${indent 2 (finding.recommendation)}
          ${gray "──────────────────────────────────────────────────────────────"}
        '';
    in
    {
      assertions = builtins.concatMap (
        finding:
        lib.optional (finding.action == "throw") {
          assertion = false;
          message = formatFinding finding;
        }
      ) cfg.findings;

      warnings = builtins.concatMap (
        finding: lib.optional (finding.action == "warn") (formatFinding finding)
      ) cfg.findings;
    };
}
