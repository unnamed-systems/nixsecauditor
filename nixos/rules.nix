{ lib, config, ... }:
let
  ruleSubmodule = lib.types.submodule (
    { name, config, ... }:
    {
      options = {

        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
          example = false;
          description = ''
            Enable or disable this rule. When disabled the rule produces no
            findings and has no evaluation-time effect.
          '';
        };

        id = lib.mkOption {
          type = lib.types.str;
          default = name;
          readOnly = true;
          example = "cleartext-user-password";
          description = ''
            Unique, read-only identifier for the rule. Defaults to the attribute
            name under `security.nixsecauditor.rules`.
          '';
        };

        name = lib.mkOption {
          type = lib.types.str;
          apply = lib.trim;
          default = name;
          example = "Usage of cleartext user password instead of a hashed password";
          description = ''
            Short human-readable rule name. Shown in generated reports and in
            evaluation warnings or errors.
          '';
        };

        description = lib.mkOption {
          type = lib.types.coercedTo (lib.types.nullOr lib.types.str) (
            value: if value == null then "<not provided>" else value
          ) lib.types.str;
          apply = lib.trim;
          default = "<not provided>";
          example = ''
            Detects users whose configuration sets a password in
            `config.users.users.<name>.password` or `config.users.users.<name>.initialPassword`.
            Storing or distributing cleartext passwords in configuration files
            increases the risk of credential leakage and accidental disclosure,
            as such files are often shared, reviewed, or cached.
          '';
          description = ''
            Brief description of what the rule checks and why it matters.
            May include a short remediation hint or note about likely false
            positives. Keep it concise.
          '';
        };

        severity = lib.mkOption {
          type = lib.types.enum [
            "info"
            "low"
            "medium"
            "high"
            "critical"
            "unknown"
          ];
          default = "unknown";
          example = "critical";
          description = ''
            Severity assigned to findings from this rule. May be overridden per
            match. Use standard levels (info/low/medium/high/critical/unknown).
          '';
        };

        action = lib.mkOption {
          type = lib.types.enum [
            "log"
            "warn"
            "throw"
          ];
          default = "throw";
          example = "log";
          description = ''
            Default action for matches:
            - log: record only in the full audit reports;
            - warn: emit an evaluation-time warning (config.warnings);
            - throw: fail NixOS configuration evaluation (config.assertions).
            Can be overridden per match.
          '';
        };

        databases = allDatabases;

        urls = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          example = [ "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password" ];
          description = ''
            List of reference URLs (documentation, advisories or remediation
            guides) related to this rule.
          '';
        };

        matches = lib.mkOption {
          type = lib.types.listOf (matchSubmodule config);
          default = [ ];
          example = lib.literalExpression ''
            builtins.concatMap (
              { file, value }:
              builtins.concatLists (
                lib.mapAttrsToList (
                  username: user:
                  if user ? password && user.password != null then
                    [
                      {
                        location = file;
                        evidence = "config.users.users.''${lib.strings.escapeNixIdentifier username}.password = \"…\"";
                        confidence = "high";
                        urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password" ];
                        recommendation = '''
                          Replace the cleartext password with a hashed password option:
                          `config.users.users.''${lib.strings.escapeNixIdentifier username}.hashedPassword`
                          or `config.users.users.''${lib.strings.escapeNixIdentifier username}.hashedPasswordFile`.
                        ''';
                      }
                    ]
                  else if user ? initialPassword && user.initialPassword != null then
                    [
                      {
                        location = file;
                        evidence = "config.users.users.''${lib.strings.escapeNixIdentifier username}.initialPassword = \"…\"";
                        confidence = "high";
                        urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.users._name_.initialPassword" ];
                        recommendation = '''
                          Replace the cleartext password with a hashed initial password option:
                          `config.users.users.''${lib.strings.escapeNixIdentifier username}.initialHashedPassword`.
                        ''';
                      }
                    ]
                  else
                    [ ]
                ) value
              )
            ) options.users.users.definitionsWithLocations;
          '';
          description = ''
            Matches produced by this rule. Each match is a structured object
            (location, evidence, confidence, recommendation, databases, urls, action).
          '';
        };

      };
    }
  );

  matchSubmodule =
    ruleConfig:
    lib.types.submodule {
      options = {

        location = lib.mkOption {
          type = lib.types.coercedTo (lib.types.nullOr lib.types.str) (
            value: if value == null then "<not provided>" else value
          ) lib.types.str;
          apply = lib.trim;
          default = "<not provided>";
          example = "/etc/nixos/hardware-configuration.nix";
          description = ''
            Human-readable location where the finding was detected. Prefer precise
            references such as file paths.
          '';
        };

        evidence = lib.mkOption {
          type = lib.types.coercedTo (lib.types.nullOr lib.types.str) (
            value: if value == null then "<not provided>" else value
          ) lib.types.str;
          apply = lib.trim;
          default = "<not provided>";
          example = "config.users.users.root.password = \"…\"";
          description = ''
            Concise, non-sensitive snippet or summary that triggered the match.
            Must not contain secrets.
          '';
        };

        confidence = lib.mkOption {
          type = lib.types.enum [
            "low"
            "medium"
            "high"
          ];
          default = "high";
          example = "low";
          description = ''
            Confidence that the match represents a real issue:
            - low: likely needs manual review;
            - medium: probable issue;
            - high: confirmed or very likely.
          '';
        };

        recommendation = lib.mkOption {
          type = lib.types.coercedTo (lib.types.nullOr lib.types.str) (
            value: if value == null then "<not provided>" else value
          ) lib.types.str;
          apply = lib.trim;
          default = "<not provided>";
          example = ''
            Replace the cleartext password with a hashed password option:
            `config.users.users.root.hashedPassword`
            or `config.users.users.root.hashedPasswordFile`.
          '';
          description = ''
            Short, actionable remediation for this specific match.
          '';
        };

        # Additional fields to rule's ones

        severity = lib.mkOption {
          type = lib.types.enum [
            "info"
            "low"
            "medium"
            "high"
            "critical"
            "unknown"
          ];
          default = ruleConfig.severity;
          defaultText = lib.literalExpression "ruleConfig.severity";
          example = "critical";
          description = ''
            Optional per-match override of the rule's default severity.
          '';
        };

        action = lib.mkOption {
          type = lib.types.enum [
            "log"
            "warn"
            "throw"
          ];
          default = ruleConfig.action;
          example = "warn";
          description = ''
            Optional per-match override of the rule's default action.
          '';
        };

        databases = allDatabases;

        urls = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          example = [
            "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.initialPassword"
          ];
          description = ''
            Per-match reference URLs (advisories, fixes or documentation).
          '';
        };

      };
    };

  allDatabases = {
    cve = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "CVE-2025-12345" ];
      description = ''
        Optional list of CVE (Common Vulnerabilities and Exposures) identifiers related to this rule or match.
      '';
    };

    cwe = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "CWE-123" ];
      description = ''
        Optional list of CWE (Common Weakness Enumeration) identifiers related to this rule or match.
      '';
    };

    bdu = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "BDU:2025-12345" ];
      description = ''
        Optional list of BDU (Data Security Threats Database - БДУ ФСТЭК России) identifiers related to this rule or match.
      '';
    };

    cnnvd = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "CNNVD-2025-12345" ];
      description = ''
        Optional list of CNNVD (China National Vulnerability Database of Information Security - 国家信息安全漏洞库) identifiers related to this rule or match.
      '';
    };

    cnvd = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "CNVD-2025-12345" ];
      description = ''
        Optional list of CNVD (China National Vulnerability Database - 国家信息安全漏洞共享平台) identifiers related to this rule or match.
      '';
    };

    kev = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "KEV-2025-1234" ];
      description = ''
        Optional list of KEV (CISA Known Exploited Vulnerabilities) identifiers related to this rule or match.
      '';
    };

    edb = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "EDB-12345" ];
      description = ''
        Optional list of EDB (Exploit-DB) identifiers related to this rule or match.
      '';
    };

    ghsa = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "GHSA-xxxx-xxxx-xxxx" ];
      description = ''
        Optional list of GHSA (GitHub Security Advisories) identifiers related to this rule or match.
      '';
    };

    jvn = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "JVN#12345678" ];
      description = ''
        Optional list of JVN (Japan Vulnerability Notes - 日本脆弱性ノート) identifiers related to this rule or match.
      '';
    };

    oval = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "oval:org.mitre.oval:def:12345" ];
      description = ''
        Optional list of OVAL (Open Vulnerability and Assessment Language) identifiers related to this rule or match.
      '';
    };

    ics_cert = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "ICSA-12-123-12" ];
      description = ''
        Optional list of ICS-CERT (CISA Industrial Control Systems Cyber Emergency Response Team) identifiers related to this rule or match.
      '';
    };
  };
in
{
  options.security.nixsecauditor.rules = lib.mkOption {
    type = lib.types.attrsOf ruleSubmodule;
    default = { };
    example = lib.literalExpression ''
      {
        cleartext-user-password = {
          name = "Usage of cleartext user password instead of a hashed password";
          description = '''
            Detects users whose configuration sets a password in
            `config.users.users.<name>.password` or `config.users.users.<name>.initialPassword`.
            Storing or distributing cleartext passwords in configuration files
            increases the risk of credential leakage and accidental disclosure,
            as such files are often shared, reviewed, or cached.
          ''';
          databases.cwe = [ "CWE-260" ];

          severity = "high";
          action = "warn";

          matches = builtins.concatMap (
            { file, value }:
            builtins.concatLists (
              lib.mapAttrsToList (
                username: user:
                if user ? password && user.password != null then
                  [
                    {
                      location = file;
                      evidence = "config.users.users.''${lib.strings.escapeNixIdentifier username}.password = \"…\"";
                      confidence = "high";
                      urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password" ];
                      recommendation = '''
                        Replace the cleartext password with a hashed password option:
                        `config.users.users.''${lib.strings.escapeNixIdentifier username}.hashedPassword`
                        or `config.users.users.''${lib.strings.escapeNixIdentifier username}.hashedPasswordFile`.
                      ''';
                    }
                  ]
                else if user ? initialPassword && user.initialPassword != null then
                  [
                    {
                      location = file;
                      evidence = "config.users.users.''${lib.strings.escapeNixIdentifier username}.initialPassword = \"…\"";
                      confidence = "high";
                      urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.users._name_.initialPassword" ];
                      recommendation = '''
                        Replace the cleartext password with a hashed initial password option:
                        `config.users.users.''${lib.strings.escapeNixIdentifier username}.initialHashedPassword`.
                      ''';
                    }
                  ]
                else
                  [ ]
              ) value
            )
          ) options.users.users.definitionsWithLocations;
        };
      }
    '';
    description = ''
      Map of security rules evaluated by NixSecAuditor. Each rule is a
      submodule that defines metadata, severity, default action, references,
      and the matches it produces. Set `enable = false` to exclude a rule
      from evaluation and from generated reports.
    '';
  };
}
