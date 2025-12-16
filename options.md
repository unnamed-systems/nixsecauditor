## security\.nixsecauditor\.findings

Aggregated list of findings from all matches of enabled rules\.



*Type:*
list of anything *(read only)*



*Default:*
` [ ] `

*Declared by:*
 - [nixos/findings\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/findings.nix)



## security\.nixsecauditor\.report\.evaluation-time\.enable



Enable or disable evaluation-time reporting of NixSecAuditor findings\.

When enabled:

 - ` warn ` findings produce NixOS evaluation warnings;
 - ` throw ` findings fail evaluation via assertions;
 - ` log ` findings are ignored during evaluation\.

When disabled, no warnings or errors are emitted, but all findings are still
collected for full audit reports or external processing (e\.g\., CI pipelines)\.



*Type:*
boolean



*Default:*
` true `



*Example:*
` false `

*Declared by:*
 - [nixos/report/evaluation-time\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/report/evaluation-time.nix)



## security\.nixsecauditor\.report\.outPackages\.json



Machine-readable JSON report generated from ` config.security.nixsecauditor.findings `, the aggregated list of matches from all enabled rules\.



*Type:*
package *(read only)*



*Default:*
` "/nix/store/v9xp7hz2bdxcgjcg6xslpgasxsk84nnk-report.json" `

*Declared by:*
 - [nixos/report/json\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/report/json.nix)



## security\.nixsecauditor\.report\.outPackages\.markdown



Human-readable Markdown report generated from ` config.security.nixsecauditor.findings `, the aggregated list of matches from all enabled rules\.



*Type:*
package *(read only)*



*Default:*
` "/nix/store/f0jdkrjj1sh4zfhfkd1yw1z3h85bqvki-report.md" `

*Declared by:*
 - [nixos/report/markdown\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/report/markdown.nix)



## security\.nixsecauditor\.rules



Map of security rules evaluated by NixSecAuditor\. Each rule is a
submodule that defines metadata, severity, default action, references,
and the matches it produces\. Set ` enable = false ` to exclude a rule
from evaluation and from generated reports\.



*Type:*
attribute set of (submodule)



*Default:*
` { } `



*Example:*

````
{
  cleartext-user-password = {
    name = "Usage of cleartext user password instead of a hashed password";
    description = ''
      Detects users whose configuration sets a password in
      `config.users.users.<name>.password` or `config.users.users.<name>.initialPassword`.
      Storing or distributing cleartext passwords in configuration files
      increases the risk of credential leakage and accidental disclosure,
      as such files are often shared, reviewed, or cached.
    '';
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
                evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.password = \"…\"";
                confidence = "high";
                urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password" ];
                recommendation = ''
                  Replace the cleartext password with a hashed password option:
                  `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPassword`
                  or `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPasswordFile`.
                '';
              }
            ]
          else if user ? initialPassword && user.initialPassword != null then
            [
              {
                location = file;
                evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.initialPassword = \"…\"";
                confidence = "high";
                urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.users._name_.initialPassword" ];
                recommendation = ''
                  Replace the cleartext password with a hashed initial password option:
                  `config.users.users.${lib.strings.escapeNixIdentifier username}.initialHashedPassword`.
                '';
              }
            ]
          else
            [ ]
        ) value
      )
    ) options.users.users.definitionsWithLocations;
  };
}

````

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.enable



Enable or disable this rule\. When disabled the rule produces no
findings and has no evaluation-time effect\.



*Type:*
boolean



*Default:*
` true `



*Example:*
` false `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.action



Default action for matches:

 - log: record only in the full audit reports;
 - warn: emit an evaluation-time warning (config\.warnings);
 - throw: fail NixOS configuration evaluation (config\.assertions)\.
   Can be overridden per match\.



*Type:*
one of “log”, “warn”, “throw”



*Default:*
` "throw" `



*Example:*
` "log" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.bdu



Optional list of BDU (Data Security Threats Database - БДУ ФСТЭК России) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "BDU:2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.cnnvd



Optional list of CNNVD (China National Vulnerability Database of Information Security - 国家信息安全漏洞库) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CNNVD-2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.cnvd



Optional list of CNVD (China National Vulnerability Database - 国家信息安全漏洞共享平台) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CNVD-2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.cve



Optional list of CVE (Common Vulnerabilities and Exposures) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CVE-2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.cwe



Optional list of CWE (Common Weakness Enumeration) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CWE-123"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.edb



Optional list of EDB (Exploit-DB) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "EDB-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.ghsa



Optional list of GHSA (GitHub Security Advisories) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "GHSA-xxxx-xxxx-xxxx"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.ics_cert



Optional list of ICS-CERT (CISA Industrial Control Systems Cyber Emergency Response Team) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "ICSA-12-123-12"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.jvn



Optional list of JVN (Japan Vulnerability Notes - 日本脆弱性ノート) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "JVN#12345678"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.kev



Optional list of KEV (CISA Known Exploited Vulnerabilities) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "KEV-2025-1234"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.databases\.oval



Optional list of OVAL (Open Vulnerability and Assessment Language) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "oval:org.mitre.oval:def:12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.description



Brief description of what the rule checks and why it matters\.
May include a short remediation hint or note about likely false
positives\. Keep it concise\.



*Type:*
string



*Default:*
` "<not provided>" `



*Example:*

````
''
  Detects users whose configuration sets a password in
  `config.users.users.<name>.password` or `config.users.users.<name>.initialPassword`.
  Storing or distributing cleartext passwords in configuration files
  increases the risk of credential leakage and accidental disclosure,
  as such files are often shared, reviewed, or cached.
''
````

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.id



Unique, read-only identifier for the rule\. Defaults to the attribute
name under ` security.nixsecauditor.rules `\.



*Type:*
string *(read only)*



*Default:*
` "‹name›" `



*Example:*
` "cleartext-user-password" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches



Matches produced by this rule\. Each match is a structured object
(location, evidence, confidence, recommendation, databases, urls, action)\.



*Type:*
list of (submodule)



*Default:*
` [ ] `



*Example:*

````
builtins.concatMap (
  { file, value }:
  builtins.concatLists (
    lib.mapAttrsToList (
      username: user:
      if user ? password && user.password != null then
        [
          {
            location = file;
            evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.password = \"…\"";
            confidence = "high";
            urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password" ];
            recommendation = ''
              Replace the cleartext password with a hashed password option:
              `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPassword`
              or `config.users.users.${lib.strings.escapeNixIdentifier username}.hashedPasswordFile`.
            '';
          }
        ]
      else if user ? initialPassword && user.initialPassword != null then
        [
          {
            location = file;
            evidence = "config.users.users.${lib.strings.escapeNixIdentifier username}.initialPassword = \"…\"";
            confidence = "high";
            urls = [ "https://nixos.org/manual/nixos/stable/options#opt-users.users._name_.initialPassword" ];
            recommendation = ''
              Replace the cleartext password with a hashed initial password option:
              `config.users.users.${lib.strings.escapeNixIdentifier username}.initialHashedPassword`.
            '';
          }
        ]
      else
        [ ]
    ) value
  )
) options.users.users.definitionsWithLocations;

````

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.action



Optional per-match override of the rule’s default action\.



*Type:*
one of “log”, “warn”, “throw”



*Default:*
` "throw" `



*Example:*
` "warn" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.confidence



Confidence that the match represents a real issue:

 - low: likely needs manual review;
 - medium: probable issue;
 - high: confirmed or very likely\.



*Type:*
one of “low”, “medium”, “high”



*Default:*
` "high" `



*Example:*
` "low" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.bdu



Optional list of BDU (Data Security Threats Database - БДУ ФСТЭК России) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "BDU:2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.cnnvd



Optional list of CNNVD (China National Vulnerability Database of Information Security - 国家信息安全漏洞库) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CNNVD-2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.cnvd



Optional list of CNVD (China National Vulnerability Database - 国家信息安全漏洞共享平台) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CNVD-2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.cve



Optional list of CVE (Common Vulnerabilities and Exposures) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CVE-2025-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.cwe



Optional list of CWE (Common Weakness Enumeration) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "CWE-123"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.edb



Optional list of EDB (Exploit-DB) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "EDB-12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.ghsa



Optional list of GHSA (GitHub Security Advisories) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "GHSA-xxxx-xxxx-xxxx"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.ics_cert



Optional list of ICS-CERT (CISA Industrial Control Systems Cyber Emergency Response Team) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "ICSA-12-123-12"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.jvn



Optional list of JVN (Japan Vulnerability Notes - 日本脆弱性ノート) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "JVN#12345678"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.kev



Optional list of KEV (CISA Known Exploited Vulnerabilities) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "KEV-2025-1234"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.databases\.oval



Optional list of OVAL (Open Vulnerability and Assessment Language) identifiers related to this rule or match\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "oval:org.mitre.oval:def:12345"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.evidence



Concise, non-sensitive snippet or summary that triggered the match\.
Must not contain secrets\.



*Type:*
string



*Default:*
` "<not provided>" `



*Example:*
` "config.users.users.root.password = \"…\"" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.location



Human-readable location where the finding was detected\. Prefer precise
references such as file paths\.



*Type:*
string



*Default:*
` "<not provided>" `



*Example:*
` "/etc/nixos/hardware-configuration.nix" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.recommendation



Short, actionable remediation for this specific match\.



*Type:*
string



*Default:*
` "<not provided>" `



*Example:*

````
''
  Replace the cleartext password with a hashed password option:
  `config.users.users.root.hashedPassword`
  or `config.users.users.root.hashedPasswordFile`.
''
````

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.matches\.\*\.urls



Per-match reference URLs (advisories, fixes or documentation)\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.initialPassword"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.name



Short human-readable rule name\. Shown in generated reports and in
evaluation warnings or errors\.



*Type:*
string



*Default:*
` "‹name›" `



*Example:*
` "Usage of cleartext user password instead of a hashed password" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.severity



Severity assigned to findings from this rule\. May be overridden per
match\. Use standard levels (info/low/medium/high/critical/unknown)\.



*Type:*
one of “info”, “low”, “medium”, “high”, “critical”, “unknown”



*Default:*
` "unknown" `



*Example:*
` "critical" `

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)



## security\.nixsecauditor\.rules\.\<name>\.urls



List of reference URLs (documentation, advisories or remediation
guides) related to this rule\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "https://nixos.org/manual/nixos/stable/options#opt-users.extraUsers._name_.password"
]
```

*Declared by:*
 - [nixos/rules\.nix](https://github.com/yunfachi/NixSecAuditor/blob/master/nixos/rules.nix)


