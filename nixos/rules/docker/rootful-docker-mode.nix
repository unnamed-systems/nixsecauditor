{
  options,
  lib,
  config,
  ...
}:
{
  config.security.nixsecauditor.rules.rootful-docker-mode = {
    name = "Docker running in rootful mode";
    description = ''
      Detects when Docker is enabled but rootless mode is not enabled via
      `config.virtualisation.docker.rootless.enable`.
      Running Docker in rootful mode significantly increases the risk of
      container breakout, privilege escalation, and other vulnerabilities.
    '';
    databases.cwe = [
      "CWE-250"
      "CWE-269"
    ];
    urls = [
      "https://docs.docker.com/engine/security/rootless/"
    ];

    severity = "high";
    action = "warn";

    matches =
      let
        dockerEnableDefinitionFile =
          (lib.findFirst (
            { file, value }: value == true
          ) { } options.virtualisation.docker.enable.definitionsWithLocations).file or null;
        rootlessDefinitionFile =
          (lib.findFirst (
            { file, value }: value == false
          ) { } options.virtualisation.docker.rootless.enable.definitionsWithLocations).file or null;
        rootfulSetManually = rootlessDefinitionFile != null;
      in
      if config.virtualisation.docker.enable && !config.virtualisation.docker.rootless.enable then
        [
          {
            location = if rootfulSetManually then rootlessDefinitionFile else dockerEnableDefinitionFile;
            evidence =
              if rootfulSetManually then
                "config.virtualisation.docker.rootless.enable = false"
              else
                "config.virtualisation.docker.enable = false";
            confidence = "high";
            recommendation = ''
              Enable rootless mode:
              `config.virtualisation.docker.rootless.enable = true`
            '';
          }
        ]
      else
        [ ];
  };
}
