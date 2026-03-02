# NixSecAuditor

[![en](https://img.shields.io/badge/lang-en-red.svg)](/README.md)

Расширяемый правило-ориентированный статический аудитор конфигурационного кода NixOS, с несколькими форматами отчётов (JSON, Markdown, предупреждения и ошибки на этапе оценки).

## Использование

Полный список доступных опций модуля NixOS см. в [./options.md](./options.md).

Полный список правил NixSecAuditor по умолчанию см. в [./nixos/rules](./nixos/rules).

Чтобы отключить все правила NixSecAuditor, добавьте следующее в вашу конфигурацию NixOS:

```nix
{
  disabledModules = [
    (nixsecauditor.nixosModules.default + "/rules")
  ];
}
```

## Установка

### С использованием Flakes

Добавьте `nixsecauditor` в flake inputs и подключите модуль NixOS в конфигурацию системы:

```nix
{
  inputs.nixsecauditor.url = "github:yunfachi/NixSecAuditor";

  outputs = { nixpkgs, nixsecauditor, ... }:
    {
      nixosConfigurations.nixos = nixpkgs.lib.nixosSystem {
        modules = [
          # Другие модули...
          nixsecauditor.nixosModules.default
        ];
      };
    };
}
```

Затем включите NixSecAuditor в вашей конфигурации NixOS:

```nix
{
  security.nixsecauditor.enable = true;
}
```

### Без Flakes

Импортируйте модуль напрямую из Git-репозитория:

```nix
{ pkgs, lib, ... }:
let
  nixsecauditor = import (builtins.fetchGit {
    url = "https://github.com/yunfachi/NixSecAuditor";
  });
in 
{
  imports = [ nixsecauditor.nixosModules.default ];

  security.nixsecauditor.enable = true;
}
```

## Лицензия

Этот проект распространяется под лицензией [MIT License](./LICENSE).
