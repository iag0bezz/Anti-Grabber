# AntiGrabber

Serviço Windows de segurança defensiva que protege contra **grabbers** —
malware que rouba tokens de sessão do Discord, credenciais da Steam e dados
de outros apps instalados, geralmente exfiltrando via webhook do Discord ou
requisições HTTP para domínios não relacionados ao app original.

A detecção é 100% baseada em **metadados e comportamento**: qual processo
acessou qual arquivo, qual processo abriu qual conexão de rede, para qual
domínio. O AntiGrabber nunca lê, decodifica ou exibe o conteúdo real de um
token ou credencial — só compara nomes de processo e domínios contra uma
whitelist.

## Como funciona

- **NetworkFilterWorker** intercepta tráfego TCP:443 de saída via
  [WinDivert](https://reqrypt.org/windivert.html) (modo usuário, sem driver
  assinado próprio), extrai o SNI do handshake TLS e bloqueia conexões de
  processos não autorizados para domínios sensíveis (`discord.com`,
  `steamcommunity.com`, etc). Não faz MITM nem inspeciona tráfego cifrado.
- **UnifiedAppLocator** encontra instalações de Discord, Steam, navegadores e
  launchers por 5 métodos combinados (processo em execução → registro →
  atalhos → paths padrão do AppData → varredura limitada de disco).
- **TokenFileWatcher** observa os diretórios sensíveis detectados e
  correlaciona com a rede: mesmo processo lendo arquivo sensível + abrindo
  conexão de rede numa janela curta é sinal de alerta.
- **Tray app** (Electron, `tray-ui/`) mostra o status (ocioso / protegendo /
  bloqueio recente) e um feed de atividade em linguagem simples, sem jargão
  técnico. Fala com o Service pelo mesmo named pipe de sempre — o protocolo
  IPC não mudou, só o cliente virou Node em vez de WPF.

## 100% offline, sem conta de usuário

Este projeto não tem login, backend próprio nem sincronização em nuvem — e
essa é uma decisão de arquitetura permanente, não um item de roadmap. Uma
ferramenta que existe pra impedir vazamento de dados não pode exigir que o
usuário envie dados para um servidor de terceiros.

A única exceção é um canal opcional de atualização de regras: um JSON
assinado com domínios/padrões conhecidos de exfiltração, baixado via GET
público do GitHub Releases — sem login, sem telemetria, sem identificar o
usuário. Ele fica desativado até você configurar `RuleUpdate:RulesUrl` e
`RuleUpdate:PublicKeyPem` em `appsettings.json`.

## Logs

100% locais, rotacionados (14 dias / 10 MB por arquivo), nunca transmitidos.
Ficam em `%ProgramData%\AntiGrabber\logs\`.

## Build

Requer .NET 8 SDK. Pra mexer no Tray, requer também Node.js (só pra
desenvolvimento local via `npm start` dentro de `tray-ui/` — não é
necessário pra empacotar o instalador, que não embute o Electron).

```powershell
dotnet build AntiGrabber.sln
```

## Gerar o instalador .exe

Requer [Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install
JRSoftware.InnoSetup`).

```powershell
.\scripts\build-installer.ps1
```

Publica Service/TestHarness como `.exe` self-contained single-file win-x64,
empacota só o código do Tray (JS/HTML/CSS, ~20KB, sem o runtime Electron) e
compila `dist\installer\AntiGrabberSetup.exe` — um instalador único (~45MB)
com wizard, componentes opcionais (serviço / bandeja / TestHarness), atalhos
de Menu Iniciar e desinstalador próprio registrado em
Adicionar/Remover Programas.

**O runtime do Electron (Node+Chromium, ~150MB) não vem embutido.** O
instalador baixa direto de
`github.com/electron/electron/releases` (versão fixada, verificada por
SHA256 antes de extrair) durante a instalação, e cacheia em
`%LocalAppData%\AntiGrabber\electron-runtime\` — reinstalar não baixa de
novo. Ver `installer/AntiGrabber.iss` (seção `[Code]`) pra atualizar a
versão fixada.

O pacote NuGet `WindivertDotnet` não inclui os binários nativos do driver.
Baixe o redistributable oficial em https://reqrypt.org/windivert.html e
copie `WinDivert.dll` + `WinDivert64.sys` para dentro de
`dist\AntiGrabber.Service\` **antes** de rodar `build-installer.ps1` (assim
eles entram empacotados no instalador).

Só publicar sem empacotar instalador: `.\scripts\publish.ps1` (Service +
TestHarness) e `.\scripts\build-tray.ps1` (Tray).

## Instalar / desinstalar

Rode `dist\installer\AntiGrabberSetup.exe` como Administrador. Ele registra
o serviço (`sc create`, start automático, `sc failure` configurando
recuperação automática nativa do Windows — SCM reinicia o serviço sozinho se
ele cair, sem processo watchdog extra), baixa o runtime Electron se ainda
não estiver em cache, e cria os atalhos escolhidos.

Pra desinstalar, use "Adicionar ou remover programas" ou o atalho
"Desinstalar AntiGrabber" no Menu Iniciar — o instalador Inno Setup gera o
desinstalador automaticamente, que para/remove o serviço, o driver WinDivert
residual e os dados locais em `%ProgramData%\AntiGrabber`. O runtime Electron
cacheado em `%LocalAppData%` fica (é compartilhável entre reinstalações);
remova manualmente se quiser liberar o espaço.

## Testar

O `AntiGrabber.TestHarness` prova que a proteção funciona sem nunca extrair
credencial real — o payload enviado é sempre a string sintética fixa
`TEST_PAYLOAD_NAO_E_TOKEN_REAL|`, nunca derivada de um arquivo real.

```powershell
dotnet run --project AntiGrabber.TestHarness -- --test-mode --scenario=discord-webhook --webhook-url=<seu-webhook-de-teste>
```

Use um webhook criado por você mesmo para teste — nunca um webhook de
terceiros. `PASS` = o AntiGrabberService bloqueou a conexão. `FAIL` = a
conexão completou (falha de detecção a corrigir).

Cenários disponíveis: `discord-webhook` (exige `--webhook-url` seu) e
`steam-exfil` (usa `https://steamcommunity.com/` como destino público por
padrão, não precisa de `--webhook-url`).

## Limitações conhecidas

- **Correlação "acesso a arquivo recente" é parcial.** `TokenFileWatcher`
  usa `FileSystemWatcher` com `NotifyFilters.LastAccess`, mas o Windows por
  padrão não atualiza o timestamp de último acesso em tempo real
  (`fsutil behavior query disablelastaccess` = gerenciado pelo sistema) —
  então leitura pura de um arquivo sensível (o padrão típico de um grabber)
  muitas vezes não dispara evento nenhum. Escrita/criação/rename disparam
  normalmente. **Isso não afeta o bloqueio em si** — quem bloqueia a
  exfiltração é o `NetworkFilterWorker`, testado e funcionando independente
  disso. Só a mensagem "bloqueamos um roubo" vs "bloqueamos uma conexão
  suspeita" fica menos precisa.

**Conta de usuário / login / sincronização em nuvem NÃO é uma opção
futura** — é uma decisão de arquitetura permanente (ver seção acima).

## Segurança

Veja [SECURITY.md](SECURITY.md) para processo de disclosure responsável.
