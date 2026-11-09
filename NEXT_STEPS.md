# Próximos passos — AntiGrabber

Continuação de sessão. Atualizado em 2026-11-09.

## Estado atual

- Branch `main`, árvore limpa. Trabalho desta sessão já commitado e no remoto
  (proteção de conta Minecraft + ETW + domínios de exfiltração + scan de
  roubo de sessão + ferramentas de teste em `tester/`).
- **Serviço instalado é a build ANTIGA** (`C:\Program Files\AntiGrabber\
  Service\AntiGrabber.Service.exe`, binário de 05/10/2026). NÃO tem ETW,
  leitura de conta, domínios de exfiltração nem detecção de roubo de sessão.
  O `rules.json` em `%ProgramData%\AntiGrabber\` não tem telegram/pastebin/
  ngrok, e o log mostra o bug velho `pid=desconhecido`.

## ACHADO CRÍTICO — bloqueio de rede está vazando

Teste ao vivo (2026-11-09) contra o serviço rodando: `node.exe` → `discord.com`
(domínio sensível, code host não liberado). O serviço **logou 11 "Bloqueado"**
mas as **11 tentativas voltaram HTTP 200** (IPv4, Cloudflare 162.159.137.232).
Ou seja: loga bloqueio mas o tráfego passa. Reproduzível, 5/5 e 3/3.

Hipóteses da causa (a confirmar):
1. Caminho *fail-open* libera: ClientHello fragmentado, retransmissão TCP, ou
   parse `Incomplete`/`GiveUp` reencaminhando o fluxo da conexão que vence.
2. WinDivert não está de fato descartando o pacote nesta máquina (modo/driver).

Isto afeta provavelmente a build nova também — o caminho de drop em
`NetworkFilterWorker.DecideAsync` não mudou nesta sessão.

## Prioridades

### P1 — consertar a confiabilidade do bloqueio (coração do produto)
- Reproduzir o vazamento e achar a causa exata (precisa do serviço rodando
  elevado + diagnóstico do WinDivert).
- Conserto provável: ao bloquear, **matar o fluxo inteiro** — injetar um RST
  TCP e marcar o 5-tuple como bloqueado por um tempo — em vez de só não
  reencaminhar o pacote do ClientHello. Assim retransmissão e ClientHello
  fragmentado do mesmo fluxo também caem.
- Teste obrigatório: cenário que prova que a conexão REALMENTE cai (não só que
  o log diz "bloqueado"). O `tester/exfil-test.js --url https://discord.com/`
  já serve de prova end-to-end — tem que dar `BLOQUEOU`/`PASS`.

### P2 — instalar a build nova
- `.\scripts\build-installer.ps1` (precisa Inno Setup + WinDivert) OU subir tag
  `v*.*.*` e deixar o CI (`.github/workflows/release.yml`) buildar.
- O CI agora roda `selftest-all` antes de empacotar.

### P3 — fechar o buraco do mod → domínio próprio
- Mod rodando dentro do jogo recebe o token por `--accessToken` (memória), NÃO
  lê o arquivo de conta → o caminho "leu conta → bloqueia" não dispara pra ele.
  Se mandar pro servidor próprio na 443 (não Discord/Telegram/canal conhecido),
  passa.
- Fazer o scan de mods (`BlockInvestigator.ScanFile`) rodar **proativo**: ao
  detectar jar novo na pasta de mods, antes de qualquer conexão — não só depois
  de um bloqueio. Com teste.

## Validações pendentes (precisam de admin + build nova instalada)

```powershell
# 1) sessão ETW real (provider/keyword/evento) — terminal ELEVADO
dotnet run --project AntiGrabber.TestHarness -- --test-mode --scenario=etw-smoke

# 2) bloqueio end-to-end: leu conta -> barra qualquer domínio
node tester\exfil-test.js --url https://example.com/
java -jar tester\java\exfil-test.jar --url https://example.com/
#   esperado: BLOQUEOU nos dois vetores -> PASS
```

## Diagnóstico do WinDivert (rodar ELEVADO e me mandar a saída)

```powershell
sc.exe query WinDivert
Get-Content "$env:ProgramData\AntiGrabber\logs\service-*.log" -Tail 40
# repetir o teste discord e ver se delta de "Bloqueado" == nº de tentativas
```

## Testes que já passam (offline, sem admin)

```powershell
dotnet run --project AntiGrabber.TestHarness -- --test-mode --scenario=selftest-all
# 11/11 PASS em 2026-11-09
```

## Caminhos NÃO verificados em máquina real (risco de falso negativo/positivo)

- Verificados: launcher oficial (MS Store), Prism, Modrinth.
- NÃO verificados: TLauncher, Feather, Badlion, CurseForge, ATLauncher, Lunar.
- NÃO verificado: se o javaw do jogo no TLauncher lê `TlauncherProfiles.json`
  (seria falso positivo — bloquearia a rede do jogo por 60s).
- NÃO verificados: nomes de método do token em SRG (Forge 1.17–1.20.4) e
  intermediary (Fabric). Os nomes Mojang 26.x foram confirmados pelo AuthMe.

## Ferramentas de teste (tester/)

- `catcher.js` — servidor localhost:3000 (HTTP POST + WebSocket), mostra o
  payload. Serviço DESLIGADO.
- `exfil-test.js` / `java/exfil-test.jar` — abrem o arquivo de conta só pelo
  handle (sem ler o token), mandam payload sintético por HTTP + WS. Alvo de
  bloqueio = HTTPS/443 (`localhost:3000` nunca é interceptado). Jar gerado por
  `java/build.ps1` (gitignored; JDK do Prism `java-runtime-epsilon` tem javac).
