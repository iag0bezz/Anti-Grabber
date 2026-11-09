# Tester de produção — AntiGrabber

Ferramentas de QA pra você, como tester, confirmar o bloqueio de roubo de
conta **numa execução real**. Não fazem parte do produto instalado.

Nenhuma delas é um stealer: abrem o arquivo de conta do launcher **só pelo
handle** (pra o monitor ETW registrar a leitura) e **nunca leem o conteúdo
do token**. O que enviam é sempre um payload sintético fixo
(`TEST_PAYLOAD_NAO_E_TOKEN_REAL|<hora>`), igual ao `AntiGrabber.TestHarness`.

## Por que o alvo é HTTPS/443

O bloqueio acontece no `NetworkFilterWorker`, que só intercepta saída na
porta **443** (TCP/QUIC). `localhost:3000` nunca passa por lá. Então:

- **Alvo de bloqueio** = HTTPS externo na 443 (`https://example.com/`).
- **Catcher** (`localhost:3000`) só serve pra ver o payload com o serviço
  **desligado** — prova que a ferramenta manda.

`example.com` é de propósito: não é domínio sensível, então bloquear prova
que a lógica **"leu arquivo de conta → barra qualquer domínio"** funciona.
(Com `api.telegram.org` o bloqueio também viria da lista de exfiltração,
misturando as causas.)

## Arquivos

- `catcher.js` — servidor em `localhost:3000` (HTTP POST + WebSocket) que
  imprime o que chega. Sem dependência (`node catcher.js`).
- `exfil-test.js` — tester em Node. `node exfil-test.js [opções]`.
- `java/ExfilTest.java` + `java/build.ps1` — tester em Java; `build.ps1`
  gera `java/exfil-test.jar` (`java -jar exfil-test.jar [opções]`).

Opções (as duas ferramentas): `--url <http(s)>`, `--ws <ws(s)>` (derivado da
`--url` se omitido), `--account <caminho>` (senão, autodetecta o arquivo de
conta de um launcher instalado), `--timeout <ms>`.

## Gerar o jar

```powershell
cd tester\java
.\build.ps1          # acha o JDK do Prism sozinho, ou: .\build.ps1 -JdkBin "C:\...\bin"
```

## Teste 1 — a ferramenta manda (serviço DESLIGADO)

```powershell
sc stop AntiGrabberService          # como admin
node tester\catcher.js              # num terminal
```

Noutro terminal:

```powershell
node tester\exfil-test.js --url http://localhost:3000/exfil --ws ws://localhost:3000
# ou:  java -jar tester\java\exfil-test.jar --url http://localhost:3000/exfil --ws ws://localhost:3000
```

O catcher deve logar o payload nas duas vias (HTTP e WS). Confirma que o
tester funciona.

## Teste 2 — o bloqueio funciona (serviço LIGADO, build nova)

Precisa do serviço com a proteção nova instalado e rodando (admin).

```powershell
node tester\exfil-test.js --url https://example.com/
java -jar tester\java\exfil-test.jar --url https://example.com/
```

Esperado: as duas vias dão `BLOQUEOU` e a saída termina em
**`PASS`** (exit 0). O serviço viu o processo (`node.exe`/`java.exe`) abrir o
arquivo de conta e, nos 60s seguintes, barrou a saída na 443 mesmo pra um
domínio não sensível.

`FAIL` (saiu `ENVIOU`) = a conexão passou: o serviço está desligado, é a
build antiga, ou nenhum arquivo de conta foi aberto (passe `--account`).

## O que isto NÃO cobre

- Mod que manda o token pra domínio próprio do atacante na memória do jogo
  (o token não sai de arquivo) — fora do alcance da rede.
- Atraso de ~1s do ETW: ler e enviar no mesmo instante pode escapar.
