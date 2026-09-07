# Próximos passos

Contexto pra retomar sem perder o fio — última atualização: sessão de 2026-09-07 (pós tag `v0.9.0`).

## 1. QUIC/UDP 443 — wiring completo (DONE nesta sessão)

Todo o checklist da versão anterior deste documento foi implementado e testado:
- `AntiGrabber.Service/Network/QuicCryptoFrameExtractor.cs` — extrai frames CRYPTO do payload decifrado (PADDING/PING/ACK/CRYPTO reconhecidos; frame desconhecido faz desistir, fail-open)
- `AntiGrabber.Service/Network/QuicClientHelloReassembler.cs` — remonta ClientHello espalhado por vários Initial packets (offset absoluto do CRYPTO frame, sem a complexidade de seq number do TCP)
- `AntiGrabber.Service/Network/UdpProcessResolver.cs` — PID por porta UDP local via `GetExtendedUdpTable` (equivalente ao `TcpProcessResolver`)
- `AntiGrabber.Service/Network/UdpFlowKey.cs` — chave de fluxo UDP (mesmo formato do `TcpFlowKey`)
- `NetworkFilterWorker.cs` — filtro WinDivert agora `outbound and (tcp.DstPort == 443 or udp.DstPort == 443)` quando `NetworkFilter:InspectQuic` está ligado; pacotes UDP roteados pro caminho QUIC, decisão via o mesmo `DecideAsync` (parametrizado por `isUdp` pra escolher TCP/UDP process resolver)
- Kill switch: `appsettings.json` → `NetworkFilter:InspectQuic` (default `true`; `false` volta ao filtro só-TCP, sem rebuild)
- Testes: `AntiGrabber.TestHarness.exe --test-mode --scenario=quic-crypto-selftest`, `--scenario=quic-header-selftest` (já existiam) e o novo `--scenario=quic-wiring-selftest` (extractor + reassembler ponta a ponta, sem cripto real). Os 5 self-tests QUIC + os 2 TLS/TCP passam. `dotnet build AntiGrabber.sln` sem erro.

Só inspeciona o Initial packet (onde o ClientHello viaja em claro) — pacotes de fases seguintes (Handshake/1-RTT) passam liberados por design, decisão já foi tomada no Initial.

**Ainda não verificado:** comportamento em tráfego QUIC real (Chrome/Edge falando HTTP/3 de verdade) — só rodei os self-tests sintéticos/RFC, não subi o serviço com WinDivert numa máquina real. Ver item 2.

## 2. Testes manuais pendentes (não dá pra validar neste ambiente sem WinDivert/driver real)

- **QUIC/UDP 443 com tráfego real**: subir o serviço com WinDivert de verdade (driver `WinDivert64.sys` + LocalSystem), abrir Chrome/Edge numa sensível (ex: Steam/Discord se falarem HTTP/3) e confirmar nos logs que o Initial packet é decifrado, SNI extraído e a decisão bate com a mesma regra do caminho TCP. Também testar `NetworkFilter:InspectQuic=false` e confirmar que volta a filtrar só TCP.
- **Reassembly de ClientHello fragmentado (TCP)**: subir o serviço numa máquina Windows de verdade, forçar conexão HTTPS com ClientHello grande (Chrome com bastante extensions/GREASE) e confirmar nos logs que passa sem quebrar
- **Diálogo de "Sair"**: abrir a Tray, clicar Sair, confirmar que aparecem os 2 botões certos ("Continuar proteção" / "Sair e parar proteção"), testar os dois caminhos (incluindo negar o UAC no segundo)
- **Botão "Revalidar regras"**: clicar, confirmar que o timestamp atualiza e que bate com o log do serviço

## 3. Dúvida em aberto — Discord Rich Presence

Confirmado (bloqueio real reportado): `Discord.exe` fala direto com `api.spotify.com` (Spotify Connect).

Não confirmado: se as outras contas linkadas no Discord (Xbox, PlayStation, Steam, Twitch, YouTube) são resolvidas pelo `Discord.exe` local ou pelo backend do Discord nos servidores deles. Não tem regra pra essas — só adicionar se aparecer bloqueio real reportado (evita regra especulativa).

## 4. Chave privada das public rules

Backup já foi feito pelo usuário (confirmado). Fluxo de assinatura documentado em memória (`reference_public_rules_workflow`). Se a assinatura falhar em sessão futura por não achar o arquivo, perguntar onde foi guardada — nunca gerar par novo sem OK explícito (invalidaria a `PublicKeyPem` em `appsettings.json`, quebrando a validação em todo cliente já instalado até a próxima atualização do app).

## 5. Estado de versão

Tag atual: `v0.9.0`. Cobre: fragmentação TCP fechada, primitivas QUIC (não wired), whitelist pública expandida, poll de rules 60min + revalidação manual, escolha explícita no "Sair".
