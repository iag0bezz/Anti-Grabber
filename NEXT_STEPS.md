# Próximos passos

Contexto pra retomar sem perder o fio — última atualização: sessão que terminou na tag `v0.9.0` (2026-09-07).

## 1. QUIC/UDP 443 — falta terminar o wiring

Já feito e testado contra o vetor oficial RFC 9001 A.2 (isolado, sem tocar tráfego real):
- `AntiGrabber.Service/Network/QuicInitialCrypto.cs` — deriva chaves + decifra payload do Initial packet
- `AntiGrabber.Service/Network/QuicLongHeaderParser.cs` — lê DCID/SCID/token/length, acha onde começa o packet number protegido
- Testes: `AntiGrabber.TestHarness.exe --test-mode --scenario=quic-crypto-selftest` e `--scenario=quic-header-selftest`

**Falta pra virar proteção de verdade:**
1. Extrair frame CRYPTO do payload decifrado (varint type/offset/length, reassembly se o ClientHello vier em mais de um Initial packet — CRYPTO frame já traz offset explícito, mais simples que o caso TCP)
2. Resolver PID por porta UDP local (equivalente ao `TcpProcessResolver.cs`, via `GetExtendedUdpTable`)
3. Mudar filtro WinDivert em `NetworkFilterWorker.cs` de `outbound and tcp.DstPort == 443` pra incluir `or udp.DstPort == 443`, e rotear pacotes UDP pro caminho QUIC
4. Reaproveitar `DecideAsync` já existente (mesma lógica de bloqueio/allow do caminho TCP)
5. Sugestão: atrás de flag em `appsettings.json` (`NetworkFilter:InspectQuic`), desligável sem rebuild se der problema

Plano detalhado completo foi discutido na sessão anterior (fragmentação TCP + QUIC) — pedir pra reconstruir o plano se precisar do detalhe outra vez.

## 2. Testes manuais pendentes (não dá pra validar neste ambiente sem Windows/GUI)

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
