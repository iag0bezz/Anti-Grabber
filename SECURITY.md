# Política de segurança

## Reportar uma vulnerabilidade

Este projeto lida com proteção contra roubo de credenciais — leve reports de
segurança a sério. Se você encontrar uma vulnerabilidade:

1. **Não abra uma issue pública** descrevendo a falha em detalhe.
2. Abra uma issue com o título "Security: [resumo vago]" pedindo um canal
   privado, ou contate os mantenedores diretamente (ver perfil do
   repositório) para receber um endereço de contato.
3. Descreva impacto, passos de reprodução e, se possível, uma sugestão de
   correção.
4. Aguarde confirmação de recebimento antes de divulgar publicamente
   (disclosure responsável — pedimos um prazo razoável para corrigir antes
   da divulgação total).

## O que conta como vulnerabilidade aqui

- Qualquer forma de contornar o `NetworkFilterWorker` para exfiltrar dados
  sem ser bloqueado.
- Qualquer processo local conseguindo se passar pelo Service no named pipe
  (ACL bypass) ou mandar comando de desativar a proteção.
- Qualquer caminho de código que leia/decodifique conteúdo real de token
  Discord ou credencial Steam (isso violaria a decisão de arquitetura do
  projeto, não é uma feature aceitável nem em PR).
- Qualquer envio de dado do usuário para servidor que não seja o canal
  público de regras (que não deve, em si, receber nada do usuário — só GET).

## Fora de escopo

- Bugs de UI sem impacto de segurança (reporte como issue normal).
- Falsos positivos/negativos de detecção sem exploit associado (issue normal).
