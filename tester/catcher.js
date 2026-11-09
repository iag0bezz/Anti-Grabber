// Catcher de teste do AntiGrabber — NÃO faz parte do produto, é ferramenta de QA.
//
// Sobe um servidor em localhost:3000 que recebe HTTP POST e WebSocket e imprime o que
// chega. Serve pra VER o payload sintético quando o serviço está DESLIGADO (prova que o
// exfil-test manda). Com o serviço LIGADO, o teste de bloqueio usa alvo HTTPS/443 e este
// catcher nem é tocado — a conexão não sai (ver README).
//
// Sem dependência: WebSocket implementado na mão (só frames de texto do cliente).
// Rodar: node catcher.js [porta]

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.argv[2] || 3000);
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const now = () => new Date().toISOString();

function log(vector, msg) {
  console.log(`[${now()}] [${vector}] ${msg}`);
}

const server = http.createServer((req, res) => {
  if (req.method === "POST") {
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 1_000_000) req.destroy(); // teste manda poucos bytes
    });
    req.on("end", () => {
      log("HTTP", `POST ${req.url} de ${req.socket.remoteAddress} — corpo: ${JSON.stringify(body)}`);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    return;
  }
  res.writeHead(200, { "content-type": "text/plain" });
  res.end(`AntiGrabber catcher de teste ativo em :${PORT}\nPOST /exfil ou WebSocket ws://localhost:${PORT}\n`);
});

// Handshake WebSocket (RFC 6455) na mão: responde 101 e lê frames de texto mascarados.
server.on("upgrade", (req, socket) => {
  const key = req.headers["sec-websocket-key"];
  if (!key) {
    socket.destroy();
    return;
  }
  const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  log("WS", `cliente conectado de ${socket.remoteAddress}`);

  let buf = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    // Decodifica quantos frames completos houver no buffer.
    for (;;) {
      const frame = decodeFrame(buf);
      if (!frame) break;
      buf = frame.rest;
      if (frame.opcode === 0x8) {
        log("WS", "frame de fechamento");
        socket.end();
        return;
      }
      if (frame.opcode === 0x1) log("WS", `texto recebido: ${JSON.stringify(frame.payload.toString("utf8"))}`);
    }
  });
  socket.on("close", () => log("WS", "cliente desconectado"));
  socket.on("error", () => {});
});

// Decodifica UM frame do cliente (sempre mascarado). Devolve null se incompleto.
function decodeFrame(b) {
  if (b.length < 2) return null;
  const opcode = b[0] & 0x0f;
  const masked = (b[1] & 0x80) !== 0;
  let len = b[1] & 0x7f;
  let off = 2;
  if (len === 126) {
    if (b.length < 4) return null;
    len = b.readUInt16BE(2);
    off = 4;
  } else if (len === 127) {
    if (b.length < 10) return null;
    len = Number(b.readBigUInt64BE(2));
    off = 10;
  }
  const maskLen = masked ? 4 : 0;
  if (b.length < off + maskLen + len) return null;
  const mask = masked ? b.subarray(off, off + 4) : null;
  const data = b.subarray(off + maskLen, off + maskLen + len);
  const payload = Buffer.alloc(len);
  for (let i = 0; i < len; i++) payload[i] = masked ? data[i] ^ mask[i & 3] : data[i];
  return { opcode, payload, rest: b.subarray(off + maskLen + len) };
}

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Catcher de teste ouvindo em http://localhost:${PORT} (HTTP POST + WebSocket).`);
  console.log("Deixe o serviço AntiGrabber DESLIGADO pra ver o payload chegar aqui.");
});
