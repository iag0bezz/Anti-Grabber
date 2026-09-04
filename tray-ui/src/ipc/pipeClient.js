'use strict';

const net = require('net');
const { EventEmitter } = require('events');

const PIPE_PATH = '\\\\.\\pipe\\AntiGrabber.IpcPipe';
const CONNECT_TIMEOUT_MS = 4000;

const IpcMessageType = Object.freeze({
  Ping: 0,
  Pong: 1,
  Status: 2,
  BlockEvent: 3,
  AllowAlwaysCommand: 4,
  AllowAlwaysAck: 5,
  RulesSnapshot: 6,
  RemoveRuleCommand: 7,
  SetRuleEnabledCommand: 8,
});

class PipeClient extends EventEmitter {
  constructor() {
    super();
    this._socket = null;
    this._connected = false;
    this._recvBuffer = Buffer.alloc(0);
    this._reconnectTimer = null;
    this._stopped = false;
  }

  get connected() {
    return this._connected;
  }

  start() {
    this._stopped = false;
    this._connect();
  }

  stop() {
    this._stopped = true;
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    if (this._socket) this._socket.destroy();
  }

  send(envelope) {
    if (!this._connected || !this._socket) return false;
    const json = Buffer.from(JSON.stringify(envelope), 'utf8');
    const header = Buffer.alloc(4);
    header.writeInt32LE(json.length, 0);
    this._socket.write(Buffer.concat([header, json]));
    return true;
  }

  _connect() {
    if (this._stopped) return;

    const socket = net.connect(PIPE_PATH);
    this._socket = socket;

    const connectTimeout = setTimeout(() => {
      if (!this._connected) socket.destroy();
    }, CONNECT_TIMEOUT_MS);

    socket.on('connect', () => {
      clearTimeout(connectTimeout);
      this._connected = true;
      this._recvBuffer = Buffer.alloc(0);
      this.emit('connected');
    });

    socket.on('data', (chunk) => this._onData(chunk));

    const onClose = () => {
      clearTimeout(connectTimeout);
      this._connected = false;
      this.emit('disconnected');
      if (!this._stopped) this._scheduleReconnect();
    };

    socket.on('close', onClose);
    socket.on('error', () => {
    });
  }

  _scheduleReconnect() {
    if (this._stopped) return;
    if (this._reconnectTimer) return;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this._connect();
    }, 3000);
  }

  _onData(chunk) {
    this._recvBuffer = Buffer.concat([this._recvBuffer, chunk]);

    while (true) {
      if (this._recvBuffer.length < 4) return;
      const length = this._recvBuffer.readInt32LE(0);
      if (length <= 0 || length > 64 * 1024) {
        this.emit('disconnected');
        this._socket.destroy();
        return;
      }
      if (this._recvBuffer.length < 4 + length) return;

      const jsonBuf = this._recvBuffer.subarray(4, 4 + length);
      this._recvBuffer = this._recvBuffer.subarray(4 + length);

      try {
        const envelope = JSON.parse(jsonBuf.toString('utf8'));
        this.emit('message', envelope);
      } catch {
      }
    }
  }
}

module.exports = { PipeClient, IpcMessageType };
