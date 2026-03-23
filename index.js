// WebSocket-to-TCP Relay Server (deploy on Render/Railway)
// Accepts WebSocket connections, first message = "host:port",
// then relays raw TCP bidirectionally.

const http = require('http');
const net = require('net');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'ctf2026';

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK');
});

server.on('upgrade', (req, socket, head) => {
  // Verify secret in path
  if (!req.url.includes(SECRET)) {
    socket.destroy();
    return;
  }

  // WebSocket handshake
  const key = req.headers['sec-websocket-key'];
  const accept = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-5AB5DC11E65A')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n` +
    '\r\n'
  );

  let remote = null;
  let wsBuf = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    wsBuf = Buffer.concat([wsBuf, chunk]);

    while (true) {
      const frame = decodeFrame(wsBuf);
      if (!frame) break;
      wsBuf = frame.rest;

      if (frame.opcode === 0x8) { // close
        if (remote) remote.destroy();
        socket.destroy();
        return;
      }

      if (frame.opcode === 0x9) { // ping
        socket.write(encodeFrame(frame.payload, 0xA)); // pong
        continue;
      }

      if (!remote) {
        // First message: target host:port
        const target = frame.payload.toString();
        const [host, port] = target.split(':');
        console.log(`[+] Connect ${host}:${port}`);

        remote = net.connect(parseInt(port), host, () => {
          socket.write(encodeFrame('OK', 0x1));
        });

        remote.on('data', (data) => {
          try {
            socket.write(encodeFrame(data, 0x2));
          } catch {}
        });

        remote.on('error', (e) => {
          try {
            socket.write(encodeFrame(`ERR:${e.message}`, 0x1));
            socket.destroy();
          } catch {}
        });

        remote.on('close', () => {
          try { socket.write(encodeFrame(Buffer.alloc(0), 0x8)); } catch {}
          socket.destroy();
        });
      } else {
        // Relay to TCP
        try { remote.write(frame.payload); } catch {}
      }
    }
  });

  socket.on('close', () => { if (remote) remote.destroy(); });
  socket.on('error', () => { if (remote) remote.destroy(); });
});

function encodeFrame(data, opcode) {
  const payload = typeof data === 'string' ? Buffer.from(data) : data;
  let header;

  if (payload.length < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | opcode;
    header[1] = payload.length;
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }

  return Buffer.concat([header, payload]);
}

function decodeFrame(buf) {
  if (buf.length < 2) return null;

  const opcode = buf[0] & 0x0F;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7F;
  let off = 2;

  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    off = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    off = 10;
  }

  const totalNeeded = off + (masked ? 4 : 0) + len;
  if (buf.length < totalNeeded) return null;

  let payload;
  if (masked) {
    const mask = buf.slice(off, off + 4);
    off += 4;
    payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = buf[off + i] ^ mask[i % 4];
  } else {
    payload = buf.slice(off, off + len);
  }

  return { opcode, payload, rest: buf.slice(off + len) };
}

server.listen(PORT, () => {
  console.log(`[+] Relay server on port ${PORT}`);
});
