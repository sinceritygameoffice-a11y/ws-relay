const http = require('http');
const net = require('net');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'ctf2026';

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
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (buf.length < 10) return null; len = Number(buf.readBigUInt64BE(2)); off = 10; }
  const totalNeeded = off + (masked ? 4 : 0) + len;
  if (buf.length < totalNeeded) return null;
  let payload;
  if (masked) {
    const mask = buf.slice(off, off + 4); off += 4;
    payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = buf[off + i] ^ mask[i % 4];
  } else {
    payload = buf.slice(off, off + len);
  }
  return { opcode, payload, rest: buf.slice(off + len) };
}

const server = http.createServer((req, res) => {
  // Check if this is a WebSocket upgrade that Render forwarded as regular request
  if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
    // Manually handle upgrade
    handleUpgrade(req, req.socket, Buffer.alloc(0));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK');
});

server.on('upgrade', handleUpgrade);

function handleUpgrade(req, socket, head) {
  if (!req.url.includes(SECRET)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }

  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-5AB5DC11E65A')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n' +
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

      if (frame.opcode === 0x8) {
        if (remote) remote.destroy();
        socket.destroy();
        return;
      }
      if (frame.opcode === 0x9) {
        socket.write(encodeFrame(frame.payload, 0xA));
        continue;
      }

      if (!remote) {
        const target = frame.payload.toString();
        const colonIdx = target.lastIndexOf(':');
        const host = target.substring(0, colonIdx);
        const port = parseInt(target.substring(colonIdx + 1));
        console.log('[+] Connect ' + host + ':' + port);

        remote = net.connect(port, host, () => {
          socket.write(encodeFrame('OK', 0x1));
        });
        remote.on('data', (data) => {
          try { socket.write(encodeFrame(data, 0x2)); } catch {}
        });
        remote.on('error', (e) => {
          try { socket.write(encodeFrame('ERR:' + e.message, 0x1)); socket.destroy(); } catch {}
        });
        remote.on('close', () => { try { socket.destroy(); } catch {} });
      } else {
        try { remote.write(frame.payload); } catch {}
      }
    }
  });

  socket.on('close', () => { if (remote) remote.destroy(); });
  socket.on('error', () => { if (remote) remote.destroy(); });
}

server.listen(PORT, () => { console.log('[+] Relay on port ' + PORT); });
