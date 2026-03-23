const http = require('http');
const https = require('https');
const url = require('url');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'ctf2026';

const server = http.createServer(async (req, res) => {
  // Health check
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('OK');
  }

  // Relay: /relay/<secret>/<encoded-url>
  const match = req.url.match(/^\/relay\/([^/]+)\/(.+)/);
  if (!match || match[1] !== SECRET) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  let targetUrl;
  try {
    targetUrl = decodeURIComponent(match[2]);
  } catch {
    res.writeHead(400);
    return res.end('Bad URL');
  }

  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    res.writeHead(400);
    return res.end('Invalid URL');
  }

  try {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const mod = isHttps ? https : http;

    // Build headers
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (['host', 'connection', 'proxy-connection', 'proxy-authorization'].includes(k.toLowerCase())) continue;
      headers[k] = v;
    }
    headers['host'] = parsed.host;

    // Collect request body
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: req.method,
      headers,
      rejectUnauthorized: false,
    };

    const proxyReq = mod.request(options, (proxyRes) => {
      // Copy response headers
      const rh = {};
      for (const [k, v] of Object.entries(proxyRes.headers)) {
        if (['content-encoding', 'transfer-encoding', 'content-security-policy',
             'x-frame-options', 'strict-transport-security'].includes(k.toLowerCase())) continue;
        rh[k] = v;
      }
      rh['access-control-allow-origin'] = '*';
      rh['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';

      // Stream response
      const resChunks = [];
      proxyRes.on('data', c => resChunks.push(c));
      proxyRes.on('end', () => {
        const resBody = Buffer.concat(resChunks);
        rh['content-length'] = resBody.length;
        res.writeHead(proxyRes.statusCode, rh);
        res.end(resBody);
      });
    });

    proxyReq.on('error', (e) => {
      console.log('[!] ' + e.message);
      res.writeHead(502);
      res.end('Relay error: ' + e.message);
    });

    proxyReq.setTimeout(30000, () => { proxyReq.destroy(); });

    if (body.length > 0) proxyReq.write(body);
    proxyReq.end();

  } catch (e) {
    res.writeHead(500);
    res.end('Error: ' + e.message);
  }
});

server.listen(PORT, () => {
  console.log('[+] HTTP Relay on port ' + PORT);
});

process.on('uncaughtException', (e) => {
  if (e.code !== 'ECONNRESET' && e.code !== 'EPIPE') {
    console.log('[!] ' + e.message);
  }
});
