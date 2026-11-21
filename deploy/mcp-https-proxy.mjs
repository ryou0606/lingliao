import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';

const DOMAIN = process.env.MCP_PROXY_HOST || 'chat.example.com';
const CERT_REGISTRY = process.env.MCP_CERT_REGISTRY || '';
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || '';
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || '';
const UPSTREAM_HOST = process.env.MCP_UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.MCP_UPSTREAM_PORT || 9900);
const LISTEN_HOST = process.env.MCP_PROXY_LISTEN || '::';
const LISTEN_PORT = Number(process.env.MCP_PROXY_PORT || 443);

const allowedPaths = new Set([
  '/mcp',
  '/.well-known/neighbor-chat-mcp',
]);

function certificateMaterial() {
  if (TLS_CERT_PATH && TLS_KEY_PATH) {
    return {
      id: `files:${TLS_CERT_PATH}:${TLS_KEY_PATH}`,
      key: fs.readFileSync(TLS_KEY_PATH),
      cert: fs.readFileSync(TLS_CERT_PATH),
    };
  }
  if (CERT_REGISTRY) {
    const entries = JSON.parse(fs.readFileSync(CERT_REGISTRY, 'utf8'));
    const entry = Array.isArray(entries) ? entries.find((item) => item && item.host === DOMAIN) : null;
    if (!entry?.cert || !entry?.key) {
      throw new Error(`certificate for ${DOMAIN} is not listed in MCP_CERT_REGISTRY`);
    }
    return {
      id: `registry:${entry.cert}:${entry.key}`,
      key: fs.readFileSync(entry.key),
      cert: fs.readFileSync(entry.cert),
    };
  }
  throw new Error('Set TLS_CERT_PATH and TLS_KEY_PATH, or MCP_CERT_REGISTRY, before starting the MCP HTTPS proxy.');
}

let certificate = certificateMaterial();

function upstreamHeaders(request) {
  return {
    ...request.headers,
    host: `${UPSTREAM_HOST}:${UPSTREAM_PORT}`,
    'x-forwarded-host': request.headers.host || DOMAIN,
    'x-forwarded-proto': 'https',
    'x-forwarded-for': request.socket.remoteAddress || '',
    connection: 'close',
  };
}

function reject(res, statusCode, message) {
  const body = JSON.stringify({ error: message });
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

const proxy = https.createServer({ key: certificate.key, cert: certificate.cert }, (request, response) => {
  const path = new URL(request.url || '/', `https://${DOMAIN}`).pathname;
  if (!allowedPaths.has(path)) {
    reject(response, 404, 'not_found');
    return;
  }

  const upstream = http.request({
    hostname: UPSTREAM_HOST,
    port: UPSTREAM_PORT,
    method: request.method,
    path: request.url,
    headers: upstreamHeaders(request),
  }, (upstreamResponse) => {
    response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
    upstreamResponse.pipe(response);
  });

  upstream.on('error', (error) => {
    if (!response.headersSent) reject(response, 502, 'upstream_unavailable');
    else response.destroy(error);
  });
  request.on('aborted', () => upstream.destroy());
  request.pipe(upstream);
});

proxy.on('tlsClientError', (error) => {
  console.error(`TLS client error: ${error.message}`);
});

proxy.listen({ host: LISTEN_HOST, port: LISTEN_PORT }, () => {
  console.log(`Neighbor Chat MCP HTTPS proxy listening on [${LISTEN_HOST}]:${LISTEN_PORT}`);
});

function refreshCertificate() {
  try {
    const next = certificateMaterial();
    if (next.id === certificate.id) return;
    proxy.setSecureContext({ key: next.key, cert: next.cert });
    certificate = next;
    console.log('Reloaded the MCP proxy certificate.');
  } catch (error) {
    console.error(`Certificate refresh skipped: ${error.message}`);
  }
}

setInterval(refreshCertificate, 60_000).unref();
