const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');

const appDir = path.resolve(__dirname, '..');

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function httpsGet(port, route, ca) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host: '127.0.0.1', port, path: route, ca, rejectUnauthorized: true }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function stop(child) {
  if (child && child.exitCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGTERM');
    await exited;
  }
}

test('MCP HTTPS proxy forwards only the MCP paths', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-proxy-'));
  const certPath = path.join(dir, 'cert.pem');
  const keyPath = path.join(dir, 'key.pem');
  const registryPath = path.join(dir, 'registry.json');
  const configPath = path.join(dir, 'openssl.cnf');
  fs.writeFileSync(configPath, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=chat.example.com\n[ext]\nsubjectAltName=DNS:chat.example.com,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-config', configPath], { stdio: 'ignore' });
  const ca = fs.readFileSync(certPath);
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      path: req.url,
      forwardedHost: req.headers['x-forwarded-host'],
      forwardedProto: req.headers['x-forwarded-proto'],
    }));
  });
  const upstreamPort = await listen(upstream);
  const proxyPort = 13983;
  const baseEnv = {
    ...process.env,
    MCP_PROXY_HOST: 'chat.example.com',
    MCP_PROXY_PORT: String(proxyPort),
    MCP_PROXY_LISTEN: '127.0.0.1',
    MCP_UPSTREAM_HOST: '127.0.0.1',
    MCP_UPSTREAM_PORT: String(upstreamPort),
  };
  delete baseEnv.TLS_CERT_PATH;
  delete baseEnv.TLS_KEY_PATH;
  delete baseEnv.MCP_CERT_REGISTRY;

  async function startProxy(extra) {
    const child = spawn(process.execPath, [path.join(appDir, 'deploy/mcp-https-proxy.mjs')], {
      cwd: appDir,
      env: { ...baseEnv, ...extra },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        await httpsGet(proxyPort, '/mcp', ca);
        return child;
      } catch (_) {
        if (child.exitCode !== null) throw new Error('MCP proxy exited before listening');
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }
    await stop(child);
    throw new Error('MCP proxy did not listen');
  }

  let proxy;
  try {
    proxy = await startProxy({ TLS_CERT_PATH: certPath, TLS_KEY_PATH: keyPath });
    const allowed = await httpsGet(proxyPort, '/mcp', ca);
    assert.equal(allowed.status, 200);
    const allowedBody = JSON.parse(allowed.body);
    assert.equal(allowedBody.path, '/mcp');
    assert.equal(allowedBody.forwardedProto, 'https');
    assert.ok(allowedBody.forwardedHost);
    const discovery = await httpsGet(proxyPort, '/.well-known/neighbor-chat-mcp', ca);
    assert.equal(discovery.status, 200);
    const hidden = await httpsGet(proxyPort, '/api/health', ca);
    assert.equal(hidden.status, 404);
    const root = await httpsGet(proxyPort, '/', ca);
    assert.equal(root.status, 404);
    await stop(proxy);
    proxy = null;

    fs.writeFileSync(registryPath, JSON.stringify([{ host: 'chat.example.com', cert: certPath, key: keyPath }]));
    proxy = await startProxy({ MCP_CERT_REGISTRY: registryPath });
    const viaRegistry = await httpsGet(proxyPort, '/mcp', ca);
    assert.equal(viaRegistry.status, 200);
  } finally {
    await stop(proxy);
    await new Promise((resolve) => upstream.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('MCP HTTPS proxy refuses to start without a certificate', async () => {
  const env = { ...process.env, MCP_PROXY_PORT: '13980', MCP_PROXY_LISTEN: '127.0.0.1' };
  delete env.TLS_CERT_PATH;
  delete env.TLS_KEY_PATH;
  delete env.MCP_CERT_REGISTRY;
  const child = spawn(process.execPath, [path.join(appDir, 'deploy/mcp-https-proxy.mjs')], {
    cwd: appDir,
    env,
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  const [code] = await once(child, 'exit');
  assert.notEqual(code, 0);
});
