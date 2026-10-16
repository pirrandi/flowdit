// Nivel 1 — recon pasivo/no destructivo. A diferencia de Nivel 0, estas
// tools SÍ tocan la red del target — por eso, aunque el tier no exige gate
// obligatorio, TODAS validan scope explícitamente con assertTargetInScope()
// antes de mandar un solo paquete. El scope protege contra el escenario más
// grave (atacar algo no autorizado) y esa protección no puede depender de
// qué tan "peligrosa" sea la tool.
//
// Detalle deliberado: los resultados se persisten en target_ports/
// target_endpoints — las mismas tablas que ya alimentan la vista de Targets
// existente. Así el pentester ve lo que la IA encontró en la UI normal, sin
// componentes nuevos, y sin duplicar el modelo de datos.

const net = require('net');
const dns = require('dns').promises;
const db  = require('../../db');
const { assertTargetInScope, describeFetchError } = require('./targetScope');

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017];
const DEFAULT_SUBDOMAIN_WORDLIST = ['www', 'mail', 'api', 'admin', 'dev', 'staging', 'test', 'ftp', 'vpn', 'remote', 'portal', 'app', 'beta'];

function scanOnePort(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function scanPorts(host, ports, concurrency = 20) {
  const open = [];
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const results = await Promise.all(batch.map(p => scanOnePort(host, p)));
    results.forEach((isOpen, idx) => { if (isOpen) open.push(batch[idx]); });
  }
  return open;
}

// No usa ON CONFLICT porque no hay un unique index sobre (target_id, port) —
// dedup manual contra lo que ya existe antes de insertar.
async function recordOpenPorts(targetId, openPorts, userId) {
  const { rows: existing } = await db.query(`SELECT port FROM target_ports WHERE target_id=$1`, [targetId]);
  const existingPorts = new Set(existing.map(r => r.port));
  for (const port of openPorts) {
    if (existingPorts.has(port)) continue;
    await db.query(
      `INSERT INTO target_ports (target_id, port, protocol, state, added_by) VALUES ($1,$2,'tcp','open',$3)`,
      [targetId, port, userId || null]
    );
  }
}

// Un endpoint es el path, no cada combinación de parámetros: el query string
// y el fragmento se descartan antes de guardar. Visto en vivo: 764 "endpoints"
// guardados en un proyecto, 737 de ellos el mismo /api/... con un
// cache-buster (`?_=...`) distinto en cada request — 26 paths reales.
// También `//api//x/` y `/api/x` son el mismo endpoint. No se pasa a
// minúsculas: los paths distinguen mayúsculas. La migración del índice único
// (migrate.js) replica esta misma normalización en SQL — mantenerlas iguales.
const MAX_ENDPOINT_PATH_LENGTH = 1000; // VARCHAR(1000) de target_endpoints.path

function normalizeEndpointPath(path) {
  const bare = String(path).split('#')[0].split('?')[0];
  const collapsed = (bare.startsWith('/') ? bare : `/${bare}`).replace(/\/{2,}/g, '/');
  return collapsed.length > 1 ? collapsed.replace(/\/$/, '') : collapsed;
}

async function recordEndpoint(targetId, rawPath, method, statusCode, userId) {
  // Truncar en vez de dejar que el INSERT tire: el request ya se hizo y su
  // resultado tiene que llegarle al modelo igual.
  const path = normalizeEndpointPath(rawPath).slice(0, MAX_ENDPOINT_PATH_LENGTH);
  await db.query(
    `INSERT INTO target_endpoints (target_id, path, method, status_code, added_by) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (target_id, path, method) DO NOTHING`,
    [targetId, path, method, statusCode, userId || null]
  );
}

const scanToolsLevel1 = [
  {
    name: 'port_scan',
    tier: 1,
    description:
      'Run a lightweight TCP connect scan against a target to find open ports. ' +
      'Uses a small default list of common ports unless you specify your own. ' +
      "This is a native TCP-connect scan (no nmap) — good enough to confirm " +
      'services are reachable, not a substitute for a full port scanner. ' +
      'Results are saved to the target so the pentester sees them in the normal Targets view.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string', description: 'The target to scan (must be in scope)' },
        ports: { type: 'array', items: { type: 'integer' }, description: 'Optional — specific ports to check instead of the default common-ports list' },
      },
      required: ['target_id'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      const ports = (input.ports && input.ports.length) ? input.ports : DEFAULT_PORTS;
      const open = await scanPorts(target.host, ports);
      await recordOpenPorts(input.target_id, open, ctx.startedBy);
      return { host: target.host, scanned: ports.length, open_ports: open };
    },
  },

  {
    name: 'subdomain_enum',
    tier: 1,
    description:
      'Enumerate subdomains of a domain-type target via DNS resolution against ' +
      'a small built-in wordlist (or a custom one you provide), then confirm ' +
      'each one actually serves something over HTTPS (a HEAD request to "/") ' +
      "— DNS resolving is NOT proof a subdomain is real: a wildcard DNS record " +
      'or a catch-all reverse proxy makes every possible subdomain resolve and ' +
      'often serve identical content, which looks like many findings but is ' +
      'really one misconfiguration. Check `wildcard_warning` in the result, and ' +
      'the per-subdomain `reachable`/`status`/`error` fields, before reporting ' +
      'subdomains as distinct findings. Only works on targets of type "domain" ' +
      '— will error on IP/CIDR/URL targets. IMPORTANT: discovered subdomains ' +
      'are NOT automatically added as new targets — they may be out of the ' +
      'authorized scope even if the parent domain is in scope. Report them to ' +
      'the pentester; do not attempt to act against a discovered subdomain ' +
      'until it is explicitly added to scope.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string', description: 'A domain-type target to enumerate against' },
        wordlist: { type: 'array', items: { type: 'string' }, description: 'Optional — custom subdomain prefixes to try instead of the default list' },
      },
      required: ['target_id'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      if (target.type !== 'domain') {
        return { error: `target "${target.host}" is type "${target.type}", not "domain" — subdomain_enum only applies to domain targets` };
      }

      const words = (input.wordlist && input.wordlist.length) ? input.wordlist : DEFAULT_SUBDOMAIN_WORDLIST;
      const found = [];
      const resolutionErrors = [];
      await Promise.all(words.map(async (word) => {
        const candidate = `${word}.${target.host}`;
        let addresses;
        try {
          addresses = await dns.resolve4(candidate);
        } catch (err) {
          // ENOTFOUND/ENODATA = NXDOMAIN o sin registro A — el subdominio
          // genuinamente no existe, se ignora en silencio. Cualquier OTRO
          // código (ECONNREFUSED, ETIMEOUT, SERVFAIL...) significa que el
          // resolver DNS del propio contenedor falló para este lookup —
          // muy distinto de "no existe", y antes se perdía en el mismo
          // catch silencioso, produciendo falsos negativos (found: []
          // aunque el DNS estuviera roto de punta a punta).
          if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
            resolutionErrors.push({ subdomain: candidate, error: err.code || err.message });
          }
          return;
        }

        // Que DNS resuelva NO confirma que el subdominio sea real — un
        // wildcard DNS (`*.dominio`) o un proxy catch-all hace que
        // CUALQUIER subdominio resuelva y a veces hasta sirva la misma
        // página, sin que exista un backend distinto detrás. Visto en vivo:
        // 13 subdominios "encontrados", los 13 con la misma IP, ninguno
        // funcionando de verdad (cert mismatch). HEAD real a la raíz —
        // mismo timeout corto que el resto de las tools de Nivel 1, no
        // sigue redirects (no hace falta para solo confirmar alcanzable).
        let reachable = false, status = null, error = null;
        try {
          const res = await fetch(`https://${candidate}/`, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(6000) });
          reachable = true;
          status = res.status;
        } catch (err) {
          error = describeFetchError(err);
        }

        found.push({ subdomain: candidate, addresses, reachable, status, error });
      }));

      const result = { base_domain: target.host, checked: words.length, found };
      if (resolutionErrors.length) result.resolution_errors = resolutionErrors;

      // Firma de wildcard DNS: si más de uno resolvió y TODOS comparten la
      // misma IP, es casi seguro un catch-all — avisar explícito en vez de
      // dejar que se vea como N hallazgos genuinos e independientes.
      const uniqueIps = new Set(found.flatMap(f => f.addresses));
      if (found.length > 1 && uniqueIps.size === 1) {
        result.wildcard_warning = `Los ${found.length} subdominios resueltos comparten la misma IP (${[...uniqueIps][0]}) — probablemente wildcard DNS o un proxy catch-all, no subdominios reales independientes. Mirá el campo "reachable"/"status"/"error" de cada uno antes de reportarlos como hallazgos distintos.`;
      }

      return result;
    },
  },

  {
    name: 'fetch_endpoint',
    tier: 1,
    description:
      'Fetch a single URL path on a target with a safe, read-only HTTP method ' +
      '(GET or HEAD only — for POST/PUT/DELETE or sending a crafted payload, ' +
      'use send_http_request or test_payload instead, which require approval). ' +
      'Returns status code, a few response headers, and a truncated body. ' +
      'Results are saved to the target so the pentester sees them in the normal Targets view.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string', description: 'The target to fetch from (must be in scope)' },
        path: { type: 'string', description: 'URL path, e.g. "/robots.txt" or "/api/health"' },
        method: { type: 'string', enum: ['GET', 'HEAD'], description: 'Defaults to GET' },
        scheme: { type: 'string', enum: ['https', 'http'], description: 'Defaults to https' },
      },
      required: ['target_id', 'path'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      const method = input.method || 'GET';
      if (method !== 'GET' && method !== 'HEAD') {
        return { error: `method "${method}" not allowed here — use send_http_request (Nivel 2, requiere aprobación) for anything beyond GET/HEAD` };
      }
      const scheme = input.scheme || 'https';
      const url = `${scheme}://${target.host}${input.path.startsWith('/') ? '' : '/'}${input.path}`;

      let response;
      try {
        response = await fetch(url, { method, redirect: 'manual', signal: AbortSignal.timeout(8000) });
      } catch (err) {
        return { error: `request failed: ${describeFetchError(err)}` };
      }

      const body = method === 'GET' ? (await response.text()).slice(0, 2000) : null;
      await recordEndpoint(input.target_id, input.path, method, response.status, ctx.startedBy);

      return {
        url, status: response.status,
        headers: { 'content-type': response.headers.get('content-type'), server: response.headers.get('server'), location: response.headers.get('location') },
        body_preview: body,
      };
    },
  },

  {
    name: 'fetch_page_source',
    tier: 1,
    description:
      'Fetch the FULL source of a URL on a target — HTML, JavaScript, CSS, ' +
      'anything served as text — like viewing page source in a browser. ' +
      "Unlike fetch_endpoint (which truncates to a 2000-char preview), this " +
      'returns the real content, paginated via offset/limit for large files. ' +
      'For HTML responses, it also extracts every linked <script src> and ' +
      '<link href> URL so you can discover what client-side assets exist and ' +
      'fetch them next. Read the actual client-side code — hardcoded values, ' +
      'comments, API paths, dangerous patterns — instead of only probing ' +
      'behavior blindly from the outside; this finds things black-box testing misses.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string' },
        path:      { type: 'string', description: 'e.g. "/", "/static/js/main.a1b2c3.js"' },
        scheme:    { type: 'string', enum: ['https', 'http'] },
        offset:    { type: 'integer', description: 'Character offset to resume reading from, for files bigger than one call can return (default 0)' },
        limit:     { type: 'integer', description: 'Max characters to return starting at offset (default 20000)' },
      },
      required: ['target_id', 'path'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      const scheme = input.scheme || 'https';
      const url = `${scheme}://${target.host}${input.path.startsWith('/') ? '' : '/'}${input.path}`;

      let response;
      try {
        response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
      } catch (err) {
        return { error: `request failed: ${describeFetchError(err)}` };
      }

      const fullText = await response.text();
      const offset = input.offset || 0;
      const limit  = input.limit  || 20000;
      const slice  = fullText.slice(offset, offset + limit);

      const result = {
        url, status: response.status,
        content_type: response.headers.get('content-type'),
        total_length: fullText.length,
        offset, returned_length: slice.length,
        truncated: fullText.length > offset + limit, // si true, volver a llamar con offset += returned_length para seguir leyendo
        content: slice,
      };

      if ((response.headers.get('content-type') || '').includes('html')) {
        const scriptSrcs = [...fullText.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map(m => m[1]);
        const linkHrefs  = [...fullText.matchAll(/<link[^>]+href=["']([^"']+)["']/gi)].map(m => m[1]);
        result.linked_assets = [...new Set([...scriptSrcs, ...linkHrefs])];
      }

      await recordEndpoint(input.target_id, input.path, 'GET', response.status, ctx.startedBy);
      return result;
    },
  },

  {
    name: 'search_page_source',
    tier: 1,
    description:
      'Fetch a URL on a target and search its full content for a regex ' +
      'pattern, returning only the matches with surrounding context — the ' +
      'equivalent of grep, applied to a remote target instead of a local ' +
      'filesystem. Use this to search large JS bundles for hardcoded ' +
      'secrets/API keys, dangerous sinks (eval(, innerHTML, document.write), ' +
      'internal endpoint paths, or any pattern, without pulling the whole ' +
      'file into your context. Matches are windowed by character position, ' +
      "not by line — minified JS often ships as one giant line, so line-based " +
      'grep would be useless on it.',
    input_schema: {
      type: 'object',
      properties: {
        target_id:     { type: 'string' },
        path:          { type: 'string' },
        scheme:        { type: 'string', enum: ['https', 'http'] },
        pattern:       { type: 'string', description: 'Regex pattern (JavaScript regex syntax)' },
        flags:         { type: 'string', description: 'Optional regex flags, e.g. "i" for case-insensitive (default "i")' },
      },
      required: ['target_id', 'path', 'pattern'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      const scheme = input.scheme || 'https';
      const url = `${scheme}://${target.host}${input.path.startsWith('/') ? '' : '/'}${input.path}`;

      let response;
      try {
        response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
      } catch (err) {
        return { error: `request failed: ${describeFetchError(err)}` };
      }
      const text = await response.text();

      let re;
      try {
        const flags = (input.flags || 'i').replace(/g/g, '') + 'g'; // forzar global una sola vez
        re = new RegExp(input.pattern, flags);
      } catch (err) {
        return { error: `invalid regex: ${err.message}` };
      }

      const WINDOW = 150;
      const matches = [];
      let m;
      while ((m = re.exec(text)) !== null && matches.length < 50) {
        const start = Math.max(0, m.index - WINDOW);
        const end   = Math.min(text.length, m.index + m[0].length + WINDOW);
        matches.push({ position: m.index, match: m[0].slice(0, 300), context: text.slice(start, end) });
        if (m[0].length === 0) re.lastIndex++; // evita loop infinito con patrones que matchean string vacío
      }

      await recordEndpoint(input.target_id, input.path, 'GET', response.status, ctx.startedBy);
      return { url, total_length: text.length, match_count: matches.length, matches };
    },
  },
];

module.exports = { scanToolsLevel1, normalizeEndpointPath };
