// Decrypts the site in the browser. Pages live under s/; every request there is answered from the
// encrypted files in e/ using the key the password page (index.html) handed over. The key is kept
// in IndexedDB as a non-extractable CryptoKey for 12 hours.
const ROOT = new URL('./', self.registration.scope).href, PREFIX = ROOT + 's/';
const TTL = 12 * 60 * 60 * 1000, encoder = new TextEncoder();
const TYPES = {
  html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8', json: 'application/json; charset=utf-8', svg: 'image/svg+xml', txt: 'text/plain; charset=utf-8',
  ftl: 'text/plain; charset=utf-8', pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp',
  gif: 'image/gif', mp4: 'video/mp4', webm: 'video/webm', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', wasm: 'application/wasm',
  djvu: 'image/vnd.djvu', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', doc: 'application/msword'
};

function store(mode, action) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('pweb-diploma-gate', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('session');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const tx = request.result.transaction('session', mode), result = action(tx.objectStore('session'));
      tx.oncomplete = () => resolve(result.result); tx.onerror = () => reject(tx.error);
    };
  });
}
let session = null, manifest = null;
async function current() {
  session ||= await store('readonly', s => s.get('current')).catch(() => null);
  if (session && session.expires < Date.now()) await forget();
  return session;
}
async function forget() { session = null; manifest = null; await store('readwrite', s => s.delete('current')).catch(() => {}); }

async function decrypt(key, data, label) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(0, 12), additionalData: encoder.encode(label) }, key, data.subarray(12)));
}
async function files(key, fresh) {
  if (!manifest || fresh) {
    const response = await fetch(ROOT + 'm.bin', { cache: 'no-cache' });
    manifest = JSON.parse(new TextDecoder().decode(await decrypt(key, new Uint8Array(await response.arrayBuffer()), 'manifest'))).files;
  }
  return manifest;
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
  const { type, key, notes } = event.data || {}, port = event.ports[0];
  const done = type === 'login'
    ? (session = { key, notes, expires: Date.now() + TTL }, manifest = null, store('readwrite', s => s.put(session, 'current')))
    : type === 'logout' ? forget() : Promise.resolve();
  event.waitUntil(done.then(() => port?.postMessage(true), () => port?.postMessage(false)));
});
self.addEventListener('fetch', event => { if (event.request.url.startsWith(PREFIX)) event.respondWith(serve(event.request)); });

async function serve(request) {
  const url = new URL(request.url), navigation = request.mode === 'navigate';
  let path = decodeURIComponent(url.pathname.slice(new URL(PREFIX).pathname.length));
  const login = () => navigation ? Response.redirect(ROOT + '?to=' + encodeURIComponent(path + url.search), 302) : new Response('Unauthorized', { status: 401 });
  const s = await current();
  if (!s) return login();
  if (path === '__session.json') return new Response(JSON.stringify({ notes: s.notes }), { headers: { 'Content-Type': TYPES.json, 'Cache-Control': 'no-store' } });
  let list;
  // A new deploy or a changed password: the manifest is re-read on every page load.
  try { list = await files(s.key, navigation); } catch { await forget(); return login(); }
  if (path === '' || path.endsWith('/')) path += 'index.html';
  const file = list[path];
  if (!file) return list[path + '/index.html'] ? Response.redirect(url.origin + url.pathname + '/' + url.search, 301) : new Response('Not found', { status: 404 });
  let part = 0;
  const body = new ReadableStream({
    async pull(controller) {
      if (part >= file.parts) { controller.close(); return; }
      const name = `${file.id}.${part++}`, response = await fetch(ROOT + 'e/' + name);
      if (!response.ok) throw new Error('missing ' + name);
      controller.enqueue(await decrypt(s.key, new Uint8Array(await response.arrayBuffer()), name));
    }
  });
  const type = TYPES[path.split('.').pop().toLowerCase()] || 'application/octet-stream';
  return new Response(body, { headers: { 'Content-Type': type, 'Content-Length': String(file.size), 'Cache-Control': 'no-store' } });
}
