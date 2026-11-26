// Service Worker del Autenticador Soberano: caché versionada y estrategia cache-first
// para los archivos de la app. Así funciona completamente sin conexión.
// No intercepta nada fuera de su alcance (/app/) ni peticiones que no sean GET,
// por lo que /health siempre va a la red.

const VERSION = 'autenticador-v1.1.0';
const ARCHIVOS = [
  './',
  './index.html',
  './manifest.json',
  './css/app.css',
  './js/app.js',
  './js/almacen.js',
  './js/boveda.js',
  './js/cripto.js',
  './js/escaner.js',
  './js/otpauth.js',
  './js/totp.js',
  './icons/icono.svg',
  './icons/icono-mascara.svg',
  './icons/icono-192.png',
  './icons/icono-512.png',
];

self.addEventListener('install', (evento) => {
  evento.waitUntil(
    caches.open(VERSION)
      .then((cache) => cache.addAll(ARCHIVOS.map((ruta) => new Request(ruta, { cache: 'reload' }))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (evento) => {
  evento.waitUntil(
    caches.keys()
      .then((claves) => Promise.all(claves.filter((c) => c.startsWith('autenticador-') && c !== VERSION).map((c) => caches.delete(c))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (evento) => {
  const peticion = evento.request;
  if (peticion.method !== 'GET') return;
  const url = new URL(peticion.url);
  const alcance = new URL(self.registration.scope);
  if (url.origin !== alcance.origin || !url.pathname.startsWith(alcance.pathname)) return;

  // Navegaciones: siempre la página principal en caché (la URL puede llevar ?… o variantes).
  if (peticion.mode === 'navigate') {
    evento.respondWith(
      caches.match('./index.html', { ignoreSearch: true }).then((r) => r || fetch(peticion)),
    );
    return;
  }

  evento.respondWith(
    caches.match(peticion, { ignoreSearch: true }).then((enCache) => {
      if (enCache) return enCache;
      return fetch(peticion).then((respuesta) => {
        if (respuesta.ok && respuesta.type === 'basic') {
          const copia = respuesta.clone();
          caches.open(VERSION).then((cache) => cache.put(peticion, copia));
        }
        return respuesta;
      });
    }),
  );
});
