const CACHE_NAME = 'securevault-shell-v17';
// Every asset is same-origin; nothing is fetched from third-party CDNs.
// './' (not './index.html'): Cloudflare Pages redirects /index.html to /, and redirected responses can't serve navigations.
const APP_SHELL = [
    './',
    './securevault.js',
    './securevault-decrypt-kit.js',
    './securevault.css',
    './manifest.webmanifest',
    './icon.svg',
    './vendor/fontawesome/css/all.min.css',
    './vendor/fontawesome/webfonts/fa-solid-900.woff2',
    './vendor/fontawesome/webfonts/fa-regular-400.woff2',
    './fonts/inter-latin.woff2',
    './fonts/inter-latin-ext.woff2',
    './fonts/jetbrains-mono-latin.woff2',
    './fonts/jetbrains-mono-latin-ext.woff2'
];

self.addEventListener('install', (event) => {
    event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const request = event.request;
    if (request.method !== 'GET') return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;

    // Network-first for the page and script so security fixes are picked up as soon as they are deployed
    if (request.mode === 'navigate' || url.pathname.endsWith('.js')) {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    if (response.ok) {
                        const copy = response.clone();
                        caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
                    }
                    return response;
                })
                .catch(() => caches.match(request).then((hit) => hit || caches.match('./')))
        );
        return;
    }

    // Stale-while-revalidate for static same-origin assets
    event.respondWith(
        caches.match(request).then((cached) => {
            const network = fetch(request)
                .then((response) => {
                    if (response.ok && response.type === 'basic') {
                        const copy = response.clone();
                        caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
                    }
                    return response;
                })
                .catch(() => cached);
            return cached || network;
        })
    );
});
