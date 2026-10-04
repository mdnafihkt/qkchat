import { precacheAndRoute, cleanupOutdatedCaches } from "workbox-precaching";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Purge any stale/legacy caches from previous app versions or share sheet remnants
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames
          .filter((cacheName) => !cacheName.startsWith("workbox-precache"))
          .map((cacheName) => caches.delete(cacheName))
      );
      await self.clients.claim();
    })()
  );
});

// Clean up outdated precaches and route precached assets
cleanupOutdatedCaches();
precacheAndRoute(self.__WB_MANIFEST || []);

// Strictly protect against caching any sensitive or dynamic network requests
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Never cache API, socket, blob, or backend requests
  if (
    event.request.method !== "GET" ||
    url.pathname.startsWith("/socket.io") ||
    url.pathname.startsWith("/health") ||
    url.protocol === "blob:" ||
    url.protocol === "ws:" ||
    url.protocol === "wss:"
  ) {
    return;
  }
});
