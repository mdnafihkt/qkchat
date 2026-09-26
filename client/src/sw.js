import { precacheAndRoute, cleanupOutdatedCaches } from "workbox-precaching";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

cleanupOutdatedCaches();
precacheAndRoute(self.__WB_MANIFEST || []);

// IndexedDB Helper for Service Worker
function saveSharedPayloadInSW(payload) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("QkChatLedger", 2);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains("messages")) {
        const store = db.createObjectStore("messages", { keyPath: "seq", autoIncrement: true });
        store.createIndex("roomId", "roomId", { unique: false });
        store.createIndex("messageId", "messageId", { unique: true });
      }
      if (!db.objectStoreNames.contains("shared_payload")) {
        db.createObjectStore("shared_payload", { keyPath: "id" });
      }
    };
    request.onsuccess = (event) => {
      const db = event.target.result;
      const tx = db.transaction("shared_payload", "readwrite");
      const store = tx.objectStore("shared_payload");
      const record = { id: "latest", ...payload, timestamp: Date.now() };
      const putReq = store.put(record);
      putReq.onsuccess = () => resolve(true);
      putReq.onerror = (err) => reject(err);
    };
    request.onerror = (err) => reject(err);
  });
}

// Intercept Web Share Target POST requests
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  if (event.request.method === "POST" && url.pathname === "/share-target") {
    console.log("[SW] Intercepted POST /share-target request!");
    event.respondWith(
      (async () => {
        try {
          const formData = await event.request.formData();
          console.log("[SW] Received FormData keys:", Array.from(formData.keys()));

          const title = formData.get("title") || "";
          const text = formData.get("text") || "";
          const sharedUrl = formData.get("url") || "";
          
          let files = [];

          // Log all entries for debugging on device
          for (const [key, value] of formData.entries()) {
            console.log(`[SW] FormData entry: key="${key}", type=${typeof value}, isFile=${value instanceof File}`);
            if (value instanceof File) {
              console.log(`[SW] File details: name="${value.name}", size=${value.size}, type="${value.type}"`);
              if (value.size > 0) {
                files.push(value);
              }
            }
          }

          let fileBlob = null;
          let fileName = "";
          let fileType = "";

          if (files.length > 0) {
            fileBlob = files[0];
            fileName = files[0].name || "shared_media";
            fileType = files[0].type || "application/octet-stream";
            console.log("[SW] Selected file for sharing:", fileName, fileType, fileBlob.size);
          } else {
            console.warn("[SW] No File objects found in POST /share-target formData!");
          }

          const saveResult = await saveSharedPayloadInSW({
            title,
            text,
            url: sharedUrl,
            fileBlob,
            fileName,
            fileType,
          });

          console.log("[SW] saveSharedPayloadInSW result:", saveResult);
          return Response.redirect("/share", 303);
        } catch (err) {
          console.error("[SW] Failed to handle Web Share Target POST:", err);
          return Response.redirect("/share", 303);
        }
      })()
    );
  }
});
