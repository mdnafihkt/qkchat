/**
 * Centralized Blob Object URL registry and cleanup utility.
 * Tracks active object URLs per room to prevent memory leaks and ensure
 * complete teardown upon room leave, message pruning, and component unmount.
 */

const roomBlobUrls = new Map(); // roomId -> Set<string>

/**
 * Creates a Blob Object URL and registers it under the specified roomId.
 * @param {string} roomId
 * @param {Blob|File} blob
 * @returns {string} The created blob object URL
 */
export function createTrackedBlobUrl(roomId, blob) {
  if (!blob) return "";
  const url = URL.createObjectURL(blob);
  if (roomId) {
    if (!roomBlobUrls.has(roomId)) {
      roomBlobUrls.set(roomId, new Set());
    }
    roomBlobUrls.get(roomId).add(url);
  }
  return url;
}

/**
 * Revokes a specific Blob URL and removes it from tracking.
 * @param {string} url
 * @param {string} [roomId] - Optional roomId hint for faster lookup
 */
export function revokeTrackedBlobUrl(url, roomId) {
  if (!url || typeof url !== "string" || !url.startsWith("blob:")) return;
  try {
    URL.revokeObjectURL(url);
  } catch (err) {
    if (import.meta.env.DEV) {
      console.warn("Failed to revoke object URL:", err);
    }
  }

  if (roomId && roomBlobUrls.has(roomId)) {
    roomBlobUrls.get(roomId).delete(url);
  } else {
    for (const urls of roomBlobUrls.values()) {
      if (urls.has(url)) {
        urls.delete(url);
        break;
      }
    }
  }
}

/**
 * Revokes all Blob URLs registered for a specific room.
 * Called when leaving a room, when a room is deleted, or when a room unmounts.
 * @param {string} roomId
 */
export function revokeRoomBlobUrls(roomId) {
  if (!roomId || !roomBlobUrls.has(roomId)) return;
  const urls = roomBlobUrls.get(roomId);
  for (const url of urls) {
    try {
      URL.revokeObjectURL(url);
    } catch (err) {
      if (import.meta.env.DEV) {
        console.warn("Failed to revoke object URL:", err);
      }
    }
  }
  roomBlobUrls.delete(roomId);
}

/**
 * Revokes all tracked Blob URLs across all rooms.
 * Called on top-level unmount or full app reset.
 */
export function revokeAllBlobUrls() {
  for (const urls of roomBlobUrls.values()) {
    for (const url of urls) {
      try {
        URL.revokeObjectURL(url);
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn("Failed to revoke object URL:", err);
        }
      }
    }
  }
  roomBlobUrls.clear();
}
