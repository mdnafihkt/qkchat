// Utility to manage per-room peer identities (zero-knowledge, stored client-side only)

export function getOrCreateRoomPeerId(roomId) {
  if (!roomId) return null;
  const storageKey = `qkchat_peer_id_${roomId}`;
  let peerId = localStorage.getItem(storageKey);
  if (!peerId) {
    peerId = "peer_" + crypto.randomUUID();
    localStorage.setItem(storageKey, peerId);
  }
  return peerId;
}

export function removeRoomPeerId(roomId) {
  if (!roomId) return;
  localStorage.removeItem(`qkchat_peer_id_${roomId}`);
}
