const STORAGE_KEY = "qkchat_room_sequences";

// In-memory sequence tracking:
// sequenceState[roomId] = { outgoingSeq: number, highestAcceptedSeq: number }
const sequenceState = {};

// In-memory set of seen message IDs per room:
// seenMessageIds[roomId] = Set<string>
const seenMessageIds = {};

// Helper to load persisted sequences from localStorage
function loadPersistedSequences() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    return {};
  }
}

// Helper to save persisted sequences to localStorage
function savePersistedSequences(seqs) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seqs));
  } catch (e) {
    // Ignore storage quota errors
  }
}

/**
 * Initialize sequence numbers and seen message IDs for a room from loaded messages.
 */
export function initRoomSequence(roomId, messages = []) {
  if (!roomId) return;

  const persisted = loadPersistedSequences();
  const roomPersisted = persisted[roomId] || { outgoingSeq: 0, highestAcceptedSeq: 0 };

  if (!seenMessageIds[roomId]) {
    seenMessageIds[roomId] = new Set();
  }

  let maxOwnSeq = roomPersisted.outgoingSeq || 0;
  let maxAcceptedSeq = roomPersisted.highestAcceptedSeq || 0;

  for (const msg of messages) {
    if (msg.id) {
      seenMessageIds[roomId].add(String(msg.id));
    }
    const msgSeq = typeof msg.seq === "number" ? msg.seq : (typeof msg.msgSeq === "number" ? msg.msgSeq : null);
    if (msgSeq !== null) {
      if (msg.isOwn) {
        if (msgSeq > maxOwnSeq) maxOwnSeq = msgSeq;
      } else {
        if (msgSeq > maxAcceptedSeq) maxAcceptedSeq = msgSeq;
      }
    }
  }

  sequenceState[roomId] = {
    outgoingSeq: maxOwnSeq,
    highestAcceptedSeq: maxAcceptedSeq,
  };

  persisted[roomId] = {
    outgoingSeq: maxOwnSeq,
    highestAcceptedSeq: maxAcceptedSeq,
  };
  savePersistedSequences(persisted);
}

/**
 * Get the next monotonically increasing outgoing sequence number for a room.
 */
export function getNextOutgoingSeq(roomId) {
  if (!roomId) return 1;

  if (!sequenceState[roomId]) {
    const persisted = loadPersistedSequences();
    sequenceState[roomId] = persisted[roomId] || { outgoingSeq: 0, highestAcceptedSeq: 0 };
  }

  sequenceState[roomId].outgoingSeq = (sequenceState[roomId].outgoingSeq || 0) + 1;

  const persisted = loadPersistedSequences();
  persisted[roomId] = {
    ...(persisted[roomId] || {}),
    outgoingSeq: sequenceState[roomId].outgoingSeq,
  };
  savePersistedSequences(persisted);

  return sequenceState[roomId].outgoingSeq;
}

/**
 * Get the highest accepted incoming sequence number for a room.
 */
export function getHighestAcceptedSeq(roomId) {
  if (!roomId) return 0;
  if (!sequenceState[roomId]) {
    const persisted = loadPersistedSequences();
    sequenceState[roomId] = persisted[roomId] || { outgoingSeq: 0, highestAcceptedSeq: 0 };
  }
  return sequenceState[roomId].highestAcceptedSeq || 0;
}

/**
 * Check if a messageId has already been seen in a room.
 */
export function isMessageIdSeen(roomId, messageId) {
  if (!roomId || !messageId) return false;
  return seenMessageIds[roomId]?.has(String(messageId)) || false;
}

/**
 * Record a messageId as seen in a room.
 */
export function recordMessageIdSeen(roomId, messageId) {
  if (!roomId || !messageId) return;
  if (!seenMessageIds[roomId]) {
    seenMessageIds[roomId] = new Set();
  }
  seenMessageIds[roomId].add(String(messageId));
}

/**
 * Validates an incoming message against replay attacks and records it if valid.
 * Returns { valid: boolean, reason?: string }
 */
export function validateAndAcceptMessage(roomId, messageId, seq) {
  if (!roomId) return { valid: false, reason: "MISSING_ROOM_ID" };
  if (!messageId) return { valid: false, reason: "MISSING_MESSAGE_ID" };

  const idStr = String(messageId);
  if (isMessageIdSeen(roomId, idStr)) {
    return { valid: false, reason: "DUPLICATE_MESSAGE_ID" };
  }

  if (typeof seq !== "number" || !Number.isInteger(seq)) {
    return { valid: false, reason: "INVALID_SEQUENCE_NUMBER" };
  }

  const currentHighest = getHighestAcceptedSeq(roomId);
  if (seq <= currentHighest) {
    return {
      valid: false,
      reason: "DUPLICATE_OR_OLD_SEQUENCE_NUMBER",
      currentHighest,
      seq,
    };
  }

  // Accept message
  recordMessageIdSeen(roomId, idStr);

  if (!sequenceState[roomId]) {
    sequenceState[roomId] = { outgoingSeq: 0, highestAcceptedSeq: 0 };
  }
  sequenceState[roomId].highestAcceptedSeq = seq;

  const persisted = loadPersistedSequences();
  persisted[roomId] = {
    ...(persisted[roomId] || {}),
    highestAcceptedSeq: seq,
  };
  savePersistedSequences(persisted);

  return { valid: true };
}

/**
 * Clear replay protection tracking for a room.
 */
export function clearRoomReplayState(roomId) {
  if (!roomId) return;
  delete sequenceState[roomId];
  delete seenMessageIds[roomId];
  const persisted = loadPersistedSequences();
  if (persisted[roomId]) {
    delete persisted[roomId];
    savePersistedSequences(persisted);
  }
}
