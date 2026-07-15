const DB_NAME = "QkChatLedger";
const DB_VERSION = 1;

export function initDB() {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = (event) => {
      console.error("IndexedDB error:", event.target.error);
      reject(event.target.error);
    };

    request.onsuccess = (event) => {
      resolve(event.target.result);
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains("messages")) {
        const store = db.createObjectStore("messages", {
          keyPath: "seq",
          autoIncrement: true,
        });
        store.createIndex("roomId", "roomId", { unique: false });
        store.createIndex("messageId", "messageId", { unique: true });
      }
    };
  });
}

// Save a new message
export async function saveMessage(roomId, messageData) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    
    const record = {
      roomId,
      messageId: messageData.messageId,
      timestamp: messageData.timestamp || Date.now(),
      isOwn: messageData.isOwn,
      status: messageData.status || "sent",
      ciphertext: messageData.ciphertext,
      iv: messageData.iv,
    };

    const request = store.add(record);

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = (event) => {
      // If a message with the same messageId already exists, don't fail, just update/skip.
      // But typically check duplicates before calling saveMessage.
      console.error("Failed to save message to ledger:", event.target.error);
      reject(event.target.error);
    };
  });
}

// Get all messages for a room (ordered by insertion seq)
export async function getRoomMessages(roomId) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readonly");
    const store = transaction.objectStore("messages");
    const index = store.index("roomId");
    const request = index.getAll(IDBKeyRange.only(roomId));

    request.onsuccess = () => {
      const results = request.result || [];
      // Explicitly sort by seq to guarantee sequential ordering
      results.sort((a, b) => a.seq - b.seq);
      resolve(results);
    };

    request.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

// Update message status (e.g. from "sending" to "sent" or "delivered")
export async function updateMessageStatus(messageId, status) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const index = store.index("messageId");
    const getRequest = index.get(messageId);

    getRequest.onsuccess = () => {
      const record = getRequest.result;
      if (record) {
        record.status = status;
        const putRequest = store.put(record);
        putRequest.onsuccess = () => resolve(true);
        putRequest.onerror = (event) => reject(event.target.error);
      } else {
        resolve(false);
      }
    };

    getRequest.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

// Update message fileBlob and status
export async function updateMessageFileBlob(messageId, fileBlob, status) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const index = store.index("messageId");
    const getRequest = index.get(messageId);

    getRequest.onsuccess = () => {
      const record = getRequest.result;
      if (record) {
        if (fileBlob) record.fileBlob = fileBlob;
        if (status) record.status = status;
        const putRequest = store.put(record);
        putRequest.onsuccess = () => resolve(true);
        putRequest.onerror = (event) => reject(event.target.error);
      } else {
        resolve(false);
      }
    };

    getRequest.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

// Clear all messages for a room (e.g. when leaving chat)
export async function clearRoomMessages(roomId) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const index = store.index("roomId");
    const request = index.openCursor(IDBKeyRange.only(roomId));

    request.onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      } else {
        resolve();
      }
    };

    request.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

// Clear all expired messages across all rooms based on a retention period
export async function clearExpiredMessages(retentionPeriodMs) {
  if (!retentionPeriodMs) return;
  const db = await initDB();
  const cutoff = Date.now() - retentionPeriodMs;
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor) {
        if (cursor.value.timestamp < cutoff) {
          cursor.delete();
        }
        cursor.continue();
      } else {
        resolve();
      }
    };

    request.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

// Clear messages for all rooms EXCEPT the currently active room
export async function clearAllRoomsExcept(activeRoomId) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor) {
        if (cursor.value.roomId !== activeRoomId) {
          cursor.delete();
        }
        cursor.continue();
      } else {
        resolve();
      }
    };

    request.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

// Clear all messages in the entire database
export async function clearAllMessages() {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const request = store.clear();

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = (event) => {
      reject(event.target.error);
    };
  });
}

