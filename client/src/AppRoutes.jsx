import React, { useState, useEffect, useRef } from "react";
import { Routes, Route, useNavigate, Navigate, useLocation } from "react-router-dom";
import io from "socket.io-client";
import { AlertCircle, X } from "lucide-react";
import {
  deriveKey,
  generateRandomSalt,
  decryptMessage,
  decryptBinary,
  deriveAuthKey,
  signNonce,
  exportAuthKeyHex,
} from "./utils/crypto";
import { saveMessage, getRoomMessages, updateMessageStatus, clearRoomMessages, clearExpiredMessages } from "./utils/ledger";
import { getOrCreateRoomPeerId, removeRoomPeerId } from "./utils/peer";
import {
  initRoomSequence,
  getHighestAcceptedSeq,
  validateAndAcceptMessage,
  isMessageIdSeen,
  recordMessageIdSeen,
  clearRoomReplayState,
} from "./utils/replayProtection";
import {
  createTrackedBlobUrl,
  revokeTrackedBlobUrl,
  revokeRoomBlobUrls,
  revokeAllBlobUrls,
} from "./utils/blobRegistry";
import HomeSelection from "./components/HomeSelection/HomeSelection";
import StartChat from "./components/StartChat/StartChat";
import JoinChat from "./components/JoinChat/JoinChat";
import ChatPage from "./components/ChatPage/ChatPage";
import SessionRecovery from "./components/SessionRecovery/SessionRecovery";

// Helper component to trigger error toast notification and redirect Home
function FallbackRedirect({ onError }) {
  const location = useLocation();

  useEffect(() => {
    onError(`The page or route "${location.pathname}" does not exist.`);
  }, [location.pathname, onError]);

  return <Navigate to="/" replace />;
}

export default function AppRoutes({ SOCKET_URL }) {
  const navigate = useNavigate();
  const [socket, setSocket] = useState(null);
  const [rooms, setRooms] = useState({}); // { [roomId]: { roomId, roomName, cryptoKey, messages, isConnected, unreadCount, retentionPeriod, isLocked } }
  const [activeRoomId, setActiveRoomId] = useState("");
  const [isInitialized, setIsInitialized] = useState(false);
  const [errorToast, setErrorToast] = useState("");

  const triggerErrorToast = (msg) => {
    setErrorToast(msg);
  };

  useEffect(() => {
    if (errorToast) {
      const timer = setTimeout(() => {
        setErrorToast("");
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [errorToast]);

  // Refs for stale closures in socket handlers
  const roomsRef = useRef({});
  const activeRoomIdRef = useRef("");
  const socketRef = useRef(null);

  useEffect(() => {
    roomsRef.current = rooms;
  }, [rooms]);

  useEffect(() => {
    activeRoomIdRef.current = activeRoomId;
  }, [activeRoomId]);

  useEffect(() => {
    socketRef.current = socket;
  }, [socket]);

  // Read stored room list, session keys, and room custom names
  const getStoredActiveRooms = () => {
    try {
      const stored = localStorage.getItem("qkchat_active_rooms");
      if (stored) return JSON.parse(stored);
    } catch (e) {}
    const legacy = localStorage.getItem("room_id");
    return legacy ? [legacy] : [];
  };

  const setStoredActiveRooms = (roomIdsList) => {
    localStorage.setItem("qkchat_active_rooms", JSON.stringify(roomIdsList));
    if (roomIdsList.length > 0) {
      localStorage.setItem("room_id", roomIdsList[0]);
    } else {
      localStorage.removeItem("room_id");
    }
  };

  const getStoredRoomNames = () => {
    try {
      const stored = localStorage.getItem("qkchat_room_names");
      if (stored) return JSON.parse(stored);
    } catch (e) {}
    return {};
  };

  const setStoredRoomName = (rId, name) => {
    const namesMap = getStoredRoomNames();
    if (name && name.trim()) {
      namesMap[rId] = name.trim();
    } else {
      delete namesMap[rId];
    }
    localStorage.setItem("qkchat_room_names", JSON.stringify(namesMap));
  };

  const getStoredRoomSalts = () => {
    try {
      const stored = localStorage.getItem("qkchat_room_salts");
      if (stored) return JSON.parse(stored);
    } catch (e) {}
    return {};
  };

  const getStoredRoomSalt = (rId) => {
    return getStoredRoomSalts()[rId] || null;
  };

  const setStoredRoomSalt = (rId, salt) => {
    const salts = getStoredRoomSalts();
    if (salt) {
      salts[rId] = salt;
    } else {
      delete salts[rId];
    }
    localStorage.setItem("qkchat_room_salts", JSON.stringify(salts));
  };

  const removeStoredRoomSalt = (rId) => {
    const salts = getStoredRoomSalts();
    delete salts[rId];
    localStorage.setItem("qkchat_room_salts", JSON.stringify(salts));
  };

  // Helper to load messages from ledger for a specific room
  const loadMessagesFromLedger = async (targetRoomId, key) => {
    if (!key) return [];
    try {
      const records = await getRoomMessages(targetRoomId);
      const decryptedMessages = [];
      for (const record of records) {
        const decryptedText = await decryptMessage(key, {
          ciphertext: record.ciphertext,
          iv: record.iv,
        });

        if (decryptedText !== null) {
          let msgData;
          try {
            msgData = JSON.parse(decryptedText);
          } catch (err) {
            msgData = { type: "text", text: decryptedText };
          }
          if (record.encryptedFile && key) {
            try {
              const decryptedBuf = await decryptBinary(
                key,
                record.encryptedFile.encryptedBytes,
                record.encryptedFile.iv
              );
              if (decryptedBuf) {
                const blob = new Blob([decryptedBuf], {
                  type: record.encryptedFile.mimeType || msgData.fileType || "application/octet-stream",
                });
                msgData.fileData = createTrackedBlobUrl(targetRoomId, blob);
                msgData.fileName = record.encryptedFile.fileName || msgData.fileName;
                msgData.fileType = record.encryptedFile.mimeType || msgData.fileType;
              }
            } catch (fileErr) {
              if (import.meta.env.DEV) {
                console.error("Failed to decrypt stored file:", fileErr);
              }
            }
          } else if (record.fileBlob) {
            msgData.fileData = createTrackedBlobUrl(targetRoomId, record.fileBlob);
          }
          const seq = typeof msgData.seq === "number" ? msgData.seq : (typeof record.msgSeq === "number" ? record.msgSeq : undefined);
          decryptedMessages.push({
            id: record.messageId,
            ...msgData,
            seq,
            isOwn: record.isOwn,
            status: record.status,
            time: new Date(record.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              hour12: true,
            }),
            timestamp: record.timestamp,
          });
        } else {
          decryptedMessages.push({
            id: record.messageId || Date.now(),
            text: "[Encrypted message - Failed to decrypt]",
            isOwn: record.isOwn,
            time: new Date(record.timestamp).toLocaleTimeString(),
            timestamp: record.timestamp,
          });
        }
      }
      if (records.length > 0) {
        const hasFailedMessages = decryptedMessages.some((m) => m.text === "[Encrypted message - Failed to decrypt]");
        const hasSuccessfulMessages = decryptedMessages.some((m) => m.text !== "[Encrypted message - Failed to decrypt]");
        if (hasFailedMessages && !hasSuccessfulMessages) {
          throw new Error("Invalid password: Failed to decrypt messages");
        }
      }
      initRoomSequence(targetRoomId, decryptedMessages);
      return decryptedMessages;
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error(`Failed to load messages for room ${targetRoomId}:`, err);
      }
      throw err;
    }
  };

  const autoSync = async (activeSocket, targetRoomId) => {
    if (!activeSocket || !targetRoomId) return;
    try {
      const records = await getRoomMessages(targetRoomId);
      let lastTimestamp = 0;
      if (records.length > 0) {
        lastTimestamp = Math.max(...records.map((r) => r.timestamp));
      }
      activeSocket.emit("sync_request", {
        roomId: targetRoomId,
        timestamp: lastTimestamp,
      });
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error(`Failed to trigger autoSync for room ${targetRoomId}:`, err);
      }
    }
  };

  // Leave / Close a specific Room
  const handleLeaveRoom = async (targetRoomId) => {
    const peerId = getOrCreateRoomPeerId(targetRoomId);
    if (socketRef.current) {
      socketRef.current.emit("leave_room", { roomId: targetRoomId, peerId, clearSlot: true });
    }

    await clearRoomMessages(targetRoomId).catch((err) => {
      if (import.meta.env.DEV) {
        console.error(`Failed to clear ledger for room ${targetRoomId}:`, err);
      }
    });

    removeStoredRoomSalt(targetRoomId);
    removeRoomPeerId(targetRoomId);
    setStoredRoomName(targetRoomId, "");
    clearRoomReplayState(targetRoomId);
    revokeRoomBlobUrls(targetRoomId);
    const updatedList = getStoredActiveRooms().filter((id) => id !== targetRoomId);
    setStoredActiveRooms(updatedList);

    setRooms((prev) => {
      const next = { ...prev };
      delete next[targetRoomId];
      return next;
    });

    if (activeRoomIdRef.current === targetRoomId) {
      if (updatedList.length > 0) {
        setActiveRoomId(updatedList[0]);
      } else {
        setActiveRoomId("");
        navigate("/");
      }
    }
  };

  // Delete Room for ALL peers in the room
  const handleDeleteRoomForAll = async (targetRoomId) => {
    if (socketRef.current) {
      socketRef.current.emit("delete_room", { roomId: targetRoomId });
    }
    await handleLeaveRoom(targetRoomId);
    navigate("/");
  };

  // Socket setup
  const initSocketIfNeeded = () => {
    if (socketRef.current) return socketRef.current;

    const newSocket = io(SOCKET_URL);
    setSocket(newSocket);
    socketRef.current = newSocket;

    newSocket.on("connect", () => {
      const currentRooms = roomsRef.current;
      Object.keys(currentRooms).forEach((rId) => {
        const room = currentRooms[rId];
        if (!room.isLocked && room.authKey) {
          const peerId = getOrCreateRoomPeerId(rId);
          newSocket.emit("get_join_challenge", { roomId: rId }, async (res) => {
            if (res && res.success && res.nonce) {
              try {
                const authProof = await signNonce(room.authKey, res.nonce);
                newSocket.emit("join_room", { roomId: rId, peerId, authProof }, (ack) => {
                  if (ack && ack.success) {
                    autoSync(newSocket, rId);
                  }
                });
              } catch (err) {
                if (import.meta.env.DEV) {
                  console.error(`Failed to solve challenge on reconnect for room ${rId}:`, err);
                }
              }
            }
          });
        }
      });

      setRooms((prev) => {
        const next = { ...prev };
        Object.keys(next).forEach((rId) => {
          next[rId] = { ...next[rId], isConnected: true };
        });
        return next;
      });
    });

    newSocket.on("disconnect", () => {
      setRooms((prev) => {
        const next = { ...prev };
        Object.keys(next).forEach((rId) => {
          next[rId] = { ...next[rId], isConnected: false };
        });
        return next;
      });
    });

    newSocket.on("room_full", ({ roomId: rId, message }) => {
      if (!rId) return;
      if (import.meta.env.DEV) {
        console.warn(`Room full rejection for ${rId}: ${message}`);
      }
      setRooms((prev) => {
        const room = prev[rId];
        if (!room) return prev;
        return {
          ...prev,
          [rId]: { ...room, isRoomFull: true },
        };
      });
    });

    newSocket.on("user_joined", (data) => {
      const rId = typeof data === "object" ? data.roomId : data;
      if (rId && roomsRef.current[rId]) {
        autoSync(newSocket, rId);
      }
    });

    newSocket.on("message_delivered", async ({ messageId, roomId: rId }) => {
      if (!rId || !roomsRef.current[rId]) return;
      setRooms((prev) => {
        const room = prev[rId];
        if (!room) return prev;
        const updatedMessages = room.messages.map((msg) =>
          msg.id === messageId ? { ...msg, status: "delivered" } : msg
        );
        return { ...prev, [rId]: { ...room, messages: updatedMessages } };
      });
      await updateMessageStatus(messageId, "delivered");
    });

    newSocket.on("sync_request", async (data) => {
      const { senderId, roomId: rId, timestamp } = data;
      if (!rId || !roomsRef.current[rId]) return;
      try {
        const records = await getRoomMessages(rId);
        const pendingMessages = records
          .filter((r) => r.timestamp > timestamp)
          .map((r) => ({
            id: r.messageId,
            timestamp: r.timestamp,
            ciphertext: r.ciphertext,
            iv: r.iv,
            wasOwn: r.isOwn,
          }));

        if (pendingMessages.length > 0) {
          newSocket.emit("sync_response", {
            roomId: rId,
            recipientId: senderId,
            messages: pendingMessages,
          });
        }
      } catch (err) {
        if (import.meta.env.DEV) {
          console.error("Failed to handle sync_request:", err);
        }
      }
    });

    newSocket.on("sync_response", async (data) => {
      const { roomId: rId, messages: syncMessages } = data;
      if (!rId || !roomsRef.current[rId] || !syncMessages || syncMessages.length === 0) return;

      const room = roomsRef.current[rId];
      if (room.isLocked || !room.cryptoKey) return;

      const newRemoteMessages = [];
      for (const item of syncMessages) {
        if (isMessageIdSeen(rId, item.id) || room.messages.some((m) => m.id === item.id)) {
          continue;
        }

        const decryptedText = await decryptMessage(room.cryptoKey, {
          ciphertext: item.ciphertext,
          iv: item.iv,
        });

        if (decryptedText !== null) {
          let msgData;
          try {
            msgData = JSON.parse(decryptedText);
          } catch (err) {
            msgData = { type: "text", text: decryptedText };
          }

          const seq = typeof msgData.seq === "number" ? msgData.seq : undefined;
          recordMessageIdSeen(rId, item.id);

          newRemoteMessages.push({
            id: item.id,
            ...msgData,
            seq,
            senderId: item.wasOwn ? null : data.senderId,
            isOwn: !item.wasOwn,
            status: "sent",
            time: new Date(item.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              hour12: true,
            }),
            timestamp: item.timestamp,
          });
        }
      }

      if (newRemoteMessages.length > 0) {
        setRooms((prev) => {
          const currentRoom = prev[rId];
          if (!currentRoom) return prev;
          const merged = [...currentRoom.messages, ...newRemoteMessages];
          initRoomSequence(rId, merged);
          const isCurrentActive = activeRoomIdRef.current === rId;
          return {
            ...prev,
            [rId]: {
              ...currentRoom,
              messages: merged,
              unreadCount: isCurrentActive ? 0 : currentRoom.unreadCount + newRemoteMessages.length,
            },
          };
        });

        for (const msg of newRemoteMessages) {
          const originalItem = syncMessages.find((x) => x.id === msg.id);
          await saveMessage(rId, {
            messageId: msg.id,
            timestamp: msg.timestamp,
            isOwn: msg.isOwn,
            status: msg.status,
            ciphertext: originalItem.ciphertext,
            iv: originalItem.iv,
            seq: msg.seq,
          });
        }
      }
    });

    newSocket.on("receive_message", async (data) => {
      if (!data || typeof data !== "object") return;
      if (data.senderId === newSocket.id) return;
      const rId = data.roomId || activeRoomIdRef.current;
      if (!rId) return;

      const room = roomsRef.current[rId];
      if (!room || room.isLocked || !room.cryptoKey) return;

      // 1. Early rejection of duplicate messageId from envelope
      if (data.id && (isMessageIdSeen(rId, data.id) || room.messages.some((m) => m.id === data.id))) {
        if (import.meta.env.DEV) {
          console.warn(`[Replay Protection] Ignored packet with duplicate messageId: ${data.id} in room: ${rId}`);
        }
        return;
      }

      // 2. Early rejection of duplicate/old sequence number from envelope
      if (typeof data.seq === "number") {
        const highestAccepted = getHighestAcceptedSeq(rId);
        if (data.seq <= highestAccepted) {
          if (import.meta.env.DEV) {
            console.warn(`[Replay Protection] Ignored packet with outer seq ${data.seq} <= highest accepted ${highestAccepted} in room: ${rId}`);
          }
          return;
        }
      }

      const decryptedText = await decryptMessage(room.cryptoKey, {
        ciphertext: data.ciphertext,
        iv: data.iv,
      });

      const timestamp = Date.now();
      let newMessageObj;

      if (decryptedText === null) {
        if (import.meta.env.DEV) {
          console.error(`Failed to decrypt message for room ${rId}`);
        }
        newMessageObj = {
          id: Date.now(),
          text: "[Encrypted message - Failed to decrypt]",
          isOwn: false,
          time: new Date().toLocaleTimeString(),
          timestamp,
        };
      } else {
        let msgData;
        try {
          msgData = JSON.parse(decryptedText);
        } catch (err) {
          msgData = { type: "text", text: decryptedText };
        }

        const messageId = msgData.id || data.id;
        if (!messageId) {
          if (import.meta.env.DEV) {
            console.warn(`[Replay Protection] Ignored packet missing messageId in room: ${rId}`);
          }
          return;
        }

        // 3. Authenticated sequence number verification inside ciphertext
        const seq = msgData.seq;
        if (typeof seq !== "number" || !Number.isInteger(seq)) {
          if (import.meta.env.DEV) {
            console.warn(`[Replay Protection] Ignored message without valid authenticated sequence number in room: ${rId}`);
          }
          return;
        }

        // 4. Verify outer sequence matches authenticated inner sequence
        if (typeof data.seq === "number" && data.seq !== seq) {
          if (import.meta.env.DEV) {
            console.warn(`[Replay Protection] Ignored message: outer seq (${data.seq}) does not match authenticated seq (${seq})`);
          }
          return;
        }

        // 5. Validate sequence number and messageId against replay protection state
        const validation = validateAndAcceptMessage(rId, messageId, seq);
        if (!validation.valid) {
          if (import.meta.env.DEV) {
            console.warn(`[Replay Protection] Replay rejected (${validation.reason}): messageId=${messageId}, seq=${seq} in room: ${rId}`);
          }
          return;
        }

        await saveMessage(rId, {
          messageId,
          timestamp,
          isOwn: false,
          status: "sent",
          ciphertext: data.ciphertext,
          iv: data.iv,
          seq,
        });

        newMessageObj = {
          id: messageId,
          ...msgData,
          seq,
          senderId: data.senderId,
          isOwn: false,
          time: new Date(timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            hour12: true,
          }),
          timestamp,
        };

        if (msgData.id && msgData.type !== "file") {
          newSocket.emit("message_delivered", {
            roomId: rId,
            messageId: msgData.id,
            senderId: data.senderId,
          });
        }
      }

      setRooms((prev) => {
        const currentRoom = prev[rId];
        if (!currentRoom) return prev;
        const isCurrentActive = activeRoomIdRef.current === rId;
        return {
          ...prev,
          [rId]: {
            ...currentRoom,
            messages: [...currentRoom.messages, newMessageObj],
            unreadCount: isCurrentActive ? 0 : currentRoom.unreadCount + 1,
          },
        };
      });
    });

    newSocket.on("room_deleted", async (data) => {
      const rId = typeof data === "object" ? data.roomId : data;
      if (rId) {
        if (
          data &&
          typeof data === "object" &&
          data.deletedBy &&
          socketRef.current &&
          data.deletedBy === socketRef.current.id
        ) {
          navigate("/");
          return;
        }
        await handleLeaveRoom(rId);
        navigate("/");
      }
    });

    return newSocket;
  };

  // Initialize active rooms on mount
  useEffect(() => {
    const initializeRooms = async () => {
      sessionStorage.removeItem("qkchat_room_keys");
      sessionStorage.removeItem("chat_key");
      const activeRoomIds = getStoredActiveRooms();
      const storedNamesMap = getStoredRoomNames();
      const storedSaltsMap = getStoredRoomSalts();
      const loadedRooms = {};

      if (activeRoomIds.length > 0) {
        const activeSock = initSocketIfNeeded();

        for (const rId of activeRoomIds) {
          const salt = storedSaltsMap[rId] || null;

          loadedRooms[rId] = {
            roomId: rId,
            roomName: storedNamesMap[rId] || "",
            cryptoKey: null,
            salt,
            messages: [],
            isConnected: activeSock.connected,
            unreadCount: 0,
            retentionPeriod: parseInt(localStorage.getItem(`qkchat_retention_${rId}`) || "86400000"),
            isLocked: true,
          };
        }

        setRooms(loadedRooms);
        setActiveRoomId(activeRoomIds[0]);
      }

      setIsInitialized(true);
    };

    initializeRooms();

    return () => {
      revokeAllBlobUrls();
    };
  }, []);

  // Periodically prune expired messages across all unlocked rooms
  useEffect(() => {
    const pruneAllRooms = async () => {
      const currentRooms = roomsRef.current;
      for (const rId of Object.keys(currentRooms)) {
        const room = currentRooms[rId];
        if (room && room.retentionPeriod) {
          await clearExpiredMessages(room.retentionPeriod);
          const cutoff = Date.now() - room.retentionPeriod;
          setRooms((prev) => {
            const target = prev[rId];
            if (!target) return prev;
            const remaining = [];
            for (const m of target.messages) {
              if (m.timestamp >= cutoff) {
                remaining.push(m);
              } else if (m.fileData && typeof m.fileData === "string" && m.fileData.startsWith("blob:")) {
                revokeTrackedBlobUrl(m.fileData, rId);
              }
            }
            return {
              ...prev,
              [rId]: {
                ...target,
                messages: remaining,
              },
            };
          });
        }
      }
    };

    pruneAllRooms();
    const interval = setInterval(pruneAllRooms, 10000);
    return () => clearInterval(interval);
  }, []);

  // Join or Create a Room with Credentials, Custom Name, and optional Retention
  const handleJoinWithCredentials = async (
    joinRoomId,
    joinPassword,
    joinRoomName = "",
    joinRetentionPeriod = null,
    joinSalt = null
  ) => {
    try {
      const activeSock = initSocketIfNeeded();

      // Resolve room salt: explicitly passed -> stored in metadata -> query server -> generate new
      let salt = joinSalt || getStoredRoomSalt(joinRoomId);
      if (!salt && activeSock) {
        salt = await new Promise((resolve) => {
          activeSock.emit("get_room_salt", { roomId: joinRoomId }, (res) => {
            resolve(res && res.success && res.salt ? res.salt : null);
          });
          setTimeout(() => resolve(null), 1200);
        });
      }

      if (!salt) {
        salt = generateRandomSalt();
      }

      setStoredRoomSalt(joinRoomId, salt);
      const key = await deriveKey(joinPassword, salt);
      const authKey = await deriveAuthKey(joinPassword, salt);
      const authKeyHex = await exportAuthKeyHex(authKey);

      // Store custom room name if provided
      if (joinRoomName && joinRoomName.trim()) {
        setStoredRoomName(joinRoomId, joinRoomName.trim());
      }

      // Store initial retention period if provided
      if (joinRetentionPeriod) {
        localStorage.setItem(`qkchat_retention_${joinRoomId}`, joinRetentionPeriod.toString());
      }

      // Request join challenge nonce from server
      const challengeNonce = await new Promise((resolve, reject) => {
        activeSock.emit("get_join_challenge", { roomId: joinRoomId }, (res) => {
          if (res && res.success && res.nonce) {
            resolve(res.nonce);
          } else {
            reject(new Error(res?.error || "Failed to get join challenge"));
          }
        });
        setTimeout(() => reject(new Error("Challenge request timed out")), 5000);
      });

      // Sign nonce with HMAC auth key
      const authProof = await signNonce(authKey, challengeNonce);

      // Verify and load messages from ledger (decrypts existing messages with key)
      const initialMsgs = await loadMessagesFromLedger(joinRoomId, key);

      // Get or create per-room peer ID and emit authenticated join room on socket
      const peerId = getOrCreateRoomPeerId(joinRoomId);
      await new Promise((resolve, reject) => {
        activeSock.emit(
          "join_room",
          {
            roomId: joinRoomId,
            peerId,
            salt,
            authProof,
            roomVerifier: authKeyHex,
          },
          (ack) => {
            if (ack && ack.success) {
              resolve(ack);
            } else {
              const errMsg =
                ack?.error === "INVALID_CREDENTIALS"
                  ? "Invalid password for this room"
                  : ack?.error === "ROOM_FULL"
                  ? "Room capacity reached (2 peers max)"
                  : ack?.error || "Failed to join room";
              reject(new Error(errMsg));
            }
          }
        );
        setTimeout(() => reject(new Error("Join room timed out")), 5000);
      });

      // Update active room list in localStorage only after successful authentication
      const currentList = getStoredActiveRooms();
      if (!currentList.includes(joinRoomId)) {
        currentList.push(joinRoomId);
        setStoredActiveRooms(currentList);
      }

      autoSync(activeSock, joinRoomId);

      const roomName = getStoredRoomNames()[joinRoomId] || (joinRoomName ? joinRoomName.trim() : "");
      const retention = parseInt(localStorage.getItem(`qkchat_retention_${joinRoomId}`) || "86400000");

      setRooms((prev) => ({
        ...prev,
        [joinRoomId]: {
          roomId: joinRoomId,
          roomName,
          cryptoKey: key,
          authKey,
          salt,
          messages: initialMsgs,
          isConnected: activeSock.connected,
          unreadCount: 0,
          retentionPeriod: retention,
          isLocked: false,
        },
      }));

      setActiveRoomId(joinRoomId);
      return Promise.resolve();
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error("Failed to join room:", err);
      }
      return Promise.reject(err);
    }
  };

  // Set / Rename Room Name
  const handleSetRoomName = (targetRoomId, newName) => {
    setStoredRoomName(targetRoomId, newName);
    setRooms((prev) => {
      const room = prev[targetRoomId];
      if (!room) return prev;
      return {
        ...prev,
        [targetRoomId]: {
          ...room,
          roomName: newName.trim(),
        },
      };
    });
  };

  // Switch Active Room View
  const handleSwitchRoom = (targetRoomId) => {
    setActiveRoomId(targetRoomId);
    setRooms((prev) => {
      const room = prev[targetRoomId];
      if (!room) return prev;
      return {
        ...prev,
        [targetRoomId]: {
          ...room,
          unreadCount: 0,
        },
      };
    });
  };

  const handleUnlockRoom = async (targetRoomId, password) => {
    return handleJoinWithCredentials(targetRoomId, password);
  };

  const handleUpdateRetentionPeriod = async (targetRoomId, newPeriod) => {
    localStorage.setItem(`qkchat_retention_${targetRoomId}`, newPeriod.toString());
    setRooms((prev) => {
      const room = prev[targetRoomId];
      if (!room) return prev;
      return {
        ...prev,
        [targetRoomId]: { ...room, retentionPeriod: newPeriod },
      };
    });
    await clearExpiredMessages(newPeriod);
  };

  if (!isInitialized) {
    return null;
  }

  const currentActiveRoom = rooms[activeRoomId] || null;

  return (
    <div className="app-container">
      <Routes>
        <Route
          path="/"
          element={
            <HomeSelection
              rooms={rooms}
              onSelectRoom={(rId) => {
                handleSwitchRoom(rId);
                navigate("/chat");
              }}
              onLeaveRoom={handleLeaveRoom}
              onUnlockRoom={handleUnlockRoom}
            />
          }
        />
        <Route
          path="/start"
          element={
            <StartChat
              onJoin={async (rId, pwd, name, retention, salt) => {
                await handleJoinWithCredentials(rId, pwd, name, retention, salt);
                navigate("/chat");
              }}
            />
          }
        />
        <Route
          path="/join"
          element={
            <JoinChat
              onJoin={async (rId, pwd, name, retention, salt) => {
                await handleJoinWithCredentials(rId, pwd, name, retention, salt);
                navigate("/chat");
              }}
            />
          }
        />
        <Route
          path="/recovery"
          element={
            <SessionRecovery
              roomId={activeRoomId || (getStoredActiveRooms()[0] || "")}
              onRecoveryComplete={async (rId, pwd) => {
                await handleUnlockRoom(rId, pwd);
                navigate("/chat");
              }}
            />
          }
        />
        <Route
          path="/chat"
          element={
            <ChatPage
              socket={socket}
              rooms={rooms}
              activeRoomId={activeRoomId}
              currentRoom={currentActiveRoom}
              setRooms={setRooms}
              onSwitchRoom={handleSwitchRoom}
              onJoinNewRoom={handleJoinWithCredentials}
              onLeaveRoom={handleLeaveRoom}
              onDeleteRoomForAll={handleDeleteRoomForAll}
              onUnlockRoom={handleUnlockRoom}
              onUpdateRetentionPeriod={handleUpdateRetentionPeriod}
              onSetRoomName={handleSetRoomName}
            />
          }
        />

        {/* Catch-all fallback route for non-existing pages */}
        <Route
          path="*"
          element={<FallbackRedirect onError={triggerErrorToast} />}
        />
      </Routes>

      {/* Global Error Notification Toast */}
      {errorToast && (
        <div className="global-error" role="alert">
          <AlertCircle size={18} />
          <span>{errorToast}</span>
          <button onClick={() => setErrorToast("")} title="Dismiss notification">
            <X size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
