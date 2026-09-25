import React, { useState, useEffect, useRef } from "react";
import { Routes, Route, useNavigate, Navigate, useLocation } from "react-router-dom";
import io from "socket.io-client";
import { AlertCircle, X } from "lucide-react";
import { deriveKey, decryptMessage, exportKeyToJWK, importKeyFromJWK } from "./utils/crypto";
import { saveMessage, getRoomMessages, updateMessageStatus, clearRoomMessages, clearExpiredMessages } from "./utils/ledger";
import { getOrCreateRoomPeerId, removeRoomPeerId } from "./utils/peer";
import HomeSelection from "./components/HomeSelection/HomeSelection";
import StartChat from "./components/StartChat/StartChat";
import JoinChat from "./components/JoinChat/JoinChat";
import ChatPage from "./components/ChatPage/ChatPage";
import SessionRecovery from "./components/SessionRecovery/SessionRecovery";
import SharePicker from "./components/SharePicker/SharePicker";

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
  const [pendingSharedItem, setPendingSharedItem] = useState(null);
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

  const getStoredRoomKeys = () => {
    try {
      const stored = sessionStorage.getItem("qkchat_room_keys");
      if (stored) return JSON.parse(stored);
    } catch (e) {}
    const legacyKey = sessionStorage.getItem("chat_key");
    const legacyRoom = localStorage.getItem("room_id");
    if (legacyKey && legacyRoom) {
      return { [legacyRoom]: legacyKey };
    }
    return {};
  };

  const setStoredRoomKey = (rId, jwkString) => {
    const keysMap = getStoredRoomKeys();
    keysMap[rId] = jwkString;
    sessionStorage.setItem("qkchat_room_keys", JSON.stringify(keysMap));
    sessionStorage.setItem("chat_key", jwkString);
  };

  const removeStoredRoomKey = (rId) => {
    const keysMap = getStoredRoomKeys();
    delete keysMap[rId];
    sessionStorage.setItem("qkchat_room_keys", JSON.stringify(keysMap));
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
          if (record.fileBlob) {
            msgData.fileData = URL.createObjectURL(record.fileBlob);
          }
          decryptedMessages.push({
            id: record.messageId,
            ...msgData,
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
      return decryptedMessages;
    } catch (err) {
      console.error(`Failed to load messages for room ${targetRoomId}:`, err);
      return [];
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
      console.error(`Failed to trigger autoSync for room ${targetRoomId}:`, err);
    }
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
        if (!room.isLocked) {
          const peerId = getOrCreateRoomPeerId(rId);
          newSocket.emit("join_room", { roomId: rId, peerId });
          autoSync(newSocket, rId);
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
      console.warn(`Room full rejection for ${rId}: ${message}`);
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
        console.error("Failed to handle sync_request:", err);
      }
    });

    newSocket.on("sync_response", async (data) => {
      const { roomId: rId, messages: syncMessages } = data;
      if (!rId || !roomsRef.current[rId] || !syncMessages || syncMessages.length === 0) return;

      const room = roomsRef.current[rId];
      if (room.isLocked || !room.cryptoKey) return;

      const newRemoteMessages = [];
      for (const item of syncMessages) {
        if (room.messages.some((m) => m.id === item.id)) {
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

          newRemoteMessages.push({
            id: item.id,
            ...msgData,
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
          });
        }
      }
    });

    newSocket.on("receive_message", async (data) => {
      if (data.senderId === newSocket.id) return;
      const rId = data.roomId || activeRoomIdRef.current;
      if (!rId) return;

      const room = roomsRef.current[rId];
      if (!room || room.isLocked || !room.cryptoKey) return;

      if (room.messages.some((m) => m.id === data.id)) return;

      const decryptedText = await decryptMessage(room.cryptoKey, {
        ciphertext: data.ciphertext,
        iv: data.iv,
      });

      const timestamp = Date.now();
      let newMessageObj;

      if (decryptedText === null) {
        console.error(`Failed to decrypt message for room ${rId}`);
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

        const messageId = msgData.id || Date.now();
        if (room.messages.some((m) => m.id === messageId)) return;

        await saveMessage(rId, {
          messageId,
          timestamp,
          isOwn: false,
          status: "sent",
          ciphertext: data.ciphertext,
          iv: data.iv,
        });

        newMessageObj = {
          id: messageId,
          ...msgData,
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
        await handleLeaveRoom(rId);
      }
    });

    return newSocket;
  };

  // Initialize active rooms on mount
  useEffect(() => {
    const initializeRooms = async () => {
      const activeRoomIds = getStoredActiveRooms();
      const storedKeysMap = getStoredRoomKeys();
      const storedNamesMap = getStoredRoomNames();
      const loadedRooms = {};

      if (activeRoomIds.length > 0) {
        const activeSock = initSocketIfNeeded();

        for (const rId of activeRoomIds) {
          const jwkStr = storedKeysMap[rId];
          let key = null;
          let isLocked = true;
          let roomMsgs = [];

          if (jwkStr) {
            try {
              key = await importKeyFromJWK(jwkStr);
              isLocked = false;
              roomMsgs = await loadMessagesFromLedger(rId, key);
              const peerId = getOrCreateRoomPeerId(rId);
              activeSock.emit("join_room", { roomId: rId, peerId });
              autoSync(activeSock, rId);
            } catch (err) {
              console.warn(`Failed to import key for room ${rId}:`, err);
              isLocked = true;
            }
          }

          loadedRooms[rId] = {
            roomId: rId,
            roomName: storedNamesMap[rId] || "",
            cryptoKey: key,
            messages: roomMsgs,
            isConnected: activeSock.connected,
            unreadCount: 0,
            retentionPeriod: parseInt(localStorage.getItem(`qkchat_retention_${rId}`) || "86400000"),
            isLocked,
          };
        }

        setRooms(loadedRooms);
        setActiveRoomId(activeRoomIds[0]);
      }

      setIsInitialized(true);
    };

    initializeRooms();
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
            return {
              ...prev,
              [rId]: {
                ...target,
                messages: target.messages.filter((m) => m.timestamp >= cutoff),
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
  const handleJoinWithCredentials = async (joinRoomId, joinPassword, joinRoomName = "", joinRetentionPeriod = null) => {
    try {
      const activeSock = initSocketIfNeeded();
      const key = await deriveKey(joinPassword, joinRoomId);

      // Save key in sessionStorage
      try {
        const jwk = await exportKeyToJWK(key);
        setStoredRoomKey(joinRoomId, jwk);
      } catch (err) {
        console.warn("Unable to persist key to sessionStorage:", err);
      }

      // Store custom room name if provided
      if (joinRoomName && joinRoomName.trim()) {
        setStoredRoomName(joinRoomId, joinRoomName.trim());
      }

      // Store initial retention period if provided
      if (joinRetentionPeriod) {
        localStorage.setItem(`qkchat_retention_${joinRoomId}`, joinRetentionPeriod.toString());
      }

      // Update active room list in localStorage
      const currentList = getStoredActiveRooms();
      if (!currentList.includes(joinRoomId)) {
        currentList.push(joinRoomId);
        setStoredActiveRooms(currentList);
      }

      const initialMsgs = await loadMessagesFromLedger(joinRoomId, key);

      // Get or create per-room peer ID and emit join room on socket
      const peerId = getOrCreateRoomPeerId(joinRoomId);
      activeSock.emit("join_room", { roomId: joinRoomId, peerId });
      autoSync(activeSock, joinRoomId);

      const roomName = getStoredRoomNames()[joinRoomId] || (joinRoomName ? joinRoomName.trim() : "");
      const retention = parseInt(localStorage.getItem(`qkchat_retention_${joinRoomId}`) || "86400000");

      setRooms((prev) => ({
        ...prev,
        [joinRoomId]: {
          roomId: joinRoomId,
          roomName,
          cryptoKey: key,
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
      console.error("Failed to join room:", err);
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

  // Leave / Close a specific Room
  const handleLeaveRoom = async (targetRoomId) => {
    const peerId = getOrCreateRoomPeerId(targetRoomId);
    if (socketRef.current) {
      socketRef.current.emit("leave_room", { roomId: targetRoomId, peerId, clearSlot: true });
    }

    await clearRoomMessages(targetRoomId).catch((err) => {
      console.error(`Failed to clear ledger for room ${targetRoomId}:`, err);
    });

    removeStoredRoomKey(targetRoomId);
    removeRoomPeerId(targetRoomId);
    setStoredRoomName(targetRoomId, "");
    const updatedList = getStoredActiveRooms().filter((id) => id !== targetRoomId);
    setStoredActiveRooms(updatedList);

    setRooms((prev) => {
      const next = { ...prev };
      delete next[targetRoomId];
      return next;
    });

    if (activeRoomId === targetRoomId) {
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
              onJoin={async (rId, pwd, name, retention) => {
                await handleJoinWithCredentials(rId, pwd, name, retention);
                navigate("/chat");
              }}
            />
          }
        />
        <Route
          path="/join"
          element={
            <JoinChat
              onJoin={async (rId, pwd) => {
                await handleJoinWithCredentials(rId, pwd);
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
          path="/share"
          element={
            <SharePicker
              rooms={rooms}
              onSelectRoomForShare={(rId, payload) => {
                handleSwitchRoom(rId);
                setPendingSharedItem({ roomId: rId, payload });
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
              pendingSharedItem={pendingSharedItem}
              onClearPendingSharedItem={() => setPendingSharedItem(null)}
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
