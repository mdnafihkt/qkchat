import React, { useState, useEffect, useRef } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import io from "socket.io-client";
import { deriveKey, decryptMessage, exportKeyToJWK, importKeyFromJWK } from "./utils/crypto";
import { saveMessage, getRoomMessages, updateMessageStatus, clearRoomMessages } from "./utils/ledger";
import HomeSelection from "./components/HomeSelection/HomeSelection";
import StartChat from "./components/StartChat/StartChat";
import JoinChat from "./components/JoinChat/JoinChat";
import ChatPage from "./components/ChatPage/ChatPage";
import SessionRecovery from "./components/SessionRecovery/SessionRecovery";

export default function AppRoutes({ SOCKET_URL }) {
  const navigate = useNavigate();
  const [socket, setSocket] = useState(null);
  const [roomId, setRoomId] = useState("");
  const [password, setPassword] = useState("");
  const [cryptoKey, setCryptoKey] = useState(null);
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [sessionRecoveryNeeded, setSessionRecoveryNeeded] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);

  // Keep a ref to the latest messages state to avoid stale closure issues in socket handlers
  const messagesRef = useRef([]);
  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  // Check for session recovery on mount
  useEffect(() => {
    const initializeSession = async () => {
      const storedRoomId = localStorage.getItem("room_id");
      const storedCryptoKey = sessionStorage.getItem("chat_key");

      if (storedRoomId && storedCryptoKey) {
        // Both room and key exist - auto reconnect
        setRoomId(storedRoomId);
        await attemptAutoReconnect(storedRoomId, storedCryptoKey);
        navigate("/chat");
      } else if (storedRoomId && !storedCryptoKey) {
        // Room exists but key missing - prompt for password
        setSessionRecoveryNeeded(true);
        setRoomId(storedRoomId);
        navigate("/recovery");
      }
      
      setIsInitialized(true);
    };

    initializeSession();
  }, [navigate]);

  const loadMessagesFromLedger = async (targetRoomId, key) => {
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
            timestamp: record.timestamp
          });
        } else {
          decryptedMessages.push({
            id: record.messageId || Date.now(),
            text: "[Encrypted message - Failed to decrypt]",
            isOwn: record.isOwn,
            time: new Date(record.timestamp).toLocaleTimeString(),
            timestamp: record.timestamp
          });
        }
      }
      setMessages(decryptedMessages);
    } catch (err) {
      console.error("Failed to load messages from ledger:", err);
    }
  };

  const autoSync = async (activeSocket, activeRoomId) => {
    if (!activeSocket || !activeRoomId) return;
    try {
      const records = await getRoomMessages(activeRoomId);
      let lastTimestamp = 0;
      if (records.length > 0) {
        lastTimestamp = Math.max(...records.map(r => r.timestamp));
      }
      activeSocket.emit("sync_request", {
        roomId: activeRoomId,
        timestamp: lastTimestamp
      });
    } catch (err) {
      console.error("Failed to trigger autoSync:", err);
    }
  };

  const setupSocketListeners = (newSocket, activeRoomId, activeKey) => {
    newSocket.on("connect", () => {
      setIsConnected(true);
      newSocket.emit("join_room", activeRoomId);
      autoSync(newSocket, activeRoomId);
    });

    newSocket.on("disconnect", () => {
      setIsConnected(false);
    });

    newSocket.on("user_joined", (id) => {
      autoSync(newSocket, activeRoomId);
    });

    newSocket.on("message_delivered", async ({ messageId }) => {
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === messageId ? { ...msg, status: "delivered" } : msg
        )
      );
      await updateMessageStatus(messageId, "delivered");
    });

    newSocket.on("sync_request", async (data) => {
      const { senderId, timestamp } = data;
      try {
        const records = await getRoomMessages(activeRoomId);
        const pendingMessages = records
          .filter(r => r.timestamp > timestamp)
          .map(r => ({
            id: r.messageId,
            timestamp: r.timestamp,
            ciphertext: r.ciphertext,
            iv: r.iv,
            wasOwn: r.isOwn
          }));

        if (pendingMessages.length > 0) {
          newSocket.emit("sync_response", {
            roomId: activeRoomId,
            recipientId: senderId,
            messages: pendingMessages
          });
        }
      } catch (err) {
        console.error("Failed to handle sync_request:", err);
      }
    });

    newSocket.on("sync_response", async (data) => {
      const { messages: syncMessages } = data;
      if (!syncMessages || syncMessages.length === 0) return;

      const newRemoteMessages = [];
      for (const item of syncMessages) {
        if (messagesRef.current.some(m => m.id === item.id)) {
          continue;
        }

        const decryptedText = await decryptMessage(activeKey, {
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
            isOwn: !item.wasOwn,
            status: "sent",
            time: new Date(item.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              hour12: true,
            }),
            timestamp: item.timestamp
          });
        }
      }

      if (newRemoteMessages.length > 0) {
        setMessages((prev) => [...prev, ...newRemoteMessages]);

        for (const msg of newRemoteMessages) {
          const originalItem = syncMessages.find(x => x.id === msg.id);
          await saveMessage(activeRoomId, {
            messageId: msg.id,
            timestamp: msg.timestamp,
            isOwn: msg.isOwn,
            status: msg.status,
            ciphertext: originalItem.ciphertext,
            iv: originalItem.iv
          });
        }
      }
    });

    newSocket.on("receive_message", async (data) => {
      if (data.senderId === newSocket.id) {
        return;
      }
      
      if (!activeKey) return;

      // Avoid duplicate display
      if (messagesRef.current.some(m => m.id === data.id)) {
        return;
      }
      
      const decryptedText = await decryptMessage(activeKey, {
        ciphertext: data.ciphertext,
        iv: data.iv,
      });

      if (decryptedText === null) {
        console.error("Failed to decrypt message");
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            text: "[Encrypted message - Failed to decrypt]",
            isOwn: false,
            time: new Date().toLocaleTimeString(),
          },
        ]);
      } else {
        let msgData;
        try {
          msgData = JSON.parse(decryptedText);
        } catch (err) {
          msgData = { type: "text", text: decryptedText };
        }

        const messageId = msgData.id || Date.now();
        
        // Avoid duplicate display
        if (messagesRef.current.some(m => m.id === messageId)) {
          return;
        }

        const timestamp = Date.now();

        await saveMessage(activeRoomId, {
          messageId,
          timestamp,
          isOwn: false,
          status: "sent",
          ciphertext: data.ciphertext,
          iv: data.iv
        });

        setMessages((prev) => [
          ...prev,
          {
            id: messageId,
            ...msgData,
            isOwn: false,
            time: new Date(timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              hour12: true,
            }),
            timestamp
          },
        ]);

        if (msgData.id) {
          newSocket.emit("message_delivered", {
            roomId: activeRoomId,
            messageId: msgData.id,
            senderId: data.senderId,
          });
        }
      }
    });
  };

  const attemptAutoReconnect = async (reconnectRoomId, reconnectKeyStr) => {
    try {
      if (socket) {
        socket.disconnect();
      }

      const key = await importKeyFromJWK(reconnectKeyStr);
      setCryptoKey(key);
      await loadMessagesFromLedger(reconnectRoomId, key);

      const newSocket = io(SOCKET_URL);
      setSocket(newSocket);

      return new Promise((resolve, reject) => {
        setupSocketListeners(newSocket, reconnectRoomId, key);

        newSocket.on("connect", () => {
          resolve();
        });

        newSocket.on("connect_error", (err) => {
          reject(err);
        });
      });
    } catch (err) {
      console.error("Auto-reconnect failed:", err);
      sessionStorage.removeItem("chat_key");
      setSessionRecoveryNeeded(true);
      navigate("/recovery");
    }
  };

  const handleJoinWithCredentials = async (joinRoomId, joinPassword) => {
    if (socket) {
      socket.disconnect();
    }

    try {
      const key = await deriveKey(joinPassword, joinRoomId);
      setCryptoKey(key);

      localStorage.setItem("room_id", joinRoomId);
      
      try {
        const jwk = await exportKeyToJWK(key);
        sessionStorage.setItem("chat_key", jwk);
      } catch (err) {
        console.warn("Unable to persist crypto key for session recovery:", err);
      }

      await loadMessagesFromLedger(joinRoomId, key);

      const newSocket = io(SOCKET_URL);
      setSocket(newSocket);
      setRoomId(joinRoomId);
      setPassword(joinPassword);
      setSessionRecoveryNeeded(false);

      return new Promise((resolve, reject) => {
        setupSocketListeners(newSocket, joinRoomId, key);

        newSocket.on("connect", () => {
          resolve();
        });

        newSocket.on("connect_error", (err) => {
          reject(err);
        });
      });
    } catch (err) {
      console.error(err);
      throw err;
    }
  };

  const handleLeave = () => {
    if (socket) {
      socket.disconnect();
    }
    const currentRoomId = roomId;
    setSocket(null);
    setCryptoKey(null);
    setMessages([]);
    setRoomId("");
    setPassword("");
    localStorage.removeItem("room_id");
    sessionStorage.removeItem("chat_key");
    setSessionRecoveryNeeded(false);

    if (currentRoomId) {
      clearRoomMessages(currentRoomId).catch(err => {
        console.error("Failed to clear room messages from ledger:", err);
      });
    }
  };

  if (!isInitialized) {
    return null;
  }

  return (
    <div className="app-container">
      <Routes>
        <Route path="/" element={<HomeSelection />} />
        <Route
          path="/start"
          element={<StartChat onJoin={handleJoinWithCredentials} />}
        />
        <Route
          path="/join"
          element={<JoinChat onJoin={handleJoinWithCredentials} />}
        />
        <Route
          path="/recovery"
          element={
            <SessionRecovery
              roomId={roomId}
              onRecoveryComplete={handleJoinWithCredentials}
            />
          }
        />
        <Route
          path="/chat"
          element={
            <ChatPage
              socket={socket}
              cryptoKey={cryptoKey}
              roomId={roomId}
              messages={messages}
              setMessages={setMessages}
              isConnected={isConnected}
              handleLeave={handleLeave}
            />
          }
        />
      </Routes>
    </div>
  );
}
