import React, { useState, useEffect } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import io from "socket.io-client";
import { deriveKey, decryptMessage, exportKeyToJWK, importKeyFromJWK } from "./utils/crypto";
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

  const attemptAutoReconnect = async (reconnectRoomId, reconnectKeyStr) => {
    try {
      // Clean up any existing socket before creating a new one
      if (socket) {
        socket.disconnect();
      }

      // Import the stored key from JWK JSON
      const key = await importKeyFromJWK(reconnectKeyStr);
      setCryptoKey(key);

      const newSocket = io(SOCKET_URL);
      setSocket(newSocket);

      return new Promise((resolve, reject) => {
        newSocket.on("connect", () => {
          setIsConnected(true);
          newSocket.emit("join_room", reconnectRoomId);
          resolve();
        });

        newSocket.on("connect_error", (err) => {
          reject(err);
        });

        newSocket.on("disconnect", () => {
          setIsConnected(false);
        });

        newSocket.on("user_joined", (id) => {
          // No log in production
        });

        newSocket.on("message_delivered", ({ messageId }) => {
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === messageId ? { ...msg, status: "delivered" } : msg
            )
          );
        });

        newSocket.on("receive_message", async (data) => {
          // Ignore messages sent by this client (we already added them locally)
          if (data.senderId === newSocket.id) {
            return;
          }
          
          if (!key) return;
          
          const decryptedText = await decryptMessage(key, {
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
            setMessages((prev) => [
              ...prev,
              {
                id: messageId,
                ...msgData,
                isOwn: false,
                time: new Date().toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  hour12: true,
                }),
              },
            ]);

            // Confirm delivery back to sender
            if (msgData.id) {
              newSocket.emit("message_delivered", {
                roomId: reconnectRoomId,
                messageId: msgData.id,
                senderId: data.senderId,
              });
            }
          }
        });
      });
    } catch (err) {
      console.error("Auto-reconnect failed:", err);

      // If the stored key is invalid/corrupt (not a CryptoKey), clear it and prompt recovery.
      sessionStorage.removeItem("chat_key");
      setSessionRecoveryNeeded(true);
      navigate("/recovery");
    }
  };

  const handleJoinWithCredentials = async (joinRoomId, joinPassword) => {
    // Prevent multiple parallel sockets if re-joining
    if (socket) {
      socket.disconnect();
    }

    try {
      // Derive PBKDF2 key from password and roomId (as salt)
      const key = await deriveKey(joinPassword, joinRoomId);
      setCryptoKey(key);

      // Persist room_id in localStorage
      localStorage.setItem("room_id", joinRoomId);
      
      // Persist crypto key in sessionStorage (as JWK JSON)
      try {
        const jwk = await exportKeyToJWK(key);
        sessionStorage.setItem("chat_key", jwk);
      } catch (err) {
        // If exporting fails, keep key in memory and continue (session recovery won't work)
        console.warn("Unable to persist crypto key for session recovery:", err);
      }

      const newSocket = io(SOCKET_URL);
      setSocket(newSocket);
      setRoomId(joinRoomId);
      setPassword(joinPassword);
      setSessionRecoveryNeeded(false);

      // Return a promise to wait connection to succeed fully before navigating
      return new Promise((resolve, reject) => {
        newSocket.on("connect", () => {
          setIsConnected(true);
          newSocket.emit("join_room", joinRoomId);
          resolve();
        });

        newSocket.on("connect_error", (err) => {
          reject(err);
        });

        newSocket.on("disconnect", () => {
          setIsConnected(false);
        });

        newSocket.on("user_joined", (id) => {          
        });

        newSocket.on("message_delivered", ({ messageId }) => {
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === messageId ? { ...msg, status: "delivered" } : msg
            )
          );
        });

        newSocket.on("receive_message", async (data) => {
          // Ignore messages sent by this client (we already added them locally)
          if (data.senderId === newSocket.id) {
            return;
          }
          
          // Attempt to decrypt incoming message using the local key
          if (!key) return;
          
          const decryptedText = await decryptMessage(key, {
            ciphertext: data.ciphertext,
            iv: data.iv,
          });

          if (decryptedText === null) {
            // Could not decrypt -> potentially wrong password or bad data
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
              // Fallback for older plaintext messages
              msgData = { type: "text", text: decryptedText };
            }

            const messageId = msgData.id || Date.now();
            setMessages((prev) => [
              ...prev,
              {
                id: messageId,
                ...msgData,
                isOwn: false,
                time: new Date().toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  hour12: true,
                }),
              },
            ]);

            // Confirm delivery back to sender
            if (msgData.id) {
              newSocket.emit("message_delivered", {
                roomId: joinRoomId,
                messageId: msgData.id,
                senderId: data.senderId,
              });
            }
          }
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
    setSocket(null);
    setCryptoKey(null);
    setMessages([]);
    setRoomId("");
    setPassword("");
    // Clear session recovery state
    localStorage.removeItem("room_id");
    sessionStorage.removeItem("chat_key");
    setSessionRecoveryNeeded(false);
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
