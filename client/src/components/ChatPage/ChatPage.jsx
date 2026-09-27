import React, { useState, useEffect, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  encryptMessage,
  encryptBinary,
  decryptBinary,
} from "../../utils/crypto";
import {
  saveMessage,
  updateMessageStatus,
  updateMessageFileBlob,
} from "../../utils/ledger";
import ChatHeader from "./ChatHeader";
import ChatSidebar from "./ChatSidebar";
import ChatMessages from "./ChatMessages";
import MessageComposer from "./MessageComposer";
import LockedRoomView from "./LockedRoomView";
import RoomRestrictedView from "./RoomRestrictedView";
import QRCodeModal from "./QRCodeModal";
import DragDropOverlay from "./DragDropOverlay";
import "./ChatPage.css";

export default function ChatPage({
  socket,
  rooms = {},
  activeRoomId = "",
  currentRoom = null,
  setRooms,
  onLeaveRoom,
  onDeleteRoomForAll,
  onUnlockRoom,
  onUpdateRetentionPeriod,
  onSetRoomName,
}) {
  const [newMessage, setNewMessage] = useState("");
  const [showQRCode, setShowQRCode] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [roomNameInput, setRoomNameInput] = useState(
    currentRoom?.roomName || ""
  );
  const [transfers, setTransfers] = useState({});
  const [isDragging, setIsDragging] = useState(false);

  const messagesEndRef = useRef(null);
  const activeTransfersRef = useRef({});
  const dragCounterRef = useRef(0);
  const navigate = useNavigate();

  const messages = useMemo(
    () => currentRoom?.messages || [],
    [currentRoom?.messages]
  );
  const cryptoKey = currentRoom?.cryptoKey || null;
  const isConnected = currentRoom?.isConnected ?? false;
  const retentionPeriod = currentRoom?.retentionPeriod || 86400000;
  const isLocked = currentRoom?.isLocked ?? false;
  const isRoomFull = currentRoom?.isRoomFull ?? false;

  useEffect(() => {
    setRoomNameInput(currentRoom?.roomName || "");
  }, [activeRoomId, currentRoom?.roomName]);

  // Redirect if no active rooms exist
  useEffect(() => {
    if (Object.keys(rooms).length === 0) {
      navigate("/");
    }
  }, [rooms, navigate]);

  // Scroll to bottom on new message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Socket file chunk receiver
  useEffect(() => {
    if (!socket) return;

    const handleReceiveFileChunk = async (chunk) => {
      const {
        roomId: chunkRoomId,
        transferId,
        chunkIndex,
        iv,
        encryptedData,
      } = chunk;
      const targetRoomId = chunkRoomId || activeRoomId;
      if (targetRoomId !== activeRoomId || !cryptoKey) return;

      const msg = messages.find((m) => m.transferId === transferId);

      if (!activeTransfersRef.current[transferId]) {
        activeTransfersRef.current[transferId] = {
          chunks: [],
          receivedCount: 0,
          totalChunks: msg ? msg.totalChunks : null,
          fileName: msg ? msg.fileName : "",
          fileType: msg ? msg.fileType : "",
          fileSize: msg ? msg.fileSize : 0,
          messageId: msg ? msg.id : "",
        };
      }

      const transfer = activeTransfersRef.current[transferId];

      if (!transfer.totalChunks && msg) {
        transfer.totalChunks = msg.totalChunks;
        transfer.fileName = msg.fileName;
        transfer.fileType = msg.fileType;
        transfer.fileSize = msg.fileSize;
        transfer.messageId = msg.id;
      }

      if (transfer.chunks[chunkIndex]) return;

      try {
        const decryptedData = await decryptBinary(cryptoKey, encryptedData, iv);
        transfer.chunks[chunkIndex] = decryptedData;
        transfer.receivedCount += 1;

        const total = transfer.totalChunks;
        if (total) {
          const progress = Math.round((transfer.receivedCount / total) * 100);
          setTransfers((prev) => ({
            ...prev,
            [transferId]: { progress, status: "Receiving" },
          }));

          if (transfer.receivedCount === total) {
            const fileBlob = new Blob(transfer.chunks, {
              type: transfer.fileType,
            });
            const fileUrl = URL.createObjectURL(fileBlob);

            setRooms((prev) => {
              const r = prev[activeRoomId];
              if (!r) return prev;
              const updatedMsgs = r.messages.map((m) =>
                m.transferId === transferId
                  ? { ...m, fileData: fileUrl, status: "delivered" }
                  : m
              );
              return {
                ...prev,
                [activeRoomId]: { ...r, messages: updatedMsgs },
              };
            });

            if (transfer.messageId) {
              await updateMessageFileBlob(
                transfer.messageId,
                fileBlob,
                "delivered"
              );
              if (msg && msg.senderId) {
                socket.emit("message_delivered", {
                  roomId: activeRoomId,
                  messageId: transfer.messageId,
                  senderId: msg.senderId,
                });
              }
            }

            delete activeTransfersRef.current[transferId];
            setTransfers((prev) => {
              const next = { ...prev };
              delete next[transferId];
              return next;
            });
          }
        }
      } catch (err) {
        console.error("Failed to process incoming chunk:", err);
      }
    };

    socket.on("receive_file_chunk", handleReceiveFileChunk);
    return () => {
      socket.off("receive_file_chunk", handleReceiveFileChunk);
    };
  }, [socket, cryptoKey, messages, activeRoomId, setRooms]);

  // Handle Drag & Drop File Upload
  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current += 1;
    if (e.dataTransfer?.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current -= 1;
    if (dragCounterRef.current === 0) {
      setIsDragging(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounterRef.current = 0;

    if (isLocked || isRoomFull || !cryptoKey) return;

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      Array.from(files).forEach((file) => {
        processFileSend(file);
      });
    }
  };

  // Text Message Sending
  const handleSend = async (e) => {
    if (e) e.preventDefault();
    if (!newMessage.trim() || !socket || !cryptoKey || isLocked) return;

    const messageId =
      Date.now() + "-" + Math.random().toString(36).substring(2, 9);
    const timestamp = Date.now();

    const newMsgItem = {
      id: messageId,
      type: "text",
      text: newMessage,
      isOwn: true,
      status: "sending",
      time: new Date(timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true,
      }),
      timestamp,
    };

    // Append message to active room state immediately
    setRooms((prev) => {
      const r = prev[activeRoomId];
      if (!r) return prev;
      return {
        ...prev,
        [activeRoomId]: {
          ...r,
          messages: [...r.messages, newMsgItem],
        },
      };
    });

    const textToSend = newMessage;
    setNewMessage("");

    try {
      const payload = JSON.stringify({
        id: messageId,
        type: "text",
        text: textToSend,
      });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      await saveMessage(activeRoomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv,
      });

      socket.emit(
        "send_message",
        {
          roomId: activeRoomId,
          message: encryptedPayload,
        },
        async () => {
          setRooms((prev) => {
            const r = prev[activeRoomId];
            if (!r) return prev;
            const updatedMsgs = r.messages.map((msg) =>
              msg.id === messageId ? { ...msg, status: "sent" } : msg
            );
            return {
              ...prev,
              [activeRoomId]: { ...r, messages: updatedMsgs },
            };
          });
          await updateMessageStatus(messageId, "sent");
        }
      );
    } catch (err) {
      console.error("Failed to send message", err);
    }
  };

  const getFileIcon = (fileType) => {
    if (fileType.startsWith("image/")) return "image";
    if (fileType.includes("pdf")) return "pdf";
    if (fileType.includes("spreadsheet") || fileType.includes("excel"))
      return "spreadsheet";
    if (fileType.includes("word") || fileType.includes("document"))
      return "document";
    if (fileType.includes("presentation") || fileType.includes("powerpoint"))
      return "presentation";
    return "file";
  };

  // File Upload and Chunked Transmission
  const processFileSend = async (file) => {
    if (!file || !socket || !cryptoKey || isLocked) return;

    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
      alert(
        `File size must be less than 50MB. Your file is ${(
          file.size /
          (1024 * 1024)
        ).toFixed(2)}MB.`
      );
      return;
    }

    const CHUNK_SIZE = 512 * 1024;
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const transferId =
      Date.now() + "-" + Math.random().toString(36).substring(2, 9);
    const messageId = "msg-" + transferId;
    const timestamp = Date.now();
    const localUrl = URL.createObjectURL(file);

    const fileMsgItem = {
      id: messageId,
      type: "file",
      transferId,
      fileName: file.name,
      fileType: file.type,
      fileData: localUrl,
      fileIcon: getFileIcon(file.type),
      isOwn: true,
      status: "sending",
      time: new Date(timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true,
      }),
      timestamp,
      totalChunks,
    };

    setRooms((prev) => {
      const r = prev[activeRoomId];
      if (!r) return prev;
      return {
        ...prev,
        [activeRoomId]: {
          ...r,
          messages: [...r.messages, fileMsgItem],
        },
      };
    });

    setTransfers((prev) => ({
      ...prev,
      [transferId]: { progress: 0, status: "Encrypting" },
    }));

    try {
      const payload = JSON.stringify({
        id: messageId,
        type: "file",
        transferId,
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size,
        totalChunks,
        fileIcon: getFileIcon(file.type),
      });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      await saveMessage(activeRoomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv,
      });

      await updateMessageFileBlob(messageId, file, "sending");

      socket.emit(
        "send_message",
        { roomId: activeRoomId, message: encryptedPayload },
        async () => {
          setTransfers((prev) => ({
            ...prev,
            [transferId]: { progress: 0, status: "Uploading" },
          }));

          const readChunk = (blob) => {
            return new Promise((resolve) => {
              const reader = new FileReader();
              reader.onload = (ev) => resolve(ev.target.result);
              reader.readAsArrayBuffer(blob);
            });
          };

          for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
            const start = chunkIndex * CHUNK_SIZE;
            const end = Math.min(start + CHUNK_SIZE, file.size);
            const blobSlice = file.slice(start, end);

            const arrayBuffer = await readChunk(blobSlice);
            const { encryptedData, iv } = await encryptBinary(
              cryptoKey,
              arrayBuffer
            );

            await new Promise((resolve) => {
              socket.emit(
                "send_file_chunk",
                {
                  roomId: activeRoomId,
                  chunk: {
                    transferId,
                    chunkIndex,
                    iv,
                    encryptedData,
                  },
                },
                () => {
                  resolve();
                }
              );
            });

            const progress = Math.round(((chunkIndex + 1) / totalChunks) * 100);
            setTransfers((prev) => ({
              ...prev,
              [transferId]: { progress, status: "Uploading" },
            }));
          }

          setRooms((prev) => {
            const r = prev[activeRoomId];
            if (!r) return prev;
            const updatedMsgs = r.messages.map((msg) =>
              msg.id === messageId ? { ...msg, status: "sent" } : msg
            );
            return {
              ...prev,
              [activeRoomId]: { ...r, messages: updatedMsgs },
            };
          });
          await updateMessageStatus(messageId, "sent");
          await updateMessageFileBlob(messageId, null, "sent");
          setTransfers((prev) => {
            const next = { ...prev };
            delete next[transferId];
            return next;
          });
        }
      );
    } catch (err) {
      console.error("Failed to upload file in chunks:", err);
      setTransfers((prev) => ({
        ...prev,
        [transferId]: { progress: 0, status: "Failed" },
      }));
    }
  };

  return (
    <div
      className={`glass-panel chat-container ${
        isDragging ? "dragging-over" : ""
      }`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {/* Header */}
      <ChatHeader
        currentRoom={currentRoom}
        activeRoomId={activeRoomId}
        isConnected={isConnected}
        showSidebar={showSidebar}
        onToggleSidebar={() => setShowSidebar(!showSidebar)}
        onShowQRCode={() => setShowQRCode(true)}
        onNavigateHome={() => navigate("/")}
        onLeaveRoom={onLeaveRoom}
      />

      {/* Main Layout */}
      <div className="chat-layout-wrapper">
        {/* Settings Drawer */}
        <ChatSidebar
          isOpen={showSidebar}
          onClose={() => setShowSidebar(false)}
          currentRoom={currentRoom}
          activeRoomId={activeRoomId}
          isLocked={isLocked}
          roomNameInput={roomNameInput}
          onRoomNameChange={(name) => {
            setRoomNameInput(name);
            if (onSetRoomName) {
              onSetRoomName(activeRoomId, name);
            }
          }}
          retentionPeriod={retentionPeriod}
          onUpdateRetentionPeriod={onUpdateRetentionPeriod}
          onShowQRCode={() => setShowQRCode(true)}
          onDeleteRoomForAll={onDeleteRoomForAll}
          onLeaveRoom={onLeaveRoom}
        />

        {/* Chat Main Content Area */}
        <div className="chat-main-content">
          {isRoomFull ? (
            <RoomRestrictedView
              activeRoomId={activeRoomId}
              onLeaveRoom={onLeaveRoom}
              onNavigateHome={() => navigate("/")}
            />
          ) : isLocked ? (
            <LockedRoomView
              activeRoomId={activeRoomId}
              onUnlockRoom={onUnlockRoom}
              onLeaveRoom={onLeaveRoom}
            />
          ) : (
            <>
              <ChatMessages
                messages={messages}
                transfers={transfers}
                activeRoomId={activeRoomId}
                messagesEndRef={messagesEndRef}
              />

              <MessageComposer
                newMessage={newMessage}
                onMessageChange={setNewMessage}
                onSend={handleSend}
                onFileSelect={processFileSend}
                disabled={isLocked || !cryptoKey}
              />
            </>
          )}
        </div>
      </div>

      {/* QR Code Overlay Modal */}
      <QRCodeModal
        isOpen={showQRCode}
        onClose={() => setShowQRCode(false)}
        roomId={activeRoomId}
      />

      {/* Drag & Drop Visual Overlay */}
      <DragDropOverlay
        isDragging={isDragging && !isLocked && !isRoomFull && !!cryptoKey}
      />
    </div>
  );
}
