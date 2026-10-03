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
  updateMessageEncryptedFile,
} from "../../utils/ledger";
import {
  getNextOutgoingSeq,
  recordMessageIdSeen,
} from "../../utils/replayProtection";
import ChatHeader from "./ChatHeader";
import ChatSidebar from "./ChatSidebar";
import ChatMessages from "./ChatMessages";
import MessageComposer from "./MessageComposer";
import LockedRoomView from "./LockedRoomView";
import RoomRestrictedView from "./RoomRestrictedView";
import QRCodeModal from "./QRCodeModal";
import DragDropOverlay from "./DragDropOverlay";
import "./ChatPage.css";

const CHUNK_SIZE = 512 * 1024; // 512 KB
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
const MAX_CHUNKS = Math.ceil(MAX_FILE_SIZE / CHUNK_SIZE) + 10; // ~110 chunks
const TRANSFER_TIMEOUT_MS = 60 * 1000; // 60 seconds

function getChunkAad(transferId, chunkIndex, totalChunks, fileSize) {
  return new TextEncoder().encode(
    `${transferId}:${chunkIndex}:${totalChunks}:${fileSize}`
  );
}

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

  // Socket file chunk receiver with authenticated metadata, strict validation, and timeout expiry
  useEffect(() => {
    if (!socket) return;

    const abortTransfer = (transferId, reason) => {
      if (import.meta.env.DEV) {
        console.warn(`[File Transfer] Aborting transfer ${transferId}: ${reason}`);
      }
      const t = activeTransfersRef.current[transferId];
      if (t) {
        if (t.timeoutId) clearTimeout(t.timeoutId);
        t.chunks = null;
        delete activeTransfersRef.current[transferId];
      }
      setTransfers((prev) => {
        const next = { ...prev };
        delete next[transferId];
        return next;
      });
    };

    const handleReceiveFileChunk = async (chunk) => {
      if (!chunk || typeof chunk !== "object") return;
      const {
        roomId: chunkRoomId,
        transferId,
        chunkIndex,
        totalChunks,
        fileSize,
        iv,
        encryptedData,
        encryptedMeta,
      } = chunk;

      const targetRoomId = chunkRoomId || activeRoomId;
      if (targetRoomId !== activeRoomId || !cryptoKey) return;

      // 1. Basic Type and Structure Validations
      if (
        typeof transferId !== "string" ||
        !transferId.trim() ||
        typeof chunkIndex !== "number" ||
        !Number.isInteger(chunkIndex) ||
        typeof totalChunks !== "number" ||
        !Number.isInteger(totalChunks) ||
        typeof fileSize !== "number" ||
        !Number.isInteger(fileSize) ||
        !iv ||
        !encryptedData ||
        !encryptedMeta
      ) {
        if (import.meta.env.DEV) {
          console.warn("[File Transfer] Rejected malformed chunk: missing or invalid field types");
        }
        return;
      }

      // 2. Range Validations
      if (
        totalChunks <= 0 ||
        totalChunks > MAX_CHUNKS ||
        chunkIndex < 0 ||
        chunkIndex >= totalChunks ||
        fileSize <= 0 ||
        fileSize > MAX_FILE_SIZE
      ) {
        if (import.meta.env.DEV) {
          console.warn("[File Transfer] Rejected malformed chunk: values out of allowed bounds", {
            chunkIndex,
            totalChunks,
            fileSize,
          });
        }
        return;
      }

      // 3. Validate against file announcement message descriptor if present
      const msg = messages.find((m) => m.transferId === transferId);
      if (msg) {
        if (msg.totalChunks && msg.totalChunks !== totalChunks) {
          if (import.meta.env.DEV) {
            console.warn("[File Transfer] Rejected malformed chunk: totalChunks mismatch with message descriptor");
          }
          return;
        }
        if (msg.fileSize && msg.fileSize !== fileSize) {
          if (import.meta.env.DEV) {
            console.warn("[File Transfer] Rejected malformed chunk: fileSize mismatch with message descriptor");
          }
          return;
        }
      }

      // 4. Decrypt and Authenticate Metadata
      const metaStr = await decryptMessage(cryptoKey, encryptedMeta);
      if (!metaStr) {
        if (import.meta.env.DEV) {
          console.warn("[File Transfer] Rejected malformed chunk: metadata decryption/authentication failed");
        }
        return;
      }

      let meta;
      try {
        meta = JSON.parse(metaStr);
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn("[File Transfer] Rejected malformed chunk: metadata is not valid JSON");
        }
        return;
      }

      if (
        meta.transferId !== transferId ||
        meta.chunkIndex !== chunkIndex ||
        meta.totalChunks !== totalChunks ||
        meta.fileSize !== fileSize
      ) {
        if (import.meta.env.DEV) {
          console.warn("[File Transfer] Rejected malformed chunk: authenticated metadata does not match chunk headers", {
            meta,
            chunk: { transferId, chunkIndex, totalChunks, fileSize },
          });
        }
        return;
      }

      // 5. Decrypt and Authenticate Chunk Data with AAD
      const aad = getChunkAad(transferId, chunkIndex, totalChunks, fileSize);
      const decryptedData = await decryptBinary(cryptoKey, encryptedData, iv, aad);
      if (!decryptedData) {
        if (import.meta.env.DEV) {
          console.warn(`[File Transfer] Rejected malformed chunk: chunk ${chunkIndex} authentication/decryption failed`);
        }
        return;
      }

      // 6. Initialize or Retrieve Transfer Assembly State
      if (!activeTransfersRef.current[transferId]) {
        activeTransfersRef.current[transferId] = {
          chunks: new Array(totalChunks),
          receivedCount: 0,
          totalChunks,
          fileSize,
          fileName: meta.fileName || msg?.fileName || "download",
          fileType: meta.fileType || msg?.fileType || "application/octet-stream",
          messageId: msg ? msg.id : "",
          accumulatedBytes: 0,
          timeoutId: setTimeout(() => {
            abortTransfer(transferId, `Incomplete transfer timed out after ${TRANSFER_TIMEOUT_MS}ms`);
          }, TRANSFER_TIMEOUT_MS),
        };
      }

      const transfer = activeTransfersRef.current[transferId];

      // Refresh timeout upon receiving a valid chunk
      if (transfer.timeoutId) clearTimeout(transfer.timeoutId);
      transfer.timeoutId = setTimeout(() => {
        abortTransfer(transferId, `Incomplete transfer timed out after ${TRANSFER_TIMEOUT_MS}ms`);
      }, TRANSFER_TIMEOUT_MS);

      // Verify declared properties match ongoing transfer state
      if (transfer.totalChunks !== totalChunks || transfer.fileSize !== fileSize) {
        abortTransfer(transferId, "Transfer parameters changed mid-transfer");
        return;
      }

      // Late message association if message descriptor arrived after chunk 0
      if (!transfer.messageId && msg) {
        transfer.messageId = msg.id;
        if (!transfer.fileName && msg.fileName) transfer.fileName = msg.fileName;
        if (!transfer.fileType && msg.fileType) transfer.fileType = msg.fileType;
      }

      // Ignore duplicate chunks (idempotent)
      if (transfer.chunks[chunkIndex]) return;

      // Cumulative size check: ensure received bytes cannot exceed declared fileSize
      if (transfer.accumulatedBytes + decryptedData.byteLength > transfer.fileSize) {
        abortTransfer(transferId, "Cumulative chunk bytes exceeded declared fileSize");
        return;
      }

      transfer.chunks[chunkIndex] = decryptedData;
      transfer.receivedCount += 1;
      transfer.accumulatedBytes += decryptedData.byteLength;

      const progress = Math.round((transfer.receivedCount / transfer.totalChunks) * 100);
      setTransfers((prev) => ({
        ...prev,
        [transferId]: { progress, status: "Receiving" },
      }));

      // 7. Check Completion
      if (transfer.receivedCount === transfer.totalChunks) {
        if (transfer.timeoutId) clearTimeout(transfer.timeoutId);

        // Final size validation
        if (transfer.accumulatedBytes !== transfer.fileSize) {
          abortTransfer(transferId, `Total received bytes (${transfer.accumulatedBytes}) does not equal declared fileSize (${transfer.fileSize})`);
          return;
        }

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

        const targetMessageId = transfer.messageId || msg?.id;
        if (targetMessageId) {
          try {
            const fileBuffer = await fileBlob.arrayBuffer();
            const { encryptedData: encryptedBytes, iv: fileIv } =
              await encryptBinary(cryptoKey, fileBuffer);
            await updateMessageEncryptedFile(
              targetMessageId,
              {
                encryptedBytes,
                iv: fileIv,
                mimeType: transfer.fileType,
                fileName: transfer.fileName,
              },
              "delivered"
            );
          } catch (encErr) {
            if (import.meta.env.DEV) {
              console.error("Failed to encrypt received file for storage:", encErr);
            }
          }

          if (msg && msg.senderId) {
            socket.emit("message_delivered", {
              roomId: activeRoomId,
              messageId: targetMessageId,
              senderId: msg.senderId,
            });
          }
        }

        // Clean up completed transfer state
        transfer.chunks = null;
        delete activeTransfersRef.current[transferId];
        setTransfers((prev) => {
          const next = { ...prev };
          delete next[transferId];
          return next;
        });
      }
    };

    socket.on("receive_file_chunk", handleReceiveFileChunk);
    return () => {
      socket.off("receive_file_chunk", handleReceiveFileChunk);
      // Clean up all pending timeouts when unmounting/changing socket
      Object.values(activeTransfersRef.current).forEach((t) => {
        if (t && t.timeoutId) clearTimeout(t.timeoutId);
      });
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
    const nextSeq = getNextOutgoingSeq(activeRoomId);
    recordMessageIdSeen(activeRoomId, messageId);

    const newMsgItem = {
      id: messageId,
      type: "text",
      text: newMessage,
      seq: nextSeq,
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
        seq: nextSeq,
      });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      await saveMessage(activeRoomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv,
        seq: nextSeq,
      });

      socket.emit(
        "send_message",
        {
          roomId: activeRoomId,
          message: {
            ...encryptedPayload,
            id: messageId,
            seq: nextSeq,
          },
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
      if (import.meta.env.DEV) {
        console.error("Failed to send message", err);
      }
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

    if (file.size > MAX_FILE_SIZE) {
      alert(
        `File size must be less than 50MB. Your file is ${(
          file.size /
          (1024 * 1024)
        ).toFixed(2)}MB.`
      );
      return;
    }

    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const transferId =
      Date.now() + "-" + Math.random().toString(36).substring(2, 9);
    const messageId = "msg-" + transferId;
    const timestamp = Date.now();
    const nextSeq = getNextOutgoingSeq(activeRoomId);
    recordMessageIdSeen(activeRoomId, messageId);
    const localUrl = URL.createObjectURL(file);

    const fileMsgItem = {
      id: messageId,
      type: "file",
      transferId,
      fileName: file.name,
      fileType: file.type,
      fileData: localUrl,
      fileIcon: getFileIcon(file.type),
      seq: nextSeq,
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
        seq: nextSeq,
      });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      await saveMessage(activeRoomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv,
        seq: nextSeq,
      });

      const fileBuffer = await file.arrayBuffer();
      const { encryptedData: encryptedBytes, iv: fileIv } = await encryptBinary(
        cryptoKey,
        fileBuffer
      );
      await updateMessageEncryptedFile(
        messageId,
        {
          encryptedBytes,
          iv: fileIv,
          mimeType: file.type,
          fileName: file.name,
        },
        "sending"
      );

      socket.emit(
        "send_message",
        {
          roomId: activeRoomId,
          message: {
            ...encryptedPayload,
            id: messageId,
            seq: nextSeq,
          },
        },
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
            const aad = getChunkAad(transferId, chunkIndex, totalChunks, file.size);
            const { encryptedData, iv } = await encryptBinary(
              cryptoKey,
              arrayBuffer,
              aad
            );

            const chunkMeta = {
              transferId,
              chunkIndex,
              totalChunks,
              fileSize: file.size,
              fileName: file.name,
              fileType: file.type,
            };
            const encryptedMeta = await encryptMessage(cryptoKey, JSON.stringify(chunkMeta));

            await new Promise((resolve) => {
              socket.emit(
                "send_file_chunk",
                {
                  roomId: activeRoomId,
                  chunk: {
                    transferId,
                    chunkIndex,
                    totalChunks,
                    fileSize: file.size,
                    iv,
                    encryptedData,
                    encryptedMeta,
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
          setTransfers((prev) => {
            const next = { ...prev };
            delete next[transferId];
            return next;
          });
        }
      );
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error("Failed to upload file in chunks:", err);
      }
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
        salt={currentRoom?.salt}
      />

      {/* Drag & Drop Visual Overlay */}
      <DragDropOverlay
        isDragging={isDragging && !isLocked && !isRoomFull && !!cryptoKey}
      />
    </div>
  );
}
