import { useState, useEffect, useRef } from "react";
import {
  Lock,
  SendHorizontal,
  LogOut,
  Paperclip,
  File,
  Download,
  QrCode,
  X,
  Copy,
  CheckCheck,
  Check,
  Clock,
  Menu,
  ChevronDown,
  Home,
  Tag,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { encryptMessage, encryptBinary, decryptBinary } from "../../utils/crypto";
import { saveMessage, updateMessageStatus, updateMessageFileBlob } from "../../utils/ledger";
import QRCode from "react-qr-code";
import "./ChatPage.css";

// Supported document file types
const SUPPORTED_DOCUMENT_TYPES = {
  "application/pdf": { ext: "pdf", name: "PDF" },
  "application/msword": { ext: "doc", name: "Word Document" },
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
    ext: "docx",
    name: "Word Document",
  },
  "application/vnd.ms-powerpoint": { ext: "ppt", name: "PowerPoint" },
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
    ext: "pptx",
    name: "PowerPoint",
  },
  "application/vnd.ms-excel": { ext: "xls", name: "Excel Spreadsheet" },
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
    ext: "xlsx",
    name: "Excel Spreadsheet",
  },
  "text/plain": { ext: "txt", name: "Text File" },
  "text/csv": { ext: "csv", name: "CSV File" },
  "application/zip": { ext: "zip", name: "ZIP Archive" },
};

export default function ChatPage({
  socket,
  rooms = {},
  activeRoomId = "",
  currentRoom = null,
  setRooms,
  onSwitchRoom,
  onJoinNewRoom,
  onLeaveRoom,
  onUnlockRoom,
  onUpdateRetentionPeriod,
  onSetRoomName,
}) {
  const [newMessage, setNewMessage] = useState("");
  const [showQRCode, setShowQRCode] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  
  const [roomNameInput, setRoomNameInput] = useState(currentRoom?.roomName || "");
  useEffect(() => {
    setRoomNameInput(currentRoom?.roomName || "");
  }, [activeRoomId, currentRoom?.roomName]);

  // Unlock State
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);

  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
  const [isCopied, setIsCopied] = useState(false);
  const [transfers, setTransfers] = useState({});
  const activeTransfersRef = useRef({});
  const navigate = useNavigate();

  const messages = currentRoom?.messages || [];
  const cryptoKey = currentRoom?.cryptoKey || null;
  const isConnected = currentRoom?.isConnected ?? false;
  const retentionPeriod = currentRoom?.retentionPeriod || 86400000;
  const isLocked = currentRoom?.isLocked ?? false;

  // Redirect if no active rooms exist
  useEffect(() => {
    if (Object.keys(rooms).length === 0) {
      navigate("/");
    }
  }, [rooms, navigate]);

  useEffect(() => {
    // Scroll to bottom on new message
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleUnlockSubmit = async (e) => {
    e.preventDefault();
    setUnlockError("");
    if (!unlockPassword.trim()) {
      setUnlockError("Password is required.");
      return;
    }
    setIsUnlocking(true);
    try {
      await onUnlockRoom(activeRoomId, unlockPassword.trim());
      setUnlockPassword("");
    } catch (err) {
      setUnlockError("Failed to unlock room. Check your password.");
    } finally {
      setIsUnlocking(false);
    }
  };

  useEffect(() => {
    if (!socket) return;

    const handleReceiveFileChunk = async (chunk) => {
      const { roomId: chunkRoomId, transferId, chunkIndex, iv, encryptedData } = chunk;
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
          messageId: msg ? msg.id : ""
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
            [transferId]: { progress, status: "Receiving" }
          }));

          if (transfer.receivedCount === total) {
            const fileBlob = new Blob(transfer.chunks, { type: transfer.fileType });
            const fileUrl = URL.createObjectURL(fileBlob);

            setRooms((prev) => {
              const r = prev[activeRoomId];
              if (!r) return prev;
              const updatedMsgs = r.messages.map((m) =>
                m.transferId === transferId ? { ...m, fileData: fileUrl, status: "delivered" } : m
              );
              return { ...prev, [activeRoomId]: { ...r, messages: updatedMsgs } };
            });

            if (transfer.messageId) {
              await updateMessageFileBlob(transfer.messageId, fileBlob, "delivered");
              if (msg && msg.senderId) {
                socket.emit("message_delivered", {
                  roomId: activeRoomId,
                  messageId: transfer.messageId,
                  senderId: msg.senderId
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

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && e.shiftKey) {
      e.preventDefault();
      handleSend(e);
    }
  };

  const handleSend = async (e) => {
    if (e) e.preventDefault();
    if (!newMessage.trim() || !socket || !cryptoKey || isLocked) return;

    const messageId = Date.now() + "-" + Math.random().toString(36).substring(2, 9);
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
      timestamp
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
      const payload = JSON.stringify({ id: messageId, type: "text", text: textToSend });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      await saveMessage(activeRoomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv
      });

      socket.emit("send_message", {
        roomId: activeRoomId,
        message: encryptedPayload,
      }, async () => {
        setRooms((prev) => {
          const r = prev[activeRoomId];
          if (!r) return prev;
          const updatedMsgs = r.messages.map((msg) =>
            msg.id === messageId ? { ...msg, status: "sent" } : msg
          );
          return { ...prev, [activeRoomId]: { ...r, messages: updatedMsgs } };
        });
        await updateMessageStatus(messageId, "sent");
      });
    } catch (err) {
      console.error("Failed to send message", err);
    }
  };

  const getFileIcon = (fileType) => {
    if (fileType.startsWith("image/")) return "image";
    if (fileType.includes("pdf")) return "pdf";
    if (fileType.includes("spreadsheet") || fileType.includes("excel")) return "spreadsheet";
    if (fileType.includes("word") || fileType.includes("document")) return "document";
    if (fileType.includes("presentation") || fileType.includes("powerpoint")) return "presentation";
    return "file";
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file || !socket || !cryptoKey || isLocked) return;

    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
      alert(`File size must be less than 50MB. Your file is ${(file.size / (1024 * 1024)).toFixed(2)}MB.`);
      return;
    }

    const CHUNK_SIZE = 512 * 1024;
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const transferId = Date.now() + "-" + Math.random().toString(36).substring(2, 9);
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
      totalChunks
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
      [transferId]: { progress: 0, status: "Encrypting" }
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
        fileIcon: getFileIcon(file.type)
      });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      await saveMessage(activeRoomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv
      });

      await updateMessageFileBlob(messageId, file, "sending");

      socket.emit("send_message", { roomId: activeRoomId, message: encryptedPayload }, async () => {
        setTransfers((prev) => ({
          ...prev,
          [transferId]: { progress: 0, status: "Uploading" }
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
          const { encryptedData, iv } = await encryptBinary(cryptoKey, arrayBuffer);

          await new Promise((resolve) => {
            socket.emit("send_file_chunk", {
              roomId: activeRoomId,
              chunk: {
                transferId,
                chunkIndex,
                iv,
                encryptedData
              }
            }, () => {
              resolve();
            });
          });

          const progress = Math.round(((chunkIndex + 1) / totalChunks) * 100);
          setTransfers((prev) => ({
            ...prev,
            [transferId]: { progress, status: "Uploading" }
          }));
        }

        setRooms((prev) => {
          const r = prev[activeRoomId];
          if (!r) return prev;
          const updatedMsgs = r.messages.map((msg) =>
            msg.id === messageId ? { ...msg, status: "sent" } : msg
          );
          return { ...prev, [activeRoomId]: { ...r, messages: updatedMsgs } };
        });
        await updateMessageStatus(messageId, "sent");
        await updateMessageFileBlob(messageId, null, "sent");
        setTransfers((prev) => {
          const next = { ...prev };
          delete next[transferId];
          return next;
        });
      });
    } catch (err) {
      console.error("Failed to upload file in chunks:", err);
      setTransfers((prev) => ({
        ...prev,
        [transferId]: { progress: 0, status: "Failed" }
      }));
    }

    e.target.value = null;
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div className="glass-panel chat-container">
      {/* Header */}
      <div className="chat-header">
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <button
            onClick={() => setShowSidebar(!showSidebar)}
            className="icon-btn header-action-btn hamburger-btn"
            style={{
              background: "transparent",
              color: "var(--text-muted)",
              padding: "0.25rem",
              width: "auto",
              height: "auto",
              borderRadius: "0",
            }}
            title="Toggle Rooms & Settings Menu"
          >
            <Menu size={20} />
          </button>
          <div>
            <h2
              style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: "0.4rem" }}
              onClick={() => setShowQRCode(!showQRCode)}
              title="Click to show QR code"
            >
              {currentRoom?.roomName || (activeRoomId.length > 16 ? activeRoomId.substring(0, 14) + "..." : activeRoomId)}
              <QrCode size={16} />
            </h2>            
            <div className="connection-status">
                {isConnected ? "Connected" : "Reconnecting..."}
                <span className={`connection-status-dot ${!isConnected ? "offline" : "online"}`}></span>     
            </div>
                       
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          {currentRoom && (
            <>
              <button
                onClick={() => navigate("/")}
                className="btn-header-home"
                title="Back to Home Hub"
              >
                <Home size={20} />
                <span>Home</span>
              </button>
              <button
                onClick={() => onLeaveRoom(activeRoomId)}
                className="btn-header-home"                
                title="Leave Current Room"
              >
                <LogOut size={20} />
                <span>Leave Room</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Main Layout */}
      <div className="chat-layout-wrapper">
        {showSidebar && (
          <div className="sidebar-overlay" onClick={() => setShowSidebar(false)} />
        )}

        {/* Sidebar */}
        <aside className={`chat-sidebar ${showSidebar ? "open" : ""}`}>
          <div className="sidebar-header">
            <h3>Room Settings</h3>
            <button
              className="sidebar-close-btn"
              onClick={() => setShowSidebar(false)}
              title="Close Drawer"
            >
              <X size={20} />
            </button>
          </div>

          <div className="sidebar-body">
            {/* Room Settings Section */}
            {currentRoom && !isLocked && (
              <>
                <div className="settings-section">
                  <h4>Room Display Name</h4>
                  <p className="settings-desc">Set a local custom name for this room (stored zero-knowledge on your device).</p>
                  <div className="input-wrapper">
                    <Tag size={16} className="input-icon" />
                    <input
                      type="text"
                      placeholder="e.g. Project Delta"
                      value={roomNameInput}
                      onChange={(e) => {
                        setRoomNameInput(e.target.value);
                        if (onSetRoomName) {
                          onSetRoomName(activeRoomId, e.target.value);
                        }
                      }}
                    />
                  </div>
                </div>

                <div className="settings-section">
                  <h4>Message Retention</h4>
                  <p className="settings-desc">Choose how long messages remain stored in your local browser before being permanently pruned.</p>
                  
                  <div className="custom-dropdown-container">
                    <button
                      type="button"
                      className="dropdown-trigger"
                      onClick={() => setDropdownOpen(!dropdownOpen)}
                      title="Select Retention Period"
                    >
                      <Clock size={16} className="dropdown-trigger-icon" />
                      <span className="dropdown-selected-label">
                        {
                          [
                            { value: 3600000, label: "1 Hour" },
                            { value: 43200000, label: "12 Hours" },
                            { value: 86400000, label: "24 Hours" },
                            { value: 604800000, label: "7 Days" }
                          ].find(opt => opt.value === retentionPeriod)?.label || "Select Period"
                        }
                      </span>
                      <ChevronDown size={16} className={`dropdown-arrow ${dropdownOpen ? "open" : ""}`} />
                    </button>

                    {dropdownOpen && (
                      <div className="dropdown-menu">
                        {[
                          { value: 3600000, label: "1 Hour", desc: "For temporary discussions" },
                          { value: 43200000, label: "12 Hours", desc: "Keep history for half a day" },
                          { value: 86400000, label: "24 Hours", desc: "Standard daily rotation" },
                          { value: 604800000, label: "7 Days", desc: "Longer term recovery limit" }
                        ].map((opt) => (
                          <div
                            key={opt.value}
                            className={`dropdown-item ${retentionPeriod === opt.value ? "active" : ""}`}
                            onClick={() => {
                              onUpdateRetentionPeriod(activeRoomId, opt.value);
                              setDropdownOpen(false);
                            }}
                          >
                            <div className="dropdown-item-details">
                              <span className="dropdown-item-title">{opt.label}</span>
                              <span className="dropdown-item-desc">{opt.desc}</span>
                            </div>
                            {retentionPeriod === opt.value && (
                              <Check size={16} className="dropdown-item-check" />
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="settings-section">
                  <h4>Session Sharing</h4>
                  <p className="settings-desc">Invite peers to this secure room using the room ID or a QR code.</p>
                  
                  <div className="session-share-actions">
                    <div
                      className="share-field copyable-field"
                      onClick={() => copyToClipboard(activeRoomId)}
                      title="Click to copy Chat Room ID"
                    >
                      <span className="share-text">{activeRoomId}</span>
                      {isCopied ? (
                        <CheckCheck size={16} className="text-primary" />
                      ) : (
                        <Copy size={16} />
                      )}
                    </div>

                    <button
                      className="btn-sidebar-qr"
                      onClick={() => setShowQRCode(true)}
                      title="Open QR Code Share Overlay"
                    >
                      <QrCode size={16} />
                      <span>Show QR Code</span>
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </aside>

        {/* Chat Main Section */}
        <div className="chat-main-content">
          {isLocked ? (
            /* Locked Room View */
            <div className="locked-room-container">
              <div className="locked-card glass-panel">
                <Lock size={48} className="text-primary locked-icon" />
                <h3>Room Locked</h3>
                <p className="locked-desc">
                  Decryption key missing for room <strong>{activeRoomId}</strong>. Enter the password to unlock this room.
                </p>

                <form onSubmit={handleUnlockSubmit} className="unlock-form">
                  <div className="input-wrapper">
                    <Lock size={18} className="input-icon" />
                    <input
                      type="password"
                      placeholder="Enter room password"
                      value={unlockPassword}
                      onChange={(e) => setUnlockPassword(e.target.value)}
                      disabled={isUnlocking}
                      autoFocus
                    />
                  </div>

                  {unlockError && <div className="error-msg">{unlockError}</div>}

                  <div className="unlock-actions">
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={isUnlocking || !unlockPassword.trim()}
                    >
                      {isUnlocking ? "Unlocking..." : "Unlock Room"}
                    </button>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => onLeaveRoom(activeRoomId)}
                    >
                      Remove Room
                    </button>
                  </div>
                </form>
              </div>
            </div>
          ) : (
            /* Normal Chat View */
            <>
              <div className="messages-area">
                {messages.length === 0 && (
                  <div
                    style={{
                      textAlign: "center",
                      color: "var(--text-muted)",
                      margin: "auto",
                    }}
                  >
                    <Lock size={32} style={{ margin: "0 auto 1rem", opacity: 0.5 }} />
                    <p>Session initialized: {activeRoomId}</p>
                    <p style={{ fontSize: "0.8rem", marginTop: "0.25rem" }}>
                      Messages are not stored and will be permanently lost when you leave.
                    </p>
                  </div>
                )}

                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`message-bubble ${msg.isOwn ? "own" : "peer"}`}
                  >
                    {msg.type === "file" ? (
                      (() => {
                        const transfer = transfers[msg.transferId];
                        return (
                          <div className="file-attachment">
                            {msg.fileType && msg.fileType.startsWith("image/") ? (
                              <div className="image-container">
                                {msg.fileData ? (
                                  <div style={{ position: "relative" }}>
                                    <img
                                      src={msg.fileData}
                                      alt={msg.fileName}
                                      className="attached-image"
                                    />
                                    {transfer && (
                                      <div className="file-transfer-overlay">
                                        <div className="transfer-status-text">{transfer.status}...</div>
                                        <div className="transfer-progress-bar-container">
                                          <div className="transfer-progress-bar" style={{ width: `${transfer.progress}%` }}></div>
                                        </div>
                                        <div className="transfer-percentage-text">{transfer.progress}%</div>
                                      </div>
                                    )}
                                    {!transfer && (
                                      <a
                                        href={msg.fileData}
                                        download={msg.fileName}
                                        className="image-download-btn"
                                        title="Download Image"
                                      >
                                        <Download size={18} />
                                      </a>
                                    )}
                                  </div>
                                ) : (
                                  <div className="image-loading-placeholder">
                                    <Clock size={20} className="spinner-icon" />
                                    {transfer ? (
                                      <>
                                        <span>{transfer.status} {transfer.progress}%...</span>
                                        <div className="transfer-progress-bar-container" style={{ width: "80%", marginTop: "8px" }}>
                                          <div className="transfer-progress-bar" style={{ width: `${transfer.progress}%` }}></div>
                                        </div>
                                      </>
                                    ) : (
                                      <span>Encrypting {msg.fileName}...</span>
                                    )}
                                  </div>
                                )}
                              </div>
                            ) : (
                              <div className="attached-file">
                                <File size={24} className="file-icon" />
                                <div className="file-info">
                                  <span className="file-name" title={msg.fileName}>
                                    {msg.fileName}
                                  </span>
                                  {transfer ? (
                                    <div className="transfer-progress-section" style={{ marginTop: "4px" }}>
                                      <span className="transfer-status-text" style={{ fontSize: "0.75rem", color: "var(--text-muted)", display: "block" }}>
                                        {transfer.status} ({transfer.progress}%)
                                      </span>
                                      <div className="transfer-progress-bar-container" style={{ marginTop: "4px" }}>
                                        <div className="transfer-progress-bar" style={{ width: `${transfer.progress}%` }}></div>
                                      </div>
                                    </div>
                                  ) : msg.fileType ? (
                                    <span className="file-type">{msg.fileType}</span>
                                  ) : null}
                                </div>
                                {msg.fileData && !transfer ? (
                                  <a
                                    href={msg.fileData}
                                    download={msg.fileName}
                                    className="download-btn"
                                    title="Download"
                                  >
                                    <Download size={18} />
                                  </a>
                                ) : (
                                  !transfer && (
                                    <div className="file-loading-placeholder">
                                      <Clock size={16} className="spinner-icon" />
                                    </div>
                                  )
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })()
                    ) : (
                      <div className="text">{msg.text}</div>
                    )}
                    <div className="message-meta">
                      <span className="time">{msg.time}</span>
                      {msg.isOwn && (
                        <span className={`status-indicator ${msg.status || "sent"}`} title={msg.status || "sent"}>
                          {msg.status === "sending" && <Clock size={12} />}
                          {(msg.status === "sent" || !msg.status) && <Check size={12} />}
                          {msg.status === "delivered" && <CheckCheck size={12} />}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </div>

              <form onSubmit={handleSend} className="input-area">
                <input
                  type="file"
                  ref={fileInputRef}
                  style={{ display: "none" }}
                  onChange={handleFileChange}
                  accept=".pdf,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.txt,.csv,.zip,image/*"
                  title="Attach document or image files"
                />
                <button
                  type="button"
                  className="icon-btn attachment-btn"
                  onClick={() => fileInputRef.current?.click()}
                  title="Attach file"
                >
                  <Paperclip size={20} />
                </button>
                <textarea
                  placeholder={`Message in ${activeRoomId}...`}
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  rows={1}
                />
                <button
                  type="submit"
                  className="icon-btn"
                  disabled={!newMessage.trim()}
                >
                  <SendHorizontal size={20} />
                </button>
              </form>
            </>
          )}
        </div>
      </div>

      {/* QR Code Overlay */}
      {showQRCode && (
        <div className="qr-code-overlay">
          <div className="qr-code-modal">
            <div className="qr-code-header">
              <button
                onClick={() => setShowQRCode(false)}
                className="close-btn"
                title="Close"
              >
                <X size={20} />
              </button>
            </div>
            <div className="qr-code-content">
              <QRCode
                value={activeRoomId}
                size={200}
                style={{ height: "auto", maxWidth: "100%", width: "50%" }}
                viewBox={`0 0 256 256`}
              />
              <p className="qr-code-text">Scan to join session</p>
              <div
                className="copyable-field"
                onClick={() => copyToClipboard(activeRoomId)}
              >
                <span>{activeRoomId}</span>
                {isCopied ? (
                  <CheckCheck size={16}/>
                ) : (
                  <Copy size={16} />
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
