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
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { encryptMessage } from "../../utils/crypto";
import { saveMessage, updateMessageStatus } from "../../utils/ledger";
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
  cryptoKey,
  roomId,
  messages,
  setMessages,
  isConnected,
  handleLeave,
  retentionPeriod,
  onUpdateRetentionPeriod,
}) {
  const [newMessage, setNewMessage] = useState("");
  const [showQRCode, setShowQRCode] = useState(false);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
  const [isCopied, setIsCopied] = useState(false);
  const navigate = useNavigate();

  // If a user navigates directly to /chat without a socket connection, boot them back.
  useEffect(() => {
    if (!socket || !roomId) {
      navigate("/");
    }
  }, [socket, roomId, navigate]);

  useEffect(() => {
    // Scroll to bottom on new message
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async (e) => {
    e.preventDefault();
    if (!newMessage.trim() || !socket || !cryptoKey) return;

    const messageId = Date.now() + "-" + Math.random().toString(36).substring(2, 9);
    const timestamp = Date.now();

    // Add to local state immediately as 'sending'
    setMessages((prev) => [
      ...prev,
      {
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
      },
    ]);
    
    const textToSend = newMessage;
    setNewMessage("");

    try {
      // Create JSON payload indicating text type and containing the message ID
      const payload = JSON.stringify({ id: messageId, type: "text", text: textToSend });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      // Save to local ledger
      await saveMessage(roomId, {
        messageId,
        timestamp,
        isOwn: true,
        status: "sending",
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv
      });

      // Send the encrypted blob to the relay server with server acknowledgment callback
      socket.emit("send_message", {
        roomId,
        message: encryptedPayload,
      }, async () => {
        // Server acknowledged -> update local status to 'sent'
        setMessages((prev) =>
          prev.map((msg) =>
            msg.id === messageId ? { ...msg, status: "sent" } : msg
          )
        );
        // Also update in ledger
        await updateMessageStatus(messageId, "sent");
      });
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

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file || !socket || !cryptoKey) return;

    // Check file size (50MB limit for documents)
    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
      alert(
        `File size must be less than ${maxSize / (1024 * 1024)}MB. Your file is ${(file.size / (1024 * 1024)).toFixed(2)}MB.`
      );
      return;
    }

    // Optional: Check if file type is supported (allows all files but alerts user)
    const isSupported = Object.keys(SUPPORTED_DOCUMENT_TYPES).includes(
      file.type
    );
    if (!isSupported) {
      console.warn(
        `File type "${file.type}" not in primary supported list, but sending anyway.`
      );
    }

    const messageId = Date.now() + "-" + Math.random().toString(36).substring(2, 9);
    const timestamp = Date.now();

    // Immediately add to messages list as 'sending' with empty/loading data
    setMessages((prev) => [
      ...prev,
      {
        id: messageId,
        type: "file",
        fileName: file.name,
        fileType: file.type,
        fileData: "",
        fileIcon: getFileIcon(file.type),
        isOwn: true,
        status: "sending",
        time: new Date(timestamp).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: true,
        }),
        timestamp
      },
    ]);

    const reader = new FileReader();
    reader.onload = async (event) => {
      const base64Data = event.target.result;

      // Update local state with loaded fileData
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === messageId ? { ...msg, fileData: base64Data } : msg
        )
      );

      try {
        const payload = JSON.stringify({
          id: messageId,
          type: "file",
          fileName: file.name,
          fileType: file.type,
          fileData: base64Data,
          fileIcon: getFileIcon(file.type),
        });
        const encryptedPayload = await encryptMessage(cryptoKey, payload);

        // Save to local ledger
        await saveMessage(roomId, {
          messageId,
          timestamp,
          isOwn: true,
          status: "sending",
          ciphertext: encryptedPayload.ciphertext,
          iv: encryptedPayload.iv
        });

        socket.emit("send_message", { roomId, message: encryptedPayload }, async () => {
          // Server acknowledged -> update local status to 'sent'
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === messageId ? { ...msg, status: "sent" } : msg
            )
          );
          // Also update in ledger
          await updateMessageStatus(messageId, "sent");
        });
      } catch (err) {
        console.error("Failed to send file", err);
      }
    };
    reader.readAsDataURL(file);
    e.target.value = null;
  };

  const onLeaveClick = () => {
    handleLeave();
    navigate("/");
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  if (!socket || !roomId) return null;

  return (
    <div className="glass-panel chat-container">
      <div className="chat-header">
        <div>
          <h2
            style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: "0.5rem" }}
            onClick={() => setShowQRCode(!showQRCode)}
            title="Click to show QR code"
          >
            Session: {roomId}
            <QrCode size={16} />
          </h2>
          <p>E2E Encrypted</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <div className="retention-selector-wrapper" title="Message Retention Period">
            <Clock size={14} className="retention-icon" />
            <select
              value={retentionPeriod}
              onChange={(e) => onUpdateRetentionPeriod(parseInt(e.target.value))}
              className="retention-select"
            >
              <option value={3600000}>1 Hour</option>
              <option value={43200000}>12 Hours</option>
              <option value={86400000}>24 Hours</option>
              <option value={604800000}>7 Days</option>
            </select>
          </div>
          <span
            className={`status-badge ${!isConnected ? "disconnected" : ""}`}
          >
            {isConnected ? "Connected" : "Reconnecting..."}
          </span>
          <button
            onClick={handleLeave}
            className="icon-btn"
            style={{
              background: "transparent",
              color: "var(--text-muted)",
              padding: "0.25rem",
            }}
            title="Leave Room"
          >
            <LogOut size={20} />
          </button>
        </div>
      </div>

      {showQRCode && (
        <div className="qr-code-overlay">
          <div className="qr-code-modal">
            <div className="qr-code-header">
              <h3>Share Session</h3>
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
                value={roomId}
                size={200}
                style={{ height: "auto", maxWidth: "100%", width: "100%" }}
                viewBox={`0 0 256 256`}
              />
              <p className="qr-code-text">Scan to join session</p>
              <div
                className="copyable-field"
                onClick={() => copyToClipboard(roomId)}
              >
                <span>{roomId}</span>
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
            <p>Session initialized.</p>
            <p style={{ fontSize: "0.8rem", marginTop: "0.25rem" }}>
              Messages are not stored and will be permanently lost when you
              leave.
            </p>
          </div>
        )}

        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`message-bubble ${msg.isOwn ? "own" : "peer"}`}
          >
            {msg.type === "file" ? (
              <div className="file-attachment">
                {msg.fileType && msg.fileType.startsWith("image/") ? (
                  <div className="image-container">
                    {msg.fileData ? (
                      <>
                        <img
                          src={msg.fileData}
                          alt={msg.fileName}
                          className="attached-image"
                        />
                        <a
                          href={msg.fileData}
                          download={msg.fileName}
                          className="image-download-btn"
                          title="Download Image"
                        >
                          <Download size={18} />
                        </a>
                      </>
                    ) : (
                      <div className="image-loading-placeholder">
                        <Clock size={20} className="spinner-icon" />
                        <span>Encrypting {msg.fileName}...</span>
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
                      {msg.fileType && (
                        <span className="file-type">{msg.fileType}</span>
                      )}
                    </div>
                    {msg.fileData ? (
                      <a
                        href={msg.fileData}
                        download={msg.fileName}
                        className="download-btn"
                        title="Download"
                      >
                        <Download size={18} />
                      </a>
                    ) : (
                      <div className="file-loading-placeholder">
                        <Clock size={16} className="spinner-icon" />
                      </div>
                    )}
                  </div>
                )}
              </div>
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
          title="Attach document or image files (PDF, Word, PowerPoint, Excel, etc.)"
        />
        <button
          type="button"
          className="icon-btn attachment-btn"
          onClick={() => fileInputRef.current?.click()}
          title="Attach file: PDF, Word, PowerPoint, Excel, Images, etc."
        >
          <Paperclip size={20} />
        </button>
        <input
          type="text"
          placeholder="Type an encrypted message..."
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
          autoComplete="off"
        />
        <button
          type="submit"
          className="icon-btn"
          disabled={!newMessage.trim()}
        >
          <SendHorizontal size={20} />
        </button>
      </form>
    </div>
  );
}
