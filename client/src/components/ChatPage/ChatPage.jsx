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
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { encryptMessage } from "../../utils/crypto";
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

    try {
      // Create JSON payload indicating text type
      const payload = JSON.stringify({ type: "text", text: newMessage });
      const encryptedPayload = await encryptMessage(cryptoKey, payload);

      // Send the encrypted blob to the relay server
      socket.emit("send_message", {
        roomId,
        message: encryptedPayload,
      });

      // Add to local state as our own message
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
          type: "text",
          text: newMessage,
          isOwn: true,
          time: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            hour12: true,
          }),
        },
      ]);
      setNewMessage("");
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

    const reader = new FileReader();
    reader.onload = async (event) => {
      const base64Data = event.target.result;

      try {
        const payload = JSON.stringify({
          type: "file",
          fileName: file.name,
          fileType: file.type,
          fileData: base64Data,
          fileIcon: getFileIcon(file.type),
        });
        const encryptedPayload = await encryptMessage(cryptoKey, payload);

        socket.emit("send_message", { roomId, message: encryptedPayload });

        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            type: "file",
            fileName: file.name,
            fileType: file.type,
            fileData: base64Data,
            fileIcon: getFileIcon(file.type),
            isOwn: true,
            time: new Date().toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              hour12: true,
            }),
          },
        ]);
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
                  <img
                    src={msg.fileData}
                    alt={msg.fileName}
                    className="attached-image"
                  />
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
                    <a
                      href={msg.fileData}
                      download={msg.fileName}
                      className="download-btn"
                      title="Download"
                    >
                      <Download size={18} />
                    </a>
                  </div>
                )}
              </div>
            ) : (
              <div className="text">{msg.text}</div>
            )}
            <div className="time">{msg.time}</div>
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
