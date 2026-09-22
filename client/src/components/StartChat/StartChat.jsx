import { useState, useEffect } from "react";
import { Shield, Lock, Copy, Info, Check, Clock, Tag } from "lucide-react";
import { useNavigate } from "react-router-dom";
import QRCode from "react-qr-code";
import "./StartChat.css";

export default function StartChat({ onJoin }) {
  const navigate = useNavigate();
  const [newChatDetails, setNewChatDetails] = useState({
    id: "",
    name: "",
    password: "",
    retentionPeriod: 86400000, // 24 Hours default
  });
  const [isCopied, setIsCopied] = useState(false);
  const [isJoining, setIsJoining] = useState(false);

  useEffect(() => {
    const generateSegment = () => Math.random().toString(36).substring(2, 10);
    const randomId = generateSegment() + "-" + generateSegment();
    setNewChatDetails((prev) => ({ ...prev, id: randomId }));
  }, []);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const handleStart = async () => {
    if (newChatDetails.password.trim()) {
      setIsJoining(true);
      try {
        await onJoin(
          newChatDetails.id,
          newChatDetails.password,
          newChatDetails.name,
          newChatDetails.retentionPeriod
        );
        navigate("/chat");
      } catch (err) {
        console.error("Failed to connect", err);
        setIsJoining(false);
      }
    }
  };

  const qrPayload = newChatDetails.id;

  return (
    <div className="glass-panel start-chat-container">
      <button className="back-btn" onClick={() => navigate("/")}>
        &larr; Back
      </button>
      <div className="panel-header">
        <img src="/qkchat.png" className="text-primary start-chat-logo" alt="Logo" />        
        <h2>Configure Secure Room</h2>
      </div>

      <div className="start-chat-content">
        <div className="qr-container">
          <div className="qr-box">
            {qrPayload ? (
              <QRCode
                className="qr-code"
                value={qrPayload}
                bgColor="#ffffff"
                fgColor="#000000"
                level="Q"
              />
            ) : (
              <div style={{ width: 160, height: 160 }} />
            )}
          </div>
          <p className="qr-hint">Have peer scan to join</p>
        </div>

        <div className="room-details-container">
          <div className="credentials-box">
            {/* Chat ID */}
            <div className="credential-row">
              <label>Chat ID</label>
              <div
                className="copyable-field"
                onClick={() => copyToClipboard(newChatDetails.id)}
              >
                <span>{newChatDetails.id}</span>
                {isCopied ? (
                  <Check size={16} className="text-primary" />
                ) : (
                  <Copy size={16} />
                )}
              </div>
            </div>

            {/* Room Name / Alias */}
            <div className="credential-row">
              <label htmlFor="startRoomName">Room Name / Alias (Optional)</label>
              <div className="input-wrapper" style={{ marginTop: "0.25rem" }}>
                <Tag size={18} className="input-icon" />
                <input
                  id="startRoomName"
                  type="text"
                  placeholder="e.g. Project Sync, Alice & Bob"
                  value={newChatDetails.name}
                  onChange={(e) =>
                    setNewChatDetails({
                      ...newChatDetails,
                      name: e.target.value,
                    })
                  }
                />
              </div>
            </div>

            {/* Password */}
            <div className="credential-row">
              <label htmlFor="startPassword">Set Room Password (Required)</label>
              <div className="input-wrapper" style={{ marginTop: "0.25rem" }}>
                <Lock size={18} className="input-icon" />
                <input
                  id="startPassword"
                  type="password"
                  placeholder="Choose a strong password"
                  value={newChatDetails.password}
                  onChange={(e) =>
                    setNewChatDetails({
                      ...newChatDetails,
                      password: e.target.value,
                    })
                  }
                />
              </div>
            </div>

            {/* Message Retention Configuration */}
            <div className="credential-row">
              <label>Initial Message Retention</label>
              <div className="retention-options-grid">
                {[
                  { value: 3600000, label: "1 Hour" },
                  { value: 43200000, label: "12 Hours" },
                  { value: 86400000, label: "24 Hours" },
                  { value: 604800000, label: "7 Days" },
                ].map((opt) => (
                  <button
                    type="button"
                    key={opt.value}
                    className={`retention-chip ${
                      newChatDetails.retentionPeriod === opt.value ? "active" : ""
                    }`}
                    onClick={() =>
                      setNewChatDetails({
                        ...newChatDetails,
                        retentionPeriod: opt.value,
                      })
                    }
                  >
                    <Clock size={14} />
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="info-box">
            <Info size={16} />
            <span>
              All configuration data (room name, keys, messages) remains strictly zero-knowledge on your device.
            </span>
          </div>

          <button
            className="btn-primary"
            disabled={!newChatDetails.password.trim() || isJoining}
            onClick={handleStart}
            style={{
              marginTop: "1rem",
              width: "100%",
              opacity: newChatDetails.password.trim() && !isJoining ? 1 : 0.5,
            }}
          >
            {isJoining ? "Creating Room..." : "Create & Enter Room"}
          </button>
        </div>
      </div>
    </div>
  );
}
