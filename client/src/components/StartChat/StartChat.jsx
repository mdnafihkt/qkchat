import { useState, useEffect } from "react";
import { Shield, Lock, Copy, Info, Check } from "lucide-react";
import { useNavigate } from "react-router-dom";
import QRCode from "react-qr-code";
import "./StartChat.css";

export default function StartChat({ onJoin }) {
  const navigate = useNavigate();
  const [newChatDetails, setNewChatDetails] = useState({
    id: "",
    password: "",
  });
  const [isCopied, setIsCopied] = useState(false);
  const [isJoining, setIsJoining] = useState(false);

  useEffect(() => {
    // Generate relatively strong ID on mount
    const generateSegment = () => Math.random().toString(36).substring(2, 10);
    const randomId = generateSegment() + "-" + generateSegment();
    setNewChatDetails({ id: randomId, password: "" });
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
        await onJoin(newChatDetails.id, newChatDetails.password);
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
        <img src="/qkchat.png" className="text-primary start-chat-logo" />        
        <h2>Your Secure Room</h2>
      </div>

      <div className="start-chat-content">
        <div className="qr-container">
          <div
            className="qr-box"
            style={{
              background: "white",
              padding: "16px",
              borderRadius: "12px",
            }}
          >
            {qrPayload ? (
              <QRCode
                className="qr-code"
                value={qrPayload}
                bgColor="#ffffff"
                fgColor="#000000"
                level="Q"
              />
            ) : (
              <div style={{ width: 180, height: 180 }} />
            )}
          </div>
          <p className="qr-hint">Have your peer scan this to get the Chat ID</p>
        </div>

        <div className="room-details-container">
          <div className="credentials-box">
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
            <div className="credential-row">
              <label>Set your Password</label>
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
          </div>
          <div className="info-box">
            <Info size={16} />
            <span>
              Keep this window open. The session begins when your peer joins
              with the same Password.
            </span>
          </div>

          <button
            className="btn-primary"
            disabled={!newChatDetails.password.trim() || isJoining}
            onClick={handleStart}
            style={{
              marginTop: "1.5rem",
              width: "100%",
              opacity: newChatDetails.password.trim() && !isJoining ? 1 : 0.5,
            }}
          >
            {isJoining ? "Entering info..." : "Enter Room"}
          </button>
        </div>
      </div>
    </div>
  );
}
