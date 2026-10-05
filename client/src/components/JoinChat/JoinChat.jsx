import { useState } from "react";
import { LogIn, Camera, User, Lock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import QRScanner from "../QRScanner";
import "./JoinChat.css";

export default function JoinChat({ onJoin }) {
  const navigate = useNavigate();
  const [joinId, setJoinId] = useState("");
  const [joinSalt, setJoinSalt] = useState("");
  const [joinPassword, setJoinPassword] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState("");
  const [isJoining, setIsJoining] = useState(false);

  const handleManualJoin = async (e) => {
    e.preventDefault();
    setError("");
    if (!joinId.trim() || !joinPassword.trim()) {
      setError("Chat ID and Password are required.");
      return;
    }
    setIsJoining(true);
    try {
      await onJoin(joinId.trim(), joinPassword.trim(), "", null, joinSalt || null);
      // Clear temporary share/QR payloads and input values after successful use (C-02)
      setJoinId("");
      setJoinSalt("");
      setJoinPassword("");
      navigate("/chat");
    } catch (err) {
      setError(err.message || "Failed to connect to chat room");
      setIsJoining(false);
    }
  };

  const handleQRScanSuccess = async (decodedText) => {
    setIsScanning(false);
    setError("");
    try {
      const parsed = JSON.parse(decodedText);
      if (parsed && parsed.id) {
        setJoinId(parsed.id);
        if (parsed.salt) {
          setJoinSalt(parsed.salt);
        }
        return;
      }
    } catch (e) {}

    if (decodedText.includes(":")) {
      const parts = decodedText.split(":");
      setJoinId(parts[0]);
      setJoinSalt(parts[1]);
    } else {
      setJoinId(decodedText);
    }
  };

  return (
    <div className="join-chat-container glass-panel">
      <button
        className="back-btn"
        onClick={() => {
          setIsScanning(false);
          setError("");
          navigate("/");
        }}
      >
        &larr; Back
      </button>
      <div className="panel-header">
        <LogIn size={32} className="text-primary" />
        <h2>Join Room</h2>
      </div>

      {!isScanning ? (
        <>
          <button
            className="btn-secondary scan-btn"
            onClick={() => setIsScanning(true)}
          >
            <Camera size={20} />
            Scan QR Code
          </button>

          <div className="divider">
            <span>OR ENTER MANUALLY</span>
          </div>

          <form onSubmit={handleManualJoin} className="join-form">
            <div className="form-group">
              <label htmlFor="joinId">Chat ID</label>
              <div className="input-wrapper">
                <User size={18} className="input-icon" />
                <input
                  id="joinId"
                  type="text"
                  placeholder="Enter Session ID"
                  value={joinId}
                  onChange={(e) => setJoinId(e.target.value)}
                  autoComplete="off"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="joinPassword">Decryption Key (Password)</label>
              <div className="input-wrapper">
                <Lock size={18} className="input-icon" />
                <input
                  id="joinPassword"
                  type="password"
                  placeholder="Enter Password"
                  value={joinPassword}
                  onChange={(e) => setJoinPassword(e.target.value)}
                />
              </div>
            </div>

            {error && <div className="error-msg">{error}</div>}

            <button
              type="submit"
              className="btn-primary"
              disabled={isJoining}
              style={{
                marginTop: "1rem",
                width: "100%",
                opacity: isJoining ? 0.5 : 1,
              }}
            >
              {isJoining ? "Please wait..." : "Join Secure Session"}
            </button>
          </form>
        </>
      ) : (
        <div className="scanner-section">
          <QRScanner
            onScanSuccess={handleQRScanSuccess}
            onScanFailure={(err) => {
              /* optionally handle errors softly */
            }}
          />
          {error && (
            <div className="error-msg" style={{ marginBottom: "1rem" }}>
              {error}
            </div>
          )}
          <button className="btn-text" onClick={() => setIsScanning(false)}>
            Cancel Scanning
          </button>
        </div>
      )}
    </div>
  );
}
