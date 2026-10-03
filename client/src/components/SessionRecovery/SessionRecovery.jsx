import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Lock, KeyRound } from "lucide-react";
import "./SessionRecovery.css";

export default function SessionRecovery({ roomId, onRecoveryComplete }) {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleRecovery = async (e) => {
    e.preventDefault();
    setError("");

    if (!password.trim()) {
      setError("Password is required.");
      return;
    }

    setIsLoading(true);
    try {
      await onRecoveryComplete(roomId, password);
      navigate("/chat");
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error("Recovery failed:", err);
      }
      setError("Failed to recover session. Please check your password and try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    localStorage.removeItem("room_id");
    sessionStorage.removeItem("chat_key");
    sessionStorage.removeItem("qkchat_room_keys");
    navigate("/");
  };

  return (
    <div className="recovery-container glass-panel">
      <div className="panel-header">
        <KeyRound size={32} className="text-primary" />
        <h2>Recover Your Session</h2>
      </div>

      <div className="recovery-content">
        <p className="recovery-message">
          We found your previous chat session. Enter your password to continue where you left off.
        </p>

        <div className="room-info">
          <label>Chat Room ID</label>
          <div className="room-id-display">{roomId}</div>
        </div>

        <form onSubmit={handleRecovery} className="recovery-form">
          <div className="form-group">
            <label htmlFor="recoveryPassword">Decryption Key (Password)</label>
            <div className="input-wrapper">
              <Lock size={18} className="input-icon" />
              <input
                id="recoveryPassword"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
                autoFocus
              />
            </div>
          </div>

          {error && <div className="error-msg">{error}</div>}

          <div className="recovery-buttons">
            <button
              type="submit"
              className="btn-primary"
              disabled={isLoading}
            >
              {isLoading ? "Recovering..." : "Recover Session"}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={handleClear}
              disabled={isLoading}
            >
              Start Fresh
            </button>
          </div>
        </form>

        <p className="recovery-hint">
          Your chat session is stored securely in your browser. No login required.
        </p>
      </div>
    </div>
  );
}
