import React, { useState } from "react";
import { Lock } from "lucide-react";

export default function LockedRoomView({
  activeRoomId = "",
  onUnlockRoom,
  onLeaveRoom,
}) {
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);

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
    } catch {
      setUnlockError("Failed to unlock room. Check your password.");
    } finally {
      setIsUnlocking(false);
    }
  };

  return (
    <div className="locked-room-container">
      <div className="locked-card glass-panel">
        <Lock size={48} className="text-primary locked-icon" />
        <h3>Room Locked</h3>
        <p className="locked-desc">
          Decryption key missing for room <strong>{activeRoomId}</strong>. Enter
          the password to unlock this room.
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
  );
}
