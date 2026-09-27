import React from "react";
import { ShieldAlert } from "lucide-react";

export default function RoomRestrictedView({
  activeRoomId = "",
  onLeaveRoom,
  onNavigateHome,
}) {
  return (
    <div className="locked-room-container">
      <div className="locked-card glass-panel">
        <ShieldAlert
          size={48}
          className="text-primary locked-icon"
          style={{ color: "var(--accent-danger, #ef4444)" }}
        />
        <h3>Room Access Restricted</h3>
        <p className="locked-desc">
          Unable to join room <strong>{activeRoomId}</strong>. You may have
          entered an incorrect Room ID or the room has reached its 2-peer limit.
        </p>

        <div
          style={{
            textAlign: "left",
            fontSize: "0.85rem",
            color: "var(--text-muted)",
            margin: "1rem 0",
            lineHeight: "1.5",
          }}
        >
          <p style={{ marginBottom: "0.4rem" }}>
            <strong>Troubleshooting steps:</strong>
          </p>
          <ul style={{ paddingLeft: "1.2rem", margin: 0 }}>
            <li>
              If you previously joined from another device or browser tab, leave
              the room on that device first to free up your slot.
            </li>
            <li>Double-check the Room ID for typos.</li>
            <li>
              If the issue persists, remove this room and start a new chat with
              your peer.
            </li>
          </ul>
        </div>

        <div className="unlock-actions" style={{ marginTop: "1.25rem" }}>
          <button
            type="button"
            className="btn-primary"
            onClick={onNavigateHome}
          >
            Return Home
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => onLeaveRoom(activeRoomId)}
          >
            Remove Room
          </button>
        </div>
      </div>
    </div>
  );
}
