import React from "react";
import { Menu, QrCode, Home, LogOut } from "lucide-react";

export default function ChatHeader({
  currentRoom,
  activeRoomId = "",
  isConnected = false,
  onToggleSidebar,
  onShowQRCode,
  onNavigateHome,
  onLeaveRoom,
}) {
  const displayName =
    currentRoom?.roomName ||
    (activeRoomId.length > 16
      ? activeRoomId.substring(0, 14) + "..."
      : activeRoomId);

  return (
    <div className="chat-header">
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
        <button
          onClick={onToggleSidebar}
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
            style={{
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
            }}
            onClick={onShowQRCode}
            title="Click to show QR code"
          >
            {displayName}
            <QrCode size={16} />
          </h2>
          <div className="connection-status">
            {isConnected ? "Connected" : "Reconnecting..."}
            <span
              className={`connection-status-dot ${
                !isConnected ? "offline" : "online"
              }`}
            ></span>
          </div>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
        {currentRoom && (
          <>
            <button
              onClick={onNavigateHome}
              className="btn-header-home"
              title="Back to Home Hub"
            >
              <Home size={20} />
              <span className="text">Home</span>
            </button>
            <button
              onClick={() => onLeaveRoom(activeRoomId)}
              className="btn-header-home"
              title="Leave Current Room"
            >
              <LogOut size={20} />
              <span className="text">Leave Room</span>
            </button>
          </>
        )}
      </div>
    </div>
  );
}
