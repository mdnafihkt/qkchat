import { useState } from "react";
import { PlusCircle, LogIn, MessageSquare, Lock, X, ChevronRight } from "lucide-react";
import { useNavigate } from "react-router-dom";
import "./HomeSelection.css";

export default function HomeSelection({
  rooms = {},
  onSelectRoom,
  onLeaveRoom,
  onUnlockRoom,
}) {
  const navigate = useNavigate();
  const roomList = Object.values(rooms);

  return (
    <div className="home-container">
      <div className="home-header">
        <div className="logo-container">
          <img src="/qkchat.png" className="text-primary logo" alt="QkChat Logo" />
          <h1>
            Qk<span>Chat</span>
          </h1>
        </div>
        <p>End-to-end encrypted, zero-knowledge ephemeral messaging.</p>
      </div>

      {/* Primary Action Cards (Top Section) */}
      <div className="cards-grid">
        <div
          className="action-card primary-card"
          onClick={() => navigate("/start")}
        >
          <div className="card-icon-wrapper">
            <PlusCircle className="responsive-icon" />
          </div>
          <h2>Start New Chat</h2>
          <p>Generate a secure room and get a QR code to invite your peer.</p>
        </div>

        <div
          className="action-card secondary-card"
          onClick={() => navigate("/join")}
        >
          <div className="card-icon-wrapper">
            <LogIn className="responsive-icon" />
          </div>
          <h2>Join a Chat</h2>
          <p>Enter an existing Chat ID or scan a QR code from your peer.</p>
        </div>
      </div>

      {/* Joined Rooms Section (Room Hub) */}
      {roomList.length > 0 && (
        <div className="joined-rooms-section">
          <div className="section-header">
            <h3>Your Active Rooms ({roomList.length})</h3>
          </div>

          <div className="joined-rooms-grid">
            {roomList.map((room) => (
              <div
                key={room.roomId}
                className={`room-card ${room.isLocked ? "locked" : ""}`}
                onClick={() => onSelectRoom(room.roomId)}
              >
                <div className="room-card-header">
                  <div className="room-title-area">
                    <span className={`status-dot ${room.isConnected ? "online" : "offline"}`} />
                    <span className="room-card-title">{room.roomId}</span>
                    {room.isLocked && <Lock size={14} className="lock-icon" />}
                  </div>

                  <button
                    className="btn-room-remove"
                    onClick={(e) => {
                      e.stopPropagation();
                      onLeaveRoom(room.roomId);
                    }}
                    title="Leave & remove room"
                  >
                    <X size={16} />
                  </button>
                </div>

                <div className="room-card-body">
                  <span className="room-status-text">
                    {room.isLocked
                      ? "Locked • Password required to view messages"
                      : `${room.messages.length} ${room.messages.length === 1 ? "message" : "messages"}`}
                  </span>
                  
                  {room.unreadCount > 0 && (
                    <span className="unread-badge-card">{room.unreadCount} unread</span>
                  )}
                </div>

                <div className="room-card-footer">
                  <span className="enter-room-text">Enter Chat</span>
                  <ChevronRight size={16} className="arrow-icon" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
