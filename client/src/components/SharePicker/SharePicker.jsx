import { useState, useEffect } from "react";
import { Share2, File, FileText, Lock, ChevronRight, AlertCircle, ArrowLeft, Send } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getSharedPayload, clearSharedPayload } from "../../utils/ledger";
import "./SharePicker.css";

export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export default function SharePicker({ rooms = {}, onSelectRoomForShare }) {
  const navigate = useNavigate();
  const [sharedPayload, setSharedPayload] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const roomList = Object.values(rooms);

  useEffect(() => {
    async function loadPayload() {
      try {
        console.log("[SharePicker] Loading shared payload from IndexedDB...");
        const payload = await getSharedPayload();
        console.log("[SharePicker] Retreived payload from IndexedDB:", payload);
        setSharedPayload(payload);
      } catch (err) {
        console.error("[SharePicker] Failed to load shared payload:", err);
      } finally {
        setIsLoading(false);
      }
    }
    loadPayload();
  }, []);

  const handleShareToRoom = async (roomId) => {
    if (!sharedPayload) return;
    await onSelectRoomForShare(roomId, sharedPayload);
    await clearSharedPayload();
    navigate("/chat");
  };

  const handleDiscard = async () => {
    await clearSharedPayload();
    navigate("/");
  };

  if (isLoading) {
    return (
      <div className="share-picker-container glass-panel">
        <p className="loading-text">Loading shared content...</p>
      </div>
    );
  }

  const hasText = sharedPayload?.text || sharedPayload?.url || sharedPayload?.title;
  const hasFile = sharedPayload?.fileBlob;

  return (
    <div className="share-picker-container glass-panel">
      <div className="share-header">
        <button className="back-btn" onClick={() => navigate("/")}>
          <ArrowLeft size={18} />
          <span>Back</span>
        </button>
        <div className="share-title-row">
          <Share2 size={24} className="text-primary" />
          <h2>Share to QkChat</h2>
        </div>
        <p className="share-subtitle">Select an active secure room to share this content to.</p>
      </div>

      {/* Shared Payload Preview Card */}
      {!sharedPayload || (!hasText && !hasFile) ? (
        <div className="empty-share-card">
          <AlertCircle size={32} className="empty-icon" />
          <p>No incoming shared content found.</p>
          <button className="btn-primary" onClick={() => navigate("/")}>
            Go to Home Hub
          </button>
        </div>
      ) : (
        <>
          <div className="shared-content-preview">
            <h4>Shared Content Preview</h4>
            {hasText && (
              <div className="shared-text-box">
                <FileText size={18} className="shared-icon" />
                <div className="shared-text-content">
                  {sharedPayload.title && <strong>{sharedPayload.title}</strong>}
                  <p>{sharedPayload.text || sharedPayload.url}</p>
                </div>
              </div>
            )}

            {hasFile && (
              <div className="shared-file-box">
                <File size={24} className="text-primary" />
                <div className="file-details">
                  <span className="file-name">{sharedPayload.fileName || "Shared File"}</span>
                  <span className="file-size">{formatBytes(sharedPayload.fileBlob?.size || 0)}</span>
                </div>
              </div>
            )}
          </div>

          {/* Target Room Selection List */}
          <div className="room-selection-section">
            <h4>Select Target Room ({roomList.length})</h4>

            {roomList.length === 0 ? (
              <div className="no-rooms-warning">
                <p>No active rooms currently joined on this device.</p>
                <button className="btn-primary" onClick={() => navigate("/start")}>
                  Start New Chat Room
                </button>
              </div>
            ) : (
              <div className="rooms-picker-list">
                {roomList.map((room) => (
                  <div
                    key={room.roomId}
                    className={`room-picker-card ${room.isLocked ? "locked" : ""}`}
                    onClick={() => !room.isLocked && handleShareToRoom(room.roomId)}
                  >
                    <div className="room-info">
                      <span className={`status-dot ${room.isConnected ? "online" : "offline"}`} />
                      <div className="room-title-stack">
                        <span className="room-title">{room.roomName || room.roomId}</span>
                        {room.roomName && <span className="room-id-sub">{room.roomId}</span>}
                      </div>
                      {room.isLocked && <Lock size={14} className="lock-icon" />}
                    </div>

                    <div className="picker-action">
                      {room.isLocked ? (
                        <span className="locked-text">Locked</span>
                      ) : (
                        <button className="btn-share-send">
                          <Send size={16} />
                          <span>Send</span>
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <button className="btn-secondary btn-discard-share" onClick={handleDiscard}>
            Discard Shared Content
          </button>
        </>
      )}
    </div>
  );
}
