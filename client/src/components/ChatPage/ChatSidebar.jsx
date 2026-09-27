import React, { useState } from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import {
  X,
  Tag,
  Clock,
  ChevronDown,
  Check,
  Copy,
  CheckCheck,
  QrCode,
  Trash2,
} from "lucide-react";

const RETENTION_OPTIONS = [
  { value: 3600000, label: "1 Hour", desc: "For temporary discussions" },
  { value: 43200000, label: "12 Hours", desc: "Keep history for half a day" },
  { value: 86400000, label: "24 Hours", desc: "Standard daily rotation" },
  { value: 604800000, label: "7 Days", desc: "Longer term recovery limit" },
];

export default function ChatSidebar({
  isOpen = false,
  onClose,
  currentRoom = null,
  activeRoomId = "",
  isLocked = false,
  roomNameInput = "",
  onRoomNameChange,
  retentionPeriod = 86400000,
  onUpdateRetentionPeriod,
  onShowQRCode,
  onDeleteRoomForAll,
  onLeaveRoom,
}) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [isCopied, setIsCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const selectedOption =
    RETENTION_OPTIONS.find((opt) => opt.value === retentionPeriod)?.label ||
    "Select Period";

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Overlay Backdrop */}
          <Motion.div
            className="sidebar-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
          />

          {/* Sidebar Drawer Panel */}
          <Motion.aside
            className="chat-sidebar"
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{
              type: "tween",
              duration: 0.25,
              ease: [0.25, 1, 0.5, 1],
            }}
          >
            <div className="sidebar-header">
              <h3>Room Settings</h3>
              <button
                className="sidebar-close-btn"
                onClick={onClose}
                title="Close Drawer"
              >
                <X size={20} />
              </button>
            </div>

            <Motion.div
              className="sidebar-body"
              initial="hidden"
              animate="visible"
              variants={{
                hidden: { opacity: 0 },
                visible: {
                  opacity: 1,
                  transition: {
                    staggerChildren: 0.08,
                    delayChildren: 0.1,
                  },
                },
              }}
            >
              {currentRoom && !isLocked && (
                <>
                  {/* Room Display Name */}
                  <Motion.div
                    className="settings-section"
                    variants={{
                      hidden: { opacity: 0, x: -15 },
                      visible: {
                        opacity: 1,
                        x: 0,
                        transition: { duration: 0.2 },
                      },
                    }}
                  >
                    <h4>Room Display Name</h4>
                    <p className="settings-desc">
                      Set a local custom name for this room (stored zero-knowledge
                      on your device).
                    </p>
                    <div className="input-wrapper">
                      <Tag size={16} className="input-icon" />
                      <input
                        type="text"
                        placeholder="e.g. Project Delta"
                        value={roomNameInput}
                        onChange={(e) => onRoomNameChange(e.target.value)}
                      />
                    </div>
                  </Motion.div>

                  {/* Message Retention */}
                  <Motion.div
                    className="settings-section"
                    variants={{
                      hidden: { opacity: 0, x: -15 },
                      visible: {
                        opacity: 1,
                        x: 0,
                        transition: { duration: 0.2 },
                      },
                    }}
                  >
                    <h4>Message Retention</h4>
                    <p className="settings-desc">
                      Choose how long messages remain stored in your local browser
                      before being permanently pruned.
                    </p>

                    <div className="custom-dropdown-container">
                      <button
                        type="button"
                        className="dropdown-trigger"
                        onClick={() => setDropdownOpen(!dropdownOpen)}
                        title="Select Retention Period"
                      >
                        <Clock size={16} className="dropdown-trigger-icon" />
                        <span className="dropdown-selected-label">
                          {selectedOption}
                        </span>
                        <ChevronDown
                          size={16}
                          className={`dropdown-arrow ${
                            dropdownOpen ? "open" : ""
                          }`}
                        />
                      </button>

                      <AnimatePresence>
                        {dropdownOpen && (
                          <Motion.div
                            className="dropdown-menu"
                            initial={{ opacity: 0, y: -8 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -8 }}
                            transition={{ duration: 0.15 }}
                          >
                            {RETENTION_OPTIONS.map((opt) => (
                              <div
                                key={opt.value}
                                className={`dropdown-item ${
                                  retentionPeriod === opt.value ? "active" : ""
                                }`}
                                onClick={() => {
                                  if (onUpdateRetentionPeriod) {
                                    onUpdateRetentionPeriod(
                                      activeRoomId,
                                      opt.value
                                    );
                                  }
                                  setDropdownOpen(false);
                                }}
                              >
                                <div className="dropdown-item-details">
                                  <span className="dropdown-item-title">
                                    {opt.label}
                                  </span>
                                  <span className="dropdown-item-desc">
                                    {opt.desc}
                                  </span>
                                </div>
                                {retentionPeriod === opt.value && (
                                  <Check
                                    size={16}
                                    className="dropdown-item-check"
                                  />
                                )}
                              </div>
                            ))}
                          </Motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </Motion.div>

                  {/* Session Sharing */}
                  <Motion.div
                    className="settings-section"
                    variants={{
                      hidden: { opacity: 0, x: -15 },
                      visible: {
                        opacity: 1,
                        x: 0,
                        transition: { duration: 0.2 },
                      },
                    }}
                  >
                    <h4>Session Sharing</h4>
                    <p className="settings-desc">
                      Invite peers to this secure room using the room ID or a QR
                      code.
                    </p>

                    <div className="session-share-actions">
                      <div
                        className="share-field copyable-field"
                        onClick={() => copyToClipboard(activeRoomId)}
                        title="Click to copy Chat Room ID"
                      >
                        <span className="share-text">{activeRoomId}</span>
                        {isCopied ? (
                          <CheckCheck size={16} className="text-primary" />
                        ) : (
                          <Copy size={16} />
                        )}
                      </div>

                      <button
                        className="btn-sidebar-qr"
                        onClick={onShowQRCode}
                        title="Open QR Code Share Overlay"
                      >
                        <QrCode size={16} />
                        <span>Show QR Code</span>
                      </button>
                    </div>
                  </Motion.div>

                  {/* Danger Zone */}
                  <Motion.div
                    className="settings-section danger-zone-section"
                    variants={{
                      hidden: { opacity: 0, x: -15 },
                      visible: {
                        opacity: 1,
                        x: 0,
                        transition: { duration: 0.2 },
                      },
                    }}
                  >
                    <h4 className="danger-zone-title">Danger Zone</h4>
                    <p className="settings-desc">
                      Destructive actions for this room. Deleting the room destroys
                      local data and terminates the room session for all peers.
                    </p>

                    <button
                      type="button"
                      className="btn-danger-delete"
                      onClick={() => {
                        if (
                          window.confirm(
                            "Are you sure you want to delete this room for all participants? This will immediately clear room data for everyone."
                          )
                        ) {
                          if (onDeleteRoomForAll) {
                            onDeleteRoomForAll(activeRoomId);
                          } else if (onLeaveRoom) {
                            onLeaveRoom(activeRoomId);
                          }
                        }
                      }}
                      title="Delete room for all peers"
                    >
                      <Trash2 size={16} />
                      <span>Delete Room for All</span>
                    </button>
                  </Motion.div>
                </>
              )}
            </Motion.div>
          </Motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
