import React, { useRef } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import { PlusCircle, LogIn, Lock, ChevronRight, LogOut, MessageSquare } from "lucide-react";
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
  const containerRef = useRef(null);

  // Scroll Progress (0 to 1 over first ~160px scroll distance)
  const { scrollYProgress } = useScroll({
    container: containerRef,
    offset: ["start start", "160px start"],
  });

  // Hero Logo & Title transforms (Large Hero state -> Compact Header state)
  const logoScale = useTransform(scrollYProgress, [0, 1], [1, 0.45]);
  const logoY = useTransform(scrollYProgress, [0, 1], [0, -4]);
  
  // Tagline transforms (Fade out with slight upward shift & blur)
  const taglineOpacity = useTransform(scrollYProgress, [0, 0.65], [1, 0]);
  const taglineY = useTransform(scrollYProgress, [0, 0.65], [0, -18]);
  const taglineFilter = useTransform(scrollYProgress, [0, 0.65], ["blur(0px)", "blur(6px)"]);

  // Action Cards transforms (Full cards in Hero -> Compact Pills in Sticky Header)
  const cardScale = useTransform(scrollYProgress, [0, 1], [1, 0.92]);
  const cardPillOpacity = useTransform(scrollYProgress, [0.3, 1], [0, 1]);
  const fullCardContentOpacity = useTransform(scrollYProgress, [0, 0.45], [1, 0]);
  
  // Sticky Compact Header background backdrop & shadow opacity
  const headerBgOpacity = useTransform(scrollYProgress, [0.4, 1], [0, 0.85]);
  const headerBorderOpacity = useTransform(scrollYProgress, [0.4, 1], [0, 1]);
  const headerShadowOpacity = useTransform(scrollYProgress, [0.4, 1], [0, 0.5]);

  return (
    <div className="home-scroll-viewport" ref={containerRef}>
      {/* Sticky Collapsing Dynamic Header Bar */}
      <motion.div
        className="sticky-header-bar"
        style={{
          backgroundColor: useTransform(headerBgOpacity, (v) => `rgba(10, 10, 15, ${v})`),
          borderColor: useTransform(headerBorderOpacity, (v) => `rgba(255, 255, 255, ${v * 0.1})`),
          boxShadow: useTransform(headerShadowOpacity, (v) => `0 10px 30px -10px rgba(0, 0, 0, ${v})`),
        }}
      >
        <div className="sticky-header-content">
          <motion.div
            className="brand-logo-group"
            onClick={() => containerRef.current?.scrollTo({ top: 0, behavior: "smooth" })}
          >
            <motion.img
              src="/qkchat.png"
              className="logo-img"
              alt="QkChat Logo"
              style={{ scale: logoScale, y: logoY }}
            />
            <motion.h1
              className="brand-title"
              style={{ scale: logoScale, transformOrigin: "left center" }}
            >
              Qk<span>Chat</span>
            </motion.h1>
          </motion.div>

          {/* Compact Header Quick Action Buttons (Fade in when scrolled) */}
          <motion.div
            className="header-pill-actions"
            style={{ opacity: cardPillOpacity }}
          >
            <motion.button
              type="button"
              className="pill-btn primary-pill"
              onClick={() => navigate("/start")}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
            >
              <PlusCircle size={16} />
              <span>Start Chat</span>
            </motion.button>
            <motion.button
              type="button"
              className="pill-btn secondary-pill"
              onClick={() => navigate("/join")}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
            >
              <LogIn size={16} />
              <span>Join Chat</span>
            </motion.button>
          </motion.div>
        </div>
      </motion.div>

      {/* Hero Section Container */}
      <div className="home-hero-container">
        {/* Animated Tagline */}
        <motion.p
          className="hero-tagline"
          style={{
            opacity: taglineOpacity,
            y: taglineY,
            filter: taglineFilter,
          }}
        >
          End-to-end encrypted, zero-knowledge ephemeral messaging.
        </motion.p>

        {/* Primary Action Cards (Full Grid view in spacious layout) */}
        <motion.div
          className="cards-grid"
          style={{ scale: cardScale }}
        >
          <motion.div
            className="action-card primary-card"
            onClick={() => navigate("/start")}
            whileHover={{ y: -6, scale: 1.01 }}
            whileTap={{ scale: 0.98 }}
            transition={{ type: "spring", stiffness: 400, damping: 25 }}
          >
            <div className="card-icon-wrapper">
              <PlusCircle className="responsive-icon" />
            </div>
            <h2>Start New Chat</h2>
            <motion.p style={{ opacity: fullCardContentOpacity }}>
              Generate a secure room and get a QR code to invite your peer.
            </motion.p>
          </motion.div>

          <motion.div
            className="action-card secondary-card"
            onClick={() => navigate("/join")}
            whileHover={{ y: -6, scale: 1.01 }}
            whileTap={{ scale: 0.98 }}
            transition={{ type: "spring", stiffness: 400, damping: 25 }}
          >
            <div className="card-icon-wrapper">
              <LogIn className="responsive-icon" />
            </div>
            <h2>Join a Chat</h2>
            <motion.p style={{ opacity: fullCardContentOpacity }}>
              Enter an existing Chat ID or scan a QR code from your peer.
            </motion.p>
          </motion.div>
        </motion.div>
      </div>

      {/* Active Rooms UX (Smooth Motion Cards List) */}
      <div className="joined-rooms-section">
        <div className="section-header">
          <h3>
            Active Rooms {roomList.length > 0 && <span className="rooms-count-pill">{roomList.length}</span>}
          </h3>
        </div>

        {roomList.length === 0 ? (
          <motion.div
            className="empty-rooms-state"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <MessageSquare size={36} className="empty-icon" />
            <p className="empty-title">No Active Chat Rooms</p>
            <p className="empty-subtitle">Start a new room or join an existing session to begin chatting securely.</p>
          </motion.div>
        ) : (
          <div className="joined-rooms-grid">
            {roomList.map((room, index) => (
              <motion.div
                key={room.roomId}
                className={`room-card ${room.isLocked ? "locked" : ""}`}
                onClick={() => onSelectRoom(room.roomId)}
                initial={{ opacity: 0, y: 20, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.94 }}
                transition={{
                  duration: 0.35,
                  delay: Math.min(index * 0.06, 0.3),
                  ease: [0.25, 0.8, 0.25, 1],
                }}
                whileHover={{ y: -4, borderColor: "rgba(99, 102, 241, 0.4)" }}
                whileTap={{ scale: 0.98 }}
              >
                <div className="room-card-header">
                  <div className="room-title-area">
                    <span className={`status-dot ${room.isConnected ? "online" : "offline"}`} />
                    <div className="title-text-stack">
                      <span className="room-card-title">{room.roomName || room.roomId}</span>
                      {room.roomName && <span className="room-card-id-sub">{room.roomId}</span>}
                    </div>
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
                    <LogOut size={18} />
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
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
