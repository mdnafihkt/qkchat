import React, { useRef } from "react";
import { motion as Motion, useScroll, useTransform } from "framer-motion";
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

  // Scroll Progress over first ~140px scroll distance
  const { scrollYProgress } = useScroll({
    container: containerRef,
    offset: ["start start", "240px start"],
  });

  // Sticky Compact Header background, border & shadow
  const headerBg = useTransform(
    scrollYProgress,
    [0, 0.8],
    ["rgba(10, 10, 15, 0)", "rgba(10, 10, 15, 0.85)"]
  );
  const headerBorder = useTransform(
    scrollYProgress,
    [0, 0.8],
    ["rgba(255, 255, 255, 0)", "rgba(255, 255, 255, 0.08)"]
  );
  const headerShadow = useTransform(
    scrollYProgress,
    [0, 0.8],
    ["0 0px 0px rgba(0, 0, 0, 0)", "0 10px 30px -10px rgba(0, 0, 0, 0.5)"]
  );

  // Logo Brand Transforms (scale down to ~0.74, anchored to left center)
  const logoScale = useTransform(scrollYProgress, [0, 1], [1, 0.74]);
  const logoY = useTransform(scrollYProgress, [0, 1], [0, -2]);

  // Collapsing Hero Container
  const heroHeight = useTransform(scrollYProgress, [0, 1], [195, 60]);
  const cardScale = useTransform(scrollYProgress, [0, 1], [1, 0.98]);

  // Card Structure & Dimensions
  const cardRadius = useTransform(scrollYProgress, [0, 1], [22, 14]);
  const cardPaddingY = useTransform(scrollYProgress, [0, 1], [20, 8]);
  const cardPaddingX = useTransform(scrollYProgress, [0, 1], [20, 14]);

  // Card Layout (smoothly transitions between centered stack and horizontal pill)
  const cardFlexDirection = useTransform(
    scrollYProgress,
    [0, 0.35, 0.36, 1],
    ["column", "column", "row", "row"]
  );
  const cardJustify = useTransform(
    scrollYProgress,
    [0, 0.35, 0.36, 1],
    ["center", "center", "flex-start", "flex-start"]
  );
  const cardTextAlign = useTransform(
    scrollYProgress,
    [0, 0.35, 0.36, 1],
    ["center", "center", "left", "left"]
  );

  // Card Icon Transforms
  const iconWrapperSize = useTransform(scrollYProgress, [0, 1], [52, 34]);
  const iconMarginBottom = useTransform(
    scrollYProgress,
    [0, 0.35, 0.36, 1],
    [12, 0, 0, 0]
  );
  const iconMarginRight = useTransform(
    scrollYProgress,
    [0, 0.35, 0.36, 1],
    [0, 0, 10, 10]
  );

  // Card Text Transforms
  const titleScale = useTransform(scrollYProgress, [0, 1], [1, 0.9]);
  const descOpacity = useTransform(scrollYProgress, [0, 0.32], [1, 0]);
  const descHeight = useTransform(scrollYProgress, [0, 0.32], [42, 0]);
  const descMarginTop = useTransform(scrollYProgress, [0, 0.32], [6, 0]);

  return (
    <div className="home-scroll-viewport" ref={containerRef}>
      {/* Sticky Header Bar containing Brand and Collapsing Action Pills */}
      <Motion.div
        className="sticky-header-bar"
        style={{
          backgroundColor: headerBg,
          borderColor: headerBorder,
          boxShadow: headerShadow,
        }}
      >
        {/* Brand Group */}
        <div className="sticky-header-content">
          <Motion.div
            className="brand-logo-group"
            onClick={() =>
              containerRef.current?.scrollTo({ top: 0, behavior: "smooth" })
            }
            style={{
              scale: logoScale,
              y: logoY,
              transformOrigin: "left center",
            }}
          >
            <img src="/qkchat.png" className="logo-img" alt="QkChat Logo" />

            <h1 className="brand-title">
              Qk<span>Chat</span>
            </h1>

            <p className="version-tag">v2.1.1</p>
          </Motion.div>
        </div>

        {/* Collapsing Hero Container */}
        <Motion.div
          className="home-hero-container"
          style={{
            height: heroHeight,
          }}
        >
          <Motion.div
            className="cards-grid"
            style={{
              scale: cardScale,
            }}
          >
            {/* Start Chat Action Card */}
            <Motion.div
              className="action-card primary-card"
              onClick={() => navigate("/start")}
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              style={{
                borderRadius: cardRadius,
                paddingTop: cardPaddingY,
                paddingBottom: cardPaddingY,
                paddingLeft: cardPaddingX,
                paddingRight: cardPaddingX,
                flexDirection: cardFlexDirection,
                justifyContent: cardJustify,
                textAlign: cardTextAlign,
              }}
            >
              <Motion.div
                className="card-icon-wrapper"
                style={{
                  width: iconWrapperSize,
                  height: iconWrapperSize,
                  minWidth: iconWrapperSize,
                  minHeight: iconWrapperSize,
                  marginBottom: iconMarginBottom,
                  marginRight: iconMarginRight,
                }}
              >
                <PlusCircle className="responsive-icon" />
              </Motion.div>

              <div className="card-text-container">
                <Motion.h2 style={{ scale: titleScale, transformOrigin: "left center" }}>
                  Start New Chat
                </Motion.h2>

                <Motion.div
                  className="card-desc-wrapper"
                  style={{
                    opacity: descOpacity,
                    height: descHeight,
                    marginTop: descMarginTop,
                    overflow: "hidden",
                  }}
                >
                  <p>
                    Generate a secure room and get a QR code to invite your peer.
                  </p>
                </Motion.div>
              </div>
            </Motion.div>

            {/* Join Chat Action Card */}
            <Motion.div
              className="action-card secondary-card"
              onClick={() => navigate("/join")}
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              style={{
                borderRadius: cardRadius,
                paddingTop: cardPaddingY,
                paddingBottom: cardPaddingY,
                paddingLeft: cardPaddingX,
                paddingRight: cardPaddingX,
                flexDirection: cardFlexDirection,
                justifyContent: cardJustify,
                textAlign: cardTextAlign,
              }}
            >
              <Motion.div
                className="card-icon-wrapper"
                style={{
                  width: iconWrapperSize,
                  height: iconWrapperSize,
                  minWidth: iconWrapperSize,
                  minHeight: iconWrapperSize,
                  marginBottom: iconMarginBottom,
                  marginRight: iconMarginRight,
                }}
              >
                <LogIn className="responsive-icon" />
              </Motion.div>

              <div className="card-text-container">
                <Motion.h2 style={{ scale: titleScale, transformOrigin: "left center" }}>
                  Join a Chat
                </Motion.h2>

                <Motion.div
                  className="card-desc-wrapper"
                  style={{
                    opacity: descOpacity,
                    height: descHeight,
                    marginTop: descMarginTop,
                    overflow: "hidden",
                  }}
                >
                  <p>
                    Enter an existing Chat ID or scan a QR code from your peer.
                  </p>
                </Motion.div>
              </div>
            </Motion.div>
          </Motion.div>
        </Motion.div>
      </Motion.div>

      {/* Active Rooms List */}
      <div className="joined-rooms-section">
        <div className="section-header">
          <h3>
            Active Rooms {roomList.length > 0 && <span className="rooms-count-pill">{roomList.length}</span>}
          </h3>
        </div>

        {roomList.length === 0 ? (
          <Motion.div
            className="empty-rooms-state"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <MessageSquare size={36} className="empty-icon" />
            <p className="empty-title">No Active Chat Rooms</p>
            <p className="empty-subtitle">Start a new room or join an existing session to begin chatting securely.</p>
          </Motion.div>
        ) : (
          <div className="joined-rooms-grid">
            {roomList.map((room, index) => (
              <Motion.div
                key={room.roomId}
                className={`room-card ${room.isLocked ? "locked" : ""}`}
                onClick={() => {
                  if (room.isLocked && onUnlockRoom) {
                    onUnlockRoom(room.roomId);
                  } else {
                    onSelectRoom(room.roomId);
                  }
                }}
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
              </Motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
