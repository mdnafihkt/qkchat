import React from "react";
import { Lock } from "lucide-react";
import MessageBubble from "./MessageBubble";

export default function ChatMessages({
  messages = [],
  transfers = {},
  activeRoomId = "",
  messagesEndRef,
}) {
  return (
    <div className="messages-area">
      {messages.length === 0 && (
        <div
          style={{
            textAlign: "center",
            color: "var(--text-muted)",
            margin: "auto",
          }}
        >
          <Lock size={32} style={{ margin: "0 auto 1rem", opacity: 0.5 }} />
          <p>Session initialized: {activeRoomId}</p>
          <p style={{ fontSize: "0.8rem", marginTop: "0.25rem" }}>
            Messages are not stored and will be permanently lost when you leave.
          </p>
        </div>
      )}

      {messages.map((msg) => (
        <MessageBubble
          key={msg.id}
          msg={msg}
          transfer={transfers[msg.transferId]}
        />
      ))}

      <div ref={messagesEndRef} />
    </div>
  );
}
