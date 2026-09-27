import React, { useState } from "react";
import QRCode from "react-qr-code";
import { X, Copy, CheckCheck } from "lucide-react";

export default function QRCodeModal({ isOpen, onClose, roomId = "" }) {
  const [isCopied, setIsCopied] = useState(false);

  if (!isOpen) return null;

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div className="qr-code-overlay" onClick={onClose}>
      <div className="qr-code-modal" onClick={(e) => e.stopPropagation()}>
        <div className="qr-code-header">
          <button
            onClick={onClose}
            className="close-btn"
            title="Close"
          >
            <X size={20} />
          </button>
        </div>
        <div className="qr-code-content">
          <QRCode
            value={roomId}
            size={200}
            style={{ height: "auto", maxWidth: "100%", width: "50%" }}
            viewBox="0 0 256 256"
          />
          <p className="qr-code-text">Scan to join session</p>
          <div
            className="copyable-field"
            onClick={() => copyToClipboard(roomId)}
          >
            <span>{roomId}</span>
            {isCopied ? (
              <CheckCheck size={16} />
            ) : (
              <Copy size={16} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
