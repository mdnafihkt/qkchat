import React from "react";
import { File, Download, Clock, Check, CheckCheck } from "lucide-react";

export default function MessageBubble({ msg, transfer }) {
  return (
    <div className={`message-bubble ${msg.isOwn ? "own" : "peer"}`}>
      {msg.type === "file" ? (
        <div className="file-attachment">
          {msg.fileType && msg.fileType.startsWith("image/") ? (
            <div className="image-container">
              {msg.fileData ? (
                <div style={{ position: "relative" }}>
                  <img
                    src={msg.fileData}
                    alt={msg.fileName}
                    className="attached-image"
                  />
                  {transfer && (
                    <div className="file-transfer-overlay">
                      <div className="transfer-status-text">
                        {transfer.status}...
                      </div>
                      <div className="transfer-progress-bar-container">
                        <div
                          className="transfer-progress-bar"
                          style={{ width: `${transfer.progress}%` }}
                        ></div>
                      </div>
                      <div className="transfer-percentage-text">
                        {transfer.progress}%
                      </div>
                    </div>
                  )}
                  {!transfer && (
                    <a
                      href={msg.fileData}
                      download={msg.fileName}
                      className="image-download-btn"
                      title="Download Image"
                    >
                      <Download size={18} />
                    </a>
                  )}
                </div>
              ) : (
                <div className="image-loading-placeholder">
                  <Clock size={20} className="spinner-icon" />
                  {transfer ? (
                    <>
                      <span>
                        {transfer.status} {transfer.progress}%...
                      </span>
                      <div
                        className="transfer-progress-bar-container"
                        style={{ width: "80%", marginTop: "8px" }}
                      >
                        <div
                          className="transfer-progress-bar"
                          style={{ width: `${transfer.progress}%` }}
                        ></div>
                      </div>
                    </>
                  ) : (
                    <span>Encrypting {msg.fileName}...</span>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="attached-file">
              <File size={24} className="file-icon" />
              <div className="file-info">
                <span className="file-name" title={msg.fileName}>
                  {msg.fileName}
                </span>
                {transfer ? (
                  <div
                    className="transfer-progress-section"
                    style={{ marginTop: "4px" }}
                  >
                    <span
                      className="transfer-status-text"
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--text-muted)",
                        display: "block",
                      }}
                    >
                      {transfer.status} ({transfer.progress}%)
                    </span>
                    <div
                      className="transfer-progress-bar-container"
                      style={{ marginTop: "4px" }}
                    >
                      <div
                        className="transfer-progress-bar"
                        style={{ width: `${transfer.progress}%` }}
                      ></div>
                    </div>
                  </div>
                ) : msg.fileType ? (
                  <span className="file-type">{msg.fileType}</span>
                ) : null}
              </div>
              {msg.fileData && !transfer ? (
                <a
                  href={msg.fileData}
                  download={msg.fileName}
                  className="download-btn"
                  title="Download"
                >
                  <Download size={18} />
                </a>
              ) : (
                !transfer && (
                  <div className="file-loading-placeholder">
                    <Clock size={16} className="spinner-icon" />
                  </div>
                )
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="text">{msg.text}</div>
      )}

      <div className="message-meta">
        <span className="time">{msg.time}</span>
        {msg.isOwn && (
          <span
            className={`status-indicator ${msg.status || "sent"}`}
            title={msg.status || "sent"}
          >
            {msg.status === "sending" && <Clock size={12} />}
            {(msg.status === "sent" || !msg.status) && <Check size={12} />}
            {msg.status === "delivered" && <CheckCheck size={12} />}
          </span>
        )}
      </div>
    </div>
  );
}
