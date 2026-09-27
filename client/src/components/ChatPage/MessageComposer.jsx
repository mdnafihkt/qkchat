import React, { useRef } from "react";
import { Paperclip, SendHorizontal } from "lucide-react";

export default function MessageComposer({
  newMessage = "",
  onMessageChange,
  onSend,
  onFileSelect,
  disabled = false,
}) {
  const fileInputRef = useRef(null);

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && e.shiftKey) {
      e.preventDefault();
      onSend(e);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file && onFileSelect) {
      onFileSelect(file);
    }
    e.target.value = null;
  };

  return (
    <form onSubmit={onSend} className="input-area">
      <input
        type="file"
        ref={fileInputRef}
        style={{ display: "none" }}
        onChange={handleFileChange}
        accept=".pdf,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.txt,.csv,.zip,image/*"
        title="Attach document or image files"
      />
      <button
        type="button"
        className="icon-btn attachment-btn"
        onClick={() => fileInputRef.current?.click()}
        title="Attach file"
        disabled={disabled}
      >
        <Paperclip size={20} />
      </button>
      <textarea
        placeholder="Message..."
        value={newMessage}
        onChange={(e) => onMessageChange(e.target.value)}
        onKeyDown={handleKeyDown}
        rows={1}
        disabled={disabled}
      />
      <button
        type="submit"
        className="icon-btn"
        disabled={disabled || !newMessage.trim()}
      >
        <SendHorizontal size={20} />
      </button>
    </form>
  );
}
