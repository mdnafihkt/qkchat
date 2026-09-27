import React from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import { UploadCloud } from "lucide-react";

export default function DragDropOverlay({ isDragging = false }) {
  return (
    <AnimatePresence>
      {isDragging && (
        <Motion.div
          className="drag-drop-overlay"
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.96 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
        >
          <div className="drag-drop-box">
            <UploadCloud size={64} className="drag-drop-icon" />
            <h3>Drop Files to Encrypt & Send</h3>
            <p>
              Files will be encrypted zero-knowledge and transmitted directly to
              your peer.
            </p>
          </div>
        </Motion.div>
      )}
    </AnimatePresence>
  );
}
