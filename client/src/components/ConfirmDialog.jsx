import React, { useEffect } from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, AlertCircle, Info, X } from "lucide-react";
import "./ConfirmDialog.css";

export function ConfirmDialog({
  isOpen = false,
  title = "Confirm Action",
  message = "Are you sure you want to proceed?",
  warning = null,
  confirmText = "Confirm",
  cancelText = "Cancel",
  type = "danger", // "danger" | "warning" | "info"
  onConfirm,
  onCancel,
}) {
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel?.();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onCancel]);

  const renderIcon = () => {
    switch (type) {
      case "danger":
        return <AlertTriangle size={20} />;
      case "warning":
        return <AlertTriangle size={20} />;
      case "info":
      default:
        return <Info size={20} />;
    }
  };

  const getConfirmBtnClass = () => {
    switch (type) {
      case "danger":
        return "confirm-danger";
      case "warning":
        return "confirm-warning";
      case "info":
      default:
        return "confirm-primary";
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <Motion.div
          className="confirm-dialog-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          onClick={onCancel}
        >
          <Motion.div
            className={`confirm-dialog-card ${type}`}
            initial={{ opacity: 0, scale: 0.94, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.94, y: 12 }}
            transition={{ type: "spring", stiffness: 350, damping: 28 }}
            onClick={(e) => e.stopPropagation()}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
            aria-describedby="confirm-dialog-message"
          >
            <div className="confirm-dialog-header">
              <div className="confirm-dialog-title-group">
                <div className={`confirm-dialog-icon ${type}`}>
                  {renderIcon()}
                </div>
                <h3 id="confirm-dialog-title" className="confirm-dialog-title">
                  {title}
                </h3>
              </div>
              <button
                type="button"
                className="confirm-dialog-close-btn"
                onClick={onCancel}
                title="Cancel and close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div className="confirm-dialog-body">
              <p id="confirm-dialog-message" className="confirm-dialog-message">
                {message}
              </p>

              {warning && (
                <div className="confirm-dialog-warning-box">
                  <AlertCircle size={16} style={{ flexShrink: 0, marginTop: "2px" }} />
                  <span>{warning}</span>
                </div>
              )}
            </div>

            <div className="confirm-dialog-actions">
              <button
                type="button"
                className="confirm-dialog-btn cancel"
                onClick={onCancel}
                autoFocus
              >
                {cancelText}
              </button>
              <button
                type="button"
                className={`confirm-dialog-btn ${getConfirmBtnClass()}`}
                onClick={onConfirm}
              >
                {confirmText}
              </button>
            </div>
          </Motion.div>
        </Motion.div>
      )}
    </AnimatePresence>
  );
}

export function ToastNotification({ toast, onDismiss }) {
  return (
    <AnimatePresence>
      {toast && (
        <div className="custom-toast-container">
          <Motion.div
            key={toast.id}
            className={`custom-toast ${toast.type || "info"}`}
            role="alert"
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -15, scale: 0.95 }}
            transition={{ duration: 0.2 }}
          >
            <div className="custom-toast-content">
              {toast.type === "error" && <AlertCircle size={18} />}
              {toast.type === "warning" && <AlertTriangle size={18} />}
              {toast.type === "info" && <Info size={18} />}
              <span>{toast.message}</span>
            </div>
            <button
              type="button"
              className="custom-toast-dismiss"
              onClick={() => onDismiss(toast.id)}
              title="Dismiss notification"
            >
              <X size={16} />
            </button>
          </Motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

export default ConfirmDialog;
