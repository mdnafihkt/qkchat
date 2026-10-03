import { useEffect, useRef, useState } from 'react';
import { Html5Qrcode } from 'html5-qrcode';

export default function QRScanner({ onScanSuccess, onScanFailure }) {
  const [isScanning, setIsScanning] = useState(false);
  const qrCodeRef = useRef(null); // To store the library instance
  const scannerId = "qr-reader";

  useEffect(() => {
    // Initialize the logic-only instance
    qrCodeRef.current = new Html5Qrcode(scannerId);

    return () => {
      // Clean up on unmount
      if (qrCodeRef.current?.isScanning) {
        qrCodeRef.current.stop().then(() => qrCodeRef.current.clear());
      }
    };
  }, []);

  const startScanner = async () => {
    try {
      await qrCodeRef.current.start(
        { facingMode: "environment" }, // Rear camera
        { fps: 10, qrbox: { width: 250, height: 250 } },
        (decodedText, decodedResult) => {
          onScanSuccess(decodedText, decodedResult);
          stopScanner(); // Auto-stop after success
        },
        onScanFailure
      );
      setIsScanning(true);
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error("Failed to start scanner:", err);
      }
    }
  };

  const stopScanner = async () => {
    if (qrCodeRef.current?.isScanning) {
      await qrCodeRef.current.stop();
      const container = document.getElementById(scannerId);
      if (container) container.innerHTML = "";
      setIsScanning(false);
    }
  };

return (
    <div className={`qr-scanner-wrapper ${isScanning ? 'is-scanning' : ''}`}>
      <div id="qr-reader" />
      
      <div className="scanner-controls">
        <button 
          onClick={isScanning ? stopScanner : startScanner} 
          className={`scanner-btn ${isScanning ? 'stop' : ''}`}
        >
          {isScanning ? 'Stop Scanning' : 'Start Camera'}
        </button>
      </div>
    </div>
  );
}