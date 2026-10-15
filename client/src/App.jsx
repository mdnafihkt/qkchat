import React from "react";
import { BrowserRouter as Router } from "react-router-dom";
import AppRoutes from "./AppRoutes";

const SOCKET_URL =
  import.meta.env.VITE_BACKEND_URL ||
  (import.meta.env.DEV ? "http://localhost:3000" : window.location.origin);

export default function App() {
  return (
    <Router>
      <AppRoutes SOCKET_URL={SOCKET_URL} />
    </Router>
  );
}
