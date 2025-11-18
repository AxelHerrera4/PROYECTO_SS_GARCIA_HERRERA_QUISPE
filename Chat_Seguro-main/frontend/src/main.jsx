import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./index.css";
import { Toaster } from "react-hot-toast";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
    <Toaster
      position="top-right"
      toastOptions={{
        style: {
          background: "var(--bg-main)",
          color: "var(--text-main)",
          border: "1px solid var(--primary)",
        },
      }}
    />
  </React.StrictMode>
);
