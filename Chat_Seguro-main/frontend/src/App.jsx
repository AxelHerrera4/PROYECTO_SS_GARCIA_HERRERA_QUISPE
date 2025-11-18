import { useState, useEffect } from "react";
import axios from "axios";
import { API_URL } from "./api/config";
import Login from "./components/Login";
import AdminLogin from "./components/AdminLogin";
import Dashboard from "./components/Dashboard";
import ChatRoom from "./components/ChatRoom";
import AdminPanel from "./components/AdminPanel";

export default function App() {
  const [nickname, setNickname] = useState(localStorage.getItem("nickname") || "");
  const [selectedRoom, setSelectedRoom] = useState(null);
  // If there's a stored nickname, default to dashboard so refresh doesn't force login
  const [view, setView] = useState(localStorage.getItem("nickname") ? "dashboard" : "login");

  // Restore chat session (room) if user was inside a room before reload
  useEffect(() => {
    const storedRoomId = localStorage.getItem("roomId");
    const storedNickname = localStorage.getItem("nickname");
    if (storedNickname && storedRoomId) {
      // Fetch room details to restore selectedRoom
      (async () => {
        try {
          const token = localStorage.getItem("token");
          const res = await axios.get(`${API_URL}/api/rooms/${storedRoomId}`, {
            headers: token ? { Authorization: `Bearer ${token}` } : {}
          });
          const room = res.data;
          if (room && room._id) {
            setSelectedRoom(room);
            setView("chat");
          }
        } catch (e) {
          // If fetch fails, fall back to dashboard view but keep nickname
          setView("dashboard");
        }
      })();
    }
  }, []);

  // Vista de login para administrador
  if (view === "adminLogin") {
    return (
      <AdminLogin
        onLogin={(adminData) => {
          setView("adminPanel");
        }}
        onBack={() => setView("login")}
      />
    );
  }

  // Vista de panel de administrador
  if (view === "adminPanel") {
    return (
      <AdminPanel
        onBack={() => {
          // No eliminar token: conservar sesión de admin al regresar a la vista de usuario
          setView("login");
        }}
      />
    );
  }

  // Vista de login para usuarios (entrada con nickname + PIN)
  if (!nickname || view === "login") {
    return (
      <Login
        onLogin={(action) => {
          if (action === "admin") {
            setView("adminLogin");
          }
        }}
        onJoinRoom={(data) => {
          // Usuario ingresó directamente con nickname + PIN
          setNickname(data.nickname);
          localStorage.setItem("nickname", data.nickname);
          setSelectedRoom(data.room);
          setView("chat");
        }}
      />
    );
  }

  // Vista de sala de chat
  if (view === "chat" && selectedRoom) {
    return (
      <ChatRoom
        roomId={selectedRoom._id}
        pin={selectedRoom.pin}
        nickname={nickname}
        onBack={() => {
          setSelectedRoom(null);
          setNickname("");
          localStorage.removeItem("nickname");
          setView("login");
        }}
      />
    );
  }

  // Vista de dashboard (por si acaso se necesita en el futuro)
  return (
    <Dashboard
      nickname={nickname}
      onEnterRoom={(room) => {
        setSelectedRoom(room);
        setView("chat");
      }}
      onLogout={() => {
        localStorage.removeItem("nickname");
        localStorage.removeItem("token");
        setNickname("");
        setView("login");
      }}
      onOpenAdmin={() => setView("adminLogin")}
    />
  );
}
