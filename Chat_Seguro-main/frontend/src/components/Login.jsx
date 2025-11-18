import { useState } from "react";
import axios from "axios";
import { API_URL } from "../api/config";
import toast from "react-hot-toast";
import "./Login.css";

export default function Login({ onLogin, onJoinRoom }) {
  const [nickname, setNickname] = useState("");
  const [pin, setPin] = useState("");
  const [loading, setLoading] = useState(false);

  const handleJoinRoom = async (e) => {
    e.preventDefault();
    
    if (!nickname.trim()) {
      toast.error("Por favor ingresa un nickname");
      return;
    }

    if (!pin.trim()) {
      toast.error("Por favor ingresa el PIN de la sala");
      return;
    }

    setLoading(true);
    try {
      const loginRes = await axios.post(`${API_URL}/api/auth/login`, {
        nickname: nickname.trim(),
      });
      localStorage.setItem("token", loginRes.data.token);
      localStorage.setItem("nickname", loginRes.data.username);
      
      const roomRes = await axios.get(`${API_URL}/api/rooms/pin/${pin.trim()}`);
      
      if (roomRes.data) {
        toast.success(`Bienvenido ${loginRes.data.username}!`);
        onJoinRoom({
          room: { ...roomRes.data, userPin: pin.trim() },  // Incluir el PIN ingresado
          nickname: loginRes.data.username
        });
      }
    } catch (err) {
      if (err.response?.status === 404) {
        toast.error("PIN invalido");
      } else {
        toast.error(err.response?.data?.message || "Error al unirse");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>Unirse a una Sala</h2>
        <p style={{ marginBottom: "1.5rem", color: "#888", fontSize: "0.9rem" }}>
          Ingresa tu nickname y el PIN de la sala
        </p>
        <form onSubmit={handleJoinRoom}>
          <input
            type="text"
            placeholder="Tu nickname (ej: Juan123)"
            value={nickname}
            onChange={(e) => setNickname(e.target.value)}
            maxLength={20}
            required
            autoFocus
          />
          <input
            type="text"
            placeholder="PIN de la sala (4 digitos)"
            value={pin}
            onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 4))}
            maxLength={4}
            pattern="\d{4}"
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? "Entrando..." : "Entrar a la Sala"}
          </button>
        </form>
        
        <div style={{ 
          marginTop: "2rem", 
          paddingTop: "1.5rem", 
          borderTop: "1px solid #e0e0e0" 
        }}>
          <p style={{ 
            textAlign: "center", 
            color: "#888", 
            fontSize: "0.85rem",
            marginBottom: "0.5rem" 
          }}>
            ¿Eres administrador?
          </p>
          <button
            type="button"
            onClick={() => onLogin("admin")}
            style={{
              width: "100%",
              padding: "0.7rem",
              backgroundColor: "#6366f1",
              color: "white",
              border: "none",
              borderRadius: "8px",
              cursor: "pointer",
              fontSize: "0.9rem",
              fontWeight: "500"
            }}
          >
            Ir al Panel de Admin
          </button>
        </div>
      </div>
    </div>
  );
}
