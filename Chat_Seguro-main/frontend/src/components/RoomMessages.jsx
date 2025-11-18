import { useEffect, useState } from "react";
import axios from "axios";
import { API_URL } from "../api/config";

export default function RoomMessages({ room, onBack }) {
  const [messages, setMessages] = useState([]);
  const token = localStorage.getItem("token");

  const fetchMessages = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/messages/${room._id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMessages(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async (messageId) => {
    if (!window.confirm("¿Eliminar este mensaje?")) return;
    try {
      await axios.delete(`${API_URL}/api/messages/${room._id}/${messageId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      fetchMessages();
    } catch (err) {
      alert("Error al eliminar mensaje");
    }
  };

  useEffect(() => {
    fetchMessages();
  }, []);

  return (
    <div className="admin-container">
      <button
        onClick={onBack}
        className="bg-gray-500 text-white px-4 py-2 rounded mb-4 hover:bg-gray-600"
      >
        ← Volver
      </button>

      <h2 className="text-xl font-semibold mb-4">
        Mensajes de la sala: {room.name}
      </h2>

      <div className="rooms-list">
        {messages.length === 0 ? (
          <p>No hay mensajes aún</p>
        ) : (
          <ul>
            {messages.map((msg) => (
              <li
                key={msg._id}
                className="border-b py-2 flex justify-between items-center"
              >
                <div>
                  <strong>{msg.sender}:</strong> {msg.content}
                </div>
                <button
                  onClick={() => handleDelete(msg._id)}
                  className="text-red-600 hover:text-red-800"
                >
                  🗑️
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
