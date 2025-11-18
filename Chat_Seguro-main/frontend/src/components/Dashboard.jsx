import { useEffect, useState } from "react";
import axios from "axios";
import { API_URL } from "../api/config";
import toast from "react-hot-toast";
import "./Dashboard.css";


export default function Dashboard({ nickname, onEnterRoom, onLogout, onOpenAdmin }) {
  const [rooms, setRooms] = useState([]);
  const [joinPin, setJoinPin] = useState("");
  const [newRoom, setNewRoom] = useState({ name: "", type: "texto", pin: "" });
  const [loadingJoin, setLoadingJoin] = useState(false);
  const [loadingCreate, setLoadingCreate] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const randomColor = () => {
    const colors = [
      "#4F46E5", "#10B981", "#F59E0B", "#EF4444",
      "#3B82F6", "#EC4899", "#8B5CF6", "#0EA5E9",
    ];
    return colors[Math.floor(Math.random() * colors.length)];
  };

  const fetchRooms = async () => {
  try {
    const token = localStorage.getItem("token");

    // 🔹 Obtener salas creadas por el usuario
    const createdRes = await axios.get(
      `${API_URL}/api/users/${nickname}/created`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    // 🔹 Obtener salas donde está unido
    const joinedRes = await axios.get(
      `${API_URL}/api/users/${nickname}/rooms`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    // Combinar ambas listas sin duplicar
    const all = [...createdRes.data, ...joinedRes.data];
    const unique = all.filter(
      (room, index, self) => index === self.findIndex((r) => r._id === room._id)
    );

    const colored = unique.map((r) => ({ ...r, color: randomColor() }));
    setRooms(colored);
  } catch (err) {
    console.error("Error al obtener salas:", err);
  }
};


  useEffect(() => {
    fetchRooms();
  }, []);

  // 🎯 Unirse a sala por PIN
  const handleJoinByPin = async (e) => {
    e.preventDefault();
    if (!joinPin.trim()) {
      toast.error("Ingresa un PIN válido");
      return;
    }
    setLoadingJoin(true);
    try {
      const token = localStorage.getItem("token");
      const res = await axios.post(
        `${API_URL}/api/users/join`,
        { nickname, pin: joinPin },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success(`Te has unido a la sala: ${res.data.roomName}`);
      setJoinPin("");
      fetchRooms();
    } catch (err) {
      toast.error(err.response?.data?.message || "No se pudo unir a la sala");
    } finally {
      setLoadingJoin(false);
    }
  };

  // 🏗️ Crear nueva sala
  const handleCreateRoom = async (e) => {
    e.preventDefault();
    if (!newRoom.name.trim()) {
      toast.error("Ingresa un nombre para la sala");
      return;
    }
    setLoadingCreate(true);
    try {
      const token = localStorage.getItem("token");
      await axios.post(`${API_URL}/api/rooms`, newRoom, {
        headers: { Authorization: `Bearer ${token}` },
      });
      toast.success("Sala creada correctamente");
      setNewRoom({ name: "", type: "texto", pin: "" });
      setShowCreateForm(false);
      fetchRooms();
    } catch (err) {
      toast.error(err.response?.data?.message || "Error al crear sala");
    } finally {
      setLoadingCreate(false);
    }
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h2>Tus Salas</h2>
        <div className="user-actions">
          <span>Conectado como <strong>{nickname}</strong></span>
          <button onClick={onOpenAdmin}>Mis salas creadas</button>
          <button onClick={onLogout}>Salir</button>
        </div>
      </header>

      {/* Sección de crear o unirse */}
      <section className="room-actions">
        <div className="join-room">
          <h3>Unirse a una sala existente</h3>
          <form onSubmit={handleJoinByPin}>
            <input
              type="text"
              placeholder="PIN de la sala"
              value={joinPin}
              onChange={(e) => setJoinPin(e.target.value)}
              required
            />
            <button type="submit" disabled={loadingJoin}>
              {loadingJoin ? "Uniendo..." : "Unirse"}
            </button>
          </form>
        </div>

        <div className="create-room">
          <h3>Crear nueva sala</h3>
          {!showCreateForm ? (
            <button 
              className="btn-show-form"
              onClick={() => setShowCreateForm(true)}
            >
              ➕ Nueva Sala
            </button>
          ) : (
            <form onSubmit={handleCreateRoom}>
              <input
                type="text"
                placeholder="Nombre de la sala"
                value={newRoom.name}
                onChange={(e) =>
                  setNewRoom({ ...newRoom, name: e.target.value })
                }
                required
              />
              <select
                value={newRoom.type}
                onChange={(e) =>
                  setNewRoom({ ...newRoom, type: e.target.value })
                }
              >
                <option value="texto">Texto</option>
                <option value="multimedia">Multimedia</option>
              </select>
              <input
                type="text"
                placeholder="PIN (opcional)"
                value={newRoom.pin}
                onChange={(e) => setNewRoom({ ...newRoom, pin: e.target.value })}
              />
              <div className="form-buttons">
                <button type="submit" disabled={loadingCreate}>
                  {loadingCreate ? "Creando..." : "Crear Sala"}
                </button>
                <button 
                  type="button" 
                  onClick={() => {
                    setShowCreateForm(false);
                    setNewRoom({ name: "", type: "texto", pin: "" });
                  }}
                  className="btn-cancel"
                >
                  Cancelar
                </button>
              </div>
            </form>
          )}
        </div>
      </section>

      {/* Sección de salas */}
      <div className="rooms-grid">
        {rooms.map((room) => (
          <div
            key={room._id}
            className="room-card"
            style={{ background: room.color }}
            onClick={() => onEnterRoom(room)}
          >
            <div className="room-info">
              <h3>{room.name}</h3>
              <p>{room.type}</p>
              <small>PIN: {room.pin}</small>
            </div>
          </div>
        ))}

        {rooms.length === 0 && (
          <div className="empty-state">
            <p>Aún no tienes salas, pero puedes crear una o unirte con un PIN 👇</p>
          </div>
        )}
      </div>
    </div>
  );
}
