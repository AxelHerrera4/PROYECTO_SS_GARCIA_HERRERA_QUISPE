import { useEffect, useState, useRef } from "react";
import axios from "axios";
import { API_URL } from "../api/config";
import toast from "react-hot-toast";
import "./AdminPanel.css";

export default function AdminPanel({ onBack }) {
  const [adminProfile, setAdminProfile] = useState(null);
  const [show2faModal, setShow2faModal] = useState(false);
  const [qrData, setQrData] = useState(null);
  const [tempQrOtp, setTempQrOtp] = useState("");
  const [disableForm, setDisableForm] = useState({ password: "", code: "" });
  const [rooms, setRooms] = useState([]);
  const roomsRef = useRef(rooms);
  const [editingRoom, setEditingRoom] = useState(null);
  const [form, setForm] = useState({ name: "", type: "" });
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [roomToDelete, setRoomToDelete] = useState(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newRoom, setNewRoom] = useState({ name: "", type: "texto", pin: "" });
  const [loadingCreate, setLoadingCreate] = useState(false);
  const [participantsModal, setParticipantsModal] = useState({ show: false, loading: false, participants: [], room: null });
  const [downloadsModal, setDownloadsModal] = useState({ show: false, loading: false, downloads: [] });

  // 🔹 Cargar salas desde el backend
  const fetchRooms = async () => {
    try {
      const token = localStorage.getItem("token");
      console.log("📡 Obteniendo salas...");
      const res = await axios.get(`${API_URL}/api/admin/rooms`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      console.log("✅ Salas obtenidas:", res.data);
      const roomsData = res.data;

      // Para cada sala, obtener resumen unificado (histórico + online) desde el endpoint combinado
      const countsPromises = roomsData.map(async (room) => {
        try {
          const summaryRes = await axios.get(`${API_URL}/api/admin/rooms/${room._id}/participants/summary`, {
            headers: { Authorization: `Bearer ${token}` },
          });

          const summary = summaryRes.data || {};
          const counts = summary.counts || {};

          return {
            ...room,
            participantsCount: typeof counts.unique === 'number' ? counts.unique : (Array.isArray(summary.participants) ? summary.participants.length : 0),
            activeCount: typeof counts.active === 'number' ? counts.active : 0,
          };
        } catch (e) {
          // Fallback: intentar obtener por separado si el summary falla
          try {
            const partsRes = await axios.get(`${API_URL}/api/admin/rooms/${room._id}/participants`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            const activeRes = await axios.get(`${API_URL}/api/admin/rooms/${room._id}/active`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            return {
              ...room,
              participantsCount: Array.isArray(partsRes.data) ? partsRes.data.length : 0,
              activeCount: Array.isArray(activeRes.data) ? activeRes.data.length : 0,
            };
          } catch (e2) {
            return { ...room, participantsCount: 0, activeCount: 0 };
          }
        }
      });

      const roomsWithCounts = await Promise.all(countsPromises);
      setRooms(roomsWithCounts);
    } catch (err) {
      console.error("❌ Error al obtener salas:", err.response?.data || err);
      toast.error("Error al obtener las salas");
    }
  };

  useEffect(() => {
    fetchRooms();
    fetchAdminProfile();
  }, []);

  const fetchDownloads = async () => {
    try {
      setDownloadsModal({ show: true, loading: true, downloads: [] });
      const token = localStorage.getItem('token');
      const res = await axios.get(`${API_URL}/api/admin/downloads`, { headers: { Authorization: `Bearer ${token}` } });
      setDownloadsModal({ show: true, loading: false, downloads: res.data.downloads || [] });
    } catch (err) {
      console.error('Error al obtener descargas:', err.response?.data || err);
      toast.error('Error al obtener registros de descargas');
      setDownloadsModal({ show: false, loading: false, downloads: [] });
    }
  };

  const fetchAdminProfile = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const res = await axios.get(`${API_URL}/api/auth/admin/me`, { headers: { Authorization: `Bearer ${token}` } });
      setAdminProfile(res.data);
    } catch (err) {
      console.error("Error al obtener perfil admin:", err.response?.data || err);
    }
  };

  // Mantener ref sincronizada con rooms para usarla dentro del interval
  useEffect(() => { roomsRef.current = rooms; }, [rooms]);

  // Refrescar contadores de participantes activos periódicamente (cada 5s)
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    // Use the combined summary endpoint so we update both historical and active counts
    let interval = setInterval(async () => {
      const currentRooms = roomsRef.current || [];
      if (currentRooms.length === 0) return;

      try {
        const updates = await Promise.all(currentRooms.map(async (room) => {
          try {
            const summaryRes = await axios.get(`${API_URL}/api/admin/rooms/${room._id}/participants/summary`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            const summary = summaryRes.data || {};
            const counts = summary.counts || {};
            return {
              _id: room._id,
              participantsCount: typeof counts.unique === 'number' ? counts.unique : (Array.isArray(summary.participants) ? summary.participants.length : room.participantsCount || 0),
              activeCount: typeof counts.active === 'number' ? counts.active : room.activeCount || 0,
            };
          } catch (e) {
            return { _id: room._id, participantsCount: room.participantsCount || 0, activeCount: room.activeCount || 0 };
          }
        }));

        if (updates.length > 0) {
          setRooms((prev) => prev.map(r => {
            const u = updates.find(x => x._id === r._id);
            return u ? { ...r, participantsCount: u.participantsCount, activeCount: u.activeCount } : r;
          }));
        }
      } catch (e) {
        // ignore
      }
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // 🔹 Editar
  const handleEdit = (room) => {
    console.log("✏️ Editando sala:", room);
    setEditingRoom(room);
    setForm({ name: room.name, type: room.type });
  };

  // 🔹 Actualizar
  const handleUpdate = async () => {
    if (!editingRoom) return;
    if (!form.name.trim()) {
      toast.error("El nombre no puede estar vacío");
      return;
    }

    try {
      const token = localStorage.getItem("token");
      console.log("📤 Actualizando sala:", editingRoom._id, form);

      const response = await axios.put(
        `${API_URL}/api/admin/rooms/${editingRoom._id}`,
        form,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      console.log("✅ Respuesta actualización:", response.data);
      toast.success("Sala actualizada correctamente");
      setEditingRoom(null);
      fetchRooms();
    } catch (err) {
      console.error("❌ Error al actualizar:", err.response?.data || err);
      toast.error(err.response?.data?.message || "Error al actualizar sala");
    }
  };

  // 🔹 Preparar eliminación
  const handleDelete = (id) => {
    console.log("🗑️ Preparando eliminación de sala:", id);
    setRoomToDelete(id);
    setShowDeleteModal(true);
  };

  // 🔹 Ver miembros de la sala (solo admin)
  const viewParticipants = async (room) => {
    try {
      setParticipantsModal({ show: true, loading: true, participants: [], room });
      const token = localStorage.getItem("token");
      // Usar endpoint combinado que devuelve participantes + counts + online flag
      const summaryRes = await axios.get(`${API_URL}/api/admin/rooms/${room._id}/participants/summary`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const summary = summaryRes.data || {};
      const participants = Array.isArray(summary.participants) ? summary.participants : [];

      // Asegurar formato consistente: cada participante debe tener nickname, joinedAt y online
      const participantsWithState = participants.map((p) => {
        if (typeof p === 'string') {
          return { nickname: p, joinedAt: null, online: false };
        }
        return {
          nickname: p.nickname || p._id || String(p),
          joinedAt: p.joinedAt || p.joined || null,
          online: Boolean(p.online),
        };
      });

      setParticipantsModal({ show: true, loading: false, participants: participantsWithState, room });
    } catch (err) {
      console.error("Error al obtener participantes:", err.response?.data || err);
      if (err.response?.status === 401) {
        toast.error("No autorizado. Inicia sesión como admin.");
      } else {
        toast.error("Error al obtener participantes");
      }
      setParticipantsModal({ show: false, loading: false, participants: [], room: null });
    }
  };

  // Si el modal de participantes está abierto, refrescar cada 5s
  useEffect(() => {
    if (!participantsModal.show || !participantsModal.room) return;
    const interval = setInterval(() => {
      viewParticipants(participantsModal.room);
    }, 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [participantsModal.show, participantsModal.room]);

  // 🔹 Confirmar eliminación
  const confirmDelete = async () => {
    if (!roomToDelete) return;
    try {
      const token = localStorage.getItem("token");
      console.log("🚨 Eliminando sala:", roomToDelete);

      const response = await axios.delete(
        `${API_URL}/api/admin/rooms/${roomToDelete}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      console.log("✅ Respuesta eliminación:", response.data);
      toast.success("Sala eliminada correctamente");
      setShowDeleteModal(false);
      setRoomToDelete(null);
      fetchRooms();
    } catch (err) {
      console.error("❌ Error al eliminar:", err.response?.data || err);
      toast.error(err.response?.data?.message || "Error al eliminar sala");
    }
  };

  // 🔹 Cerrar modal de descargas
  const closeDownloadsModal = () => {
    setDownloadsModal({ show: false, loading: false, downloads: [] });
  };

  // 🏗️ Crear nueva sala
  const handleCreateRoom = async (e) => {
    e.preventDefault();
    if (!newRoom.name.trim()) {
      toast.error("Ingresa un nombre para la sala");
      return;
    }
    
    // Validar PIN antes de enviar
    if (newRoom.pin && newRoom.pin.trim()) {
      if (newRoom.pin.length !== 4) {
        toast.error("El PIN debe tener exactamente 4 dígitos");
        return;
      }
      if (!/^\d+$/.test(newRoom.pin)) {
        toast.error("El PIN solo puede contener números");
        return;
      }
    }
    
    setLoadingCreate(true);
    try {
      const token = localStorage.getItem("token");
      // Si el PIN está vacío, no lo enviamos
      const roomData = { 
        name: newRoom.name, 
        type: newRoom.type 
      };
      if (newRoom.pin && newRoom.pin.trim()) {
        roomData.pin = newRoom.pin;
      }
      await axios.post(`${API_URL}/api/rooms`, roomData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      toast.success("Sala creada correctamente");
      setNewRoom({ name: "", type: "texto", pin: "" });
      setShowCreateForm(false);
      fetchRooms();
    } catch (err) {
      // Mostrar errores de validación específicos del backend
      if (err.response?.data?.errors) {
        err.response.data.errors.forEach(error => {
          toast.error(error.message);
        });
      } else {
        toast.error(err.response?.data?.message || "Error al crear sala");
      }
    } finally {
      setLoadingCreate(false);
    }
  };

  return (
    <div className="admin-container">
      <header className="admin-header">
        <h2>Mis Salas Administradas</h2>
        <div className="header-actions">
          <button 
            className="create-button" 
            onClick={() => setShowCreateForm(!showCreateForm)}
          >
            {showCreateForm ? "✕ Cerrar" : "➕ Nueva Sala"}
          </button>
          <button className="back-button" onClick={onBack}>
            ← Volver
          </button>
          <button
            className="user-button"
            onClick={() => {
              // Ir a la vista de usuario (misma acción que volver)
              onBack();
            }}
            title="Ir a la vista de usuario"
            style={{ marginLeft: '0.5rem' }}
          >
            👥 Ir a Usuarios
          </button>
          {/* 2FA Controls */}
          <div style={{ marginLeft: '0.5rem', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
            {adminProfile?.totpEnabled ? (
              <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                <span style={{ color: '#10b981', fontWeight: 600 }}>🔒 2FA activo</span>
                <button
                  className="btn-2fa"
                  onClick={() => {
                    // Abrir modal para deshabilitar
                    setDisableForm({ password: '', code: '' });
                    setShow2faModal(true);
                  }}
                  title="Desactivar 2FA"
                >
                  ❌ Desactivar 2FA
                </button>
              </div>
            ) : (
              <button
                className="btn-2fa"
                onClick={async () => {
                  // Setup flow: request QR from backend
                  try {
                    const token = localStorage.getItem('token');
                    if (!token) return toast.error('Inicia sesión como admin');
                    const res = await axios.post(`${API_URL}/api/auth/admin/2fa/setup`, {}, { headers: { Authorization: `Bearer ${token}` } });
                    setQrData(res.data);
                    setShow2faModal(true);
                  } catch (err) {
                    console.error('Error solicitando 2FA setup', err.response?.data || err);
                    toast.error(err.response?.data?.message || 'Error al generar 2FA');
                  }
                }}
                title="Configurar 2FA"
              >
                🔐 Configurar 2FA
              </button>
            )}
          </div>
          <button className="icon-btn" onClick={() => fetchDownloads()} style={{ marginLeft: '0.5rem' }}>📥 Descargas</button>
        </div>
      </header>

      <div className="admin-content">
        {/* Formulario de Creación */}
        {showCreateForm && (
          <div className="create-form-section">
            <h3>🏗️ Crear Nueva Sala</h3>
            <form onSubmit={handleCreateRoom} className="create-form">
              <div className="form-row">
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
                  maxLength="4"
                />
              </div>
              <div className="form-actions">
                <button type="submit" disabled={loadingCreate} className="save-btn">
                  {loadingCreate ? "Creando..." : "✓ Crear Sala"}
                </button>
                <button 
                  type="button" 
                  onClick={() => {
                    setShowCreateForm(false);
                    setNewRoom({ name: "", type: "texto", pin: "" });
                  }}
                  className="cancel-btn"
                >
                  Cancelar
                </button>
              </div>
            </form>
          </div>
        )}

        {editingRoom ? (
          <div className="edit-form">
            <h3>✏️ Editar Sala</h3>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Nombre de la sala"
            />
            <select
              value={form.type}
              onChange={(e) => setForm({ ...form, type: e.target.value })}
            >
              <option value="texto">Texto</option>
              <option value="multimedia">Multimedia</option>
            </select>
            <div className="buttons">
              <button className="save-btn" onClick={handleUpdate}>
                💾 Guardar
              </button>
              <button
                className="cancel-btn"
                onClick={() => setEditingRoom(null)}
              >
                Cancelar
              </button>
            </div>
            {/* Modal de descargas */}
            {downloadsModal.show && (
              <div className="modal-overlay" onClick={closeDownloadsModal}>
                <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '900px' }}>
                  <h3>Registros de descargas</h3>
                  {downloadsModal.loading ? (
                    <p>Cargando...</p>
                  ) : (
                    <div style={{ maxHeight: '60vh', overflowY: 'auto' }}>
                      {downloadsModal.downloads.length === 0 ? (
                        <p>No hay descargas registradas.</p>
                      ) : (
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ textAlign: 'left', borderBottom: '1px solid #2d2d3a' }}>
                              <th>Archivo</th>
                              <th>Usuario</th>
                              <th>Sala</th>
                              <th>IP</th>
                              <th>Fecha</th>
                              <th></th>
                            </tr>
                          </thead>
                          <tbody>
                            {downloadsModal.downloads.map((d) => (
                              <tr key={d._id} style={{ borderBottom: '1px solid #2d2d3a' }}>
                                <td style={{ padding: '0.5rem' }}>{d.originalName || d.storedFilename}</td>
                                <td style={{ padding: '0.5rem' }}>{d.downloader || '-'}</td>
                                <td style={{ padding: '0.5rem' }}>{d.room ? d.room : '-'}</td>
                                <td style={{ padding: '0.5rem' }}>{d.ip || '-'}</td>
                                <td style={{ padding: '0.5rem' }}>{new Date(d.createdAt).toLocaleString()}</td>
                                <td style={{ padding: '0.5rem' }}>
                                  <a href={d.url} target="_blank" rel="noopener noreferrer" className="icon-btn">Abrir</a>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  )}
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
                    <button className="btn-cancel" onClick={closeDownloadsModal}>Cerrar</button>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="rooms-list">
            {rooms.length === 0 ? (
              <div className="empty-state">
                <p>No has creado ninguna sala todavía.</p>
                <p className="hint">👆 Usa el botón "➕ Nueva Sala" para crear tu primera sala</p>
              </div>
            ) : (
              rooms.map((room) => (
                <div key={room._id} className="room-card">
                  <div className="room-info">
                    <h3>{room.name}</h3>
                      <p className="room-type">{room.type}</p>
                      <small className="room-pin">PIN: {room.pin}</small>
                      <div style={{ marginTop: '0.6rem', display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.85rem', color: '#9ca3af' }}>Participantes: <strong style={{ color: '#fff' }}>{room.participantsCount ?? '—'}</strong></span>
                        <span style={{ fontSize: '0.85rem', color: '#9ca3af' }}>En línea: <strong style={{ color: '#10b981' }}>{room.activeCount ?? '0'}</strong></span>
                      </div>
                  </div>
                  <div className="actions">
                    <button
                      className="icon-btn edit"
                      onClick={() => {
                        console.log("CLICK EN EDITAR", room);
                        handleEdit(room);
                      }}
                    >
                      Editar
                    </button>
                    <button
                      className="icon-btn"
                      onClick={() => viewParticipants(room)}
                      title="Ver miembros"
                      style={{ background: 'linear-gradient(145deg, #f59e0b, #d97706)', color: 'white' }}
                    >
                      Miembros
                    </button>
                    <button
                      className="icon-btn delete"
                      onClick={() => {
                        console.log("CLICK EN ELIMINAR", room._id);
                        handleDelete(room._id);
                      }}
                    >
                      Eliminar
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {showDeleteModal && (
        <div
          className="modal-overlay"
          onClick={() => setShowDeleteModal(false)}
        >
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
          >
            <h3>¿Eliminar sala?</h3>
            <p>Esta acción no se puede deshacer.</p>
            <div className="modal-buttons">
              <button className="confirm-btn" onClick={confirmDelete}>
                Eliminar
              </button>
              <button
                className="cancel-btn"
                onClick={() => setShowDeleteModal(false)}
              >
                Cancelar
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Modal de participantes */}
      {participantsModal.show && (
        <div className="modal-overlay" onClick={() => setParticipantsModal({ show: false, loading: false, participants: [], room: null })}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 520 }}>
            <h3>Miembros de: {participantsModal.room?.name}</h3>
            {participantsModal.loading ? (
              <p>Cargando...</p>
            ) : (
              <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
                {participantsModal.participants.length === 0 ? (
                  <p>No hay participantes en esta sala.</p>
                ) : (
                  <ul>
                    {participantsModal.participants.map((p, i) => {
                      const joined = p.joinedAt ? new Date(p.joinedAt).toLocaleString() : null;
                      return (
                        <li key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <span style={{ width: 10, height: 10, borderRadius: 10, display: 'inline-block', background: p.online ? '#10b981' : '#6b7280' }} />
                            <strong style={{ color: '#fff' }}>{p.nickname}</strong>
                          </div>
                          <div style={{ textAlign: 'right' }}>
                            <div style={{ fontSize: '0.85rem', color: '#9ca3af' }}>{joined || '—'}</div>
                            <div style={{ fontSize: '0.75rem', color: p.online ? '#10b981' : '#6b7280' }}>{p.online ? 'En línea' : 'Desconectado'}</div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            )}
            <div style={{ marginTop: '1rem', textAlign: 'right' }}>
              <button className="cancel-btn" onClick={() => setParticipantsModal({ show: false, loading: false, participants: [], room: null })}>Cerrar</button>
            </div>
          </div>
        </div>
      )}

      {/* Modal de 2FA (setup QR o desactivar) */}
      {show2faModal && (
        <div className="modal-overlay" onClick={() => { setShow2faModal(false); setQrData(null); }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 520 }}>
            {/* If we have QR data, show setup UI */}
            {qrData ? (
              <div>
                <h3>Configurar 2FA</h3>
                <p>Escanea este código QR con tu app de autenticación (Google Authenticator, Authy)</p>
                <img src={qrData.qrDataUrl} alt="QR 2FA" style={{ width: 200, height: 200 }} />
                <p style={{ marginTop: 8 }}>Si no puedes escanear, usa este token:</p>
                <code style={{ display: 'block', marginBottom: 8 }}>{qrData.otpauth}</code>
                <div>
                  <input
                    type="text"
                    placeholder="Código TOTP de 6 dígitos"
                    value={tempQrOtp}
                    onChange={(e) => setTempQrOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    maxLength={6}
                    className="border p-2 rounded w-full mb-3"
                  />
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      className="save-btn"
                      onClick={async () => {
                        if (!tempQrOtp) return toast.error('Ingresa el código TOTP');
                        try {
                          const token = localStorage.getItem('token');
                          const res = await axios.post(`${API_URL}/api/auth/admin/2fa/confirm`, { code: tempQrOtp }, { headers: { Authorization: `Bearer ${token}` } });
                          toast.success('2FA habilitado');
                          setShow2faModal(false);
                          setQrData(null);
                          setTempQrOtp('');
                          fetchAdminProfile();
                        } catch (err) {
                          console.error('Error confirmando 2FA', err.response?.data || err);
                          toast.error(err.response?.data?.message || 'Código inválido');
                        }
                      }}
                    >Confirmar</button>
                    <button className="cancel-btn" onClick={() => { setShow2faModal(false); setQrData(null); }}>Cancelar</button>
                  </div>
                </div>
              </div>
            ) : (
              <div>
                <h3>Desactivar 2FA</h3>
                <p>Ingresa tu contraseña y (si aplica) el código TOTP actual para desactivar 2FA.</p>
                <input type="password" placeholder="Contraseña" value={disableForm.password} onChange={(e) => setDisableForm({ ...disableForm, password: e.target.value })} className="border p-2 rounded w-full mb-2" />
                <input type="text" placeholder="Código TOTP (si está activo)" value={disableForm.code} onChange={(e) => setDisableForm({ ...disableForm, code: e.target.value.replace(/\D/g, '').slice(0,6) })} className="border p-2 rounded w-full mb-3" />
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button className="save-btn" onClick={async () => {
                    try {
                      const token = localStorage.getItem('token');
                      const res = await axios.post(`${API_URL}/api/auth/admin/2fa/disable`, disableForm, { headers: { Authorization: `Bearer ${token}` } });
                      toast.success(res.data?.message || '2FA deshabilitado');
                      setShow2faModal(false);
                      fetchAdminProfile();
                    } catch (err) {
                      console.error('Error deshabilitando 2FA', err.response?.data || err);
                      toast.error(err.response?.data?.message || 'Error al deshabilitar 2FA');
                    }
                  }}>Desactivar</button>
                  <button className="cancel-btn" onClick={() => setShow2faModal(false)}>Cancelar</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
