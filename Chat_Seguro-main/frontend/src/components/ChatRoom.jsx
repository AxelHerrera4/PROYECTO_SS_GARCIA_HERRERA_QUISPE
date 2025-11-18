import { useEffect, useState, useRef } from "react";
import { socket } from "../api/socket";
import axios from "axios";
import { API_URL } from "../api/config";
import toast from "react-hot-toast";
import "./ChatRoom.css";

export default function ChatRoom({ roomId, pin, nickname, onBack }) {
  // Support restoring session from localStorage on reload
  const [currentRoomId, setCurrentRoomId] = useState(roomId || localStorage.getItem("roomId"));
  const [currentPin, setCurrentPin] = useState(pin || localStorage.getItem("roomPin"));
  const [currentNickname, setCurrentNickname] = useState(nickname || localStorage.getItem("nickname"));

  const [messages, setMessages] = useState([]);
  const [systemMessages, setSystemMessages] = useState([]);
  const [message, setMessage] = useState("");
  const [participants, setParticipants] = useState([]);
  const [joined, setJoined] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [showPanel, setShowPanel] = useState(false);
  const [roomType, setRoomType] = useState("standard");
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [messageToDelete, setMessageToDelete] = useState(null);
  const [contextMenu, setContextMenu] = useState({ show: false, x: 0, y: 0, messageId: null });
  const [editingMessage, setEditingMessage] = useState({ id: null, content: "" });
  const [isKicked, setIsKicked] = useState(false);
  const [disconnectReason, setDisconnectReason] = useState("");
  const [preview, setPreview] = useState(null); // { url, fileName }
  const [downloadConfirm, setDownloadConfirm] = useState(null); // { url, fileName }
  const messagesEndRef = useRef(null);
  const [lastActivityTs, setLastActivityTs] = useState(Date.now());
  const [showInactivityWarning, setShowInactivityWarning] = useState(false);
  const [inactivityCountdown, setInactivityCountdown] = useState(0);
  const inactivityWarnRef = useRef(null);
  const inactivityLogoutRef = useRef(null);
  const INACTIVITY_LIMIT = 5 * 60; // seconds
  const WARNING_BEFORE = 30; // seconds


  useEffect(() => {
    // If props were passed, keep state in sync
    if (roomId && roomId !== currentRoomId) setCurrentRoomId(roomId);
    if (pin && pin !== currentPin) setCurrentPin(pin);
    if (nickname && nickname !== currentNickname) setCurrentNickname(nickname);

    if (!joined && currentRoomId && currentPin && currentNickname) {
      socket.emit("joinRoom", { pin: currentPin, nickname: currentNickname });
      // persist to localStorage so reload restores session
      localStorage.setItem("roomId", currentRoomId);
      localStorage.setItem("roomPin", currentPin);
      localStorage.setItem("nickname", currentNickname);

      fetchRoomData();
      fetchHistory();
      setJoined(true);
    }

    // ✅ Enviar ping de actividad cada 2 minutos
    const activityInterval = setInterval(() => {
      if (joined && currentNickname) {
        socket.emit("userActivity", { nickname: currentNickname });
      }
    }, 2 * 60 * 1000); // 2 minutos

    return () => clearInterval(activityInterval);
  }, [currentRoomId, currentPin, currentNickname, joined]);

  // ---- Inactividad: advertencia y logout ----
  useEffect(() => {
    // reset timers
    const resetTimers = () => {
      // clear existing
      if (inactivityWarnRef.current) clearTimeout(inactivityWarnRef.current);
      if (inactivityLogoutRef.current) clearTimeout(inactivityLogoutRef.current);

      const warnDelay = (INACTIVITY_LIMIT - WARNING_BEFORE) * 1000;
      const logoutDelay = INACTIVITY_LIMIT * 1000;

      inactivityWarnRef.current = setTimeout(() => {
        setShowInactivityWarning(true);
        setInactivityCountdown(WARNING_BEFORE);
        // start countdown interval
        const tick = setInterval(() => {
          setInactivityCountdown((c) => {
            if (c <= 1) {
              clearInterval(tick);
            }
            return c - 1;
          });
        }, 1000);
      }, warnDelay);

        inactivityLogoutRef.current = setTimeout(() => {
        // Forzar desconexión
        setShowInactivityWarning(false);
        setIsKicked(true);
        setDisconnectReason("inactividad");
          socket.emit("userActivity", { nickname: currentNickname }); // último intento
          handleBack();
        }, logoutDelay);
    };

    resetTimers();

    // Activity events: mousemove, keydown, touchstart
    const activityHandler = () => {
      setLastActivityTs(Date.now());
      setShowInactivityWarning(false);
      setInactivityCountdown(0);
      socket.emit("userActivity", { nickname: currentNickname });
      resetTimers();
    };

    window.addEventListener("mousemove", activityHandler);
    window.addEventListener("keydown", activityHandler);
    window.addEventListener("touchstart", activityHandler);

    return () => {
      if (inactivityWarnRef.current) clearTimeout(inactivityWarnRef.current);
      if (inactivityLogoutRef.current) clearTimeout(inactivityLogoutRef.current);
      window.removeEventListener("mousemove", activityHandler);
      window.removeEventListener("keydown", activityHandler);
      window.removeEventListener("touchstart", activityHandler);
    };
  }, [currentNickname, onBack]);

  // 🔹 Obtener tipo de sala
  const fetchRoomData = async () => {
    try {
      const token = localStorage.getItem("token");
      const res = await axios.get(`${API_URL}/api/rooms/${currentRoomId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const room = res.data;
      console.log("Sala cargada:", room);
      setRoomType(room.type || "standard");
      
      
      // Verificar si el usuario actual es el creador de la sala
      if (room.createdBy) {
        // Si createdBy es un objeto con username
        if (room.createdBy.username === currentNickname) {
          setIsAdmin(true);
          console.log("Usuario es admin de la sala");
        }
        // Si createdBy es solo un ID, comparar con el userId guardado
        else if (typeof room.createdBy === 'string') {
          const userId = localStorage.getItem("userId");
          if (userId && room.createdBy === userId) {
            setIsAdmin(true);
            console.log(" Usuario es admin de la sala");
          }
        }
      }
    } catch (err) {
      console.error("Error cargando sala:", err);
    }
  };

  const fetchHistory = async () => {
    try {
      const token = localStorage.getItem("token");
      const res = await axios.get(`${API_URL}/api/messages/room/${currentRoomId}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });

      // La API puede devolver dos formatos:
      // - Array (usuarios normales): array de mensajes desencriptados
      // - Objeto (admins): { messages: [...], participants: [...] }
      const data = res.data;
      if (Array.isArray(data)) {
        setMessages(data);
      } else if (data && data.messages) {
        setMessages(data.messages);
        if (Array.isArray(data.participants)) {
          // data.participants puede venir como array de nicknames o de objetos
          const parts = data.participants.map(p => (p.nickname ? p.nickname : p));
          setParticipants(parts);
        }
        setIsAdmin(true);
      } else {
        // Fallback
        setMessages([]);
      }
    } catch (err) {
      console.error("Error al cargar historial:", err);
      // Si token inválido, notificar y forzar logout local
      if (err.response?.status === 401) {
        toast.error("No autorizado al obtener historial. Por favor inicia sesión nuevamente.");
        localStorage.removeItem("token");
      }
    }
  };

  // 🔹 Enviar mensaje instantáneo
  const sendMessage = () => {
    if (message.trim() === "" || isKicked) return;

    socket.emit("sendMessage", { roomId: currentRoomId, sender: currentNickname, content: message });
    setMessage("");
  };

  // 🔹 Subir archivo
  const handleFileUpload = async (e) => {
    if (isKicked) {
      toast.error("Has sido expulsado de la sala");
      return;
    }
    
    const file = e.target.files[0];
    if (!file) return;
    
    if (!currentRoomId || !currentNickname) {
      toast.error("No se ha identificado la sala o el usuario");
      return;
    }

    // Validar que sea sala multimedia
    if (roomType !== "multimedia") {
      toast.error("Esta sala no permite archivos");
      return;
    }

    // Validación cliente: extensiones permitidas y tamaño máximo 10 MB
    const allowedExts = [
      ".jpg", ".jpeg", ".png", ".gif", ".webp",
      ".mp3", ".wav", ".ogg",
      ".mp4", ".webm",
      // Documentos y comprimidos permitidos por backend
      ".pdf", ".doc", ".docx", ".zip", ".rar", ".7z"
    ];
    const maxSizeBytes = 10 * 1024 * 1024; // 10 MB
    const name = file.name || "";
    const ext = name.slice(name.lastIndexOf('.')).toLowerCase();

    if (!allowedExts.includes(ext)) {
      toast.error(`Tipo de archivo no permitido: ${ext}. Tipos permitidos: ${allowedExts.join(', ')}`, { id: "upload" });
      e.target.value = "";
      return;
    }

    if (file.size > maxSizeBytes) {
      toast.error(`El archivo excede el tamaño máximo de 10 MB. Tamaño: ${(file.size / (1024*1024)).toFixed(2)} MB`, { id: "upload" });
      e.target.value = "";
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("roomId", currentRoomId);
    formData.append("sender", currentNickname);

    // Mostrar loading
    toast.loading("Subiendo archivo...", { id: "upload" });

    try {
      const token = localStorage.getItem("token");
      const res = await axios.post(`${API_URL}/api/files/upload`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });

      const { fileUrl, messageId, fileName } = res.data;
      console.log("📎 Archivo subido:", fileUrl);

      // Añadir mensaje optimista localmente para que el uploader vea la preview inmediatamente
      try {
          const optimisticMsg = {
            _id: messageId,
            sender: currentNickname,
            content: `${API_URL}${fileUrl}`,
            type: "file",
            timestamp: new Date().toISOString(),
            fileName: fileName || file.name,
            optimistic: true,
          };
          setMessages((prev) => [...prev, optimisticMsg]);
      } catch (e) {
        console.warn('No se pudo añadir optimistc message localmente', e);
      }

      // Solo emitir el mensaje - el socket lo agregará a la UI automáticamente
      socket.emit("sendMessage", {
        roomId: currentRoomId,
        sender: currentNickname,
        content: `${API_URL}${fileUrl}`,
        type: "file",
        fileName: fileName || file.name,
        messageId: messageId,
      });

      toast.success("Archivo enviado 🎉", { id: "upload" });
    } catch (err) {
      console.error("Error subiendo archivo:", err);
      
      // Mostrar mensaje específico del servidor
      let errorMsg = "Error al subir archivo";
      
      if (err.response?.status === 403) {
        // Archivo bloqueado por seguridad
        const reason = err.response?.data?.reason || "Archivo no permitido";
        const details = err.response?.data?.details;
        
        errorMsg = details 
          ? `🚫 ${reason}\n${details}` 
          : `🚫 ${reason}`;
      } else {
        errorMsg = err.response?.data?.message || "Error al subir archivo";
      }
      
      toast.error(errorMsg, { 
        id: "upload",
        duration: 6000, // Mostrar por 6 segundos para leer el mensaje
        style: {
          maxWidth: '500px'
        }
      });
    }

    // Limpiar el input
    e.target.value = "";
  };

  // 🔹 Eliminar mensaje
  const handleDeleteMessage = async (id) => {
    setMessageToDelete(id);
    setShowDeleteModal(true);
  };

  const confirmDelete = async () => {
    const id = messageToDelete;
    setShowDeleteModal(false);
    setMessageToDelete(null);

    try {
      const token = localStorage.getItem("token");
      
      // Primero actualizar localmente de manera optimista
      setMessages((prev) =>
        prev.map((m) =>
          m._id === id ? { ...m, content: "Mensaje eliminado", type: "deleted" } : m
        )
      );

      // Luego hacer la petición al servidor
      await axios.delete(`${API_URL}/api/messages/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      // Emitir evento para actualizar a otros usuarios
      socket.emit("deleteMessage", { messageId: id, roomId: currentRoomId, nickname: currentNickname, isAdmin });
      toast.success("Mensaje eliminado");
    } catch (err) {
      console.error("Error al eliminar mensaje:", err);
      const errorMsg = err.response?.data?.message || "Error al eliminar mensaje";
      toast.error(errorMsg);
      
      // Si falla, recargar mensajes
      fetchHistory();
    }
  };

  const cancelDelete = () => {
    setShowDeleteModal(false);
    setMessageToDelete(null);
  };

  // Iniciar edición de mensaje
  const handleEditMessage = (msg) => {
    if (msg.type === "file") {
      toast.error("No puedes editar archivos");
      return;
    }
    setEditingMessage({ id: msg._id, content: msg.content });
    closeContextMenu();
  };

  // Guardar mensaje editado
  const saveEditedMessage = async () => {
    if (!editingMessage.content.trim()) {
      toast.error("El mensaje no puede estar vacío");
      return;
    }

    try {
      const token = localStorage.getItem("token");
      
      // Actualizar localmente de manera optimista
      setMessages((prev) =>
        prev.map((m) =>
          m._id === editingMessage.id ? { ...m, content: editingMessage.content, edited: true } : m
        )
      );

      // Enviar al servidor
      await axios.put(
        `${API_URL}/api/messages/${editingMessage.id}`,
        { content: editingMessage.content },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      // Emitir evento para actualizar a otros usuarios
      socket.emit("editMessage", {
        messageId: editingMessage.id,
        roomId: currentRoomId,
        newContent: editingMessage.content,
      });

      toast.success("Mensaje editado");
      setEditingMessage({ id: null, content: "" });
    } catch (err) {
      console.error("Error al editar mensaje:", err);
      toast.error("Error al editar mensaje");
      fetchHistory(); // Recargar si falla
    }
  };

  // Cancelar edición
  const cancelEdit = () => {
    setEditingMessage({ id: null, content: "" });
  };

  // Cleanup and navigate back: clear stored session and remove listeners
  const handleBack = () => {
    try {
      localStorage.removeItem("roomId");
      localStorage.removeItem("roomPin");
      localStorage.removeItem("nickname");
    } catch (e) {
      // ignore
    }

    // Notify server we're leaving the room (best-effort)
    try {
      socket.emit("leaveRoom", { roomId: currentRoomId, nickname: currentNickname });
    } catch (e) {
      // ignore
    }

    // Remove listeners registered by this component
    socket.off("newMessage");
    socket.off("messageDeleted");
    socket.off("messageEdited");
    socket.off("systemMessage");
    socket.off("activeUsersUpdate");
    socket.off("kicked");
    socket.off("sessionReplaced");
    socket.off("inactivityDisconnect");

    // Clear inactivity timers
    if (inactivityWarnRef.current) clearTimeout(inactivityWarnRef.current);
    if (inactivityLogoutRef.current) clearTimeout(inactivityLogoutRef.current);

    // Finally call parent callback to navigate back
    onBack && onBack();
  };

  // Expulsar usuario (solo admin)
  const handleKickUser = (targetNickname) => {
    if (!isAdmin) {
      toast.error("No tienes permisos para expulsar usuarios");
      return;
    }

    if (window.confirm(`¿Expulsar a ${targetNickname} de la sala?`)) {
      socket.emit("kickUser", { roomId: currentRoomId, targetNickname, adminNickname: currentNickname });
      toast.success(`${targetNickname} ha sido expulsado de la sala`);
    }
  };

  // Manejar click derecho en mensaje
  const handleContextMenu = (e, msg) => {
    e.preventDefault();
    
    // Solo mostrar menú si es tu mensaje o eres admin, y no está eliminado
    if ((msg.sender === currentNickname || isAdmin) && msg.type !== "deleted") {
      // Dimensiones aproximadas del menú contextual
      const menuWidth = 200;
      const menuHeight = 100; // Altura aproximada con 2 opciones
      
      // Obtener dimensiones de la ventana
      const windowWidth = window.innerWidth;
      const windowHeight = window.innerHeight;
      
      // Calcular posición X (evitar que se salga por la derecha)
      let x = e.clientX;
      if (x + menuWidth > windowWidth) {
        x = windowWidth - menuWidth - 10; // 10px de margen
      }
      
      // Calcular posición Y (evitar que se salga por abajo)
      let y = e.clientY;
      if (y + menuHeight > windowHeight) {
        y = windowHeight - menuHeight - 10; // 10px de margen
      }
      
      setContextMenu({
        show: true,
        x: x,
        y: y,
        messageId: msg._id,
        message: msg
      });
    }
  };

  // Cerrar menú contextual
  const closeContextMenu = () => {
    setContextMenu({ show: false, x: 0, y: 0, messageId: null, message: null });
  };

  // Mark image as corrupt when it fails to load
  const handleImageError = (messageId) => {
    if (!messageId) return;
    setMessages(prev => prev.map(m => m._id && m._id.toString() === messageId.toString() ? { ...m, corrupt: true } : m));
    toast.error('Imagen corrupta o no disponible');
  };

  const handleImageLoad = (messageId) => {
    if (!messageId) return;
    setMessages(prev => prev.map(m => m._id && m._id.toString() === messageId.toString() ? { ...m, corrupt: false } : m));
  };

  // Click en cualquier parte cierra el menú
  useEffect(() => {
    const handleClick = () => closeContextMenu();
    if (contextMenu.show) {
      document.addEventListener('click', handleClick);
      return () => document.removeEventListener('click', handleClick);
    }
  }, [contextMenu.show]);

  useEffect(() => {
    socket.on("newMessage", (data) => {
      console.log("🟢 Nuevo mensaje recibido:", data);
      // Reemplazar mensaje optimista por la versión final si existe
      setMessages((prev) => {
        if (!data || !data._id) return prev;
        const idx = prev.findIndex(m => m._id && m._id.toString() === data._id.toString());
        if (idx !== -1) {
          const existing = prev[idx];
          // Si el existente es optimista lo reemplazamos por el mensaje real
          if (existing.optimistic) {
            const finalMsg = {
              ...data,
              // Mantener fileName si el backend no lo incluyó
              fileName: data.fileName || existing.fileName,
            };
            const next = [...prev];
            next[idx] = finalMsg;
            return next;
          }
          // Si ya existe y no es optimista, no duplicar
          return prev;
        }
        return [...prev, data];
      });
    });

    socket.on("messageDeleted", ({ id, newContent }) => {
      console.log("🗑️ Mensaje eliminado recibido:", { id, newContent });
      console.log("📋 Mensajes actuales:", messages.map(m => ({ id: m._id, content: m.content })));
      setMessages((prev) => {
        const updated = prev.map((m) => {
          if (m._id === id || m._id.toString() === id.toString()) {
            console.log("✅ Encontrado mensaje para actualizar:", m._id);
            return { ...m, content: newContent || "🗑️ Mensaje eliminado", type: "deleted" };
          }
          return m;
        });
        console.log("📋 Mensajes después de actualizar:", updated.map(m => ({ id: m._id, content: m.content, type: m.type })));
        return updated;
      });
    });

    socket.on("messageEdited", ({ id, newContent }) => {
      console.log("Mensaje editado recibido:", { id, newContent });
      setMessages((prev) =>
        prev.map((m) =>
          m._id === id ? { ...m, content: newContent, edited: true } : m
        )
      );
    });

    socket.on("activeUsersUpdate", (list) => setParticipants(list || []));

    socket.on("systemMessage", (msg) => {
      setSystemMessages((prev) => {
        const last = prev[prev.length - 1];
        if (last?.content === msg.content) return prev;
        return [...prev, msg];
      });
      toast(msg.content, { icon: "" });
    });

    socket.on("kicked", ({ message }) => {
      console.log("🚫 Usuario expulsado:", message);
      setIsKicked(true);
      setDisconnectReason("expulsado");
      
      // Desconectar inmediatamente del socket de la sala
      socket.off("newMessage");
      socket.off("messageDeleted");
      socket.off("messageEdited");
      socket.off("systemMessage");
      socket.off("activeUsersUpdate");
      
      toast.error(message, { duration: 5000 });
      
      // Forzar redirección inmediata
      const timer = setTimeout(() => {
        console.log("⬅️ Redirigiendo al dashboard...");
        handleBack();
      }, 3000);
      
      return () => clearTimeout(timer);
    });

    // Mostrar alerta de inactividad si aplica (actualiza estado local si countdown llega a 0)
    socket.on("inactivityDisconnect", ({ message }) => {
      setIsKicked(true);
      setDisconnectReason("inactividad");
      setShowInactivityWarning(false);
      toast.error(message, { duration: 5000 });
      setTimeout(() => handleBack(), 3000);
    });

    // ✅ Sesión reemplazada por otro dispositivo
    socket.on("sessionReplaced", ({ message }) => {
      console.log("🔄 Sesión reemplazada:", message);
      setIsKicked(true);
      setDisconnectReason("sesión reemplazada");
      toast.error(message, { duration: 5000 });
      setTimeout(() => {
        handleBack();
      }, 3000);
    });

    // ✅ Desconexión por inactividad
    socket.on("inactivityDisconnect", ({ message }) => {
      console.log("⏰ Desconexión por inactividad:", message);
      setIsKicked(true);
      setDisconnectReason("inactividad");
      toast.error(message, { duration: 5000 });
      setTimeout(() => {
        handleBack();
      }, 3000);
    });

    return () => {
      socket.off("newMessage");
      socket.off("messageDeleted");
      socket.off("messageEdited");
      socket.off("systemMessage");
      socket.off("activeUsersUpdate");
      socket.off("kicked");
      socket.off("sessionReplaced");
      socket.off("inactivityDisconnect");
    };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, systemMessages]);

  const renderContent = (msg) => {
    // Si el mensaje fue eliminado
    if (msg.type === "deleted") {
      return <span className="deleted-message">{msg.content}</span>;
    }

    // Si es archivo
    if (msg.type === "file" || msg.content?.match(/\.(jpg|jpeg|png|gif|mp4|pdf|webm|doc|docx|xls|xlsx|zip|rar|webp)$/i)) {
      const fileName = msg.fileName || msg.content.split('/').pop();

      // Imágenes
      if (msg.content.match(/\.(jpg|jpeg|png|gif|webp)$/i)) {
        const src = msg.content.startsWith('http') ? msg.content : `${API_URL}${msg.content}`;
        // Si la imagen fue marcada como corrupta, mostrar placeholder
        if (msg.corrupt) {
          return (
            <div className="file-message image-message corrupted">
              <div className="image-placeholder">Imagen corrupta o no disponible</div>
              <div className="file-name">{fileName}</div>
            </div>
          );
        }

        return (
          <div className="file-message image-message">
            <div className="image-wrapper">
              <img
                src={src}
                alt={fileName}
                className="chat-image"
                onClick={() => setPreview({ url: src, fileName })}
                onError={() => handleImageError(msg._id)}
                onLoad={() => handleImageLoad(msg._id)}
                style={{ cursor: 'pointer' }}
              />
              <div className="image-overlay">
                <button
                  className="overlay-btn"
                  title="Ver imagen"
                  onClick={() => setPreview({ url: src, fileName })}
                >🔍</button>
                <button
                  className="overlay-btn"
                  title="Descargar imagen"
                  onClick={() => setDownloadConfirm({ url: src, fileName })}
                >⬇️</button>
              </div>
            </div>
            <div className="file-name">
              {fileName}
            </div>
          </div>
        );
      }

      // Videos
      if (msg.content.match(/\.(mp4|webm|mov)$/i)) {
        const src = msg.content.startsWith('http') ? msg.content : `${API_URL}${msg.content}`;
        return (
          <div className="file-message video-message">
            <video controls className="chat-video">
              <source src={src} type="video/mp4" />
            </video>
            <div className="file-name">{fileName}
              <button className="download-icon" title="Descargar video" onClick={() => setDownloadConfirm({ url: src, fileName })}>⬇️</button>
            </div>
          </div>
        );
      }

      // PDFs
      if (msg.content.match(/\.pdf$/i)) {
        const src = msg.content.startsWith('http') ? msg.content : `${API_URL}${msg.content}`;
        return (
          <div className="file-message pdf-message">
            <a href={src} target="_blank" rel="noopener noreferrer" className="pdf-link">
              <div className="file-icon">📄</div>
              <div className="file-info">
                <div className="file-name">{fileName}</div>
                <div className="file-action">Abrir PDF</div>
              </div>
            </a>
            <button className="download-icon" title="Descargar PDF" onClick={() => setDownloadConfirm({ url: src, fileName })}>⬇️</button>
          </div>
        );
      }

      // Otros archivos
      const src = msg.content.startsWith('http') ? msg.content : `${API_URL}${msg.content}`;
      return (
        <div className="file-message other-file">
          <div className="file-icon">📎</div>
          <div className="file-info">
            <div className="file-name">{fileName}</div>
            <div className="file-action">{/* mostrar nombre y acción */}</div>
          </div>
          <button className="download-icon" title="Descargar archivo" onClick={() => setDownloadConfirm({ url: src, fileName })}>⬇️</button>
        </div>
      );
    }
    
    // Mensaje de texto normal
    return <span className="text-message">{msg.content}</span>;
  };

  return (
    <div className="chat-container">
      {isKicked && (
        <div className="kicked-overlay">
          <div className="kicked-message">
            {disconnectReason === "expulsado" && (
              <>
                <h2>🚫 Has sido expulsado</h2>
                <p>El administrador te ha expulsado de esta sala</p>
              </>
            )}
            {disconnectReason === "sesión reemplazada" && (
              <>
                <h2>🔄 Sesión reemplazada</h2>
                <p>Tu sesión ha sido reemplazada por otro dispositivo</p>
                <p style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>Solo puedes estar conectado desde un dispositivo a la vez</p>
              </>
            )}
            {disconnectReason === "inactividad" && (
              <>
                <h2>⏰ Desconectado por inactividad</h2>
                <p>Has estado inactivo por más de 5 minutos</p>
              </>
            )}
            <p>Serás redirigido al inicio...</p>
          </div>
        </div>
      )}
      {/* Modal de vista previa de imagen */}
      {preview && (
        <div className="modal-overlay" onClick={() => setPreview(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <img src={preview.url} alt={preview.fileName} style={{ maxWidth: '90vw', maxHeight: '70vh' }} />
            <div style={{ marginTop: '0.75rem', display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button className="cancel-btn" onClick={() => setPreview(null)}>Cerrar</button>
              <button className="save-btn" onClick={() => setDownloadConfirm(preview)}>Descargar</button>
            </div>
          </div>
        </div>
      )}

      {/* Modal de confirmación de descarga */}
      {downloadConfirm && (
        <div className="modal-overlay" onClick={() => setDownloadConfirm(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Descargar archivo</h3>
            <p>Se descargará <strong>{downloadConfirm.fileName}</strong>. ¿Deseas continuar?</p>
            <div className="modal-actions">
              <button className="btn-cancel" onClick={() => setDownloadConfirm(null)}>Cancelar</button>
              <button className="btn-confirm" onClick={async () => {
                // Iniciar descarga mediante fetch para soportar cross-origin correctamente
                try {
                  const resp = await fetch(downloadConfirm.url, { credentials: 'include' });
                  if (!resp.ok) throw new Error('Network response was not ok');

                  // Para feedback de progreso usamos el stream
                  const contentLength = resp.headers.get('Content-Length');
                  if (!resp.body) throw new Error('ReadableStream no disponible');

                  const total = contentLength ? parseInt(contentLength, 10) : null;
                  const reader = resp.body.getReader();
                  let received = 0;
                  const chunks = [];

                  // Mostrar toast con progreso inicial
                  const progressId = toast.loading('Descargando... 0%', { id: 'download-progress', duration: Infinity });

                  while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    chunks.push(value);
                    received += value.length;
                    if (total) {
                      const pct = Math.round((received / total) * 100);
                      toast.loading(`Descargando... ${pct}%`, { id: 'download-progress', duration: Infinity });
                    }
                  }

                  // Combinar chunks
                  const blob = new Blob(chunks);
                  const blobUrl = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = blobUrl;
                  a.download = downloadConfirm.fileName || '';
                  document.body.appendChild(a);
                  a.click();
                  a.remove();
                  URL.revokeObjectURL(blobUrl);
                  toast.success('Descarga completada', { id: 'download-progress' });

                  // Registrar descarga en backend (auditoría)
                  try {
                    const token = localStorage.getItem('token');
                    await axios.post(`${API_URL}/api/files/downloaded`, {
                      originalName: downloadConfirm.fileName,
                      storedFilename: downloadConfirm.fileName,
                      url: downloadConfirm.url,
                      mimetype: resp.headers.get('Content-Type') || undefined,
                      room: currentRoomId,
                      downloader: currentNickname
                    }, {
                      headers: token ? { Authorization: `Bearer ${token}` } : {}
                    });
                  } catch (logErr) {
                    console.error('Error registrando descarga', logErr);
                  }

                } catch (e) {
                  console.error('Download error', e);
                  toast.error('No se pudo iniciar la descarga');
                }
                setDownloadConfirm(null);
              }}>Descargar</button>
            </div>
          </div>
        </div>
      )}
      
      <div className="chat-header">
        <div>
          <h2>{isAdmin ? " Administrador" : "Chat de Sala"}</h2>
          <p>{currentNickname}</p>
        </div>
        <div className="chat-actions">
          <button className="btn-outline" onClick={() => setShowPanel(!showPanel)}>
            👥 Participantes
          </button>
          <button className="btn-danger" onClick={handleBack}>Salir</button>
        </div>
      </div>

      {/* Modal de advertencia por inactividad */}
      {showInactivityWarning && (
        <div className="modal-overlay" onClick={() => setShowInactivityWarning(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>⏰ Sesión por expirar</h3>
            <p>Tu sesión expirará en <strong>{inactivityCountdown}s</strong> por inactividad.</p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button className="cancel-btn" onClick={() => { setShowInactivityWarning(false); }}>Cerrar</button>
              <button className="save-btn" onClick={() => { socket.emit('userActivity', { nickname: currentNickname }); setShowInactivityWarning(false); }}>Permanecer conectado</button>
            </div>
          </div>
        </div>
      )}

      {showPanel && (
        <div className="participants-panel">
          <h3>Participantes ({participants.length})</h3>
          <ul>
            {participants.map((u, i) => (
              <li key={i}>
                <span>●</span> {u.nickname}
                {isAdmin && u.nickname !== currentNickname && (
                  <button
                    className="kick-btn"
                    onClick={() => handleKickUser(u.nickname)}
                    title="Expulsar usuario"
                  >
                    🚫
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="chat-messages">
        {systemMessages.map((msg, i) => (
          <div key={`sys-${i}`} className="system-message">{msg.content}</div>
        ))}

        {messages.map((msg, i) => (
          <div 
            key={i} 
            className={`message ${msg.sender === currentNickname ? "sent" : "received"}`}
            onContextMenu={(e) => handleContextMenu(e, msg)}
          >
            <div className="message-content">
              <div className="message-header">
                <strong>{msg.sender}</strong>
                {msg.edited && <span className="edited-badge">editado</span>}
              </div>
              
              {editingMessage.id === msg._id ? (
                <div className="edit-message-box">
                  <input
                    type="text"
                    className="edit-input"
                    value={editingMessage.content}
                    onChange={(e) => setEditingMessage({ ...editingMessage, content: e.target.value })}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveEditedMessage();
                      if (e.key === "Escape") cancelEdit();
                    }}
                    autoFocus
                  />
                  <div className="edit-actions">
                    <button className="btn-save" onClick={saveEditedMessage}>✓</button>
                    <button className="btn-cancel-edit" onClick={cancelEdit}>✕</button>
                  </div>
                </div>
              ) : (
                <div className="message-body">{renderContent(msg)}</div>
              )}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-footer">
        {!isKicked && roomType === "multimedia" && (
          <label className="file-upload">
            📎
            <input type="file" onChange={handleFileUpload} style={{ display: "none" }} />
          </label>
        )}
        <input
          className="message-input"
          placeholder={isKicked ? "Has sido expulsado de la sala" : "Escribe un mensaje..."}
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            // Actualizar actividad al escribir
            socket.emit("userActivity", { nickname: currentNickname });
          }}
          onKeyDown={(e) => e.key === "Enter" && sendMessage()}
          disabled={isKicked}
        />
        <button 
          className="send-button" 
          onClick={sendMessage}
          disabled={isKicked}
        >
          Enviar
        </button>
      </div>

      {/* Modal de confirmación para eliminar */}
      {showDeleteModal && (
        <div className="modal-overlay" onClick={cancelDelete}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>¿Eliminar mensaje?</h3>
            <p>Esta acción no se puede deshacer</p>
            <div className="modal-actions">
              <button className="btn-cancel" onClick={cancelDelete}>Cancelar</button>
              <button className="btn-confirm-delete" onClick={confirmDelete}>Eliminar</button>
            </div>
          </div>
        </div>
      )}

      {/* Menú contextual */}
      {contextMenu.show && (
        <div 
          className="context-menu" 
          style={{ 
            top: `${contextMenu.y}px`, 
            left: `${contextMenu.x}px` 
          }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Solo mostrar editar si es el dueño del mensaje y no es archivo */}
          {contextMenu.message?.sender === currentNickname && contextMenu.message?.type !== "file" && (
            <div 
              className="context-menu-item"
              onClick={() => {
                handleEditMessage(contextMenu.message);
                closeContextMenu();
              }}
            >
              <span className="context-icon">✏️</span>
              Editar mensaje
            </div>
          )}
          
          <div 
            className="context-menu-item"
            onClick={() => {
              handleDeleteMessage(contextMenu.messageId);
              closeContextMenu();
            }}
          >
            <span className="context-icon">🗑️</span>
            Eliminar mensaje
          </div>
        </div>
      )}
    </div>
  );
}
