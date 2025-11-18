import { useState } from "react";
import axios from "axios";
import { API_URL } from "../api/config";
import toast from "react-hot-toast";

export default function Register({ onRegisterSuccess }) {
  const [form, setForm] = useState({
    name: "",
    username: "",
    email: "",
    password: "",
  });
  const [loading, setLoading] = useState(false);

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/auth/register`, form);
      localStorage.setItem("token", res.data.token);
      localStorage.setItem("nickname", res.data.username);
      toast.success(`Cuenta creada! Bienvenido ${res.data.username} 🎉`);
      onRegisterSuccess(res.data.username);
    } catch (err) {
      toast.error(err.response?.data?.message || "Error al registrarse");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>🧾 Crear cuenta</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            name="name"
            placeholder="Nombre completo"
            value={form.name}
            onChange={handleChange}
            required
          />
          <input
            type="text"
            name="username"
            placeholder="Nombre de usuario"
            value={form.username}
            onChange={handleChange}
            required
          />
          <input
            type="email"
            name="email"
            placeholder="Correo electrónico"
            value={form.email}
            onChange={handleChange}
            required
          />
          <input
            type="password"
            name="password"
            placeholder="Contraseña"
            value={form.password}
            onChange={handleChange}
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? "Creando..." : "Registrarse"}
          </button>
        </form>
        <p>
          ¿Ya tienes cuenta?{" "}
          <a href="#" onClick={() => onRegisterSuccess("login")}>
            Inicia sesión
          </a>
        </p>
      </div>
    </div>
  );
}
