import { useState } from "react";
import axios from "axios";
import { API_URL } from "../api/config";
import toast from "react-hot-toast";
import "./AdminLogin.css";

export default function AdminLogin({ onLogin, onBack }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [loading, setLoading] = useState(false);
  const [requires2fa, setRequires2fa] = useState(false);
  const [tempToken, setTempToken] = useState(null);
  const [code, setCode] = useState("");

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const res = await axios.post(`${API_URL}/api/auth/admin/login`, {
        username: form.username,
        password: form.password,
      });
      // Si el backend indica que requiere 2FA, mostramos input para el código
      if (res.data?.requires2fa) {
        setRequires2fa(true);
        setTempToken(res.data.tempToken || null);
        toast.success("2FA requerido. Ingresa el código de tu aplicación de autenticación.");
      } else {
        localStorage.setItem("token", res.data.token);
        localStorage.setItem("adminName", res.data.name);
        toast.success("Bienvenido Administrador");
        onLogin(res.data);
      }
    } catch (error) {
      toast.error(error.response?.data?.message || "Credenciales inválidas");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async (e) => {
    e.preventDefault();
    if (!code.trim()) return toast.error("Ingresa el código 2FA");
    setLoading(true);
    try {
      // Enviar el código junto al token temporal en la cabecera Authorization
      const headers = tempToken ? { Authorization: `Bearer ${tempToken}` } : {};
      const res = await axios.post(`${API_URL}/api/auth/admin/verify-2fa`, { code: code.trim() }, { headers });

      // Respuesta debe incluir token completo
      localStorage.setItem("token", res.data.token);
      localStorage.setItem("adminName", res.data.name || form.username);
      toast.success("2FA verificado. Bienvenido Administrador");
      setRequires2fa(false);
      setTempToken(null);
      onLogin(res.data);
    } catch (err) {
      toast.error(err.response?.data?.message || "Código 2FA inválido");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gradient-to-br from-indigo-300 to-purple-300">
      <div className="bg-white rounded-xl shadow-lg p-8 w-96">
        <h2 className="text-2xl font-semibold mb-6 text-center text-gray-700">
          Panel de Administración
        </h2>

        <form onSubmit={handleLogin}>
          <input
            type="text"
            name="username"
            placeholder="Usuario"
            value={form.username}
            onChange={handleChange}
            className="border p-2 rounded w-full mb-3"
            required
          />

          <input
            type="password"
            name="password"
            placeholder="Contraseña"
            value={form.password}
            onChange={handleChange}
            className="border p-2 rounded w-full mb-4"
            required
            autoFocus
          />

          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 text-white py-2 w-full rounded hover:bg-blue-700 transition disabled:bg-gray-400"
          >
            {loading ? "Ingresando..." : "Ingresar"}
          </button>
        </form>
        {requires2fa && (
          <form onSubmit={handleVerify2FA} style={{ marginTop: '1rem' }}>
            <p style={{ marginBottom: '0.5rem', color: '#555' }}>Introduce el código TOTP de tu app (Google Authenticator, Authy)</p>
            <input
              type="text"
              name="code"
              placeholder="Código 6 dígitos"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              maxLength={6}
              className="border p-2 rounded w-full mb-3"
              required
              autoFocus
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-green-600 text-white py-2 w-full rounded hover:bg-green-700 transition disabled:bg-gray-400"
            >
              {loading ? "Verificando..." : "Verificar 2FA"}
            </button>
          </form>
        )}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button
            type="button"
            onClick={() => onBack && onBack()}
            className="btn btn-outline"
            style={{ flex: 1 }}
          >
            ← Ir a Usuarios
          </button>
        </div>
      </div>
    </div>
  );
}
