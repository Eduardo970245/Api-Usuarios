const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const pool = require('./db');
const verificarToken = require('./middleware/verificarToken');
require('dotenv').config();

const app = express();
app.use(express.json());
//app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET;

/*
CREATE TABLE usuarios (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  rol VARCHAR(20) DEFAULT 'usuario',
  fecha_registro TIMESTAMP DEFAULT NOW()
);
*/

// ================= AUTENTICACIÓN =================

// 1. REGISTRO
app.post('/auth/registro', async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Nombre, email y password son obligatorios' });
    }

    // Verificar que el email no exista ya
    const existente = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
    if (existente.rows.length > 0) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    const hash = await bcrypt.hash(password, 10);
    const resultado = await pool.query(
      `INSERT INTO usuarios (nombre, email, password_hash, rol)
       VALUES ($1, $2, $3, $4)
       RETURNING id, nombre, email, rol, fecha_registro`,
      [nombre, email, hash, rol === 'admin' ? 'admin' : 'usuario']
    );

    res.status(201).json(resultado.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. LOGIN
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y password son obligatorios' });
    }

    const resultado = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const usuario = resultado.rows[0];
    if (!usuario) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const valido = await bcrypt.compare(password, usuario.password_hash);
    if (!valido) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
      JWT_SECRET,
      { expiresIn: '4h' }
    );

    res.json({
      token,
      usuario: { id: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. VERIFICAR TOKEN (usado por las vistas para saber si la sesión sigue activa)
app.get('/auth/verificar', verificarToken, (req, res) => {
  res.json({ valido: true, usuario: req.usuario });
});

// 4. OBTENER PERFIL DEL USUARIO AUTENTICADO
app.get('/auth/perfil', verificarToken, async (req, res) => {
  try {
    const resultado = await pool.query(
      'SELECT id, nombre, email, rol, fecha_registro FROM usuarios WHERE id = $1',
      [req.usuario.id]
    );
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json(resultado.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GESTIÓN DE USUARIOS (solo admin) =================

// 5. LISTAR TODOS LOS USUARIOS
app.get('/usuarios', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido a administradores' });
  }
  try {
    const resultado = await pool.query(
      'SELECT id, nombre, email, rol, fecha_registro FROM usuarios ORDER BY id'
    );
    res.json(resultado.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5.5 OBTENER UN USUARIO POR ID (usado por ms-prestamos para validar y obtener el nombre
//     cuando el admin crea un préstamo directo a nombre de otro usuario)
app.get('/usuarios/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido a administradores' });
  }
  try {
    const { id } = req.params;
    const resultado = await pool.query(
      'SELECT id, nombre, email, rol FROM usuarios WHERE id = $1',
      [id]
    );
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json(resultado.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. ACTUALIZAR ROL DE UN USUARIO (ej. promover a admin)
app.patch('/usuarios/:id/rol', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido a administradores' });
  }
  try {
    const { id } = req.params;
    const { rol } = req.body;

    if (!['admin', 'usuario'].includes(rol)) {
      return res.status(400).json({ error: "El rol debe ser 'admin' o 'usuario'" });
    }

    const resultado = await pool.query(
      'UPDATE usuarios SET rol = $1 WHERE id = $2 RETURNING id, nombre, email, rol',
      [rol, id]
    );
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json({ mensaje: 'Rol actualizado', usuario: resultado.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. ELIMINAR USUARIO
app.delete('/usuarios/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido a administradores' });
  }
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM usuarios WHERE id = $1', [id]);
    res.json({ mensaje: 'Usuario eliminado correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 6001;
app.listen(PORT, () => {
  console.log(`ms-usuarios escuchando en http://localhost:${PORT}`);
});
