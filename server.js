const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = '7d';

const db = new Database(path.join(__dirname, 'finanzas.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nombre TEXT NOT NULL,
    es_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS configuraciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    anio INTEGER NOT NULL,
    salario INTEGER DEFAULT 0,
    secundario INTEGER DEFAULT 0,
    otros_ing INTEGER DEFAULT 0,
    arriendo INTEGER DEFAULT 0,
    servicios INTEGER DEFAULT 0,
    internet INTEGER DEFAULT 0,
    transporte INTEGER DEFAULT 0,
    seguros INTEGER DEFAULT 0,
    cuotas INTEGER DEFAULT 0,
    meta_tipo TEXT DEFAULT 'porcentaje',
    meta_valor TEXT DEFAULT '10',
    UNIQUE(usuario_id, mes, anio),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS gastos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    mes_key TEXT NOT NULL,
    fecha TEXT NOT NULL,
    descripcion TEXT NOT NULL,
    categoria TEXT NOT NULL,
    monto INTEGER NOT NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS pagos_fijos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    anio INTEGER NOT NULL,
    concepto TEXT NOT NULL,
    pagado INTEGER DEFAULT 0,
    UNIQUE(usuario_id, mes, anio, concepto),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ingresos_extra (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    mes_key TEXT NOT NULL,
    fecha TEXT NOT NULL,
    descripcion TEXT NOT NULL,
    monto INTEGER NOT NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_gastos_usuario_mes ON gastos(usuario_id, mes_key);
  CREATE INDEX IF NOT EXISTS idx_config_usuario ON configuraciones(usuario_id, mes, anio);
  CREATE INDEX IF NOT EXISTS idx_pagos_fijos ON pagos_fijos(usuario_id, mes, anio);
  CREATE INDEX IF NOT EXISTS idx_ingresos_extra ON ingresos_extra(usuario_id, mes_key);
`);

function ensureDefaultAdmin() {
  const n = db.prepare('SELECT COUNT(*) AS c FROM usuarios').get().c;
  if (n > 0) return;
  const username = (process.env.DEFAULT_ADMIN_USER || 'admin').trim().toLowerCase();
  const password = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
  const nombre = (process.env.DEFAULT_ADMIN_NOMBRE || 'Administrador').trim() || 'Administrador';
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO usuarios (username, password_hash, nombre, es_admin) VALUES (?,?,?,1)').run(username, hash, nombre);
  console.log(`  Usuario admin creado: "${username}" (contraseña: variable DEFAULT_ADMIN_PASSWORD o "admin123"). Cámbiala desde Administración.`);
}

ensureDefaultAdmin();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    const user = db.prepare('SELECT id, username, nombre, es_admin FROM usuarios WHERE id = ?').get(decoded.id);
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    req.user = { ...user, es_admin: !!user.es_admin };
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user || !req.user.es_admin) return res.status(403).json({ error: 'Solo administradores' });
  next();
}

// ─── Auth ───
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  const user = db.prepare('SELECT * FROM usuarios WHERE username = ?').get(username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
  res.json({
    token,
    user: { id: user.id, username: user.username, nombre: user.nombre, es_admin: !!user.es_admin }
  });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ─── Admin: usuarios ───
app.get('/api/admin/usuarios', authMiddleware, adminMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, username, nombre, es_admin, created_at FROM usuarios ORDER BY id').all();
  res.json({ usuarios: rows.map(r => ({ ...r, es_admin: !!r.es_admin })) });
});

app.post('/api/admin/usuarios', authMiddleware, adminMiddleware, (req, res) => {
  const { username, nombre, password, es_admin } = req.body;
  if (!username || !nombre || !password) return res.status(400).json({ error: 'Usuario, nombre y contraseña son obligatorios' });
  const u = String(username).trim().toLowerCase();
  if (db.prepare('SELECT id FROM usuarios WHERE username = ?').get(u)) return res.status(400).json({ error: 'El usuario ya existe' });
  const hash = bcrypt.hashSync(String(password), 10);
  const isAd = es_admin ? 1 : 0;
  const ins = db.prepare('INSERT INTO usuarios (username, password_hash, nombre, es_admin) VALUES (?,?,?,?)').run(u, hash, nombre, isAd);
  const row = db.prepare('SELECT id, username, nombre, es_admin, created_at FROM usuarios WHERE id = ?').get(ins.lastInsertRowid);
  res.json({ usuario: { ...row, es_admin: !!row.es_admin } });
});

app.put('/api/admin/usuarios/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = +req.params.id;
  const target = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'Usuario no encontrado' });
  const { nombre, password, es_admin } = req.body;
  const newNombre = nombre !== undefined ? nombre : target.nombre;
  let newHash = target.password_hash;
  if (password != null && String(password).length > 0) newHash = bcrypt.hashSync(String(password), 10);
  let newEs = target.es_admin;
  if (es_admin !== undefined) {
    const want = es_admin ? 1 : 0;
    if (target.es_admin && !want) {
      const admins = db.prepare('SELECT COUNT(*) AS c FROM usuarios WHERE es_admin = 1').get().c;
      if (admins <= 1) return res.status(400).json({ error: 'Debe existir al menos un administrador' });
    }
    newEs = want;
  }
  db.prepare('UPDATE usuarios SET nombre = ?, password_hash = ?, es_admin = ? WHERE id = ?').run(newNombre, newHash, newEs, id);
  const row = db.prepare('SELECT id, username, nombre, es_admin, created_at FROM usuarios WHERE id = ?').get(id);
  res.json({ usuario: { ...row, es_admin: !!row.es_admin } });
});

app.delete('/api/admin/usuarios/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = +req.params.id;
  if (id === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  const target = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (target.es_admin) {
    const admins = db.prepare('SELECT COUNT(*) AS c FROM usuarios WHERE es_admin = 1').get().c;
    if (admins <= 1) return res.status(400).json({ error: 'No se puede eliminar el único administrador' });
  }
  db.prepare('DELETE FROM usuarios WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ─── Config ───
app.get('/api/config/:mes/:anio', authMiddleware, (req, res) => {
  const config = db.prepare(
    'SELECT * FROM configuraciones WHERE usuario_id = ? AND mes = ? AND anio = ?'
  ).get(req.user.id, +req.params.mes, +req.params.anio);
  res.json({ config: config || null });
});

app.post('/api/config', authMiddleware, (req, res) => {
  const { mes, anio, salario, secundario, otrosIng, arriendo, servicios, internet, transporte, seguros, cuotas, metaTipo, metaValor } = req.body;
  const existing = db.prepare(
    'SELECT id FROM configuraciones WHERE usuario_id = ? AND mes = ? AND anio = ?'
  ).get(req.user.id, mes, anio);

  if (existing) {
    db.prepare(`UPDATE configuraciones SET salario=?, secundario=?, otros_ing=?, arriendo=?, servicios=?,
      internet=?, transporte=?, seguros=?, cuotas=?, meta_tipo=?, meta_valor=? WHERE id=?`
    ).run(salario||0, secundario||0, otrosIng||0, arriendo||0, servicios||0, internet||0, transporte||0, seguros||0, cuotas||0, metaTipo||'porcentaje', metaValor||'10', existing.id);
  } else {
    db.prepare(`INSERT INTO configuraciones (usuario_id, mes, anio, salario, secundario, otros_ing, arriendo, servicios, internet, transporte, seguros, cuotas, meta_tipo, meta_valor)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(req.user.id, mes, anio, salario||0, secundario||0, otrosIng||0, arriendo||0, servicios||0, internet||0, transporte||0, seguros||0, cuotas||0, metaTipo||'porcentaje', metaValor||'10');
  }

  const CONCEPTOS = ['arriendo','servicios','internet','transporte','seguros','cuotas'];
  const insertPago = db.prepare(
    'INSERT OR IGNORE INTO pagos_fijos (usuario_id, mes, anio, concepto, pagado) VALUES (?, ?, ?, ?, 0)'
  );
  CONCEPTOS.forEach(c => insertPago.run(req.user.id, mes, anio, c));

  const config = db.prepare(
    'SELECT * FROM configuraciones WHERE usuario_id = ? AND mes = ? AND anio = ?'
  ).get(req.user.id, mes, anio);
  res.json({ config });
});

// ─── Pagos Fijos ───
app.get('/api/pagos-fijos/:mes/:anio', authMiddleware, (req, res) => {
  const pagos = db.prepare(
    'SELECT * FROM pagos_fijos WHERE usuario_id = ? AND mes = ? AND anio = ?'
  ).all(req.user.id, +req.params.mes, +req.params.anio);
  res.json({ pagos });
});

app.put('/api/pagos-fijos/:mes/:anio/:concepto', authMiddleware, (req, res) => {
  const { mes, anio, concepto } = req.params;
  const { pagado } = req.body;
  db.prepare(
    'INSERT INTO pagos_fijos (usuario_id, mes, anio, concepto, pagado) VALUES (?, ?, ?, ?, ?) ON CONFLICT(usuario_id, mes, anio, concepto) DO UPDATE SET pagado = ?'
  ).run(req.user.id, +mes, +anio, concepto, pagado ? 1 : 0, pagado ? 1 : 0);
  res.json({ ok: true, concepto, pagado: !!pagado });
});

// ─── Gastos ───
app.get('/api/gastos/:mes/:anio', authMiddleware, (req, res) => {
  const mesKey = `${req.params.mes}-${req.params.anio}`;
  const gastos = db.prepare(
    'SELECT * FROM gastos WHERE usuario_id = ? AND mes_key = ? ORDER BY fecha DESC'
  ).all(req.user.id, mesKey);
  res.json({ gastos });
});

app.post('/api/gastos', authMiddleware, (req, res) => {
  const { mesKey, fecha, descripcion, categoria, monto } = req.body;
  if (!descripcion || !monto || monto <= 0) return res.status(400).json({ error: 'Datos incompletos' });
  const result = db.prepare(
    'INSERT INTO gastos (usuario_id, mes_key, fecha, descripcion, categoria, monto) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, mesKey, fecha, descripcion, categoria, monto);
  const gasto = db.prepare('SELECT * FROM gastos WHERE id = ?').get(result.lastInsertRowid);
  res.json({ gasto });
});

app.delete('/api/gastos/:id', authMiddleware, (req, res) => {
  const gasto = db.prepare('SELECT * FROM gastos WHERE id = ? AND usuario_id = ?').get(+req.params.id, req.user.id);
  if (!gasto) return res.status(404).json({ error: 'Gasto no encontrado' });
  db.prepare('DELETE FROM gastos WHERE id = ?').run(+req.params.id);
  res.json({ ok: true });
});

// ─── Ingresos Extra ───
app.get('/api/ingresos-extra/:mes/:anio', authMiddleware, (req, res) => {
  const mesKey = `${req.params.mes}-${req.params.anio}`;
  const ingresos = db.prepare(
    'SELECT * FROM ingresos_extra WHERE usuario_id = ? AND mes_key = ? ORDER BY fecha DESC'
  ).all(req.user.id, mesKey);
  res.json({ ingresos });
});

app.post('/api/ingresos-extra', authMiddleware, (req, res) => {
  const { mesKey, fecha, descripcion, monto } = req.body;
  if (!descripcion || !monto || monto <= 0) return res.status(400).json({ error: 'Datos incompletos' });
  const result = db.prepare(
    'INSERT INTO ingresos_extra (usuario_id, mes_key, fecha, descripcion, monto) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, mesKey, fecha, descripcion, monto);
  const ingreso = db.prepare('SELECT * FROM ingresos_extra WHERE id = ?').get(result.lastInsertRowid);
  res.json({ ingreso });
});

app.delete('/api/ingresos-extra/:id', authMiddleware, (req, res) => {
  const ingreso = db.prepare('SELECT * FROM ingresos_extra WHERE id = ? AND usuario_id = ?').get(+req.params.id, req.user.id);
  if (!ingreso) return res.status(404).json({ error: 'Ingreso no encontrado' });
  db.prepare('DELETE FROM ingresos_extra WHERE id = ?').run(+req.params.id);
  res.json({ ok: true });
});

// ─── Export ───
app.get('/api/export/:anio', authMiddleware, (req, res) => {
  const anio = +req.params.anio;
  const configs = db.prepare('SELECT * FROM configuraciones WHERE usuario_id = ? AND anio = ?').all(req.user.id, anio);
  const allGastos = db.prepare("SELECT * FROM gastos WHERE usuario_id = ? AND mes_key LIKE ?").all(req.user.id, `%-${anio}`);
  const allPagos = db.prepare('SELECT * FROM pagos_fijos WHERE usuario_id = ? AND anio = ?').all(req.user.id, anio);
  const allIngresosExtra = db.prepare("SELECT * FROM ingresos_extra WHERE usuario_id = ? AND mes_key LIKE ?").all(req.user.id, `%-${anio}`);
  res.json({ configs, gastos: allGastos, pagos: allPagos, ingresosExtra: allIngresosExtra });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  Servidor de Finanzas corriendo en: http://localhost:${PORT}\n`);
  if (!process.env.JWT_SECRET) {
    console.log('  Aviso: define JWT_SECRET en producción para que las sesiones no se invaliden al reiniciar.\n');
  }
});
