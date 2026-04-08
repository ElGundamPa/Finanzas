const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

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
`);

const [,, comando, ...args] = process.argv;

function mostrarAyuda() {
  console.log(`
  Gestión de Usuarios - Finanzas Personales
  ==========================================

  Comandos disponibles:

    node admin.js crear <usuario> <nombre> <contraseña>
      Crea un nuevo usuario

    node admin.js listar
      Lista todos los usuarios

    node admin.js cambiar-clave <usuario> <nueva_contraseña>
      Cambia la contraseña de un usuario

    node admin.js eliminar <usuario>
      Elimina un usuario y todos sus datos

  Ejemplos:
    node admin.js crear juan "Juan Pérez" MiClave123
    node admin.js crear maria "María López" OtraClave456
    node admin.js listar
    node admin.js cambiar-clave juan NuevaClave789
    node admin.js eliminar maria
  `);
}

switch (comando) {
  case 'crear': {
    const [username, nombre, password] = args;
    if (!username || !nombre || !password) {
      console.error('\n  Error: Faltan argumentos.\n  Uso: node admin.js crear <usuario> <nombre> <contraseña>\n');
      process.exit(1);
    }
    const userLower = username.trim().toLowerCase();
    const existing = db.prepare('SELECT id FROM usuarios WHERE username = ?').get(userLower);
    if (existing) {
      console.error(`\n  Error: El usuario "${userLower}" ya existe.\n`);
      process.exit(1);
    }
    const hash = bcrypt.hashSync(password, 10);
    const isFirstUser = !db.prepare('SELECT id FROM usuarios LIMIT 1').get();
    db.prepare(
      'INSERT INTO usuarios (username, password_hash, nombre, es_admin) VALUES (?, ?, ?, ?)'
    ).run(userLower, hash, nombre.trim(), isFirstUser ? 1 : 0);
    console.log(`\n  Usuario creado exitosamente:`);
    console.log(`    Usuario:  ${userLower}`);
    console.log(`    Nombre:   ${nombre.trim()}`);
    console.log(`    Admin:    ${isFirstUser ? 'Sí (primer usuario)' : 'No'}\n`);
    break;
  }

  case 'listar': {
    const usuarios = db.prepare('SELECT id, username, nombre, es_admin, created_at FROM usuarios ORDER BY id').all();
    if (usuarios.length === 0) {
      console.log('\n  No hay usuarios registrados.\n');
    } else {
      console.log(`\n  Usuarios registrados (${usuarios.length}):`);
      console.log('  ' + '-'.repeat(60));
      usuarios.forEach(u => {
        console.log(`  ID: ${u.id} | ${u.username} | ${u.nombre} | ${u.es_admin ? 'Admin' : 'Usuario'} | ${u.created_at}`);
      });
      console.log('  ' + '-'.repeat(60) + '\n');
    }
    break;
  }

  case 'cambiar-clave': {
    const [username, newPass] = args;
    if (!username || !newPass) {
      console.error('\n  Error: Faltan argumentos.\n  Uso: node admin.js cambiar-clave <usuario> <nueva_contraseña>\n');
      process.exit(1);
    }
    const user = db.prepare('SELECT id FROM usuarios WHERE username = ?').get(username.trim().toLowerCase());
    if (!user) {
      console.error(`\n  Error: El usuario "${username}" no existe.\n`);
      process.exit(1);
    }
    const hash = bcrypt.hashSync(newPass, 10);
    db.prepare('UPDATE usuarios SET password_hash = ? WHERE id = ?').run(hash, user.id);
    console.log(`\n  Contraseña de "${username}" actualizada exitosamente.\n`);
    break;
  }

  case 'eliminar': {
    const [username] = args;
    if (!username) {
      console.error('\n  Error: Falta el nombre de usuario.\n  Uso: node admin.js eliminar <usuario>\n');
      process.exit(1);
    }
    const user = db.prepare('SELECT id, nombre FROM usuarios WHERE username = ?').get(username.trim().toLowerCase());
    if (!user) {
      console.error(`\n  Error: El usuario "${username}" no existe.\n`);
      process.exit(1);
    }
    db.prepare('DELETE FROM gastos WHERE usuario_id = ?').run(user.id);
    db.prepare('DELETE FROM configuraciones WHERE usuario_id = ?').run(user.id);
    db.prepare('DELETE FROM usuarios WHERE id = ?').run(user.id);
    console.log(`\n  Usuario "${username}" (${user.nombre}) eliminado junto con todos sus datos.\n`);
    break;
  }

  default:
    mostrarAyuda();
}

db.close();
