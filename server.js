const http = require('http');
const express = require('express');
const cors = require('cors');
const { Server: SocketIOServer } = require('socket.io');
const WebSocket = require('ws');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);

// MySQL Database Connection Pool (cPanel)
let dbPool = null;
let useDatabase = false;

// Default In-Memory Fallback Users
let memoryUsers = [
  {
    id: 1,
    rut: '1-9',
    nombre: 'Administrador',
    apellidoPaterno: 'Sistema',
    apellidoMaterno: 'Escuela',
    email: 'admin@escuelaporongo.cl',
    password: 'admin123',
    rol: 'administrador',
    createdAt: new Date().toISOString()
  },
  {
    id: 2,
    rut: '15.432.109-8',
    nombre: 'Carlos',
    apellidoPaterno: 'Muñoz',
    apellidoMaterno: 'Rojas',
    email: 'profesor@escuelaporongo.cl',
    password: 'profe123',
    rol: 'docente',
    createdAt: new Date().toISOString()
  }
];

let memoryRules = [
  { id: 1, domain: 'malicious-example.com', createdAt: new Date().toISOString() }
];

async function initDatabase() {
  const dbHost = process.env.DB_HOST;
  const dbUser = process.env.DB_USER;
  const dbPass = process.env.DB_PASS;
  const dbName = process.env.DB_NAME;
  const dbPort = parseInt(process.env.DB_PORT || '3306');

  if (!dbHost || !dbUser || !dbName) {
    console.log('ℹ️ [DB] Variables de base de datos MySQL no configuradas. Usando almacenamiento en memoria.');
    return;
  }

  try {
    dbPool = mysql.createPool({
      host: dbHost,
      user: dbUser,
      password: dbPass,
      database: dbName,
      port: dbPort,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });

    const connection = await dbPool.getConnection();
    console.log(`✅ [DB] Conectado exitosamente a la base de datos MySQL de cPanel: ${dbName} @ ${dbHost}`);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        rut VARCHAR(50) UNIQUE NOT NULL,
        nombre VARCHAR(100) NOT NULL,
        apellidoPaterno VARCHAR(100) NOT NULL,
        apellidoMaterno VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        rol VARCHAR(50) NOT NULL DEFAULT 'docente',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS rules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain VARCHAR(255) UNIQUE NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    const [existingUsers] = await connection.query('SELECT COUNT(*) as count FROM users');
    if (existingUsers[0].count === 0) {
      for (const u of memoryUsers) {
        await connection.query(
          'INSERT INTO users (rut, nombre, apellidoPaterno, apellidoMaterno, email, password, rol) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [u.rut, u.nombre, u.apellidoPaterno, u.apellidoMaterno, u.email, u.password, u.rol]
        );
      }
      console.log('✅ [DB] Usuarios iniciales por defecto sembrados en MySQL cPanel.');
    }

    connection.release();
    useDatabase = true;
  } catch (err) {
    console.error('❌ [DB] Error al conectar con la base de datos MySQL de cPanel:', err.message);
    console.log('ℹ️ [DB] Continuando con almacenamiento temporal en memoria.');
    useDatabase = false;
  }
}

initDatabase();

// Active Session Tokens
const activeAuthTokens = new Map();

function generateAuthToken(user) {
  const token = 'token_' + crypto.randomBytes(32).toString('hex');
  activeAuthTokens.set(token, {
    id: user.id,
    rut: user.rut,
    nombreCompleto: `${user.nombre} ${user.apellidoPaterno} ${user.apellidoMaterno}`,
    email: user.email,
    rol: user.rol,
    createdAt: Date.now()
  });
  return token;
}

function isValidToken(token) {
  if (!token) return false;
  return activeAuthTokens.has(token);
}

const connectedAgents = new Map();
const connectedAdmins = new Map();

// ----------------------------------------------------
// AUTHENTICATION REST API ENDPOINTS
// ----------------------------------------------------

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Ingrese usuario/RUT y contraseña' });
  }

  const cleanInput = username.trim().toLowerCase();

  try {
    let user = null;

    if (useDatabase && dbPool) {
      const [rows] = await dbPool.query(
        'SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(REPLACE(rut, ".", "")) = ?',
        [cleanInput, cleanInput.replace(/\./g, '')]
      );
      if (rows.length > 0) {
        user = rows[0];
      }
    } else {
      user = memoryUsers.find(u => 
        u.email.toLowerCase() === cleanInput || 
        u.rut.toLowerCase().replace(/\./g, '') === cleanInput.replace(/\./g, '')
      );
    }

    if (user && user.password === password) {
      const token = generateAuthToken(user);
      console.log(`[Server] Login exitoso para: ${user.nombre} ${user.apellidoPaterno} (${user.rol})`);
      return res.json({
        success: true,
        token,
        user: {
          id: user.id,
          rut: user.rut,
          nombre: user.nombre,
          apellidoPaterno: user.apellidoPaterno,
          apellidoMaterno: user.apellidoMaterno,
          nombreCompleto: `${user.nombre} ${user.apellidoPaterno} ${user.apellidoMaterno}`,
          email: user.email,
          rol: user.rol
        }
      });
    }

    return res.status(401).json({ success: false, error: 'Usuario, RUT o contraseña incorrectos' });
  } catch (err) {
    console.error('Error en /api/login:', err);
    return res.status(500).json({ success: false, error: 'Error del servidor' });
  }
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token || !isValidToken(token)) {
    return res.status(401).json({ success: false, error: 'No autorizado. Inicie sesión.' });
  }
  req.authUser = activeAuthTokens.get(token);
  next();
}

// ----------------------------------------------------
// USER & TEACHER MANAGEMENT REST API ENDPOINTS
// ----------------------------------------------------

app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    let usersList = [];
    if (useDatabase && dbPool) {
      const [rows] = await dbPool.query('SELECT id, rut, nombre, apellidoPaterno, apellidoMaterno, email, password, rol, createdAt FROM users ORDER BY id DESC');
      usersList = rows.map(u => ({
        ...u,
        nombreCompleto: `${u.nombre} ${u.apellidoPaterno} ${u.apellidoMaterno}`
      }));
    } else {
      usersList = memoryUsers.map(u => ({
        id: u.id,
        rut: u.rut,
        nombre: u.nombre,
        apellidoPaterno: u.apellidoPaterno,
        apellidoMaterno: u.apellidoMaterno,
        nombreCompleto: `${u.nombre} ${u.apellidoPaterno} ${u.apellidoMaterno}`,
        email: u.email,
        password: u.password,
        rol: u.rol,
        createdAt: u.createdAt
      }));
    }
    res.json({ success: true, users: usersList });
  } catch (err) {
    console.error('Error en GET /api/users:', err);
    res.status(500).json({ success: false, error: 'Error al consultar usuarios' });
  }
});

app.post('/api/users', authMiddleware, async (req, res) => {
  const { rut, nombre, apellidoPaterno, apellidoMaterno, email, password, rol } = req.body;

  if (!rut || !nombre || !apellidoPaterno || !apellidoMaterno || !email || !password) {
    return res.status(400).json({ success: false, error: 'Todos los campos son obligatorios' });
  }

  const cleanRut = rut.trim();
  const cleanEmail = email.trim().toLowerCase();

  try {
    if (useDatabase && dbPool) {
      const [existing] = await dbPool.query(
        'SELECT id FROM users WHERE LOWER(email) = ? OR LOWER(REPLACE(rut, ".", "")) = ?',
        [cleanEmail, cleanRut.toLowerCase().replace(/\./g, '')]
      );

      if (existing.length > 0) {
        return res.status(400).json({ success: false, error: 'El RUT o Correo electrónico ya está registrado' });
      }

      const [result] = await dbPool.query(
        'INSERT INTO users (rut, nombre, apellidoPaterno, apellidoMaterno, email, password, rol) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [cleanRut, nombre.trim(), apellidoPaterno.trim(), apellidoMaterno.trim(), cleanEmail, password, rol || 'docente']
      );

      const newUser = {
        id: result.insertId,
        rut: cleanRut,
        nombre: nombre.trim(),
        apellidoPaterno: apellidoPaterno.trim(),
        apellidoMaterno: apellidoMaterno.trim(),
        nombreCompleto: `${nombre.trim()} ${apellidoPaterno.trim()} ${apellidoMaterno.trim()}`,
        email: cleanEmail,
        password: password,
        rol: rol || 'docente',
        createdAt: new Date().toISOString()
      };

      console.log(`[Server DB] Nuevo docente/usuario registrado en MySQL: ${newUser.nombreCompleto}`);
      return res.json({ success: true, user: newUser });
    } else {
      const existingUser = memoryUsers.find(u => 
        u.email.toLowerCase() === cleanEmail || 
        u.rut.toLowerCase().replace(/\./g, '') === cleanRut.toLowerCase().replace(/\./g, '')
      );

      if (existingUser) {
        return res.status(400).json({ success: false, error: 'El RUT o Correo electrónico ya está registrado' });
      }

      const newUser = {
        id: memoryUsers.length > 0 ? Math.max(...memoryUsers.map(u => u.id)) + 1 : 1,
        rut: cleanRut,
        nombre: nombre.trim(),
        apellidoPaterno: apellidoPaterno.trim(),
        apellidoMaterno: apellidoMaterno.trim(),
        email: cleanEmail,
        password: password,
        rol: rol || 'docente',
        createdAt: new Date().toISOString()
      };

      memoryUsers.push(newUser);
      return res.json({ success: true, user: newUser });
    }
  } catch (err) {
    console.error('Error en POST /api/users:', err);
    res.status(500).json({ success: false, error: 'Error al registrar usuario' });
  }
});

// UPDATE User Account
app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { rut, nombre, apellidoPaterno, apellidoMaterno, email, password, rol } = req.body;

  if (!rut || !nombre || !apellidoPaterno || !apellidoMaterno || !email) {
    return res.status(400).json({ success: false, error: 'Campos requeridos incompletos' });
  }

  const cleanRut = rut.trim();
  const cleanEmail = email.trim().toLowerCase();

  try {
    if (useDatabase && dbPool) {
      // Check duplicate email/rut on other users
      const [existing] = await dbPool.query(
        'SELECT id FROM users WHERE (LOWER(email) = ? OR LOWER(REPLACE(rut, ".", "")) = ?) AND id != ?',
        [cleanEmail, cleanRut.toLowerCase().replace(/\./g, ''), userId]
      );

      if (existing.length > 0) {
        return res.status(400).json({ success: false, error: 'El RUT o Correo ya pertenece a otro usuario' });
      }

      if (password && password.trim()) {
        await dbPool.query(
          'UPDATE users SET rut = ?, nombre = ?, apellidoPaterno = ?, apellidoMaterno = ?, email = ?, password = ?, rol = ? WHERE id = ?',
          [cleanRut, nombre.trim(), apellidoPaterno.trim(), apellidoMaterno.trim(), cleanEmail, password, rol || 'docente', userId]
        );
      } else {
        await dbPool.query(
          'UPDATE users SET rut = ?, nombre = ?, apellidoPaterno = ?, apellidoMaterno = ?, email = ?, rol = ? WHERE id = ?',
          [cleanRut, nombre.trim(), apellidoPaterno.trim(), apellidoMaterno.trim(), cleanEmail, rol || 'docente', userId]
        );
      }

      console.log(`[Server DB] Usuario ID ${userId} actualizado en MySQL`);
      return res.json({ success: true, updatedId: userId });
    } else {
      const userIndex = memoryUsers.findIndex(u => u.id === userId);
      if (userIndex === -1) {
        return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
      }

      memoryUsers[userIndex] = {
        ...memoryUsers[userIndex],
        rut: cleanRut,
        nombre: nombre.trim(),
        apellidoPaterno: apellidoPaterno.trim(),
        apellidoMaterno: apellidoMaterno.trim(),
        email: cleanEmail,
        password: (password && password.trim()) ? password : memoryUsers[userIndex].password,
        rol: rol || 'docente'
      };

      return res.json({ success: true, updatedId: userId });
    }
  } catch (err) {
    console.error('Error en PUT /api/users:', err);
    res.status(500).json({ success: false, error: 'Error al actualizar usuario' });
  }
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  
  if (userId === 1) {
    return res.status(400).json({ success: false, error: 'No se puede eliminar la cuenta de administrador principal' });
  }

  try {
    if (useDatabase && dbPool) {
      await dbPool.query('DELETE FROM users WHERE id = ?', [userId]);
      console.log(`[Server DB] Usuario ID ${userId} eliminado de MySQL`);
    } else {
      memoryUsers = memoryUsers.filter(u => u.id !== userId);
    }

    res.json({ success: true, removedId: userId });
  } catch (err) {
    console.error('Error en DELETE /api/users:', err);
    res.status(500).json({ success: false, error: 'Error al eliminar usuario' });
  }
});

// ----------------------------------------------------
// SOCKET.IO & WEBRTC SIGNALING SERVER
// ----------------------------------------------------

const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (isValidToken(token)) {
    socket.userData = activeAuthTokens.get(token);
    return next();
  }
  return next(new Error('Authentication error: Token inválido o no proporcionado'));
});

io.on('connection', async (socket) => {
  console.log(`[Server] Admin/Docente autenticado conectado: ${socket.id} (${socket.userData.nombreCompleto})`);
  connectedAdmins.set(socket.id, socket);

  let currentRules = memoryRules;
  if (useDatabase && dbPool) {
    try {
      const [rows] = await dbPool.query('SELECT * FROM rules ORDER BY id DESC');
      currentRules = rows;
    } catch (e) {}
  }

  socket.emit('agent-list-update', getActiveAgentsList());
  socket.emit('rules-list-update', currentRules);

  socket.on('disconnect', () => {
    console.log(`[Server] Admin/Docente desconectado: ${socket.id}`);
    connectedAdmins.delete(socket.id);
  });

  socket.on('admin-command', (data) => {
    const { targetAgentId, command, payload } = data;
    console.log(`[Server] ${socket.userData.nombreCompleto} envió orden '${command}' a agente '${targetAgentId}'`);

    const agentObj = connectedAgents.get(targetAgentId);
    if (agentObj && agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
      agentObj.ws.send(JSON.stringify({
        type: command,
        adminId: socket.id,
        ...payload
      }));
    } else {
      socket.emit('command-error', { error: `Agente ${targetAgentId} fuera de línea.` });
    }
  });

  socket.on('webrtc-answer', (data) => {
    const { targetAgentId, sdp } = data;
    const agentObj = connectedAgents.get(targetAgentId);
    if (agentObj && agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
      agentObj.ws.send(JSON.stringify({
        type: 'WEBRTC_ANSWER',
        adminId: socket.id,
        sdp
      }));
    }
  });

  socket.on('webrtc-ice-candidate-admin', (data) => {
    const { targetAgentId, candidate } = data;
    const agentObj = connectedAgents.get(targetAgentId);
    if (agentObj && agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
      agentObj.ws.send(JSON.stringify({
        type: 'WEBRTC_ICE_CANDIDATE',
        adminId: socket.id,
        candidate
      }));
    }
  });
});

const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws) => {
  let currentAgentId = null;

  ws.on('message', async (messageRaw) => {
    try {
      const msg = JSON.parse(messageRaw);

      switch (msg.type) {
        case 'REGISTER_AGENT':
        case 'AGENT_HEARTBEAT':
        case 'AGENT_TAB_UPDATE':
          if (msg.data && msg.data.agentId) {
            currentAgentId = msg.data.agentId;
            connectedAgents.set(currentAgentId, {
              ws,
              info: msg.data,
              lastSeen: Date.now()
            });
            broadcastAgentsToAdmins();
          }
          break;

        case 'WEBRTC_OFFER':
          if (msg.adminId && connectedAdmins.has(msg.adminId)) {
            const adminSocket = connectedAdmins.get(msg.adminId);
            adminSocket.emit('webrtc-offer', {
              agentId: msg.agentId || currentAgentId,
              sdp: msg.sdp
            });
          }
          break;

        case 'LIVE_SCREEN_SNAPSHOT':
          if (msg.adminId && connectedAdmins.has(msg.adminId)) {
            const adminSocket = connectedAdmins.get(msg.adminId);
            adminSocket.emit('agent-screen-snapshot', {
              agentId: msg.agentId || currentAgentId,
              image: msg.image
            });
          }
          break;

        case 'WEBRTC_ICE_CANDIDATE':
          if (msg.adminId && connectedAdmins.has(msg.adminId)) {
            const adminSocket = connectedAdmins.get(msg.adminId);
            adminSocket.emit('webrtc-ice-candidate', {
              agentId: msg.agentId || currentAgentId,
              candidate: msg.candidate
            });
          }
          break;

        case 'WEBRTC_STREAM_ERROR':
        case 'WEBRTC_STREAM_CANCELLED':
          if (msg.adminId && connectedAdmins.has(msg.adminId)) {
            const adminSocket = connectedAdmins.get(msg.adminId);
            adminSocket.emit('webrtc-stream-status', {
              agentId: msg.agentId || currentAgentId,
              status: msg.type,
              error: msg.error || null
            });
          }
          break;

        case 'RULE_ADDED_NOTIFY':
          if (msg.rule) {
            if (useDatabase && dbPool) {
              await dbPool.query('INSERT IGNORE INTO rules (id, domain) VALUES (?, ?)', [msg.rule.id, msg.rule.domain]);
              const [allRules] = await dbPool.query('SELECT * FROM rules ORDER BY id DESC');
              io.emit('rules-list-update', allRules);
            } else if (!memoryRules.some(r => r.id === msg.rule.id)) {
              memoryRules.push({
                id: msg.rule.id,
                domain: msg.rule.domain,
                createdAt: new Date().toISOString()
              });
              io.emit('rules-list-update', memoryRules);
            }
          }
          break;

        default:
          console.log('[Server] Unhandled agent message type:', msg.type);
      }
    } catch (err) {
      console.error('[Server] Error handling agent websocket message:', err);
    }
  });

  ws.on('close', () => {
    if (currentAgentId) {
      console.log(`[Server] Agent disconnected: ${currentAgentId}`);
      connectedAgents.delete(currentAgentId);
      broadcastAgentsToAdmins();
    }
  });
});

server.on('upgrade', (request, socket, head) => {
  const pathname = request.url;

  if (pathname.startsWith('/socket.io/')) {
    return;
  } else {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  }
});

function getActiveAgentsList() {
  const list = [];
  const now = Date.now();
  for (const [agentId, agent] of connectedAgents.entries()) {
    if (now - agent.lastSeen <= 15000) {
      list.push({
        ...agent.info,
        status: 'online',
        lastSeen: agent.lastSeen
      });
    }
  }
  return list;
}

function broadcastAgentsToAdmins() {
  const agentsList = getActiveAgentsList();
  io.emit('agent-list-update', agentsList);
}

app.get('/api/agents', authMiddleware, (req, res) => {
  res.json({ success: true, count: connectedAgents.size, agents: getActiveAgentsList() });
});

app.get('/api/rules', authMiddleware, async (req, res) => {
  try {
    let rulesList = memoryRules;
    if (useDatabase && dbPool) {
      const [rows] = await dbPool.query('SELECT * FROM rules ORDER BY id DESC');
      rulesList = rows;
    }
    res.json({ success: true, rules: rulesList });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Error al consultar reglas' });
  }
});

app.post('/api/rules', authMiddleware, async (req, res) => {
  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'El dominio es requerido' });
  }

  const cleanDomain = domain.trim().toLowerCase();
  const ruleId = Math.floor(Math.random() * 899999) + 100000;
  const newRule = { id: ruleId, domain: cleanDomain, createdAt: new Date().toISOString() };
  
  try {
    let rulesList = memoryRules;
    if (useDatabase && dbPool) {
      await dbPool.query('INSERT INTO rules (id, domain) VALUES (?, ?)', [ruleId, cleanDomain]);
      const [rows] = await dbPool.query('SELECT * FROM rules ORDER BY id DESC');
      rulesList = rows;
    } else {
      memoryRules.push(newRule);
      rulesList = memoryRules;
    }

    io.emit('rules-list-update', rulesList);

    for (const [agentId, agentObj] of connectedAgents.entries()) {
      if (agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
        agentObj.ws.send(JSON.stringify({
          type: 'COMMAND_BLOCK_SITE',
          domain: cleanDomain
        }));
      }
    }

    res.json({ success: true, rule: newRule });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Error al crear regla en la base de datos' });
  }
});

app.delete('/api/rules/:id', authMiddleware, async (req, res) => {
  const ruleId = parseInt(req.params.id);
  
  try {
    let rulesList = memoryRules;
    if (useDatabase && dbPool) {
      await dbPool.query('DELETE FROM rules WHERE id = ?', [ruleId]);
      const [rows] = await dbPool.query('SELECT * FROM rules ORDER BY id DESC');
      rulesList = rows;
    } else {
      memoryRules = memoryRules.filter(r => r.id !== ruleId);
      rulesList = memoryRules;
    }

    io.emit('rules-list-update', rulesList);

    for (const [agentId, agentObj] of connectedAgents.entries()) {
      if (agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
        agentObj.ws.send(JSON.stringify({
          type: 'COMMAND_UNBLOCK_SITE',
          ruleId: ruleId
        }));
      }
    }

    res.json({ success: true, removedId: ruleId });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Error al eliminar regla de la base de datos' });
  }
});

setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [agentId, agent] of connectedAgents.entries()) {
    if (now - agent.lastSeen > 20000) {
      console.log(`[Server] Cleaning up timed-out agent: ${agentId}`);
      connectedAgents.delete(agentId);
      changed = true;
    }
  }
  if (changed) {
    broadcastAgentsToAdmins();
  }
}, 10000);

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🚀 Control & Signaling Server running on port ${PORT}`);
  console.log(`📡 WebSocket endpoint for Agents: ws://localhost:${PORT}`);
  console.log(`💻 Socket.io endpoint for Dashboard: http://localhost:${PORT}`);
  console.log(`====================================================`);
});
