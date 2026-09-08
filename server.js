const http = require('http');
const express = require('express');
const cors = require('cors');
const { Server: SocketIOServer } = require('socket.io');
const WebSocket = require('ws');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);

// In-Memory Database for Users (Teachers & Administrators)
let registeredUsers = [
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

// Active Session Tokens (token -> userObj)
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

// In-Memory Data Store for Agents & Rules
const connectedAgents = new Map(); // agentId -> { ws, info, lastSeen }
const connectedAdmins = new Map(); // socketId -> { socket, user }
let globalRules = [
  { id: 1, domain: 'malicious-example.com', createdAt: new Date().toISOString() }
];

// ----------------------------------------------------
// AUTHENTICATION REST API ENDPOINTS
// ----------------------------------------------------

// Login Endpoint (Supports Email or RUT)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Ingrese usuario/RUT y contraseña' });
  }

  const cleanInput = username.trim().toLowerCase();

  // Find user by Email or RUT
  const user = registeredUsers.find(u => 
    u.email.toLowerCase() === cleanInput || 
    u.rut.toLowerCase().replace(/\./g, '') === cleanInput.replace(/\./g, '')
  );

  if (user && user.password === password) {
    const token = generateAuthToken(user);
    console.log(`[Server] Login exitoso para el usuario: ${user.nombre} ${user.apellidoPaterno} (${user.rol})`);
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
});

// Middleware for protecting REST API endpoints
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

// List registered users
app.get('/api/users', authMiddleware, (req, res) => {
  const safeUsers = registeredUsers.map(u => ({
    id: u.id,
    rut: u.rut,
    nombre: u.nombre,
    apellidoPaterno: u.apellidoPaterno,
    apellidoMaterno: u.apellidoMaterno,
    nombreCompleto: `${u.nombre} ${u.apellidoPaterno} ${u.apellidoMaterno}`,
    email: u.email,
    rol: u.rol,
    createdAt: u.createdAt
  }));
  res.json({ success: true, users: safeUsers });
});

// Create new Teacher / User account
app.post('/api/users', authMiddleware, (req, res) => {
  const { rut, nombre, apellidoPaterno, apellidoMaterno, email, password, rol } = req.body;

  if (!rut || !nombre || !apellidoPaterno || !apellidoMaterno || !email || !password) {
    return res.status(400).json({ success: false, error: 'Todos los campos son obligatorios' });
  }

  const cleanRut = rut.trim();
  const cleanEmail = email.trim().toLowerCase();

  // Check if RUT or Email already exists
  const existingUser = registeredUsers.find(u => 
    u.email.toLowerCase() === cleanEmail || 
    u.rut.toLowerCase().replace(/\./g, '') === cleanRut.toLowerCase().replace(/\./g, '')
  );

  if (existingUser) {
    return res.status(400).json({ success: false, error: 'El RUT o Correo electrónico ya está registrado' });
  }

  const newUser = {
    id: registeredUsers.length > 0 ? Math.max(...registeredUsers.map(u => u.id)) + 1 : 1,
    rut: cleanRut,
    nombre: nombre.trim(),
    apellidoPaterno: apellidoPaterno.trim(),
    apellidoMaterno: apellidoMaterno.trim(),
    email: cleanEmail,
    password: password,
    rol: rol || 'docente',
    createdAt: new Date().toISOString()
  };

  registeredUsers.push(newUser);
  console.log(`[Server] Nuevo usuario creado: ${newUser.nombre} ${newUser.apellidoPaterno} (${newUser.rol})`);

  res.json({
    success: true,
    user: {
      id: newUser.id,
      rut: newUser.rut,
      nombre: newUser.nombre,
      apellidoPaterno: newUser.apellidoPaterno,
      apellidoMaterno: newUser.apellidoMaterno,
      nombreCompleto: `${newUser.nombre} ${newUser.apellidoPaterno} ${newUser.apellidoMaterno}`,
      email: newUser.email,
      rol: newUser.rol,
      createdAt: newUser.createdAt
    }
  });
});

// Delete User account
app.delete('/api/users/:id', authMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  
  if (userId === 1) {
    return res.status(400).json({ success: false, error: 'No se puede eliminar la cuenta de administrador principal' });
  }

  registeredUsers = registeredUsers.filter(u => u.id !== userId);
  console.log(`[Server] Usuario ID ${userId} eliminado`);

  res.json({ success: true, removedId: userId });
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

// Authenticate Socket.io Connections
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (isValidToken(token)) {
    socket.userData = activeAuthTokens.get(token);
    return next();
  }
  return next(new Error('Authentication error: Token inválido o no proporcionado'));
});

io.on('connection', (socket) => {
  console.log(`[Server] Admin/Docente autenticado conectado: ${socket.id} (${socket.userData.nombreCompleto})`);
  connectedAdmins.set(socket.id, socket);

  socket.emit('agent-list-update', getActiveAgentsList());
  socket.emit('rules-list-update', globalRules);

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

// Native WebSocket Server for Extension Agents
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws) => {
  let currentAgentId = null;

  ws.on('message', (messageRaw) => {
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
          if (msg.rule && !globalRules.some(r => r.id === msg.rule.id)) {
            globalRules.push({
              id: msg.rule.id,
              domain: msg.rule.domain,
              createdAt: new Date().toISOString()
            });
            io.emit('rules-list-update', globalRules);
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

// REST API Rules Endpoints
app.get('/api/agents', authMiddleware, (req, res) => {
  res.json({ success: true, count: connectedAgents.size, agents: getActiveAgentsList() });
});

app.get('/api/rules', authMiddleware, (req, res) => {
  res.json({ success: true, rules: globalRules });
});

app.post('/api/rules', authMiddleware, (req, res) => {
  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'El dominio es requerido' });
  }

  const cleanDomain = domain.trim().toLowerCase();
  const ruleId = Math.floor(Math.random() * 899999) + 100000;
  const newRule = { id: ruleId, domain: cleanDomain, createdAt: new Date().toISOString() };
  
  globalRules.push(newRule);
  io.emit('rules-list-update', globalRules);

  for (const [agentId, agentObj] of connectedAgents.entries()) {
    if (agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
      agentObj.ws.send(JSON.stringify({
        type: 'COMMAND_BLOCK_SITE',
        domain: cleanDomain
      }));
    }
  }

  res.json({ success: true, rule: newRule });
});

app.delete('/api/rules/:id', authMiddleware, (req, res) => {
  const ruleId = parseInt(req.params.id);
  globalRules = globalRules.filter(r => r.id !== ruleId);
  io.emit('rules-list-update', globalRules);

  for (const [agentId, agentObj] of connectedAgents.entries()) {
    if (agentObj.ws && agentObj.ws.readyState === WebSocket.OPEN) {
      agentObj.ws.send(JSON.stringify({
        type: 'COMMAND_UNBLOCK_SITE',
        ruleId: ruleId
      }));
    }
  }

  res.json({ success: true, removedId: ruleId });
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
