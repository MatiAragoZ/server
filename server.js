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

// Default Admin Credentials (can be configured via ENV)
const ADMIN_USER = process.env.ADMIN_USER || 'admin@escuelaporongo.cl';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

// Active Session Tokens (token -> { username, createdAt })
const activeAuthTokens = new Map();

function generateAuthToken(username) {
  const token = 'token_' + crypto.randomBytes(32).toString('hex');
  activeAuthTokens.set(token, { username, createdAt: Date.now() });
  return token;
}

function isValidToken(token) {
  if (!token) return false;
  return activeAuthTokens.has(token);
}

// In-Memory Data Store
const connectedAgents = new Map(); // agentId -> { ws, info, lastSeen }
const connectedAdmins = new Map(); // socketId -> { socket, username }
let globalRules = [
  { id: 1, domain: 'malicious-example.com', createdAt: new Date().toISOString() }
];

// Authentication REST API Endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Ingrese usuario y contraseña' });
  }

  if (username.trim() === ADMIN_USER && password === ADMIN_PASS) {
    const token = generateAuthToken(username.trim());
    console.log(`[Server] Login exitoso para el usuario: ${username}`);
    return res.json({
      success: true,
      token,
      user: { username: username.trim(), role: 'administrator' }
    });
  }

  return res.status(401).json({ success: false, error: 'Usuario o contraseña incorrectos' });
});

// Middleware for protecting REST API endpoints
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token || !isValidToken(token)) {
    return res.status(401).json({ success: false, error: 'No autorizado. Inicie sesión.' });
  }
  next();
}

// 1. Socket.io Server for Dashboard Admin connections
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
  console.log(`[Server] Admin autenticado conectado: ${socket.id} (${socket.userData.username})`);
  connectedAdmins.set(socket.id, socket);

  // Send initial state to newly connected authenticated admin
  socket.emit('agent-list-update', getActiveAgentsList());
  socket.emit('rules-list-update', globalRules);

  socket.on('disconnect', () => {
    console.log(`[Server] Admin desconectado: ${socket.id}`);
    connectedAdmins.delete(socket.id);
  });

  // Admin -> Agent Commands
  socket.on('admin-command', (data) => {
    const { targetAgentId, command, payload } = data;
    console.log(`[Server] Admin ${socket.userData.username} envió orden '${command}' a agente '${targetAgentId}'`);

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

  // WebRTC Signaling Answer / Candidate from Admin -> Agent
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

// 2. Native WebSocket Server for Chrome Extension Agents
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

// Handle HTTP Upgrade request routing (Socket.io vs Native WS Agent)
server.on('upgrade', (request, socket, head) => {
  const pathname = request.url;

  if (pathname.startsWith('/socket.io/')) {
    // Let socket.io handle its own upgrade
    return;
  } else {
    // Native WebSocket upgrade for Extension Agents
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  }
});

// Helper functions
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

// REST API Endpoints
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

// Periodic stale connection cleanup
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
