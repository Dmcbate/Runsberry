const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const SECRET = process.env.BERRY_WS_SECRET || 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET';

// 1-on-1 Messenger clients: Map<userId, Set<WebSocket>>
const clients = new Map();
// Chatroom & Group subscribers: Map<roomId, Set<WebSocket>>
const rooms = new Map();

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [uidStr, tsStr, sig] = parts;
  const uid = parseInt(uidStr, 10);
  const ts = parseInt(tsStr, 10);
  if (!uid || !ts) return null;

  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > 86400) return null;

  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(`${uid}.${ts}`)
    .digest('hex');

  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;

  return uid;
}

function sendToUser(targetUserId, payloadObj) {
  const sockets = clients.get(Number(targetUserId));
  if (!sockets || sockets.size === 0) return false;
  const data = JSON.stringify(payloadObj);
  let delivered = false;
  for (const ws of sockets) {
    if (ws.readyState === 1) {
      ws.send(data);
      delivered = true;
    }
  }
  return delivered;
}

function broadcastToRoom(roomId, payloadObj, excludeWs = null) {
  const roomSet = rooms.get(Number(roomId));
  if (!roomSet || roomSet.size === 0) return;
  const data = JSON.stringify(payloadObj);
  for (const ws of roomSet) {
    if (ws !== excludeWs && ws.readyState === 1) {
      ws.send(data);
    }
  }
}

function broadcastPresence(uid, isOnline) {
  const payload = JSON.stringify({ type: 'presence', user_id: uid, online: isOnline });
  for (const [, sockets] of clients) {
    for (const ws of sockets) {
      if (ws.readyState === 1 && ws.watchingPartnerId === uid) {
        ws.send(payload);
      }
    }
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, onlineUsers: clients.size, activeRooms: rooms.size }));
  }

  if (req.method === 'POST' && req.url === '/push') {
    if (req.headers['x-berry-secret'] !== SECRET) {
      res.writeHead(403);
      return res.end('Forbidden');
    }
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (data.to) sendToUser(data.to, data.payload);
        if (data.room_id) broadcastToRoom(data.room_id, data.payload);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400);
        res.end('Bad JSON');
      }
    });
    return;
  }

  res.writeHead(200);
  res.end('Berry Realtime Hub');
});

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token');
  const partnerParam = parseInt(url.searchParams.get('partner_id') || '0', 10);
  const roomParam = parseInt(url.searchParams.get('room_id') || '0', 10);

  const userId = verifyToken(token);
  if (!userId) {
    ws.close(4001, 'Unauthorized');
    return;
  }

  ws.userId = userId;
  ws.watchingPartnerId = partnerParam || 0;
  ws.roomId = roomParam || 0;
  ws.isAlive = true;

  if (!clients.has(userId)) clients.set(userId, new Set());
  const wasOffline = clients.get(userId).size === 0;
  clients.get(userId).add(ws);

  if (wasOffline) broadcastPresence(userId, true);

  if (ws.watchingPartnerId) {
    const partnerOnline = clients.has(ws.watchingPartnerId) && clients.get(ws.watchingPartnerId).size > 0;
    ws.send(JSON.stringify({ type: 'presence', user_id: ws.watchingPartnerId, online: partnerOnline }));
  }

  // Subscribe to Chatroom / Group channel if room_id is provided
  if (ws.roomId > 0) {
    if (!rooms.has(ws.roomId)) rooms.set(ws.roomId, new Set());
    rooms.get(ws.roomId).add(ws);
  }

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch (e) { return; }

    if (msg.type === 'ping') {
      ws.isAlive = true;
      ws.send(JSON.stringify({ type: 'pong' }));
      return;
    }

    // Chatroom & Group Broadcast Events
    if (['room_post', 'room_edit', 'room_delete', 'room_react', 'room_pin', 'room_update'].includes(msg.type)) {
      const rid = parseInt(msg.room_id || ws.roomId || '0', 10);
      if (rid > 0) {
        broadcastToRoom(rid, { ...msg, from: userId }, ws);
      }
      return;
    }

    // 1-on-1 Messenger & Private Chat Request Events
    const to = parseInt(msg.to || '0', 10);
    if (!to) return;

    if (['new_msg', 'typing', 'read', 'unsend', 'card_update', 'rtc_signal', 'incoming_call', 'call_accepted', 'call_ended', 'chat_request'].includes(msg.type)) {
      sendToUser(to, { ...msg, from: userId });

      if (msg.type === 'new_msg' || msg.type === 'unsend') {
        const mySockets = clients.get(userId);
        if (mySockets) {
          for (const s of mySockets) {
            if (s !== ws && s.readyState === 1) {
              s.send(JSON.stringify({ ...msg, from: userId }));
            }
          }
        }
      }
    }
  });

  ws.on('close', () => {
    const set = clients.get(userId);
    if (set) {
      set.delete(ws);
      if (set.size === 0) {
        clients.delete(userId);
        broadcastPresence(userId, false);
      }
    }
    if (ws.roomId > 0 && rooms.has(ws.roomId)) {
      const rSet = rooms.get(ws.roomId);
      rSet.delete(ws);
      if (rSet.size === 0) rooms.delete(ws.roomId);
    }
  });
});

setInterval(() => {
  for (const [, sockets] of clients) {
    for (const ws of sockets) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      ws.ping();
    }
  }
}, 30000);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Berry WebSocket Hub running on port ${PORT}`);
});
