const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const webpush = require('web-push');

const PORT = process.env.PORT || 8080;
const SECRET = process.env.BERRY_WS_SECRET || 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET';
const PUSH_SECRET = process.env.PUSH_SECRET || '';
const VAPID_SUBJECT = (process.env.VAPID_SUBJECT || 'mailto:dmc007bate@gmail.com').trim();
const VAPID_PUBLIC = (process.env.VAPID_PUBLIC || '').trim();
const VAPID_PRIVATE = (process.env.VAPID_PRIVATE || '').trim();

let VAPID_READY = false;
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
    VAPID_READY = true;
  } catch (err) {
    console.error('VAPID init failed:', err.message);
  }
}

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
    return res.end(JSON.stringify({
      ok: true,
      onlineUsers: clients.size,
      activeRooms: rooms.size,
      vapidReady: VAPID_READY
    }));
  }

  // Status check for Web Push (open in browser to verify)
  if (req.method === 'GET' && req.url === '/push') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      ok: true,
      vapidReady: VAPID_READY,
      secretSet: Boolean(PUSH_SECRET)
    }));
  }

  // Unified /push endpoint: handles both WebSocket relay & Background Web Push
  if (req.method === 'POST' && req.url === '/push') {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1048576) req.destroy();
    });
    req.on('end', async () => {
      // 1. Existing WebSocket Hub Relay (uses x-berry-secret header)
      if (req.headers['x-berry-secret']) {
        if (req.headers['x-berry-secret'] !== SECRET) {
          res.writeHead(403);
          return res.end('Forbidden');
        }
        try {
          const data = JSON.parse(body || '{}');
          if (data.to) sendToUser(data.to, data.payload);
          if (data.room_id) broadcastToRoom(data.room_id, data.payload);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true }));
        } catch (e) {
          res.writeHead(400);
          return res.end('Bad JSON');
        }
      }

      // 2. Background Web Push Relay (Android, Desktop & iOS 16.4+ PWA)
      try {
        const data = JSON.parse(body || '{}');
        if (!VAPID_READY) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'VAPID keys not configured' }));
        }
        if (!PUSH_SECRET || data.secret !== PUSH_SECRET) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Forbidden' }));
        }

        const payload = JSON.stringify(data.notification || {});
        const opts = { TTL: 60, urgency: data.urgency || 'high' };
        const subs = Array.isArray(data.subscriptions) ? data.subscriptions : [];

        const results = await Promise.allSettled(
          subs.map((sub) => webpush.sendNotification(sub, payload, opts))
        );
        const sent = results.filter((r) => r.status === 'fulfilled').length;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true, sent, total: subs.length }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Bad JSON' }));
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
  console.log(`Berry WebSocket Hub running on port ${PORT} (WebPush: ${VAPID_READY})`);
});
