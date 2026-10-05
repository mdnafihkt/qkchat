const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// HTTP Security Headers (P-06)
app.use(
  helmet({
    // Strict-Transport-Security (HSTS)
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    // X-Frame-Options: DENY
    frameguard: {
      action: 'deny',
    },
    // Referrer-Policy: no-referrer
    referrerPolicy: {
      policy: 'no-referrer',
    },
    // X-Content-Type-Options: nosniff
    noSniff: true,
    // Content Security Policy for API server
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

// Permissions-Policy header: Camera permitted for self (QR scanner), other powerful APIs disabled
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(self), microphone=(), geolocation=(), payment=(), usb=()'
  );
  next();
});

// Environment check
const isProduction = process.env.NODE_ENV === 'production';

// Default production domains (Netlify production custom domain & netlify.app domain)
const defaultProductionOrigins = [
  'https://qkchat.daimens.com',
  'https://qkchat.netlify.app',
];

// Helper to check for localhost / 127.0.0.1 origins
function isLocalhostOrigin(origin) {
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

// Parse allowed origins from environment or use default production domains
const envOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
      .map((o) => o.trim())
      .filter((o) => o && o !== '*')
  : defaultProductionOrigins;

// Build the active allowed origins set
// In production: strictly exclude wildcard origins and any localhost origins
const allowedOrigins = isProduction
  ? envOrigins.filter((origin) => !isLocalhostOrigin(origin) && origin !== '*')
  : envOrigins;

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. curl, health check probes, server-to-server)
    if (!origin) {
      return callback(null, true);
    }

    // Explicitly reject wildcard origins
    if (origin === '*') {
      return callback(new Error('CORS policy error: Wildcard origins not allowed.'));
    }

    // Allow localhost ONLY in development mode
    if (!isProduction && isLocalhostOrigin(origin)) {
      return callback(null, true);
    }

    // Match configured allowed origins (e.g. production Netlify domain)
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('CORS policy error: Origin not allowed.'));
  },
  credentials: true,
};

app.use(cors(corsOptions));

// Health check endpoint
app.get('/health', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.status(200).json({ status: 'ok' });
});

// 404 Catch-All Handler (D-02)
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Centralized Non-Verbose Production Error Handler (D-02)
app.use((err, req, res, next) => {
  if (!isProduction) {
    console.error('Unhandled server error:', err);
  }
  // Never expose internal stack traces or environment details
  res.status(err.status || 500).json({
    error: isProduction ? 'Internal Server Error' : (err.message || 'Internal Server Error'),
  });
});


const server = http.createServer(app);
const io = new Server(server, {
  cors: corsOptions,
  maxHttpBufferSize: 10 * 1024 * 1024, // 10MB limit per message buffer to prevent OOM DoS
});

const PORT = process.env.PORT || 3000;

// Persistent IP & Peer Token Bucket Rate Limiting (B-04)
const IP_BUCKET_CAPACITY = parseInt(process.env.IP_RATE_LIMIT_CAPACITY, 10) || 60;
const IP_REFILL_RATE_PER_SEC = parseFloat(process.env.IP_RATE_LIMIT_REFILL_RATE, 10) || 20;
const IP_REFILL_RATE_PER_MS = IP_REFILL_RATE_PER_SEC / 1000;

const PEER_BUCKET_CAPACITY = parseInt(process.env.PEER_RATE_LIMIT_CAPACITY, 10) || 40;
const PEER_REFILL_RATE_PER_SEC = parseFloat(process.env.PEER_RATE_LIMIT_REFILL_RATE, 10) || 15;
const PEER_REFILL_RATE_PER_MS = PEER_REFILL_RATE_PER_SEC / 1000;

const BUCKET_INACTIVITY_TTL_MS = 5 * 60 * 1000; // 5 minutes inactivity TTL

// Global token buckets that persist across socket reconnects
const ipRateLimitBuckets = new Map(); // ip -> { tokens, lastRefill, lastActivity }
const peerRateLimitBuckets = new Map(); // peerId -> { tokens, lastRefill, lastActivity }

// Periodically clean up inactive buckets to prevent memory accumulation
const rateLimitCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of ipRateLimitBuckets.entries()) {
    if (now - bucket.lastActivity > BUCKET_INACTIVITY_TTL_MS) {
      ipRateLimitBuckets.delete(ip);
    }
  }
  for (const [peerId, bucket] of peerRateLimitBuckets.entries()) {
    if (now - bucket.lastActivity > BUCKET_INACTIVITY_TTL_MS) {
      peerRateLimitBuckets.delete(peerId);
    }
  }
}, 60000);
if (rateLimitCleanupInterval.unref) {
  rateLimitCleanupInterval.unref();
}

function isTokenBucketRateLimited(ip, peerId) {
  const now = Date.now();

  // 1. IP token bucket
  let ipBucket = ipRateLimitBuckets.get(ip);
  if (!ipBucket) {
    ipBucket = {
      tokens: IP_BUCKET_CAPACITY,
      lastRefill: now,
      lastActivity: now,
    };
    ipRateLimitBuckets.set(ip, ipBucket);
  }

  // Refill IP tokens based on elapsed time
  const ipElapsed = now - ipBucket.lastRefill;
  ipBucket.tokens = Math.min(IP_BUCKET_CAPACITY, ipBucket.tokens + ipElapsed * IP_REFILL_RATE_PER_MS);
  ipBucket.lastRefill = now;
  ipBucket.lastActivity = now;

  // 2. Peer token bucket (if peerId is known)
  let peerBucket = null;
  if (peerId) {
    peerBucket = peerRateLimitBuckets.get(peerId);
    if (!peerBucket) {
      peerBucket = {
        tokens: PEER_BUCKET_CAPACITY,
        lastRefill: now,
        lastActivity: now,
      };
      peerRateLimitBuckets.set(peerId, peerBucket);
    }

    // Refill Peer tokens based on elapsed time
    const peerElapsed = now - peerBucket.lastRefill;
    peerBucket.tokens = Math.min(PEER_BUCKET_CAPACITY, peerBucket.tokens + peerElapsed * PEER_REFILL_RATE_PER_MS);
    peerBucket.lastRefill = now;
    peerBucket.lastActivity = now;
  }

  // Check if token can be consumed
  const hasIpToken = ipBucket.tokens >= 1;
  const hasPeerToken = !peerBucket || peerBucket.tokens >= 1;

  if (hasIpToken && hasPeerToken) {
    ipBucket.tokens -= 1;
    if (peerBucket) {
      peerBucket.tokens -= 1;
    }
    return false; // Not rate limited
  }

  return true; // Rate limited
}

// Input Validation Configuration (B-06)
// Room IDs must strictly be alphanumeric with dashes/underscores, 3 to 64 characters long
const ROOM_ID_REGEX = /^[a-zA-Z0-9_-]{3,64}$/;

function isValidRoomId(roomId) {
  if (typeof roomId !== 'string') return false;
  const trimmed = roomId.trim();
  if (trimmed.length < 3 || trimmed.length > 64) return false;
  return ROOM_ID_REGEX.test(trimmed);
}

// Socket Payload Size Limits (B-06)
const MAX_FILE_CHUNK_PAYLOAD_BYTES = 2 * 1024 * 1024; // 2MB for base64 file chunk + metadata
const MAX_SYNC_PAYLOAD_BYTES = 2 * 1024 * 1024; // 2MB for sync response message history
const MAX_STANDARD_PAYLOAD_BYTES = 128 * 1024; // 128KB for chat messages, auth proofs, room requests

function getPayloadSize(data) {
  if (data === undefined || data === null) return 0;
  if (typeof data === 'string') return Buffer.byteLength(data, 'utf8');
  if (Buffer.isBuffer(data)) return data.length;
  if (typeof data === 'object') {
    try {
      return Buffer.byteLength(JSON.stringify(data), 'utf8');
    } catch (e) {
      return -1; // Malformed / circular
    }
  }
  return 0;
}

// In-memory active room tracker (runtime state only, zero server persistence)
const activeRooms = new Map();

// In-memory pending challenges per socket: socket.id -> Map<roomId, { nonce, expiresAt }>
const pendingChallenges = new Map();

function getSocketChallenges(socketId) {
  if (!pendingChallenges.has(socketId)) {
    pendingChallenges.set(socketId, new Map());
  }
  return pendingChallenges.get(socketId);
}

function verifyAuthProof(authKeyHex, nonce, clientProofBase64) {
  try {
    if (!authKeyHex || !nonce || !clientProofBase64) return false;
    const keyBuf = Buffer.from(authKeyHex, 'hex');
    const expectedHmac = crypto.createHmac('sha256', keyBuf).update(Buffer.from(nonce, 'utf8')).digest('base64');
    const expectedBuf = Buffer.from(expectedHmac, 'base64');
    const clientBuf = Buffer.from(clientProofBase64, 'base64');
    if (expectedBuf.length !== clientBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, clientBuf);
  } catch (err) {
    return false;
  }
}

function cleanupRoom(roomId) {
  const roomState = activeRooms.get(roomId);
  if (!roomState) return;

  if (roomState.registeredPeers) roomState.registeredPeers.clear();
  if (roomState.activeSockets) roomState.activeSockets.clear();
  if (roomState.seenMessageIds) roomState.seenMessageIds.clear();
  roomState.salt = null;
  roomState.authKeyHex = null;

  activeRooms.delete(roomId);
}

function getOrCreateRoomState(roomId) {
  const now = Date.now();
  if (!activeRooms.has(roomId)) {
    activeRooms.set(roomId, {
      registeredPeers: new Set(),
      activeSockets: new Map(),
      salt: null,
      authKeyHex: null,
      seenMessageIds: new Set(),
      createdAt: now,
      lastActivity: now,
    });
  }
  const roomState = activeRooms.get(roomId);
  roomState.lastActivity = now;
  return roomState;
}

// Room Timeout Configurations (B-05)
const ABANDONED_ROOM_TIMEOUT_MS = parseInt(process.env.ABANDONED_ROOM_TIMEOUT_MS, 10) || 15 * 60 * 1000; // 15 mins
const ROOM_MAX_IDLE_TIMEOUT_MS = parseInt(process.env.ROOM_MAX_IDLE_TIMEOUT_MS, 10) || 60 * 60 * 1000; // 1 hour

// Periodically clean abandoned rooms and stale memory
const roomCleanupInterval = setInterval(() => {
  const now = Date.now();

  for (const [roomId, roomState] of activeRooms.entries()) {
    // 1. Remove rooms immediately if no active sockets remain in memory
    if (roomState.activeSockets.size === 0) {
      cleanupRoom(roomId);
      continue;
    }

    // 2. Expire abandoned rooms (1 peer waiting with no peer joining for > timeout)
    const isWaitingForPeer = roomState.registeredPeers.size < 2;
    const timeSinceActivity = now - (roomState.lastActivity || roomState.createdAt || now);

    if (isWaitingForPeer && timeSinceActivity > ABANDONED_ROOM_TIMEOUT_MS) {
      io.to(roomId).emit('room_expired', { roomId, reason: 'Room abandoned (peer never joined).' });
      io.to(roomId).emit('room_deleted', { roomId, reason: 'Room abandoned (peer never joined).' });
      for (const socketId of roomState.activeSockets.keys()) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
          s.leave(roomId);
          s.currentRoomId = null;
        }
      }
      cleanupRoom(roomId);
      continue;
    }

    // 3. Expire inactive rooms (idle > 1 hour)
    if (timeSinceActivity > ROOM_MAX_IDLE_TIMEOUT_MS) {
      io.to(roomId).emit('room_expired', { roomId, reason: 'Room expired due to inactivity.' });
      io.to(roomId).emit('room_deleted', { roomId, reason: 'Room expired due to inactivity.' });
      for (const socketId of roomState.activeSockets.keys()) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
          s.leave(roomId);
          s.currentRoomId = null;
        }
      }
      cleanupRoom(roomId);
      continue;
    }
  }

  // 4. Clean stale pending challenge nonces
  for (const [socketId, challenges] of pendingChallenges.entries()) {
    for (const [roomId, challenge] of challenges.entries()) {
      if (now > challenge.expiresAt) {
        challenges.delete(roomId);
      }
    }
    if (challenges.size === 0) {
      pendingChallenges.delete(socketId);
    }
  }
}, 60000);
if (roomCleanupInterval.unref) {
  roomCleanupInterval.unref();
}

// Socket Connection Limits Configuration (B-03)
const MAX_CONCURRENT_SOCKETS_PER_IP = parseInt(process.env.MAX_CONCURRENT_SOCKETS_PER_IP, 10) || 10;
const MAX_CONNECTION_ATTEMPTS_PER_WINDOW = parseInt(process.env.MAX_CONNECTION_ATTEMPTS_PER_WINDOW, 10) || 30;
const CONNECTION_ATTEMPT_WINDOW_MS = 60000; // 1-minute window

// Active concurrent sockets per IP: IP -> Set<socket.id>
const activeSocketsByIp = new Map();

// Connection attempt rate limiting per IP: IP -> { count, resetTime }
const connectionAttemptsByIp = new Map();

// Periodically purge expired connection attempt records to prevent memory growth
const connectionCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of connectionAttemptsByIp.entries()) {
    if (now > record.resetTime) {
      connectionAttemptsByIp.delete(ip);
    }
  }
}, 60000);
if (connectionCleanupInterval.unref) {
  connectionCleanupInterval.unref();
}

function getClientIp(socket) {
  const forwarded = socket.handshake.headers['x-forwarded-for'];
  if (forwarded && typeof forwarded === 'string') {
    const firstIp = forwarded.split(',')[0].trim();
    if (firstIp) return firstIp;
  }
  return socket.handshake.address || (socket.conn && socket.conn.remoteAddress) || '127.0.0.1';
}

function registerActiveSocket(socket, ip) {
  let ipSockets = activeSocketsByIp.get(ip);
  if (!ipSockets) {
    ipSockets = new Set();
    activeSocketsByIp.set(ip, ipSockets);
  }
  ipSockets.add(socket.id);

  const cleanup = () => {
    const currentSockets = activeSocketsByIp.get(ip);
    if (currentSockets) {
      currentSockets.delete(socket.id);
      if (currentSockets.size === 0) {
        activeSocketsByIp.delete(ip);
      }
    }
  };

  socket.once('disconnect', cleanup);
  if (socket.conn) {
    socket.conn.once('close', cleanup);
  }
}

// Socket Connection Middleware for Limits & Reconnect Protection (B-03)
io.use((socket, next) => {
  const ip = getClientIp(socket);
  const now = Date.now();

  // 1. Reject excessive connection attempts per IP
  let attemptRecord = connectionAttemptsByIp.get(ip);
  if (!attemptRecord || now > attemptRecord.resetTime) {
    attemptRecord = { count: 1, resetTime: now + CONNECTION_ATTEMPT_WINDOW_MS };
    connectionAttemptsByIp.set(ip, attemptRecord);
  } else {
    attemptRecord.count += 1;
    if (attemptRecord.count > MAX_CONNECTION_ATTEMPTS_PER_WINDOW) {
      console.warn('[CONNECTION LIMIT] Excessive connection attempts rejected.');
      socket.disconnect(true);
      return next(new Error('Too many connection attempts. Please slow down.'));
    }
  }

  // 2. Limit concurrent WebSocket connections per IP & disconnect excess sockets immediately
  const currentCount = activeSocketsByIp.has(ip) ? activeSocketsByIp.get(ip).size : 0;
  if (currentCount >= MAX_CONCURRENT_SOCKETS_PER_IP) {
    console.warn('[CONNECTION LIMIT] Concurrent connection limit exceeded.');
    socket.disconnect(true);
    return next(new Error('Connection limit exceeded. Too many concurrent connections.'));
  }

  // Register socket and track across reconnects
  registerActiveSocket(socket, ip);
  socket.clientIp = ip;
  next();
});

io.on('connection', (socket) => {
  // Secondary guard: Disconnect excess sockets immediately if limit reached
  const ip = socket.clientIp || getClientIp(socket);
  const ipSockets = activeSocketsByIp.get(ip);
  if (ipSockets && ipSockets.size > MAX_CONCURRENT_SOCKETS_PER_IP) {
    console.warn('[CONNECTION LIMIT] Excess socket disconnected immediately.');
    socket.disconnect(true);
    return;
  }
  // Packet Middleware: Payload Size Validation & Token Bucket Rate Limiting (B-06, B-04)
  socket.use((packet, next) => {
    const eventName = packet[0];
    const data = packet[1];

    // 1. Validate socket payload size before processing (B-06)
    let maxAllowedBytes = MAX_STANDARD_PAYLOAD_BYTES;
    if (eventName === 'send_file_chunk') {
      maxAllowedBytes = MAX_FILE_CHUNK_PAYLOAD_BYTES;
    } else if (eventName === 'sync_response') {
      maxAllowedBytes = MAX_SYNC_PAYLOAD_BYTES;
    }

    const payloadSize = getPayloadSize(data);
    if (payloadSize < 0 || payloadSize > maxAllowedBytes) {
      console.warn('[INPUT VALIDATION] Oversized or malformed payload rejected.');
      const ack = typeof packet[packet.length - 1] === 'function' ? packet[packet.length - 1] : null;
      if (ack) {
        ack({ success: false, error: payloadSize < 0 ? 'MALFORMED_PAYLOAD' : 'PAYLOAD_TOO_LARGE' });
      }
      socket.emit('error', 'Payload size exceeds allowed limit.');
      return next(new Error('Payload size exceeds allowed limit.'));
    }

    // 2. Persistent Token Bucket Rate Limiting (IP & Peer) (B-04)
    const peerId =
      socket.currentPeerId ||
      (data && typeof data === 'object' && typeof data.peerId === 'string' ? data.peerId : null);
    const ip = socket.clientIp || getClientIp(socket);

    if (isTokenBucketRateLimited(ip, peerId)) {
      const ack = typeof packet[packet.length - 1] === 'function' ? packet[packet.length - 1] : null;
      if (ack) {
        ack({ success: false, error: 'RATE_LIMIT_EXCEEDED' });
      }
      socket.emit('error', 'Rate limit exceeded. Please slow down.');
      return next(new Error('Rate limit exceeded. Please slow down.'));
    }
    next();
  });

  // Query room salt for joining peer
  socket.on('get_room_salt', (data, ackCallback) => {
    if (!data || typeof data !== 'object') return;
    const { roomId } = data;
    if (!isValidRoomId(roomId)) {
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_ROOM_ID' });
      return;
    }
    const roomState = activeRooms.get(roomId);
    if (typeof ackCallback === 'function') {
      ackCallback({
        success: true,
        salt: roomState ? roomState.salt : null,
      });
    }
  });

  // Issue a single-use random nonce challenge for joining a room
  socket.on('get_join_challenge', (data, ackCallback) => {
    if (!data || typeof data !== 'object') return;
    const { roomId } = data;
    if (!isValidRoomId(roomId)) {
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_ROOM_ID' });
      return;
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    const challenges = getSocketChallenges(socket.id);
    challenges.set(roomId, {
      nonce,
      expiresAt: Date.now() + 30000, // 30 seconds
    });

    if (typeof ackCallback === 'function') {
      ackCallback({ success: true, nonce });
    }
  });

  // User joins a room with mandatory challenge-response proof before reserving peer slot
  socket.on('join_room', (data, ackCallback) => {
    if (!data || typeof data !== 'object') {
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_REQUEST' });
      return;
    }
    const { roomId, peerId, salt, authProof, roomVerifier } = data;

    if (!isValidRoomId(roomId)) {
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_ROOM_ID' });
      return;
    }

    if (!peerId || typeof peerId !== 'string') {
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'MISSING_PEER_ID' });
      return;
    }

    // Verify challenge nonce
    const challenges = getSocketChallenges(socket.id);
    const challenge = challenges.get(roomId);
    challenges.delete(roomId); // Single-use challenge

    if (!challenge || Date.now() > challenge.expiresAt) {
      console.warn('[AUTH FAILED] Missing or expired challenge.');
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'CHALLENGE_EXPIRED' });
      return;
    }

    const roomState = getOrCreateRoomState(roomId);

    // If room is newly created: verify creator proof against roomVerifier
    if (!roomState.authKeyHex) {
      if (!roomVerifier || typeof roomVerifier !== 'string' || !authProof || typeof authProof !== 'string') {
        console.warn('[AUTH FAILED] Missing credentials for room creation.');
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'MISSING_CREDENTIALS' });
        return;
      }

      const isValid = verifyAuthProof(roomVerifier, challenge.nonce, authProof);
      if (!isValid) {
        console.warn('[AUTH FAILED] Invalid creator proof.');
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_CREDENTIALS' });
        return;
      }

      roomState.authKeyHex = roomVerifier;
      if (salt && typeof salt === 'string') {
        roomState.salt = salt;
      }
    } else {
      // Room already exists: verify client proof against existing roomState.authKeyHex
      if (!authProof || typeof authProof !== 'string') {
        console.warn('[AUTH FAILED] Missing authProof on join.');
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'MISSING_CREDENTIALS' });
        return;
      }

      const isValid = verifyAuthProof(roomState.authKeyHex, challenge.nonce, authProof);
      if (!isValid) {
        console.warn('[AUTH FAILED] Invalid room credentials on join.');
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_CREDENTIALS' });
        return;
      }
    }

    // Proof verified! Enforce Two-Peer Trust Model before reserving slot
    if (!roomState.registeredPeers.has(peerId)) {
      if (roomState.registeredPeers.size >= 2) {
        console.warn('[ROOM FULL] Join rejected: room capacity reached.');
        socket.emit('room_full', { roomId, message: 'Room capacity reached. Only 2 peers allowed per room.' });
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'ROOM_FULL' });
        return;
      }
      roomState.registeredPeers.add(peerId);
    }

    roomState.activeSockets.set(socket.id, peerId);
    socket.currentRoomId = roomId;
    socket.currentPeerId = peerId;
    socket.join(roomId);

    socket.to(roomId).emit('user_joined', { roomId, senderId: socket.id });

    if (typeof ackCallback === 'function') ackCallback({ success: true, salt: roomState.salt });
  });

  // User leaves a specific room (optionally clearing their peer registration slot)
  socket.on('leave_room', (data) => {
    let roomId, peerId, clearSlot;
    if (typeof data === 'object' && data !== null) {
      roomId = data.roomId;
      peerId = data.peerId;
      clearSlot = data.clearSlot;
    } else {
      roomId = data;
    }

    if (!isValidRoomId(roomId)) return;
    socket.leave(roomId);

    const roomState = activeRooms.get(roomId);
    if (roomState) {
      roomState.activeSockets.delete(socket.id);
      if (clearSlot && (peerId || socket.currentPeerId)) {
        const targetPeerId = peerId || socket.currentPeerId;
        roomState.registeredPeers.delete(targetPeerId);
      }
      if (roomState.activeSockets.size === 0) {
        cleanupRoom(roomId);
      }
    }

    socket.currentRoomId = null;
    socket.currentPeerId = null;
  });

  // Relay encrypted messages directly to the room
  socket.on('send_message', (data, callback) => {
    if (!data || typeof data !== 'object') {
      if (typeof callback === 'function') callback({ success: false, error: 'INVALID_REQUEST' });
      return;
    }
    const { roomId, message } = data;
    if (!isValidRoomId(roomId)) {
      if (typeof callback === 'function') callback({ success: false, error: 'INVALID_ROOM_ID' });
      return;
    }
    if (!message || typeof message !== 'object') {
      if (typeof callback === 'function') callback({ success: false, error: 'INVALID_MESSAGE' });
      return;
    }

    const roomState = getOrCreateRoomState(roomId);
    if (message.id && typeof message.id === 'string') {
      if (!roomState.seenMessageIds) {
        roomState.seenMessageIds = new Set();
      }
      if (roomState.seenMessageIds.has(message.id)) {
        console.warn('[REPLAY DETECTED] Duplicate messageId rejected.');
        if (typeof callback === 'function') {
          callback({ success: false, error: 'DUPLICATE_MESSAGE_ID' });
        }
        return;
      }
      roomState.seenMessageIds.add(message.id);
    }

    socket.to(roomId).emit('receive_message', {
      senderId: socket.id,
      roomId,
      ...message,
    });

    if (typeof callback === 'function') {
      callback({ success: true });
    }
  });

  socket.on('send_file_chunk', (data, callback) => {
    if (!data || typeof data !== 'object') {
      if (typeof callback === 'function') callback({ success: false, error: 'INVALID_REQUEST' });
      return;
    }
    const { roomId, chunk } = data;
    if (!isValidRoomId(roomId)) {
      if (typeof callback === 'function') callback({ success: false, error: 'INVALID_ROOM_ID' });
      return;
    }
    if (!chunk || typeof chunk !== 'object') {
      if (typeof callback === 'function') callback({ success: false, error: 'MALFORMED_CHUNK' });
      return;
    }

    // Validate chunk envelope parameters & enforce limits (A-01)
    const MAX_SERVER_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    const MAX_SERVER_CHUNKS = Math.ceil(MAX_SERVER_FILE_SIZE / (512 * 1024)) + 10; // ~110 chunks

    if (
      typeof chunk.transferId !== 'string' ||
      !chunk.transferId.trim() ||
      typeof chunk.chunkIndex !== 'number' ||
      !Number.isInteger(chunk.chunkIndex) ||
      chunk.chunkIndex < 0 ||
      typeof chunk.totalChunks !== 'number' ||
      !Number.isInteger(chunk.totalChunks) ||
      chunk.totalChunks <= 0 ||
      chunk.totalChunks > MAX_SERVER_CHUNKS ||
      typeof chunk.fileSize !== 'number' ||
      !Number.isInteger(chunk.fileSize) ||
      chunk.fileSize <= 0 ||
      chunk.fileSize > MAX_SERVER_FILE_SIZE ||
      chunk.chunkIndex >= chunk.totalChunks
    ) {
      console.warn('[MALFORMED CHUNK] Malformed or oversized chunk parameters rejected.');
      if (typeof callback === 'function') callback({ success: false, error: 'TRANSFER_LIMIT_EXCEEDED' });
      return;
    }

    socket.to(roomId).emit('receive_file_chunk', {
      roomId,
      ...chunk,
    });

    if (typeof callback === 'function') {
      callback({ success: true });
    }
  });

  // Relay delivery confirmation back to the sender
  socket.on('message_delivered', (data) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, messageId, senderId } = data;
    if (!isValidRoomId(roomId) || typeof senderId !== 'string') return;

    io.to(senderId).emit('message_delivered', { messageId, roomId });
  });

  // Relay sync request to other clients in the room
  socket.on('sync_request', (data) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, timestamp } = data;
    if (!isValidRoomId(roomId)) return;

    socket.to(roomId).emit('sync_request', {
      senderId: socket.id,
      roomId,
      timestamp,
    });
  });

  // Relay sync response directly to the specific recipient
  socket.on('sync_response', (data) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, recipientId, messages } = data;
    if (!isValidRoomId(roomId) || typeof recipientId !== 'string') return;

    io.to(recipientId).emit('sync_response', {
      senderId: socket.id,
      roomId,
      messages,
    });
  });

  // Handle room deletion for all connected users in a room
  socket.on('delete_room', (data) => {
    if (!data || typeof data !== 'object') return;
    const { roomId } = data;
    if (!isValidRoomId(roomId)) return;

    io.to(roomId).emit('room_deleted', { roomId, deletedBy: socket.id });

    // Clean up active room state immediately
    cleanupRoom(roomId);
  });

  socket.on('disconnect', () => {
    const ip = socket.clientIp;
    if (ip && activeSocketsByIp.has(ip)) {
      const currentSockets = activeSocketsByIp.get(ip);
      currentSockets.delete(socket.id);
      if (currentSockets.size === 0) {
        activeSocketsByIp.delete(ip);
      }
    }
    pendingChallenges.delete(socket.id);
    if (socket.currentRoomId) {
      const roomState = activeRooms.get(socket.currentRoomId);
      if (roomState) {
        roomState.activeSockets.delete(socket.id);
        if (roomState.activeSockets.size === 0) {
          cleanupRoom(socket.currentRoomId);
        }
      }
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Secure relay server running on port ${PORT}`);
});

