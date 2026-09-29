const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(helmet());

// Configure Allowed Origins
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
  : ['https://qkchat.daimens.com', 'http://localhost:5173', 'http://localhost:3000'];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, server-to-server) or matching allowedOrigins
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy error: Origin not allowed.'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});


const server = http.createServer(app);
const io = new Server(server, {
  cors: corsOptions,
  maxHttpBufferSize: 10 * 1024 * 1024, // 10MB limit per message buffer to prevent OOM DoS
});

const PORT = process.env.PORT || 3000;

// Rate Limiting Helper for Socket connections
const RATE_LIMIT_WINDOW_MS = 5000;
const MAX_EVENTS_PER_WINDOW = 30;

function isRateLimited(socket) {
  const now = Date.now();
  if (!socket.rateLimit) {
    socket.rateLimit = { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS };
    return false;
  }
  if (now > socket.rateLimit.resetTime) {
    socket.rateLimit.count = 1;
    socket.rateLimit.resetTime = now + RATE_LIMIT_WINDOW_MS;
    return false;
  }
  socket.rateLimit.count += 1;
  return socket.rateLimit.count > MAX_EVENTS_PER_WINDOW;
}

// Input Validation Helper
function isValidRoomId(roomId) {
  return typeof roomId === 'string' && roomId.trim().length > 0 && roomId.length <= 128;
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

function getOrCreateRoomState(roomId) {
  if (!activeRooms.has(roomId)) {
    activeRooms.set(roomId, {
      registeredPeers: new Set(),
      activeSockets: new Map(),
      salt: null,
      authKeyHex: null,
      seenMessageIds: new Set(),
    });
  }
  return activeRooms.get(roomId);
}

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  // Socket Rate Limiting Middleware
  socket.use((packet, next) => {
    if (isRateLimited(socket)) {
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
      console.warn(`[AUTH FAILED] Missing or expired challenge for socket ${socket.id} in room ${roomId}`);
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'CHALLENGE_EXPIRED' });
      return;
    }

    const roomState = getOrCreateRoomState(roomId);

    // If room is newly created: verify creator proof against roomVerifier
    if (!roomState.authKeyHex) {
      if (!roomVerifier || typeof roomVerifier !== 'string' || !authProof || typeof authProof !== 'string') {
        console.warn(`[AUTH FAILED] Missing credentials for room creation by socket ${socket.id} in room ${roomId}`);
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'MISSING_CREDENTIALS' });
        return;
      }

      const isValid = verifyAuthProof(roomVerifier, challenge.nonce, authProof);
      if (!isValid) {
        console.warn(`[AUTH FAILED] Invalid creator proof by socket ${socket.id} in room ${roomId}`);
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
        console.warn(`[AUTH FAILED] Missing authProof from socket ${socket.id} in room ${roomId}`);
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'MISSING_CREDENTIALS' });
        return;
      }

      const isValid = verifyAuthProof(roomState.authKeyHex, challenge.nonce, authProof);
      if (!isValid) {
        console.warn(`[AUTH FAILED] Invalid room credentials from socket ${socket.id} in room ${roomId}`);
        if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_CREDENTIALS' });
        return;
      }
    }

    // Proof verified! Enforce Two-Peer Trust Model before reserving slot
    if (!roomState.registeredPeers.has(peerId)) {
      if (roomState.registeredPeers.size >= 2) {
        console.log(`Rejecting socket ${socket.id} (peer ${peerId}): Room ${roomId} capacity full (2 peers max).`);
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

    console.log(`User ${socket.id} (peer ${peerId}) authenticated and joined room: ${roomId}`);
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
    console.log(`User ${socket.id} left room: ${roomId}`);

    const roomState = activeRooms.get(roomId);
    if (roomState) {
      roomState.activeSockets.delete(socket.id);
      if (clearSlot && (peerId || socket.currentPeerId)) {
        const targetPeerId = peerId || socket.currentPeerId;
        roomState.registeredPeers.delete(targetPeerId);
        console.log(`Cleared peer slot ${targetPeerId} for room: ${roomId}`);
      }
      if (roomState.activeSockets.size === 0 && roomState.registeredPeers.size === 0) {
        activeRooms.delete(roomId);
      }
    }

    socket.currentRoomId = null;
    socket.currentPeerId = null;
  });

  // Relay encrypted messages directly to the room
  socket.on('send_message', (data, callback) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, message } = data;
    if (!isValidRoomId(roomId) || !message) return;

    const roomState = getOrCreateRoomState(roomId);
    if (message.id && typeof message.id === 'string') {
      if (!roomState.seenMessageIds) {
        roomState.seenMessageIds = new Set();
      }
      if (roomState.seenMessageIds.has(message.id)) {
        console.warn(`[REPLAY DETECTED] Duplicate messageId: ${message.id} in room: ${roomId}`);
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
    if (!data || typeof data !== 'object') return;
    const { roomId, chunk } = data;
    if (!isValidRoomId(roomId) || !chunk || typeof chunk !== 'object') return;

    // Validate chunk envelope parameters
    if (
      typeof chunk.transferId !== 'string' ||
      !chunk.transferId.trim() ||
      typeof chunk.chunkIndex !== 'number' ||
      !Number.isInteger(chunk.chunkIndex) ||
      chunk.chunkIndex < 0 ||
      typeof chunk.totalChunks !== 'number' ||
      !Number.isInteger(chunk.totalChunks) ||
      chunk.totalChunks <= 0 ||
      typeof chunk.fileSize !== 'number' ||
      !Number.isInteger(chunk.fileSize) ||
      chunk.fileSize <= 0
    ) {
      console.warn(`[MALFORMED CHUNK] Rejected chunk from ${socket.id} in room: ${roomId}`);
      if (typeof callback === 'function') callback({ success: false, error: 'MALFORMED_CHUNK' });
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

    console.log(`User ${socket.id} deleted room for all: ${roomId}`);
    io.to(roomId).emit('room_deleted', { roomId, deletedBy: socket.id });

    // Clean up active room state
    activeRooms.delete(roomId);
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    pendingChallenges.delete(socket.id);
    if (socket.currentRoomId) {
      const roomState = activeRooms.get(socket.currentRoomId);
      if (roomState) {
        roomState.activeSockets.delete(socket.id);
        if (roomState.activeSockets.size === 0 && roomState.registeredPeers.size === 0) {
          activeRooms.delete(socket.currentRoomId);
        }
      }
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Secure relay server running on port ${PORT}`);
});

