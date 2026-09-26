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
  : ['https://qkchat.daimens.com', 'http://localhost:5173', 'http://localhost:3000', 'https://qkchat-test.netlify.app'];

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

// Fallback endpoint for Web Share Target POST requests if Service Worker is bypassed
app.post('/share-target', (req, res) => {
  res.redirect(303, '/share');
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

function getOrCreateRoomState(roomId) {
  if (!activeRooms.has(roomId)) {
    activeRooms.set(roomId, {
      registeredPeers: new Set(),
      activeSockets: new Map(),
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

  // User joins a room identified by the chat ID with mandatory 2-peer capacity check
  socket.on('join_room', (data, ackCallback) => {
    let roomId, peerId;
    if (typeof data === 'object' && data !== null) {
      roomId = data.roomId;
      peerId = data.peerId;
    } else {
      roomId = data;
    }

    if (!isValidRoomId(roomId)) {
      if (typeof ackCallback === 'function') ackCallback({ success: false, error: 'INVALID_ROOM_ID' });
      return;
    }

    if (peerId && typeof peerId === 'string') {
      const roomState = getOrCreateRoomState(roomId);

      // Enforce Two-Peer Trust Model: block any 3rd unique peer from joining
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
    }

    socket.join(roomId);
    console.log(`User ${socket.id} (peer ${peerId || 'legacy'}) joined room: ${roomId}`);
    socket.to(roomId).emit('user_joined', { roomId, senderId: socket.id });

    if (typeof ackCallback === 'function') ackCallback({ success: true });
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

    socket.to(roomId).emit('receive_message', {
      senderId: socket.id,
      roomId,
      ...message,
    });

    if (typeof callback === 'function') {
      callback();
    }
  });

  socket.on('send_file_chunk', (data, callback) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, chunk } = data;
    if (!isValidRoomId(roomId) || !chunk) return;

    socket.to(roomId).emit('receive_file_chunk', {
      roomId,
      ...chunk,
    });

    if (typeof callback === 'function') {
      callback();
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

