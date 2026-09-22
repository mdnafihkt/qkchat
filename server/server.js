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

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  // Socket Rate Limiting Middleware
  socket.use((packet, next) => {
    if (isRateLimited(socket)) {
      return next(new Error('Rate limit exceeded. Please slow down.'));
    }
    next();
  });

  // User joins a room identified by the chat ID
  socket.on('join_room', (roomId) => {
    if (!isValidRoomId(roomId)) return;

    // Clean up previous rooms if any
    const rooms = Array.from(socket.rooms).filter((r) => r !== socket.id);
    rooms.forEach((r) => socket.leave(r));

    socket.join(roomId);
    console.log(`User ${socket.id} joined room: ${roomId}`);
    socket.to(roomId).emit('user_joined', socket.id);
  });

  // Relay encrypted messages directly to the room
  socket.on('send_message', (data, callback) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, message } = data;
    if (!isValidRoomId(roomId) || !message) return;

    socket.to(roomId).emit('receive_message', {
      senderId: socket.id,
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

    socket.to(roomId).emit('receive_file_chunk', chunk);

    if (typeof callback === 'function') {
      callback();
    }
  });

  // Relay delivery confirmation back to the sender
  socket.on('message_delivered', (data) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, messageId, senderId } = data;
    if (!isValidRoomId(roomId) || typeof senderId !== 'string') return;

    io.to(senderId).emit('message_delivered', { messageId });
  });

  // Relay sync request to other clients in the room
  socket.on('sync_request', (data) => {
    if (!data || typeof data !== 'object') return;
    const { roomId, timestamp } = data;
    if (!isValidRoomId(roomId)) return;

    socket.to(roomId).emit('sync_request', {
      senderId: socket.id,
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
      messages,
    });
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Secure relay server running on port ${PORT}`);
});

