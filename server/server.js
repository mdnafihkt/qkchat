const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(cors({ origin: '*' }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' },
    maxHttpBufferSize: 100 * 1024 * 1024 // 100MB to handle large file uploads
});

const PORT = process.env.PORT || 3000;

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // User joins a room identified by the chat ID
    socket.on('join_room', (roomId) => {
        socket.join(roomId);
        console.log(`User ${socket.id} joined room: ${roomId}`);
        // Notify others in the room
        socket.to(roomId).emit('user_joined', socket.id);
    });

    // Relay encrypted messages directly to the room
    // We do NOT store anything on the server.
    socket.on('send_message', (data, callback) => {
        const { roomId, message } = data;
        socket.to(roomId).emit('receive_message', {
            senderId: socket.id,
            ...message
        });
        if (typeof callback === 'function') {
            callback();
        }
    });

    socket.on('send_file_chunk', (data, callback) => {
        const { roomId, chunk } = data;
        socket.to(roomId).emit('receive_file_chunk', chunk);
        if (typeof callback === 'function') {
            callback();
        }
    });

    // Relay delivery confirmation back to the sender
    socket.on('message_delivered', (data) => {
        const { roomId, messageId, senderId } = data;
        io.to(senderId).emit('message_delivered', { messageId });
    });

    // Relay sync request to other clients in the room
    socket.on('sync_request', (data) => {
        const { roomId, timestamp } = data;
        socket.to(roomId).emit('sync_request', {
            senderId: socket.id,
            timestamp
        });
    });

    // Relay sync response directly to the specific recipient
    socket.on('sync_response', (data) => {
        const { roomId, recipientId, messages } = data;
        io.to(recipientId).emit('sync_response', {
            senderId: socket.id,
            messages
        });
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
    });
});

server.listen(PORT, () => {
    console.log(`Secure relay server running on port ${PORT}`);
});
