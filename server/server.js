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

    // Relay delivery confirmation back to the sender
    socket.on('message_delivered', (data) => {
        const { roomId, messageId, senderId } = data;
        io.to(senderId).emit('message_delivered', { messageId });
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
    });
});

server.listen(PORT, () => {
    console.log(`Secure relay server running on port ${PORT}`);
});
