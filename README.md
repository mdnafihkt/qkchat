# Secure E2E Chat App

A highly secure, temporary, and end-to-end encrypted chat application.  Now live at <a href="https://qkchat.daimens.com" > qkchat.daimens.com </a>

## Features
- **End-to-End Encryption**: Messages are encrypted in the browser using AES-GCM before being sent over the network.
- **Zero Data Collection**: The server merely relays encrypted messages and does not store logs, messages, or user data. No databases are used.
- **Ephemeral Sessions**: Sessions only exist as long as users are connected.

## Technologies Used
- **Client**: React, Vite, WebCrypto API (PBKDF2, AES-GCM), Socket.io-client, Vanilla CSS (Tailwind-like custom properties)
- **Server**: Node.js, Express, Socket.io, Helmet, CORS

## Setup and Usage

### 1. Installation
Install dependencies for both server and client:
```sh
cd server
npm install

cd ../client
npm install
```

### 2. Running the App
You can start both the client and server concurrently using the provided script (make sure to give it execution permissions `chmod +x start.sh`):

```sh
./start.sh
```

Alternatively, start them separately:
- **Server**: `cd server && npm start` (or `node server.js` - runs on port 3000)
- **Client**: `cd client && npm run dev` (runs on port 5173)

### 3. Usage
1. Open the app in your browser (usually `http://localhost:5173`).
2. Enter a unique **Chat ID** and a strong **Password**.
3. Share the Chat ID and Password with your peer through a secure mechanism.
4. When your peer joins using the exact same credentials, you can begin chatting. Any incorrect password will result in the inability to decrypt the messages.

## Architecture Overview

The project consists of two main parts:

### **Client (React + Vite)**
- Built with React 19, using Vite as the build tool
- Uses **React Router** for client-side routing
- Communicates with the server via **Socket.io**
- Client-side encryption using Web Crypto API (PBKDF2 + AES-GCM)

### **Server (Node.js + Express)**
- Lightweight relay server using Socket.io
- Runs on **port 3000** (configurable via `PORT` env var)
- No database—sessions exist only while users are connected
- Relays encrypted messages without processing or storing them

---

## Page Routing Flow

The app uses **React Router** for navigation. Here's the user journey:

```
/HomeSelection
    ├── /start → StartChat
    │       └── /chat → ChatPage
    └── /join → JoinChat
            └── /chat → ChatPage
```

### Component Details:

1. **HomeSelection** (`/`)
   - Landing page with two action buttons
   - "Start New Chat" → navigate to `/start`
   - "Join a Chat" → navigate to `/join`

2. **StartChat** (`/start`)
   - Generates a random Chat ID (e.g., `abc12345-def67890`)
   - User sets a password
   - Displays QR code containing the Chat ID (for peer scanning)
   - On submit: calls `onJoin()` and navigates to `/chat`

3. **JoinChat** (`/join`)
   - Two options: scan QR code or manually enter Chat ID
   - User enters password
   - On submit: calls `onJoin()` and navigates to `/chat`

4. **ChatPage** (`/chat`)
   - The messaging interface
   - Messages encrypted/decrypted using `cryptoKey` state
   - Displays conversation history

---

## How It Works: The Flow

### **1. Initialization**
In App.jsx, the app maintains this state:
- `socket` — WebSocket connection
- `roomId` — Chat ID
- `password` — User's password (stored for re-encryption)
- `cryptoKey` — Derived AES-GCM encryption key
- `messages` — Chat history
- `isConnected` — Connection status

### **2. Key Derivation & Connection**
When `handleJoinWithCredentials()` is called (from StartChat or JoinChat):

```
Password + Chat ID (as salt)
    ↓ (PBKDF2: 100,000 iterations, SHA-256)
    → AES-GCM key (256-bit)
```

Then:
- Creates a new Socket.io connection
- Emits `join_room` with the Chat ID
- Sets up event listeners for incoming messages

### **3. Message Encryption & Transmission**
When sending a message:
1. **Client encrypts** the message using the derived key (AES-GCM encryption)
2. **Client sends** encrypted ciphertext + IV to server via `send_message`
3. **Server relays** the encrypted data to all users in the room (no decryption)
4. **Receiving client** decrypts using its local key

### **4. Decryption on Receipt**
When the client receives a message via `receive_message`:
- Uses the stored `cryptoKey` to decrypt the ciphertext
- If decryption fails (wrong password), displays "[Encrypted message - Failed to decrypt]"
- Parses the decrypted JSON and renders the message

---

## Encryption Details

The crypto.js utilities handle:

- **`deriveKey(password, saltString)`** — PBKDF2 derivation using password + Chat ID
- **`encryptMessage(key, messageText)`** — AES-GCM encryption, returns base64-encoded ciphertext + IV
- **`decryptMessage(key, encryptedData)`** — Decrypts using base64 decoding + AES-GCM

Both peers must have the **exact same password**. If passwords differ, decryption fails silently.

---

## Server Relay Mechanism

The server doesn't care about content—it just:
1. Accepts `join_room` events and adds sockets to a room
2. Broadcasts `send_message` events to all others in that room
3. Logs connections/disconnections (no message logging)
4. Discards all data when users disconnect

---

## Key Security Properties

✅ **End-to-End Encryption** — Server never sees plaintext  
✅ **Zero Knowledge** — Server can't decrypt even if it wanted to  
✅ **Ephemeral** — No messages stored anywhere  
✅ **Deterministic Keys** — Same password + Chat ID always produce same key (allows peer encryption)