// Utility to handle E2E Encryption using Web Crypto API

// Generates a cryptographically secure random 16-byte salt as a hex string
export function generateRandomSalt() {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(saltBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Derives an AES-GCM key from a password and 16-byte salt using PBKDF2
export async function deriveKey(password, roomSalt) {
    if (!password || typeof password !== 'string' || !password.trim()) {
        throw new Error('A valid non-empty password is required for key derivation.');
    }
    const enc = new TextEncoder();
    let salt;

    if (typeof roomSalt === 'string') {
        if (/^[0-9a-fA-F]{32}$/.test(roomSalt)) {
            salt = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                salt[i] = parseInt(roomSalt.substr(i * 2, 2), 16);
            }
        } else {
            salt = enc.encode(roomSalt);
        }
    } else if (roomSalt instanceof Uint8Array) {
        salt = roomSalt;
    } else {
        throw new Error('A valid room salt is required for key derivation.');
    }

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false, // Non-extractable encryption keys (F-02)
        ['encrypt', 'decrypt']
    );
}

// Helper function to convert large arrays to base64 without stack overflow
function arrayToBase64(arr) {
    const chunkSize = 8192; // Process in 8KB chunks
    let result = '';
    for (let i = 0; i < arr.length; i += chunkSize) {
        const chunk = arr.slice(i, i + chunkSize);
        result += String.fromCharCode.apply(null, chunk);
    }
    return btoa(result);
}

// Encrypts a message returning a base64 encoded ciphertext and IV
export async function encryptMessage(key, messageText) {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedMessage = enc.encode(messageText);

    const ciphertextBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encodedMessage
    );

    const ciphertextArr = Array.from(new Uint8Array(ciphertextBuf));
    const ciphertextBase64 = arrayToBase64(ciphertextArr);

    const ivArr = Array.from(iv);
    const ivBase64 = arrayToBase64(ivArr);

    return { ciphertext: ciphertextBase64, iv: ivBase64 };
}

// Helper function to safely convert base64 string to Uint8Array without stack overflow
function base64ToArray(base64String) {
    const binaryString = atob(base64String);
    const arr = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        arr[i] = binaryString.charCodeAt(i);
    }
    return arr;
}

// Decrypts a base64 encoded payload
export async function decryptMessage(key, encryptedData) {
    try {
        const dec = new TextDecoder();

        // Decode base64 iv
        const iv = base64ToArray(encryptedData.iv);

        // Decode base64 ciphertext
        const ciphertext = base64ToArray(encryptedData.ciphertext);

        const decryptedBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );

        return dec.decode(decryptedBuf);
    } catch (err) {
        if (import.meta.env.DEV) {
            console.error('Decryption failed. Incorrect password or tampered message.');
        }
        return null; // Return null on decryption failure
    }
}

// Encrypts an ArrayBuffer/TypedArray directly, returning raw encrypted ArrayBuffer and base64 encoded iv
// Supports optional additionalData (AAD) for authenticated data
export async function encryptBinary(key, binaryData, additionalData = null) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const algorithm = { name: 'AES-GCM', iv };
    if (additionalData) {
        algorithm.additionalData = additionalData;
    }
    const encryptedBuf = await crypto.subtle.encrypt(
        algorithm,
        key,
        binaryData
    );
    const ivArr = Array.from(iv);
    const ivBase64 = arrayToBase64(ivArr);
    return { encryptedData: encryptedBuf, iv: ivBase64 };
}

// Decrypts an encrypted ArrayBuffer, Blob, or TypedArray using base64 encoded iv, returning decrypted ArrayBuffer
// Supports optional additionalData (AAD) verification
export async function decryptBinary(key, encryptedData, ivBase64, additionalData = null) {
    try {
        if (!key || !encryptedData || !ivBase64) return null;
        const iv = base64ToArray(ivBase64);
        let buffer = encryptedData;
        if (typeof Blob !== 'undefined' && encryptedData instanceof Blob) {
            buffer = await encryptedData.arrayBuffer();
        } else if (ArrayBuffer.isView(encryptedData)) {
            buffer = encryptedData.buffer.slice(
                encryptedData.byteOffset,
                encryptedData.byteOffset + encryptedData.byteLength
            );
        }
        const algorithm = { name: 'AES-GCM', iv };
        if (additionalData) {
            algorithm.additionalData = additionalData;
        }
        const decryptedBuf = await crypto.subtle.decrypt(
            algorithm,
            key,
            buffer
        );
        return decryptedBuf;
    } catch (err) {
        if (import.meta.env.DEV) {
            console.error('Binary decryption failed:', err);
        }
        return null;
    }
}

// Derives a domain-separated HMAC key from password and roomSalt using PBKDF2
export async function deriveAuthKey(password, roomSalt) {
    if (!password || typeof password !== 'string' || !password.trim()) {
        throw new Error('A valid non-empty password is required for auth key derivation.');
    }
    const enc = new TextEncoder();
    let salt;

    if (typeof roomSalt === 'string') {
        if (/^[0-9a-fA-F]{32}$/.test(roomSalt)) {
            salt = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                salt[i] = parseInt(roomSalt.substr(i * 2, 2), 16);
            }
        } else {
            salt = enc.encode(roomSalt);
        }
    } else if (roomSalt instanceof Uint8Array) {
        salt = roomSalt;
    } else {
        throw new Error('A valid room salt is required for key derivation.');
    }

    // Domain separation: append "-auth" to ensure HMAC auth key is independent from AES-GCM encryption key
    const authSalt = new Uint8Array(salt.length + 5);
    authSalt.set(salt);
    authSalt.set(enc.encode("-auth"), salt.length);

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: authSalt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        true, // exportable so creator can provide room verifier hex
        ['sign', 'verify']
    );
}

// Signs a challenge nonce using the derived HMAC auth key
export async function signNonce(authKey, nonce) {
    const enc = new TextEncoder();
    const nonceBytes = enc.encode(nonce);
    const signature = await crypto.subtle.sign(
        'HMAC',
        authKey,
        nonceBytes
    );
    return arrayToBase64(Array.from(new Uint8Array(signature)));
}

// Exports auth key as hex string for room verifier initialization by creator
export async function exportAuthKeyHex(authKey) {
    const raw = await crypto.subtle.exportKey('raw', authKey);
    return Array.from(new Uint8Array(raw)).map((b) => b.toString(16).padStart(2, '0')).join('');
}


