// Utility to handle E2E Encryption using Web Crypto API

// Derives an AES-GCM key from a password and salt using PBKDF2
export async function deriveKey(password, saltString) {
    const enc = new TextEncoder();

    // Hash the salt string (e.g. Chat ID) to get a predictable 16-byte salt buffer
    const saltHashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(saltString));
    const salt = new Uint8Array(saltHashBuffer).slice(0, 16);

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
        false,
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
        console.error('Decryption failed. Incorrect password or tampered message.');
        return null; // Return null on decryption failure
    }
}
