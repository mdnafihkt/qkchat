# QkChat v2.9 — Final Security Hardening Checklist

**Objective:** Complete all remaining security work before archiving QkChat. This checklist is intended for an AI agent to execute sequentially.

---

# Priority 1 — Critical Security Fixes

## F-01 — Random PBKDF2 Salt

- [x] Generate a cryptographically secure random 16-byte salt when creating a room.
- [x] Store the salt in room metadata.
- [x] Derive AES-256 keys using `PBKDF2(password, roomSalt)`.
- [x] Remove deterministic salt generation from `roomId`.

---

## F-02 — Non-Extractable Encryption Keys

- [x] Create `CryptoKey` objects with `extractable: false`.
- [x] Remove all JWK export/import logic.
- [x] Remove encryption key storage from `sessionStorage`.
- [x] Re-derive keys during Session Recovery using password + room salt.

---

## F-03 — Encrypt Files at Rest

- [x] Stop storing decrypted `Blob`s in IndexedDB.
- [x] Store encrypted file ciphertext.
- [x] Store IV, MIME type, filename, and encrypted bytes only.
- [x] Decrypt files only in volatile memory when viewing or downloading.

---

## F-04 — Replay Protection

- [x] Add authenticated monotonically increasing sequence numbers to encrypted payloads.
- [x] Track highest accepted sequence number per room.
- [x] Reject duplicate sequence numbers.
- [x] Reject duplicate `messageId`s.
- [x] Ignore replayed packets.

---

## F-05 — Authenticated File Transfer Metadata

- [x] Encrypt/authenticate transfer metadata with each chunk.
- [x] Validate `transferId`.
- [x] Validate `chunkIndex`.
- [x] Validate `chunkCount`.
- [x] Validate declared file size.
- [x] Reject malformed transfers.
- [x] Expire incomplete transfers after timeout.

---

## F-06 — Challenge-Response Room Join

- [x] Implement nonce-based challenge from server.
- [x] Client signs nonce using room key (HMAC).
- [x] Verify proof before reserving peer slot.
- [x] Reject unauthenticated room joins.

---

# Priority 2 — Backend (Railway) Hardening

## B-01 — Remove Sensitive Logs

- [x] Remove logs containing Room IDs.
- [x] Remove logs containing Peer IDs.
- [x] Remove logs containing Socket IDs.
- [x] Remove logs containing filenames.
- [x] Remove logs containing ciphertext or IVs.
- [x] Remove logs containing shared payloads.
- [x] Keep only startup, health, warning, and fatal error logs.

---

## B-02 — Production CORS Only

- [x] Remove wildcard origins.
- [x] Remove hardcoded localhost origins from production.
- [x] Allow only the production Netlify domain.
- [x] Allow localhost only in development mode.

---

## B-03 — Socket Connection Limits

- [x] Limit concurrent WebSocket connections per IP.
- [x] Disconnect excess sockets immediately.
- [x] Apply limits across reconnects.
- [x] Reject excessive connection attempts.

---

## B-04 — Persistent Rate Limiting

- [x] Replace socket-level rate limiting.
- [x] Implement IP/Peer token bucket.
- [x] Preserve rate limit across reconnects.

---

## B-05 — Room Cleanup

- [x] Remove rooms immediately when last peer disconnects.
- [x] Expire abandoned rooms after timeout.
- [x] Clean stale room state from server memory.

---

## B-06 — Input Validation

- [x] Validate Room ID format server-side.
- [x] Reject malformed room IDs.
- [x] Validate socket payload sizes.
- [x] Reject oversized events before processing.

---

# Priority 3 — Browser & PWA Security

## P-01 — Remove Production Debug Logs

- [x] Remove IndexedDB debug logs.
- [x] Remove Share Target logs.
- [x] Remove room state logs.
- [x] Remove crypto logs.
- [x] Wrap development logs with `import.meta.env.DEV`.

---

## P-02 — Blob URL Cleanup

- [x] Revoke every `URL.createObjectURL()`.
- [x] Clean Blob URLs on component unmount.
- [x] Clean Blob URLs when leaving rooms.

---

## P-03 — Cache Protection

- [x] ensure there is no remenants from native share sheet code
- [x] Remove stale cached sensitive responses during updates.

---

## P-05 — Content Security Policy

- [x] Add strict CSP.
- [x] Allow scripts only from `self`.
- [x] Allow WebSocket connections only to Railway backend.
- [x] Block framing (`frame-ancestors 'none'`).
- [x] Disable object/embed execution.

---

## P-06 — HTTP Security Headers

Enable via Helmet.

- [x] HSTS.
- [x] X-Frame-Options = `DENY`.
- [x] Referrer-Policy = `no-referrer`.
- [x] X-Content-Type-Options = `nosniff`.
- [x] Permissions-Policy (camera only).

---

# Priority 4 — Client Data Cleanup

## C-01 — Local Room Cleanup

- [x] Delete room metadata when room is deleted.
- [x] Delete encrypted messages when leaving room.
- [x] Delete encrypted files when leaving room.
- [x] Delete peer metadata for removed rooms.
- [x] Clean stale rooms during startup.

---

## C-02 — Session Cleanup

- [x] Clear in-memory keys on logout/leave.
- [x] Clear temporary share payloads after use.
- [x] Clear abandoned transfer buffers.

---

# Priority 5 — Abuse Protection

## A-01 — File Transfer Limits

- [x] Enforce maximum file size.
- [x] Limit simultaneous transfers.
- [x] Abort transfers exceeding limits.
- [x] Ensure retry for failed file transfer after a period.
- [x] Abort inactive transfers if retry fails.

---

## A-02 — Memory Exhaustion Protection

- [x] Validate accumulated chunk size.
- [x] Reject chunk overflow.
- [x] Reject unexpected chunk ordering.
- [x] Free transfer buffers on failure.

---

# Priority 6 — Build & Deployment Hardening

## D-01 — Vite Production Build

- [x] Disable production source maps.
- [x] Verify no development artifacts are included.
- [x] Verify no secrets are bundled.

---

## D-02 — Railway Deployment

- [x] Ensure environment variables are never exposed.
- [x] Disable verbose production error responses.
- [x] Keep only required environment variables.

---

## D-03 — Netlify Deployment

- [ ] Verify `_headers` includes CSP and cache headers.
- [ ] Verify redirects do not expose sensitive endpoints.
- [ ] Ensure `public/` contains only static assets.

---

## D-04 — Dependency Audit

- [ ] Remove unused packages.
- [ ] Run `npm audit`.
- [ ] Update vulnerable dependencies.
- [ ] Keep `package-lock.json` committed.

---

# Priority 7 — UX Safety

## U-01 — Confirmation Dialogs

- [ ] Confirm before leaving a room.
- [ ] Confirm before deleting a room.
- [ ] Warn before deleting encrypted local history.

---

## U-02 — Session Locking

- [ ] Lock rooms after refresh when key is unavailable.
- [ ] Require password for Session Recovery.
- [ ] Never auto-unlock without successful key derivation.

---

# Final Release Verification

## Backend

- [ ] No sensitive logs in Railway.
- [ ] CORS restricted to production.
- [ ] Rate limiting works across reconnects.
- [ ] Connection limits enforced.
- [ ] Empty rooms removed automatically.

## Frontend

- [ ] No debug logs in production.
- [ ] No plaintext encryption keys stored.
- [ ] No plaintext files stored in IndexedDB.
- [ ] Blob URLs revoked correctly.
- [ ] Cache headers applied.

## Security

- [ ] CSP enabled.
- [ ] Helmet headers enabled.
- [ ] Replay protection active.
- [ ] File metadata authenticated.
- [ ] Room join challenge-response implemented.

## UX

- [ ] Confirmation before destructive actions.
- [ ] Session recovery works with non-extractable keys.
- [ ] Local data cleanup verified.