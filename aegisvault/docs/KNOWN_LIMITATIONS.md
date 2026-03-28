# AegisVault — Known Limitations & Future Improvements

## Current Limitations

### Security Limitations

**1. JavaScript heap exposure**
The vault key (VEK) exists as plaintext in the JavaScript heap while the vault is unlocked. A privileged attacker (OS-level malware, browser with full memory access, or malicious browser extension) could extract it. **Mitigation:** inactivity auto-lock minimizes the exposure window. This is an inherent limitation of browser-based cryptography.

**2. No client-side memory encryption**
JavaScript does not have APIs for secure/encrypted memory regions. `zeroKey()` attempts to clear the key bytes, but the garbage collector may have already copied them elsewhere. This is standard practice for browser crypto — it's best-effort.

**3. No zero-knowledge server-side search**
Search operates on decrypted data loaded into client memory. The server cannot search secret values. For large vaults (thousands of items), this means downloading and decrypting all items before searching. For a personal vault, this is acceptable.

**4. Browser extension threat**
Malicious browser extensions can inject JavaScript and access the page's JS context, including the vault key. No reliable defense in a web app. Hardware security keys for WebAuthn reduce the auth attack surface but don't protect the key while unlocked.

**5. Clipboard managers**
We auto-clear the clipboard after 30 seconds, but OS-level clipboard managers (1Clipboard, Alfred, etc.) may have already captured the secret. Users should disable clipboard history for sensitive environments.

**6. TOTP secret server knowledge**
TOTP secrets are stored server-side (encrypted with SERVER_ENCRYPTION_KEY). If the server is compromised AND the attacker gets the SERVER_ENCRYPTION_KEY, they can access TOTP secrets. This is a standard tradeoff in TOTP — the server needs the secret to verify codes. **Alternative:** use hardware security keys (WebAuthn) for MFA.

### Functionality Limitations

**7. File size limit**
Files are encrypted in-memory. Maximum: 50 MB per file. Chunked streaming encryption is not yet implemented.

**8. No full-text search of secret values**
By design. Encrypted values cannot be searched server-side.

**9. No real-time sync across devices**
When a secret is added on Device A, Device B won't see it until the next page load/refresh. Real-time sync would require WebSockets with careful key management.

**10. No native mobile app**
Web-only. Mobile browser support is functional but lacks biometric unlock, screenshot prevention, and native keyboard security.

**11. Rate limiting uses DB (not Redis)**
The current implementation uses PostgreSQL for rate limiting. Under high load or distributed deployments, this may have race conditions. Redis-backed rate limiting (e.g., @upstash/ratelimit) is recommended for production.

**12. No WebAuthn in current MVP**
`@simplewebauthn` is included as a dependency but the WebAuthn registration/login flow is not fully implemented. Scaffold is present for future completion.

---

## Recommended Future Improvements

### High Priority (Security)

- [ ] **WebAuthn (passkey) support** — complete the `@simplewebauthn` integration for passwordless/phishing-resistant login
- [ ] **Redis rate limiting** — replace DB-based rate limiting with Redis for correctness under load
- [ ] **Content Security Policy reporting** — add CSP report-uri to catch violations
- [ ] **Suspicious login detection** — alert on login from new country, new device fingerprint
- [ ] **Key rotation flow** — allow master password change with re-encryption of all DEKs
- [ ] **Secure export verification** — add HMAC to export files for integrity verification
- [ ] **Emergency kit generation** — formatted printable recovery instructions (without actual secrets)

### High Priority (Features)

- [ ] **Import from common password managers** — 1Password, Bitwarden, LastPass CSV import (with client-side parsing)
- [ ] **TOTP code generation** — store TOTP secrets and generate codes in-app (like Bitwarden)
- [ ] **Password generator** — strong password generation with configurable options
- [ ] **Breach monitoring** — check credentials against HaveIBeenPwned using k-anonymity
- [ ] **Real-time sync** — WebSocket or SSE for multi-tab/device sync
- [ ] **Biometric unlock** — Web Authentication API for biometric re-authentication (avoid re-entering master password)

### Medium Priority

- [ ] **Chunked file encryption** — support files up to 500 MB with streaming encryption
- [ ] **Thumbnail generation** — client-side image thumbnail generation (canvas API, never server-side)
- [ ] **Tags management UI** — dedicated tags management page
- [ ] **Vault categories/folders** — hierarchical organization
- [ ] **Native mobile apps** — React Native with secure enclave key storage
- [ ] **Browser extension** — autofill support (separate security model required)
- [ ] **Sharing** — encrypted secret sharing with time-limited keys (explicit feature, not core)

### Low Priority

- [ ] **Audit log export** — export audit log for compliance
- [ ] **Account activity anomaly alerts** — email on new device login
- [ ] **Offline mode** — encrypt vault in IndexedDB for offline access (requires careful key management)
- [ ] **Customizable item templates** — user-defined item type templates
- [ ] **Bulk operations** — select multiple items to delete/archive/tag

---

## Architecture Tradeoffs Made

| Decision | Tradeoff |
|---|---|
| All sensitive fields in one `encryptedData` blob | Simpler; single auth tag covers all fields. Con: can't partially decrypt. |
| KDF salt stored server-side | Enables cross-device access. Con: reveals that a user account exists to someone with DB access. |
| Key in React state/ref, not IndexedDB | Maximally ephemeral — lost on tab close. Con: must re-enter master password after closing browser. |
| XChaCha20 over AES-GCM | Larger random nonce prevents collision; no hardware acceleration on some platforms. |
| DB-backed sessions over stateless JWTs only | Enables revocation. Con: DB query on every request. Mitigate with short-lived JWT + DB only on refresh. |
