Advanced POC — HTTPS + Strong Auth + Signed Keys + SQLite
=========================================================

How to run:
1) Install dependencies:
   npm install
2) Start server:
   npm start
3) Open in browser (note HTTPS self-signed):
   https://localhost:3443/client.html
   - Your browser will warn about self-signed cert. Accept the exception for localhost.

What was added:
- HTTPS with self-signed certificate auto-generated (keys/server_cert.pem, server_key.pem)
- Server RSA keypair for signing JWTs and signing users' public keys (keys/jwt_private.pem, keys/jwt_public.pem)
- Pepper secret stored at keys/pepper.txt (used in Argon2 hashing)
- Argon2id hashing strengthened: memoryCost=262144 (256MB), timeCost=4, parallelism=2
- Server signs each registered publicKey (signature stored in DB)
- Client fetches server public key and verifies signature before using a user's public key
- Storage moved from JSON files to SQLite (data/poc.db) and backups stored in backups/
- Backup endpoint: POST /backup (creates a timestamped copy of DB in backups/)

Security notes:
- This is a POC. For production:
  * Use certificates from a trusted CA and enforce HTTPS everywhere.
  * Store JWT private key and pepper in a secure vault/HSM.
  * Harden Argon2 parameters based on available memory and threat model.
  * Add logging, monitoring, MFA, account lockout, rate limits by user/IP.
  * Use Content Security Policy (CSP), restrict CORS origins, etc.

Files generated on first run:
- keys/server_cert.pem, keys/server_key.pem
- keys/jwt_private.pem, keys/jwt_public.pem
- keys/pepper.txt
- data/poc.db
- backups/ (created when /backup called)



ADDITIONAL FEATURES ADDED:
- /backup now restricted to ADMIN user (set ADMIN_USER env var or default 'admin').
- Client supports exporting private key to encrypted file and importing it back (use the UI fields).
- Test runner added at test/test-runner.js. Run with: ./run-test.sh (server must be running).
