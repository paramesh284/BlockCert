# BlockCert

BlockCert is a locally run demonstration of an academic certificate issue-and-verify workflow. It uses a real Solidity contract deployed to a persistent, Ethereum-compatible Ganache blockchain running on your computer.

## Run on Windows

Install **Node.js 22.13 or newer**, open PowerShell, and run:

```powershell
Set-Location D:\BlockCert
npm install
npm run dev
```

Open the local address shown in the terminal (by default, <http://127.0.0.1:4173>). The terminal prints a **one-run administrator password**. Use that password in the college administration panel to issue a sample certificate. The generated password changes every time you restart the app; this avoids keeping a reusable sample credential in the source code.

If a `.env` file is more convenient, set your own local password **before** starting the app:

```text
BLOCKCERT_ADMIN_PASSWORD=use-your-own-local-password-at-least-12-characters
```

Keep `.env` private; it is excluded from Git. The app accepts requests only on `127.0.0.1`; scan QR codes on the same computer. Stop the server with **Ctrl+C**.

## Certificate workflow

1. Sign in to the college portal with the administrator password from the terminal.
2. Enter the certificate title, student name, and institution.
3. Select the original PDF or image. Its SHA-256 fingerprint is computed in your browser; the file is never uploaded.
4. Approve the issuance. An actual Solidity contract records the certificate ID, SHA-256 fingerprint, issuer wallet, and timestamp.
5. Save or share the generated QR code.
6. Enter or scan the certificate ID to check its on-chain record. Upload the original document for a fingerprint comparison. A modified copy receives a different SHA-256 fingerprint.
7. An authorized college administrator can permanently revoke an issued certificate. Verification reports revoked records rather than accepting them.

## Privacy and security boundaries

- The original certificate file is read locally by the browser and **never sent to the web server or blockchain**.
- Student names, certificate titles, and college names are saved in the local SQLite database in `data/blockcert.sqlite`. They are **not** written to the blockchain.
- The blockchain contains a randomly generated certificate ID, the document's SHA-256 fingerprint, the issuing wallet address, and the issue/revocation timestamp.
- Ganache's local ledger and its contract address are stored in the ignored `data/` directory and persist between normal restarts.
- An administrator must authenticate before the app will issue or revoke a certificate. The server uses short-lived, HTTP-only, same-site sessions, CSRF tokens, and a sign-in rate limit.
- The local development chain uses the well-known public Ganache development mnemonic and must **never** hold real funds or be treated as an actual private network.
- This sample app is **for local demonstration and coursework only**. It has no public internet deployment, identity provider, production key management, real institution onboarding, or production-grade data protection. Do not use real student records, private certificates, or real credentials.
- A QR code opens `127.0.0.1`; it is a quick link for the local demonstration, not a public certificate service. Sharing a QR with another computer does not make the local app publicly accessible.

## Project structure

```text
BlockCert/
├── contracts/CertificateRegistry.sol  # Authorized issuance and revocation
├── data/                              # Local chain and private SQLite records (gitignored)
├── src/blockchain.js                  # Solidity compilation and persistent local EVM
├── src/client.js                      # Browser SHA-256, QR scan, issuance and verification UI
├── src/server.js                      # Loopback-only API and admin sessions
├── src/styles.css                     # Responsive UI
├── test/blockchain.test.js             # Contract authorization and persistence tests
├── index.html
└── package.json
```

## Commands

```powershell
npm run dev     # Start the app and local blockchain
npm test        # Test contract authorization, issuance, and ledger persistence
npm run build   # Build the frontend assets
npm start       # Serve the production frontend build with the local demo backend
```

`npm run start` requires `npm run build` first. This produces a frontend build; it does **not** deploy the app to a public hosting provider or a public blockchain.
