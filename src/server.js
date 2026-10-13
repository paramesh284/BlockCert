import "dotenv/config";
import "dotenv/config";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { keccak256, toUtf8Bytes } from "ethers";
import { startLocalBlockchain } from "./blockchain.js";

const ROOT_DIRECTORY = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const DATA_DIRECTORY = path.join(ROOT_DIRECTORY, "data");
const DATABASE_FILE = path.join(DATA_DIRECTORY, "blockcert.sqlite");
const CONTRACT_FILE = path.join(ROOT_DIRECTORY, "contracts", "CertificateRegistry.sol");
const COOKIE_NAME = "blockcert_admin";
const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const HASH_PATTERN = /^(?:0x)?[a-f\d]{64}$/i;
const ISSUANCE_ID_PATTERN = /^0x[a-f\d]{64}$/i;
const ADMIN_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const PORT = Number(process.env.PORT || 4173);
const APP_ORIGIN = `http://127.0.0.1:${PORT}`;

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

function createDemoPassword() {
    const bytes = randomBytes(20);
    let password = "";

    for (const byte of bytes) {
        password += ADMIN_PASSWORD_ALPHABET[byte % ADMIN_PASSWORD_ALPHABET.length];
    }

    return password;
}

function createSessionCookie(value, maxAge) {
    return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

function safeFingerprint(value) {
    if (typeof value !== "string" || !HASH_PATTERN.test(value.trim())) {
        return null;
    }

    return `0x${value.trim().replace(/^0x/i, "").toLowerCase()}`;
}

function validationString(value, limit) {
    if (typeof value !== "string") {
        return null;
    }

    const normalized = value.trim().replace(/\s+/g, " ");

    if (normalized.length === 0 || normalized.length > limit) {
        return null;
    }

    return normalized;
}

function getDatabase() {
    const db = new DatabaseSync(DATABASE_FILE);
    db.exec(`
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS certificates (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            name TEXT NOT NULL,
            recipient TEXT NOT NULL,
            institution TEXT NOT NULL,
            issuer TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            transaction_hash TEXT NOT NULL,
            block_number INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
    `);

    return db;
}

function getCertificateRows(db) {
    return db.prepare(`
        SELECT id, fingerprint, name, recipient, institution, issuer, issued_at,
               transaction_hash, block_number, revoked
        FROM certificates
        ORDER BY issued_at DESC
    `).all();
}

function createApplication({ blockchain, database, adminPassword }) {
    const app = express();
    const sessions = new Map();
    const failedLogins = new Map();

    app.disable("x-powered-by");
    app.use(express.json({ limit: "8kb", strict: true }));
    app.use("/api", (_req, res, next) => {
        res.set({
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer"
        });
        next();
    });

    const adminPasswordHash = scryptSync(adminPassword, "blockcert-local-admin", 32);

    function getSession(req) {
        const cookies = req.headers.cookie ?? "";
        const sessionId = cookies
            .split(";")
            .map(cookie => cookie.trim())
            .find(cookie => cookie.startsWith(`${COOKIE_NAME}=`))
            ?.slice(COOKIE_NAME.length + 1);
        const session = sessionId ? sessions.get(sessionId) : undefined;

        if (!session) {
            return null;
        }

        if (session.expiresAt <= Date.now()) {
            sessions.delete(sessionId);
            return null;
        }

        return { id: sessionId, ...session };
    }

    function requireAdmin(req, res, next) {
        const session = getSession(req);

        if (!session) {
            res.status(401).json({ error: "Sign in with an authorized college account to continue." });
            return;
        }

        req.adminSession = session;
        next();
    }

    function requireAdminAction(req, res, next) {
        requireAdmin(req, res, () => {
            if (req.headers.origin && req.headers.origin !== APP_ORIGIN) {
                res.status(403).json({ error: "This action must come from the BlockCert app." });
                return;
            }

            if (req.headers["x-blockcert-csrf"] !== req.adminSession.csrfToken) {
                res.status(403).json({ error: "Your session has expired. Sign in again to continue." });
                return;
            }

            next();
        });
    }

    app.get("/api/health", (_req, res) => {
        res.json({
            status: "ready",
            chainId: blockchain.chainId,
            network: "BlockCert Local Chain",
            contractAddress: blockchain.contractAddress
        });
    });

    app.get("/api/admin/session", (req, res) => {
        const session = getSession(req);
        res.json({
            authenticated: Boolean(session),
            csrfToken: session?.csrfToken ?? null,
            adminAddress: session ? blockchain.adminAddress : null
        });
    });

    app.post("/api/admin/login", (req, res) => {
        const now = Date.now();
        const login = failedLogins.get(req.ip);

        if (login && login.windowStartedAt + LOGIN_WINDOW_MS <= now) {
            failedLogins.delete(req.ip);
        }

        const activeLogin = failedLogins.get(req.ip);

        if (activeLogin?.count >= MAX_LOGIN_ATTEMPTS) {
            res.status(429).json({ error: "Too many sign-in attempts. Wait 15 minutes and try again." });
            return;
        }

        if (req.headers.origin && req.headers.origin !== APP_ORIGIN) {
            res.status(403).json({ error: "This action must come from the BlockCert app." });
            return;
        }

        const submittedPassword = typeof req.body?.password === "string" ? req.body.password : "";
        const submittedHash = scryptSync(submittedPassword.slice(0, 256), "blockcert-local-admin", 32);

        if (!timingSafeEqual(adminPasswordHash, submittedHash)) {
            const priorAttempts = failedLogins.get(req.ip);
            failedLogins.set(req.ip, {
                count: (priorAttempts?.count ?? 0) + 1,
                windowStartedAt: priorAttempts?.windowStartedAt ?? now
            });
            res.status(401).json({ error: "That admin password is not correct." });
            return;
        }

        failedLogins.delete(req.ip);

        const sessionId = randomBytes(32).toString("base64url");
        const csrfToken = randomBytes(32).toString("base64url");
        sessions.set(sessionId, {
            csrfToken,
            expiresAt: now + SESSION_LIFETIME_MS
        });

        res.setHeader("Set-Cookie", createSessionCookie(sessionId, SESSION_LIFETIME_MS / 1000));
        res.json({
            authenticated: true,
            csrfToken,
            adminAddress: blockchain.adminAddress
        });
    });

    app.post("/api/admin/logout", requireAdminAction, (req, res) => {
        sessions.delete(req.adminSession.id);
        res.setHeader("Set-Cookie", createSessionCookie("", 0));
        res.json({ authenticated: false });
    });

    app.get("/api/admin/certificates", requireAdmin, (req, res) => {
        res.json({ certificates: getCertificateRows(database) });
    });

    app.post("/api/certificates", requireAdminAction, async (req, res) => {
        const name = validationString(req.body?.name, 120);
        const recipient = validationString(req.body?.recipient, 100);
        const institution = validationString(req.body?.institution, 120);
        const fingerprint = safeFingerprint(req.body?.fingerprint);

        if (!name || !recipient || !institution || !fingerprint) {
            throw new HttpError(400, "Enter the certificate title, recipient, institution, and a valid 64-digit certificate file hash.");
        }

        const id = keccak256(toUtf8Bytes(randomUUID()));
        const transaction = await blockchain.contract.issueCertificate(id, fingerprint);
        const receipt = await transaction.wait();
        const [, issuer, issuedAt] = await blockchain.contract.getCertificate(id);
        const certificate = {
            id,
            fingerprint,
            name,
            recipient,
            institution,
            issuer,
            issuedAt: Number(issuedAt),
            transaction_hash: transaction.hash,
            block_number: Number(receipt.blockNumber),
            revoked: 0
        };

        database.prepare(`
            INSERT INTO certificates (
                id, fingerprint, name, recipient, institution, issuer, issued_at,
                transaction_hash, block_number, revoked
            ) VALUES (
                :id, :fingerprint, :name, :recipient, :institution, :issuer, :issued_at,
                :transaction_hash, :block_number, :revoked
            )
        `).run(certificate);

        res.status(201).json({
            certificate,
            contractAddress: blockchain.contractAddress,
            chainId: blockchain.chainId,
            network: "BlockCert Local Chain"
        });
    });

    app.post("/api/certificates/:id/revoke", requireAdminAction, async (req, res) => {
        const id = req.params.id.toLowerCase();

        if (!ISSUANCE_ID_PATTERN.test(id)) {
            res.status(400).json({ error: "Enter a valid BlockCert certificate ID." });
            return;
        }

        const existing = database.prepare(`
            SELECT revoked FROM certificates WHERE id = ?
        `).get(id);

        if (!existing) {
            res.status(404).json({ error: "This certificate is not in the institution's issuance records." });
            return;
        }

        if (existing.revoked) {
            res.status(409).json({ error: "This certificate has already been revoked." });
            return;
        }

        const transaction = await blockchain.contract.revokeCertificate(id);
        await transaction.wait();
        database.prepare("UPDATE certificates SET revoked = 1 WHERE id = ?").run(id);

        res.json({
            id,
            revoked: true,
            transactionHash: transaction.hash
        });
    });

    app.get("/api/certificates/:id/verify", async (req, res) => {
        const id = req.params.id.toLowerCase();

        if (!ISSUANCE_ID_PATTERN.test(id)) {
            res.status(400).json({ error: "Enter a valid BlockCert certificate ID." });
            return;
        }

        const row = database.prepare(`
            SELECT id, fingerprint, name, recipient, institution, issuer, issued_at,
                   transaction_hash, block_number, revoked
            FROM certificates WHERE id = ?
        `).get(id);
        const [ledgerFingerprint, ledgerIssuer, issuedAt, ledgerRevoked] =
            await blockchain.contract.getCertificate(id);
        const onChain = Number(issuedAt) > 0;

        if (!onChain) {
            res.json({
                status: "not-found",
                onChain: false,
                message: "This certificate ID is not recorded on the BlockCert blockchain.",
                certificate: null
            });
            return;
        }

        if (!row) {
            res.json({
                status: "metadata-missing",
                onChain: true,
                message: "A blockchain entry exists, but its certificate details are unavailable. Ask the issuing institution to investigate.",
                certificate: {
                    id,
                    fingerprint: ledgerFingerprint,
                    issuer: ledgerIssuer,
                    issuedAt: Number(issuedAt),
                    revoked: Boolean(ledgerRevoked)
                }
            });
            return;
        }

        const ledgerMatches = row.fingerprint.toLowerCase() === ledgerFingerprint.toLowerCase()
            && row.issuer.toLowerCase() === ledgerIssuer.toLowerCase()
            && row.issued_at === Number(issuedAt)
            && Boolean(row.revoked) === Boolean(ledgerRevoked);
        const authorizedIssuer = await blockchain.contract.isIssuer(ledgerIssuer);

        if (!ledgerMatches || !authorizedIssuer) {
            res.json({
                status: "ledger-mismatch",
                onChain: true,
                ledgerMatches: false,
                message: "The certificate details do not match the blockchain record. Do not accept this certificate.",
                certificate: row
            });
            return;
        }

        const submittedFingerprint = safeFingerprint(req.query.fingerprint);
        const fileUploaded = Boolean(submittedFingerprint);
        let status = row.revoked ? "revoked" : "recorded";
        let message = row.revoked
            ? "This certificate has been revoked by its issuer. Do not accept it."
            : "A valid certificate issuance is recorded on the blockchain. Upload the certificate file to check that it has not been modified.";
        let hashMatches = null;

        if (fileUploaded) {
            hashMatches = submittedFingerprint === row.fingerprint.toLowerCase();

            if (!hashMatches && !row.revoked) {
                status = "file-mismatch";
                message = "The uploaded file does not match the original certificate fingerprint. It may have been modified.";
            } else if (hashMatches && !row.revoked) {
                status = "verified";
                message = "Verified. This file matches the untampered certificate issued by this institution.";
            }
        }

        res.json({
            status,
            onChain: true,
            ledgerMatches: true,
            hashMatches,
            message,
            certificate: row
        });
    });

    app.use((error, req, res, next) => {
        if (res.headersSent) {
            next(error);
            return;
        }

        const status = Number.isInteger(error.status) ? error.status : 500;

        if (status >= 500) {
            console.error(`[${req.method} ${req.path}]`, error);
        }

        res.status(status).json({
            error: status >= 500
                ? "BlockCert could not complete the request. Check the local application logs."
                : error.message
        });
    });

    return app;
}

async function main() {
    const passwordOverride = process.env.BLOCKCERT_ADMIN_PASSWORD;
    const adminPassword = passwordOverride || createDemoPassword();

    if (adminPassword.length < 12) {
        throw new Error("BLOCKCERT_ADMIN_PASSWORD must be at least 12 characters.");
    }

    await mkdir(DATA_DIRECTORY, { recursive: true });
    const database = getDatabase();
    const blockchain = await startLocalBlockchain({
        dataDirectory: DATA_DIRECTORY,
        contractFile: CONTRACT_FILE
    });

    if (!(await blockchain.contract.isIssuer(blockchain.adminAddress))) {
        throw new Error("The locally authenticated college account is not authorized by the deployed certificate contract.");
    }

    const app = createApplication({ blockchain, database, adminPassword });
    const httpServer = createServer(app);
    let vite;

    if (process.argv.includes("--production")) {
        const buildDirectory = path.join(ROOT_DIRECTORY, "dist");

        try {
            await readFile(path.join(buildDirectory, "index.html"));
        } catch (error) {
            if (error.code === "ENOENT") {
                throw new Error('Production files are missing. Run "npm run build" first.');
            }
            throw error;
        }

        app.use(express.static(buildDirectory, {
            index: "index.html",
            dotfiles: "deny",
            fallthrough: false
        }));
        app.get("/", (_req, res) => res.sendFile(path.join(buildDirectory, "index.html")));
    } else {
        const { createServer: createViteServer } = await import("vite");
        vite = await createViteServer({
            configFile: path.join(ROOT_DIRECTORY, "vite.config.js"),
            root: ROOT_DIRECTORY,
            appType: "spa",
            server: {
                middlewareMode: true,
                hmr: {
                    server: httpServer
                }
            }
        });
        app.use(vite.middlewares);
    }

    await new Promise((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(PORT, "127.0.0.1", resolve);
    });

    console.log("\n  BlockCert is ready on the local-only development network.");
    console.log(`  App:             ${APP_ORIGIN}`);
    console.log(`  Local EVM chain: ${blockchain.chainId}`);
    console.log(`  Contract:        ${blockchain.contractAddress}`);
    console.log(`  College issuer:  ${blockchain.adminAddress}`);

    if (!passwordOverride) {
        console.log(`  One-run admin password: ${adminPassword}`);
        console.log("  This demo password changes whenever the local app restarts.\n");
    } else {
        console.log("  Admin password:  BLOCKCERT_ADMIN_PASSWORD environment variable\n");
    }

    const shutdown = async () => {
        httpServer.close();
        database.close();

        if (vite) {
            await vite.close();
        }

        await blockchain.provider.disconnect();
    };

    process.once("SIGINT", () => void shutdown().finally(() => process.exit(0)));
    process.once("SIGTERM", () => void shutdown().finally(() => process.exit(0)));
}

main().catch(error => {
    console.error("BlockCert could not start:", error);
    process.exitCode = 1;
});
