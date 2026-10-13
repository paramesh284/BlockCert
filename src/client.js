import { Html5Qrcode } from "html5-qrcode";
import QRCode from "qrcode";
import "./styles.css";

const FILE_SIZE_LIMIT = 25 * 1024 * 1024;
const ISSUANCE_ID_PATTERN = /^0x[a-f\d]{64}$/i;
const STATUS_COPY = {
    verified: ["File verified", "verified"],
    recorded: ["Blockchain record found", "recorded"],
    "file-mismatch": ["Certificate file mismatch", "file-mismatch"],
    revoked: ["Certificate revoked", "revoked"],
    "ledger-mismatch": ["Blockchain record mismatch", "ledger-mismatch"],
    "metadata-missing": ["Certificate details unavailable", "metadata-missing"],
    "not-found": ["Certificate not found", "not-found"]
};

const elements = {
    adminAddress: document.querySelector("#admin-address"),
    adminWorkspace: document.querySelector("#admin-workspace"),
    issueFeedback: document.querySelector("#issue-feedback"),
    issueFile: document.querySelector("#issue-file"),
    issueFileName: document.querySelector("#issue-file-name"),
    issueFileNote: document.querySelector("#issue-file-note"),
    issueForm: document.querySelector("#issue-form"),
    issueSubmit: document.querySelector("#issue-submit"),
    issuedResult: document.querySelector("#issued-result"),
    loginFeedback: document.querySelector("#login-feedback"),
    loginForm: document.querySelector("#login-form"),
    loginPanel: document.querySelector("#login-panel"),
    logoutButton: document.querySelector("#logout-button"),
    qrReader: document.querySelector("#qr-reader"),
    recordsCount: document.querySelector("#records-count"),
    recordsList: document.querySelector("#records-list"),
    scanButton: document.querySelector("#scan-button"),
    toast: document.querySelector("#toast"),
    verifyFeedback: document.querySelector("#verify-result"),
    verifyFile: document.querySelector("#verify-file"),
    verifyFileName: document.querySelector("#verify-file-name"),
    verifyFileNote: document.querySelector("#verify-file-note"),
    verifyForm: document.querySelector("#verify-form"),
    verifyId: document.querySelector("#verify-id"),
    verifySubmit: document.querySelector("#verify-submit")
};

const state = {
    authenticated: false,
    csrfToken: null,
    scanner: null,
    scannerStarting: false,
    toastTimer: null
};

async function apiRequest(url, options = {}) {
    const headers = new Headers(options.headers ?? {});

    if (options.body && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }

    if (options.csrf) {
        headers.set("X-BlockCert-CSRF", state.csrfToken ?? "");
    }

    const response = await fetch(url, {
        ...options,
        headers,
        credentials: "same-origin",
        cache: "no-store"
    });
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "The request could not be completed.");
    }

    return data;
}

function showToast(message, kind = "success") {
    elements.toast.textContent = message;
    elements.toast.dataset.kind = kind;
    elements.toast.classList.add("show");
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => {
        elements.toast.classList.remove("show");
    }, 4000);
}

function setFeedback(element, message, kind = "error") {
    element.textContent = message;
    element.dataset.kind = kind;
}

async function calculateFingerprint(file) {
    if (!file) {
        throw new Error("Choose a certificate file first.");
    }

    if (file.size === 0) {
        throw new Error("The selected certificate file is empty.");
    }

    if (file.size > FILE_SIZE_LIMIT) {
        throw new Error("Choose a file smaller than 25 MB.");
    }

    const allowedType = new Set(["application/pdf", "image/png", "image/jpeg", "image/webp"]);
    const allowedExtension = /\.(pdf|png|jpe?g|webp)$/i.test(file.name);

    if (!allowedType.has(file.type) && !allowedExtension) {
        throw new Error("Choose a PDF, PNG, JPEG, or WebP certificate file.");
    }

    if (!window.crypto?.subtle) {
        throw new Error("File hashing needs a secure browser context. Open this app at http://127.0.0.1:4173.");
    }

    const digest = await window.crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    const hexDigest = [...new Uint8Array(digest)]
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

    return `0x${hexDigest}`;
}

function createMetaRow(label, value, { code = false } = {}) {
    const row = document.createElement("div");
    const heading = document.createElement("dt");
    const description = document.createElement("dd");

    heading.textContent = label;
    description.textContent = value;

    if (code) {
        description.classList.add("hash-value");
    }

    row.append(heading, description);
    return row;
}

function renderVerification(data) {
    const [heading, status] = STATUS_COPY[data.status] ?? ["Verification result", "recorded"];
    const panel = elements.verifyFeedback;
    const head = document.createElement("div");
    const icon = document.createElement("span");
    const text = document.createElement("div");
    const title = document.createElement("p");
    const message = document.createElement("p");

    panel.replaceChildren();
    panel.dataset.status = status;
    panel.hidden = false;
    head.className = "result-head";
    icon.className = "result-status";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = status === "verified" ? "✓" : status === "recorded" ? "●" : "!";
    title.className = "result-heading";
    title.textContent = heading;
    message.className = "result-message";
    message.textContent = data.message;
    text.append(title, message);
    head.append(icon, text);
    panel.append(head);

    if (data.certificate) {
        const details = document.createElement("dl");
        details.className = "result-meta";
        details.append(
            createMetaRow("Certificate", data.certificate.name ?? "Blockchain certificate"),
            ...(data.certificate.recipient
                ? [createMetaRow("Graduate", data.certificate.recipient)]
                : []),
            ...(data.certificate.institution
                ? [createMetaRow("Institution", data.certificate.institution)]
                : []),
            createMetaRow("Certificate ID", data.certificate.id, { code: true }),
            createMetaRow("SHA-256 fingerprint", data.certificate.fingerprint, { code: true }),
            createMetaRow("Blockchain issuer", data.certificate.issuer, { code: true }),
            createMetaRow(
                "Issued",
                new Date(Number(data.certificate.issued_at ?? data.certificate.issuedAt) * 1000).toLocaleString()
            )
        );
        panel.append(details);
    }
}

async function readSelectedFingerprint(fileInput, purpose) {
    const file = fileInput.files?.[0];

    if (!file) {
        throw new Error(purpose === "issue"
            ? "Choose the original certificate before issuing."
            : "Choose a certificate file to compare its fingerprint.");
    }

    return calculateFingerprint(file);
}

async function handleVerification(event) {
    event.preventDefault();
    elements.verifyFeedback.hidden = true;
    elements.verifySubmit.disabled = true;
    elements.verifySubmit.textContent = "Checking the blockchain…";

    try {
        const certificateId = elements.verifyId.value.trim();

        if (!ISSUANCE_ID_PATTERN.test(certificateId)) {
            throw new Error("Paste the 66-character certificate ID or scan its QR code.");
        }

        const selectedFile = elements.verifyFile.files?.[0];
        const fingerprint = selectedFile
            ? await readSelectedFingerprint(elements.verifyFile, "verify")
            : null;
        const query = fingerprint ? `?fingerprint=${encodeURIComponent(fingerprint)}` : "";
        const response = await apiRequest(
            `/api/certificates/${encodeURIComponent(certificateId.toLowerCase())}/verify${query}`
        );
        renderVerification(response);
        elements.verifyFeedback.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
        const data = {
            status: "not-found",
            message: error instanceof Error ? error.message : "Verification could not be completed."
        };
        renderVerification(data);
    } finally {
        elements.verifySubmit.disabled = false;
        elements.verifySubmit.replaceChildren(
            document.createTextNode("Verify certificate "),
            Object.assign(document.createElement("span"), {
                textContent: "→",
                ariaHidden: true
            })
        );
    }
}

function makeElement(tag, className, text) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text) {
        element.textContent = text;
    }

    return element;
}

async function buildVerificationLink(id) {
    const verifyUrl = new URL(window.location.pathname, window.location.origin);
    verifyUrl.searchParams.set("verify", id);
    return verifyUrl.toString();
}

async function renderIssuanceResult(certificate, contractAddress, chainId) {
    const verifyUrl = await buildVerificationLink(certificate.id);
    const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
        errorCorrectionLevel: "M",
        margin: 1,
        width: 320,
        color: {
            dark: "#263d2e",
            light: "#ffffff"
        }
    });
    const result = elements.issuedResult;
    const details = makeElement("div", "issued-details");
    const heading = makeElement("h5", "", "Certificate issued successfully");
    const recipient = makeElement("p", "", `${certificate.name} · ${certificate.recipient}`);
    const institution = makeElement("p", "", certificate.institution);
    const fingerprintLabel = makeElement("p", "", "Tamper-evident SHA-256 fingerprint");
    const fingerprint = makeElement("code", "", certificate.fingerprint);
    const ledger = makeElement("p", "", `Recorded on local blockchain · Chain ${chainId}`);
    const contract = makeElement("p", "", `Contract: ${contractAddress}`);
    const qr = makeElement("div", "issued-qr");
    const qrImage = makeElement("img", "", "");
    const link = makeElement("a", "", "Download QR code");

    qrImage.src = qrDataUrl;
    qrImage.alt = "QR code for the certificate’s verification page";
    link.href = qrDataUrl;
    link.download = `BlockCert-${certificate.id.slice(2, 10)}-QR.png`;
    details.append(heading, recipient, institution, fingerprintLabel, fingerprint, ledger, contract);
    qr.append(qrImage, link);
    result.replaceChildren(details, qr);
    result.hidden = false;
}

function makeRecordRow(record) {
    const article = makeElement("article", "record-row");
    const description = document.createElement("div");
    const title = makeElement("div", "record-title", record.name);
    const date = new Date(record.issued_at * 1000).toLocaleDateString();
    const subtitle = makeElement(
        "div",
        "record-subtitle",
        `${record.recipient} · ${record.institution} · ${date}`
    );
    const actions = makeElement("div", "record-actions");
    const verifyLink = makeElement("a", "", "Verify");
    const revokeButton = makeElement("button", "revoke-action", record.revoked ? "Revoked" : "Revoke");
    const qrButton = makeElement("button", "", "QR code");

    description.append(title, subtitle);
    verifyLink.href = `/?verify=${encodeURIComponent(record.id)}`;
    qrButton.type = "button";
    revokeButton.type = "button";
    revokeButton.disabled = Boolean(record.revoked);
    revokeButton.setAttribute("aria-label", `Revoke certificate for ${record.recipient}`);
    qrButton.setAttribute("aria-label", `Show QR code for ${record.recipient}`);

    verifyLink.addEventListener("click", event => {
        if (window.location.pathname === "/") {
            event.preventDefault();
            window.history.replaceState(null, "", verifyLink.href);
            elements.verifyId.value = record.id;
            document.querySelector("#verify").scrollIntoView({ behavior: "smooth" });
            void handleVerification(new Event("submit", { cancelable: true }));
        }
    });

    qrButton.addEventListener("click", () => {
        void showRecordQr(record.id, record.recipient);
    });

    revokeButton.addEventListener("click", () => {
        void revokeRecord(record);
    });

    actions.append(verifyLink, qrButton, revokeButton);
    article.append(description, actions);
    return article;
}

async function showRecordQr(id, recipient) {
    try {
        const verifyUrl = await buildVerificationLink(id);
        const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
            errorCorrectionLevel: "M",
            margin: 1,
            width: 320,
            color: { dark: "#263d2e", light: "#ffffff" }
        });

        await renderIssuanceResult(
            { id, name: "Certificate QR code", recipient, institution: "", fingerprint: "Available on the verification page" },
            "",
            "31337"
        );
        elements.issuedResult.querySelector(".issued-details p:nth-of-type(2)").textContent = `Certificate ID: ${id}`;
        elements.issuedResult.querySelector(".issued-details p:nth-of-type(3)").textContent = "Scan to open this certificate’s public verification page.";
        const qrImage = elements.issuedResult.querySelector(".issued-qr img");
        qrImage.src = qrDataUrl;
        qrImage.alt = `QR code to verify certificate for ${recipient}`;
        elements.issuedResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
        showToast(error.message || "Unable to generate a QR code.", "error");
    }
}

async function revokeRecord(record) {
    if (!window.confirm(`Revoke the certificate for ${record.recipient}? It will be permanently marked as revoked on the local blockchain.`)) {
        return;
    }

    try {
        await apiRequest(`/api/certificates/${encodeURIComponent(record.id)}/revoke`, {
            method: "POST",
            body: JSON.stringify({}),
            csrf: true
        });
        await refreshRecords();
        showToast("Certificate revoked on the local blockchain.");
    } catch (error) {
        showToast(error.message, "error");
    }
}

async function refreshRecords() {
    if (!state.authenticated) {
        return;
    }

    const { certificates } = await apiRequest("/api/admin/certificates");
    elements.recordsCount.textContent = `${certificates.length} record${certificates.length === 1 ? "" : "s"}`;
    elements.recordsList.replaceChildren();

    if (certificates.length === 0) {
        elements.recordsList.append(
            makeElement("div", "empty-records", "No certificates have been issued yet. Start with the form above.")
        );
        return;
    }

    certificates.forEach(certificate => {
        elements.recordsList.append(makeRecordRow(certificate));
    });
}

async function setAuthenticated(adminAddress) {
    state.authenticated = true;
    elements.loginPanel.hidden = true;
    elements.adminWorkspace.hidden = false;
    elements.adminAddress.textContent = `College issuer · ${adminAddress}`;
    await refreshRecords();
}

async function handleIssue(event) {
    event.preventDefault();
    elements.issueFeedback.textContent = "";
    elements.issueSubmit.disabled = true;
    elements.issueSubmit.textContent = "Writing to the blockchain…";

    try {
        const fingerprint = await readSelectedFingerprint(elements.issueFile, "issue");
        const form = new FormData(elements.issueForm);
        const payload = {
            name: String(form.get("name") ?? "").trim(),
            recipient: String(form.get("recipient") ?? "").trim(),
            institution: String(form.get("institution") ?? "").trim(),
            fingerprint
        };
        const { certificate, contractAddress, chainId } = await apiRequest("/api/certificates", {
            method: "POST",
            body: JSON.stringify(payload),
            csrf: true
        });

        await renderIssuanceResult(certificate, contractAddress, chainId);
        elements.issueForm.reset();
        elements.issueFileName.textContent = "Choose the signed certificate file";
        elements.issueFileNote.textContent = "PDF or image · processed privately on this device";
        setFeedback(elements.issueFeedback, "The certificate fingerprint has been recorded on-chain.", "success");
        await refreshRecords();
        elements.issuedResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
        setFeedback(elements.issueFeedback, error.message || "The certificate could not be issued.");
    } finally {
        elements.issueSubmit.disabled = false;
        elements.issueSubmit.replaceChildren(
            document.createTextNode("Issue and record certificate "),
            Object.assign(document.createElement("span"), {
                textContent: "→",
                ariaHidden: true
            })
        );
    }
}

async function login(event) {
    event.preventDefault();
    const submitButton = elements.loginForm.querySelector("button[type='submit']");
    submitButton.disabled = true;
    elements.loginFeedback.textContent = "";

    try {
        const password = String(new FormData(elements.loginForm).get("password") ?? "");
        const data = await apiRequest("/api/admin/login", {
            method: "POST",
            body: JSON.stringify({ password })
        });
        state.csrfToken = data.csrfToken;
        elements.loginForm.reset();
        await setAuthenticated(data.adminAddress);
    } catch (error) {
        setFeedback(elements.loginFeedback, error.message || "Unable to sign in.");
    } finally {
        submitButton.disabled = false;
    }
}

async function logout() {
    try {
        await apiRequest("/api/admin/logout", {
            method: "POST",
            body: JSON.stringify({}),
            csrf: true
        });
        state.authenticated = false;
        state.csrfToken = null;
        elements.adminWorkspace.hidden = true;
        elements.loginPanel.hidden = false;
        elements.recordsList.replaceChildren();
        setFeedback(elements.loginFeedback, "You are signed out.", "info");
    } catch (error) {
        showToast(error.message, "error");
    }
}

async function toggleScanner() {
    if (state.scanner || state.scannerStarting) {
        await stopScanner();
        return;
    }

    if (!navigator.mediaDevices?.getUserMedia) {
        showToast("Camera access is unavailable. Open BlockCert through http://127.0.0.1:4173.", "error");
        return;
    }

    state.scanner = new Html5Qrcode("qr-reader");
    state.scannerStarting = true;
    elements.qrReader.hidden = false;

    try {
        await state.scanner.start(
            { facingMode: "environment" },
            { fps: 10, qrbox: { width: 210, height: 210 } },
            async decodedText => {
                await stopScanner();
                const certificateId = getIdFromScannedValue(decodedText);

                if (!certificateId) {
                    showToast("That QR code does not contain a BlockCert certificate link.", "error");
                    return;
                }

                elements.verifyId.value = certificateId;
                await handleVerification(new Event("submit", { cancelable: true }));
            },
            () => {}
        );
        elements.scanButton.setAttribute("aria-pressed", "true");
        elements.scanButton.setAttribute("aria-label", "Stop scanning a certificate QR code");
    } catch (error) {
        await stopScanner();
        showToast(error.message || "Could not start the camera. Check your camera permission.", "error");
    } finally {
        state.scannerStarting = false;
    }
}

async function stopScanner() {
    if (!state.scanner) {
        return;
    }

    const scanner = state.scanner;
    state.scanner = null;
    state.scannerStarting = false;
    elements.scanButton.setAttribute("aria-pressed", "false");
    elements.scanButton.setAttribute("aria-label", "Scan a certificate QR code");

    if (scanner.isScanning) {
        await scanner.stop();
    }

    scanner.clear();
    elements.qrReader.hidden = true;
}

function getIdFromScannedValue(value) {
    if (ISSUANCE_ID_PATTERN.test(value.trim())) {
        return value.trim();
    }

    try {
        const scannedUrl = new URL(value);
        const certificateId = scannedUrl.searchParams.get("verify");
        return certificateId && ISSUANCE_ID_PATTERN.test(certificateId) ? certificateId : null;
    } catch {
        return null;
    }
}

function updateFilePicker(input, name, note, prompt, hint) {
    const file = input.files?.[0];

    name.textContent = file ? file.name : prompt;
    note.textContent = file
        ? `${(file.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 0 })} KB · private SHA-256 check`
        : hint;
}

async function restoreSession() {
    const session = await apiRequest("/api/admin/session");

    if (session.authenticated) {
        state.csrfToken = session.csrfToken;
        await setAuthenticated(session.adminAddress);
    }

    const requestedId = new URLSearchParams(window.location.search).get("verify");

    if (requestedId) {
        elements.verifyId.value = requestedId;
        document.querySelector("#verify").scrollIntoView({ behavior: "smooth" });
        await handleVerification(new Event("submit", { cancelable: true }));
    }
}

elements.verifyForm.addEventListener("submit", handleVerification);
elements.loginForm.addEventListener("submit", login);
elements.issueForm.addEventListener("submit", handleIssue);
elements.logoutButton.addEventListener("click", logout);
elements.scanButton.addEventListener("click", () => void toggleScanner());

elements.verifyFile.addEventListener("change", () => {
    updateFilePicker(
        elements.verifyFile,
        elements.verifyFileName,
        elements.verifyFileNote,
        "Choose a certificate file",
        "Hashed on this device. The document itself is never uploaded."
    );
});

elements.issueFile.addEventListener("change", () => {
    updateFilePicker(
        elements.issueFile,
        elements.issueFileName,
        elements.issueFileNote,
        "Choose the signed certificate file",
        "PDF or image · processed privately on this device"
    );
});

restoreSession().catch(error => {
    showToast(error.message || "The local verification service is not available.", "error");
});
