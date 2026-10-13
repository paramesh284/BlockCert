import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { startLocalBlockchain } from "../src/blockchain.js";

const contractFile = fileURLToPath(new URL("../contracts/CertificateRegistry.sol", import.meta.url));

async function makeTemporaryDataDirectory() {
    return mkdtemp(path.join(tmpdir(), "blockcert-test-"));
}

test("certificate issuance is restricted to an authorized college issuer", async t => {
    const dataDirectory = await makeTemporaryDataDirectory();
    let provider;
    t.after(async () => {
        if (provider) {
            await provider.disconnect();
        }
        await rm(dataDirectory, { recursive: true, force: true });
    });

    const blockchain = await startLocalBlockchain({
        dataDirectory,
        contractFile,
        quiet: true
    });
    provider = blockchain.provider;

    const secondSigner = await blockchain.rpcProvider.getSigner(1);
    const unauthorizedContract = blockchain.contract.connect(secondSigner);
    const certificateId = `0x${"11".repeat(32)}`;
    const fingerprint = `0x${"ab".repeat(32)}`;

    assert.equal(await blockchain.contract.isIssuer(blockchain.adminAddress), true);
    assert.equal(await blockchain.contract.isIssuer(await secondSigner.getAddress()), false);
    await assert.rejects(
        unauthorizedContract.issueCertificate(certificateId, fingerprint),
        error => error.code === "CALL_EXCEPTION" || error.code === "UNKNOWN_ERROR"
    );

    const transaction = await blockchain.contract.issueCertificate(certificateId, fingerprint);
    await transaction.wait();

    const [recordedFingerprint, issuer, issuedAt, revoked] =
        await blockchain.contract.getCertificate(certificateId);

    assert.equal(recordedFingerprint, fingerprint);
    assert.equal(issuer, blockchain.adminAddress);
    assert.ok(Number(issuedAt) > 0);
    assert.equal(revoked, false);

    await assert.rejects(
        blockchain.contract.issueCertificate(certificateId, fingerprint),
        error => error.code === "CALL_EXCEPTION" || error.code === "UNKNOWN_ERROR"
    );
});

test("issued and revoked certificate records survive a local demo restart", async t => {
    const dataDirectory = await makeTemporaryDataDirectory();
    let provider;
    t.after(async () => {
        if (provider) {
            await provider.disconnect();
        }
        await rm(dataDirectory, { recursive: true, force: true });
    });

    const firstRun = await startLocalBlockchain({
        dataDirectory,
        contractFile,
        quiet: true
    });
    provider = firstRun.provider;
    const certificateId = `0x${"22".repeat(32)}`;
    const fingerprint = `0x${"cd".repeat(32)}`;
    const issueTransaction = await firstRun.contract.issueCertificate(certificateId, fingerprint);
    await issueTransaction.wait();
    const firstDeployment = firstRun.contractAddress;
    await firstRun.provider.disconnect();

    const secondRun = await startLocalBlockchain({
        dataDirectory,
        contractFile,
        quiet: true
    });
    provider = secondRun.provider;

    assert.equal(secondRun.contractAddress, firstDeployment);

    const [persistedFingerprint, issuer, issuedAt, revoked] =
        await secondRun.contract.getCertificate(certificateId);

    assert.equal(persistedFingerprint, fingerprint);
    assert.equal(issuer, secondRun.adminAddress);
    assert.ok(Number(issuedAt) > 0);
    assert.equal(revoked, false);

    const revokeTransaction = await secondRun.contract.revokeCertificate(certificateId);
    await revokeTransaction.wait();

    const [, , , revokedCertificate] = await secondRun.contract.getCertificate(certificateId);
    assert.equal(revokedCertificate, true);
});
