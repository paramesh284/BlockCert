// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CertificateRegistry {
    struct Certificate {
        bytes32 fingerprint;
        address issuer;
        uint64 issuedAt;
        bool revoked;
    }

    address public immutable owner;

    mapping(address account => bool authorized) public isIssuer;
    mapping(bytes32 certificateId => Certificate certificate) private certificates;

    event IssuerAuthorizationChanged(address indexed issuer, bool authorized);
    event CertificateIssued(
        bytes32 indexed certificateId,
        bytes32 indexed fingerprint,
        address indexed issuer,
        uint64 issuedAt
    );
    event CertificateRevoked(bytes32 indexed certificateId, address indexed issuer);

    error Unauthorized();
    error InvalidAddress();
    error InvalidCertificateId();
    error InvalidFingerprint();
    error CertificateAlreadyExists();
    error CertificateNotFound();
    error CertificateAlreadyRevoked();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyIssuer() {
        if (!isIssuer[msg.sender]) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
        isIssuer[msg.sender] = true;
        emit IssuerAuthorizationChanged(msg.sender, true);
    }

    function setIssuer(address issuer, bool authorized) external onlyOwner {
        if (issuer == address(0)) revert InvalidAddress();
        isIssuer[issuer] = authorized;
        emit IssuerAuthorizationChanged(issuer, authorized);
    }

    function issueCertificate(bytes32 certificateId, bytes32 fingerprint) external onlyIssuer {
        if (certificateId == bytes32(0)) revert InvalidCertificateId();
        if (fingerprint == bytes32(0)) revert InvalidFingerprint();
        if (certificates[certificateId].issuedAt != 0) revert CertificateAlreadyExists();

        uint64 issuedAt = uint64(block.timestamp);
        certificates[certificateId] = Certificate({
            fingerprint: fingerprint,
            issuer: msg.sender,
            issuedAt: issuedAt,
            revoked: false
        });

        emit CertificateIssued(certificateId, fingerprint, msg.sender, issuedAt);
    }

    function revokeCertificate(bytes32 certificateId) external onlyIssuer {
        Certificate storage certificate = certificates[certificateId];
        if (certificate.issuedAt == 0) revert CertificateNotFound();
        if (certificate.revoked) revert CertificateAlreadyRevoked();
        if (certificate.issuer != msg.sender && msg.sender != owner) revert Unauthorized();

        certificate.revoked = true;
        emit CertificateRevoked(certificateId, msg.sender);
    }

    function getCertificate(bytes32 certificateId)
        external
        view
        returns (bytes32 fingerprint, address issuer, uint64 issuedAt, bool revoked)
    {
        Certificate memory certificate = certificates[certificateId];
        return (
            certificate.fingerprint,
            certificate.issuer,
            certificate.issuedAt,
            certificate.revoked
        );
    }
}
