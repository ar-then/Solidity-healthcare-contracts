// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title PatientConsentManager
/// @notice Patients register records (pointers/hashes) and grant/revoke provider access. Events provide an auditable trail.
/// @dev Store only pointers (e.g., IPFS CIDs or encrypted URIs). Do NOT store raw medical data on-chain.
contract PatientConsentManager {
    
    // The data for the 
    struct Record {
        address owner;      // patient who created the record
        string uri;         // pointer to off-chain encrypted data (e.g., IPFS CID or encrypted URL)
        bool exists;
    }

    struct Grant {
        uint256 expiresAt;  // unix timestamp; 0 = no access
        bool allowed;       // true if allowed (false if explicitly revoked)
    }

    // --- Storage ---
    // recordId is a uint generated per-patient (or global counter). We'll use a global counter for simplicity.
    uint256 private _recordCounter;

    // recordId => Record
    mapping(uint256 => Record) public records;

    // recordId => provider => Grant
    mapping(uint256 => mapping(address => Grant)) public grants;

    // optional: allow patient to delegate an operator who can manage grants for them
    mapping(address => mapping(address => bool)) public operatorApproval; // patient => operator => approved

    // --- Events (auditable trail) ---
    event RecordCreated(uint256 indexed recordId, address indexed owner, string uri);
    event RecordUpdated(uint256 indexed recordId, address indexed owner, string newUri);
    event RecordRemoved(uint256 indexed recordId, address indexed owner);

    event AccessRequested(uint256 indexed recordId, address indexed provider, address indexed patient, uint256 timestamp);
    event AccessGranted(uint256 indexed recordId, address indexed patient, address indexed provider, uint256 expiresAt);
    event AccessRevoked(uint256 indexed recordId, address indexed patient, address indexed provider);

    event OperatorApproved(address indexed patient, address indexed operator, bool approved);

    // --- Modifiers ---
    modifier onlyRecordOwner(uint256 recordId) {
        require(records[recordId].exists, "Record does not exist");
        require(records[recordId].owner == msg.sender, "Not record owner");
        _;
    }

    modifier onlyPatientOrOperator(uint256 recordId) {
        require(records[recordId].exists, "Record does not exist");
        address patient = records[recordId].owner;
        require(
            msg.sender == patient || operatorApproval[patient][msg.sender],
            "Not patient nor approved operator"
        );
        _;
    }

    // --- Constructor ---
    constructor() {}

    // --- Record management ---
    /// @notice Create a new record pointer (only pointer stored)
    /// @param uri pointer to encrypted record (IPFS CID, encrypted URL, etc.)
    /// @return recordId newly created record id
    function createRecord(string calldata uri) external returns (uint256 recordId) {
        _recordCounter++;
        recordId = _recordCounter;

        records[recordId] = Record({
            owner: msg.sender,
            uri: uri,
            exists: true
        });

        emit RecordCreated(recordId, msg.sender, uri);
    }

    /// @notice Update record pointer. Only owner or approved operator can update.
    function updateRecord(uint256 recordId, string calldata newUri) external onlyPatientOrOperator(recordId) {
        records[recordId].uri = newUri;
        emit RecordUpdated(recordId, records[recordId].owner, newUri);
    }

    /// @notice Remove a record pointer. Only the owner can remove.
    function removeRecord(uint256 recordId) external onlyRecordOwner(recordId) {
        delete records[recordId];
        // clear grants associated with the record (optional; mapping entries will be cleaned by write-once)
        // Note: we cannot iterate providers here — they remain in storage until overwritten.
        emit RecordRemoved(recordId, msg.sender);
    }

    // --- Operator approvals (patient can allow a hospital admin or app to manage grants) ---
    function setOperatorApproval(address operator, bool approved) external {
        operatorApproval[msg.sender][operator] = approved;
        emit OperatorApproved(msg.sender, operator, approved);
    }

    // --- Access control functions ---
    /// @notice Grant access to provider for a record until expiresAt (unix timestamp). Only owner/operator.
    /// @param recordId The record to grant access to
    /// @param provider The provider address (e.g., provider's wallet)
    /// @param expiresAt Unix timestamp when access expires (0 for immediate revoke). Must be in the future.
    function grantAccess(uint256 recordId, address provider, uint256 expiresAt) external onlyPatientOrOperator(recordId) {
        require(provider != address(0), "Invalid provider");
        require(records[recordId].exists, "Record does not exist");
        require(expiresAt > block.timestamp, "expiresAt must be in the future");

        grants[recordId][provider] = Grant({
            expiresAt: expiresAt,
            allowed: true
        });

        emit AccessGranted(recordId, records[recordId].owner, provider, expiresAt);
    }

    /// @notice Revoke access to provider for a record. Only owner/operator.
    function revokeAccess(uint256 recordId, address provider) external onlyPatientOrOperator(recordId) {
        require(records[recordId].exists, "Record does not exist");
        grants[recordId][provider] = Grant({
            expiresAt: 0,
            allowed: false
        });

        emit AccessRevoked(recordId, records[recordId].owner, provider);
    }

    /// @notice Provider can call this to request access (optional). Emits event so patient/operator can see requests.
    function requestAccess(uint256 recordId) external {
        require(records[recordId].exists, "Record does not exist");
        emit AccessRequested(recordId, msg.sender, records[recordId].owner, block.timestamp);
    }

    // --- View helpers ---
    /// @notice Check whether a provider currently has access
    function hasAccess(uint256 recordId, address provider) public view returns (bool) {
        Grant memory g = grants[recordId][provider];
        if (!g.allowed) return false;
        return g.expiresAt > block.timestamp;
    }

    /// @notice Get the record pointer (uri). Returns uri only if caller is owner or has access.
    function getRecordUri(uint256 recordId) external view returns (string memory) {
        require(records[recordId].exists, "Record does not exist");
        address owner = records[recordId].owner;
        if (msg.sender == owner) {
            return records[recordId].uri;
        }
        require(hasAccess(recordId, msg.sender), "No access to record");
        return records[recordId].uri;
    }

    // --- Administrative / utility ---
    function currentRecordCounter() external view returns (uint256) {
        return _recordCounter;
    }
}
