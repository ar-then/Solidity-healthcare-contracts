// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


/// @title PatientConsentManager
/// @notice Patients register records (pointers/hashes) and grant/revoke provider access. Events provide an auditable trail.
contract PatientConsentManager {
    
    // Patint data
    struct Record {
        address owner;      // patient 
        string uri;         // pointer to off-chain encrypted data
        bool exists;        // check whether the record exists in base
    }

    // Access data
    struct Grant {
        uint256 expiresAt;  // unix timestamp shows whether access is expired; 0 = no access
        bool allowed;       // true if access is allowed (false if explicitly revoked)
    }





    // A  global record counter shows the record number in the base
    uint256 private _recordCounter;


    // Record tracker (recordId => Record)
    mapping(uint256 => Record) public records;

    // Access grant tracker (recordId => grant provider => Grant)
    mapping(uint256 => mapping(address => Grant)) public grants;

    


    // Events to create and update records 
    event RecordCreated(uint256 indexed recordId, address indexed owner, string uri);
    event RecordUpdated(uint256 indexed recordId, address indexed owner, string newUri);
    event RecordRemoved(uint256 indexed recordId, address indexed owner);
    
    // Events to manage accesses
    event AccessRequested(uint256 indexed recordId, address indexed provider, address indexed patient, uint256 timestamp);
    event AccessGranted(uint256 indexed recordId, address indexed patient, address indexed provider, uint256 expiresAt);
    event AccessRevoked(uint256 indexed recordId, address indexed patient, address indexed provider);

    // Modifier defines that only the patient (record owner) can access or modify the record data
    modifier onlyRecordOwner(uint256 recordId) {
        require(records[recordId].exists, "Record does not exist");
        require(records[recordId].owner == msg.sender, "Not record owner");
        _;
    }

    // --- Constructor ---
    constructor() {}

    // Record management functions
    
    /// @notice Create a new record pointer using encrypted record URI (only pointer stored)
    /// @param uri pointer to encrypted record
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
    function updateRecord(uint256 recordId, string calldata newUri) external onlyRecordOwner(recordId) {
        records[recordId].uri = newUri;
        emit RecordUpdated(recordId, records[recordId].owner, newUri);
    }

    /// @notice Remove a record pointer. Only owner can remove.
    function removeRecord(uint256 recordId) external onlyRecordOwner(recordId) {
        delete records[recordId];
        emit RecordRemoved(recordId, msg.sender);
    }

 

    // Access control function

    /// @notice Grant access to provider for a record, for specific time. Only owner/operator can grant.
    /// @param recordId The record to grant access to
    /// @param provider The provider address (e.g., provider's wallet)
    /// @param expiresAt Unix timestamp shows when access expires (set 0 for immediate revoke). Must be in the future.
    function grantAccess(uint256 recordId, address provider, uint256 expiresAt) external onlyRecordOwner(recordId) {
        require(provider != address(0), "Invalid provider");
        require(records[recordId].exists, "Record does not exist");
        require(expiresAt > block.timestamp, "expiresAt must be in the future");

        grants[recordId][provider] = Grant({
            expiresAt: expiresAt,
            allowed: true
        });

        emit AccessGranted(recordId, records[recordId].owner, provider, expiresAt);
    }

    /// @notice Revoke access to provider for a record. Only owner/operator can remove.
    function revokeAccess(uint256 recordId, address provider) external onlyRecordOwner(recordId) {
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


    /// @notice Check whether a provider currently has access
    function hasAccess(uint256 recordId, address provider) public view returns (bool) {
        Grant memory g = grants[recordId][provider];
        if (!g.allowed) return false;
        return g.expiresAt > block.timestamp;
    }


    // Fetching the record from the base

    /// @notice Get the record uri (the record of interest). Returns uri only if caller is owner or has access.
    function getRecordUri(uint256 recordId) external view returns (string memory) {
        require(records[recordId].exists, "Record does not exist");
        address owner = records[recordId].owner;
        if (msg.sender == owner) {
            return records[recordId].uri;
        }
        require(hasAccess(recordId, msg.sender), "No access to record");
        return records[recordId].uri;
    }

    // Asministrative

    /// @notice Check the current record counter
    function currentRecordCounter() external view returns (uint256) {
        return _recordCounter;
    }
}
