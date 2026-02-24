// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MarketVerificationRegistry {
    uint8 private constant NODE_ACTION_ACTIVATED = 1;
    uint8 private constant NODE_ACTION_HEARTBEAT = 2;

    error UnauthorizedCoordinator();
    error UnauthorizedOwner();
    error AlreadyFinalized(bytes32 requestId);
    error InvalidCoordinator();
    error InvalidOwner();
    error InvalidScore();
    error InvalidResponderCount();
    error InvalidHash();
    error InvalidNodeAction();
    error LifecycleAlreadyRecorded(bytes32 lifecycleId);
    error InvalidPorInputs();
    error PorProofAlreadyRecorded(uint32 marketId, uint64 epoch);

    struct VerificationRecord {
        bytes32 requestId;
        bytes32 questionHash;
        bytes32 sourcesHash;
        int16 aggregateScoreBps;
        bool verdict;
        uint8 responders;
        bytes32 reportHash;
        string reportUri;
        address coordinator;
        uint256 timestamp;
    }

    struct PorProofRecord {
        uint32 marketId;
        uint64 epoch;
        uint256 assetsMicroUsdc;
        uint256 liabilitiesMicroUsdc;
        uint32 coverageBps;
        bool healthy;
        bytes32 proofHash;
        string proofUri;
        address coordinator;
        uint256 timestamp;
    }

    address public owner;
    address public coordinator;

    mapping(bytes32 => VerificationRecord) private _records;
    mapping(bytes32 => bool) private _lifecycleRecords;
    mapping(bytes32 => PorProofRecord) private _porProofs;
    mapping(uint32 => uint64) private _latestPorEpochByMarket;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event CoordinatorUpdated(address indexed previousCoordinator, address indexed newCoordinator);

    event VerificationFinalized(
        bytes32 indexed requestId,
        bool verdict,
        int16 aggregateScoreBps,
        uint8 responders,
        bytes32 reportHash,
        string reportUri,
        address coordinator,
        uint256 timestamp
    );

    event NodeLifecycleRecorded(
        bytes32 indexed lifecycleId,
        address indexed nodeId,
        uint8 indexed action,
        bytes32 endpointHash,
        bytes32 payloadHash,
        string endpointUrl,
        string payloadUri,
        address coordinator,
        uint256 timestamp
    );

    event PorProofRecorded(
        uint32 indexed marketId,
        uint64 indexed epoch,
        bytes32 indexed proofHash,
        uint256 assetsMicroUsdc,
        uint256 liabilitiesMicroUsdc,
        uint32 coverageBps,
        bool healthy,
        string proofUri,
        address coordinator,
        uint256 timestamp
    );

    constructor(address initialCoordinator) {
        if (initialCoordinator == address(0)) {
            revert InvalidCoordinator();
        }
        owner = msg.sender;
        coordinator = initialCoordinator;
        emit OwnershipTransferred(address(0), owner);
        emit CoordinatorUpdated(address(0), initialCoordinator);
    }

    modifier onlyCoordinator() {
        _onlyCoordinator();
        _;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyCoordinator() internal view {
        if (msg.sender != coordinator) {
            revert UnauthorizedCoordinator();
        }
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) {
            revert UnauthorizedOwner();
        }
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert InvalidOwner();
        }

        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    function setCoordinator(address newCoordinator) external onlyOwner {
        if (newCoordinator == address(0)) {
            revert InvalidCoordinator();
        }
        address previous = coordinator;
        coordinator = newCoordinator;
        emit CoordinatorUpdated(previous, newCoordinator);
    }

    function finalizeVerification(
        bytes32 requestId,
        bytes32 questionHash,
        bytes32 sourcesHash,
        int16 aggregateScoreBps,
        bool verdict,
        uint8 responders,
        bytes32 reportHash,
        string calldata reportUri
    ) external onlyCoordinator {
        if (_records[requestId].timestamp != 0) {
            revert AlreadyFinalized(requestId);
        }
        if (aggregateScoreBps < -10000 || aggregateScoreBps > 10000) {
            revert InvalidScore();
        }
        if (responders < 3 || responders > 4) {
            revert InvalidResponderCount();
        }
        if (requestId == bytes32(0) || questionHash == bytes32(0) || sourcesHash == bytes32(0) || reportHash == bytes32(0)) {
            revert InvalidHash();
        }

        VerificationRecord memory record = VerificationRecord({
            requestId: requestId,
            questionHash: questionHash,
            sourcesHash: sourcesHash,
            aggregateScoreBps: aggregateScoreBps,
            verdict: verdict,
            responders: responders,
            reportHash: reportHash,
            reportUri: reportUri,
            coordinator: msg.sender,
            timestamp: block.timestamp
        });

        _records[requestId] = record;

        emit VerificationFinalized(
            requestId,
            verdict,
            aggregateScoreBps,
            responders,
            reportHash,
            reportUri,
            msg.sender,
            block.timestamp
        );
    }

    function hasVerification(bytes32 requestId) external view returns (bool) {
        return _records[requestId].timestamp != 0;
    }

    function getVerification(bytes32 requestId) external view returns (VerificationRecord memory) {
        return _records[requestId];
    }

    function hasNodeLifecycle(bytes32 lifecycleId) external view returns (bool) {
        return _lifecycleRecords[lifecycleId];
    }

    function recordNodeLifecycle(
        bytes32 lifecycleId,
        address nodeId,
        uint8 action,
        bytes32 endpointHash,
        bytes32 payloadHash,
        string calldata endpointUrl,
        string calldata payloadUri
    ) external onlyCoordinator {
        if (lifecycleId == bytes32(0) || nodeId == address(0) || endpointHash == bytes32(0) || payloadHash == bytes32(0)) {
            revert InvalidHash();
        }
        if (action != NODE_ACTION_ACTIVATED && action != NODE_ACTION_HEARTBEAT) {
            revert InvalidNodeAction();
        }
        if (_lifecycleRecords[lifecycleId]) {
            revert LifecycleAlreadyRecorded(lifecycleId);
        }

        _lifecycleRecords[lifecycleId] = true;

        emit NodeLifecycleRecorded(
            lifecycleId,
            nodeId,
            action,
            endpointHash,
            payloadHash,
            endpointUrl,
            payloadUri,
            msg.sender,
            block.timestamp
        );
    }

    function hasPorProof(uint32 marketId, uint64 epoch) external view returns (bool) {
        return _porProofs[_porKey(marketId, epoch)].timestamp != 0;
    }

    function getPorProof(uint32 marketId, uint64 epoch) external view returns (PorProofRecord memory) {
        return _porProofs[_porKey(marketId, epoch)];
    }

    function getLatestPorProof(uint32 marketId) external view returns (PorProofRecord memory) {
        uint64 latestEpoch = _latestPorEpochByMarket[marketId];
        if (latestEpoch == 0) {
            return PorProofRecord({
                marketId: marketId,
                epoch: 0,
                assetsMicroUsdc: 0,
                liabilitiesMicroUsdc: 0,
                coverageBps: 0,
                healthy: false,
                proofHash: bytes32(0),
                proofUri: "",
                coordinator: address(0),
                timestamp: 0
            });
        }
        return _porProofs[_porKey(marketId, latestEpoch)];
    }

    function recordPorProof(
        uint32 marketId,
        uint64 epoch,
        uint256 assetsMicroUsdc,
        uint256 liabilitiesMicroUsdc,
        bytes32 proofHash,
        string calldata proofUri
    ) external onlyCoordinator {
        if (marketId == 0 || epoch == 0 || liabilitiesMicroUsdc == 0 || proofHash == bytes32(0)) {
            revert InvalidPorInputs();
        }

        bytes32 key = _porKey(marketId, epoch);
        if (_porProofs[key].timestamp != 0) {
            revert PorProofAlreadyRecorded(marketId, epoch);
        }

        uint32 coverageBps = uint32((assetsMicroUsdc * 10000) / liabilitiesMicroUsdc);
        bool healthy = coverageBps >= 10000;

        _porProofs[key] = PorProofRecord({
            marketId: marketId,
            epoch: epoch,
            assetsMicroUsdc: assetsMicroUsdc,
            liabilitiesMicroUsdc: liabilitiesMicroUsdc,
            coverageBps: coverageBps,
            healthy: healthy,
            proofHash: proofHash,
            proofUri: proofUri,
            coordinator: msg.sender,
            timestamp: block.timestamp
        });

        if (epoch > _latestPorEpochByMarket[marketId]) {
            _latestPorEpochByMarket[marketId] = epoch;
        }

        emit PorProofRecorded(
            marketId,
            epoch,
            proofHash,
            assetsMicroUsdc,
            liabilitiesMicroUsdc,
            coverageBps,
            healthy,
            proofUri,
            msg.sender,
            block.timestamp
        );
    }

    function _porKey(uint32 marketId, uint64 epoch) internal pure returns (bytes32) {
        return keccak256(abi.encode(marketId, epoch));
    }
}
