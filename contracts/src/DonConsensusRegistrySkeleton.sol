// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Registry skeleton for DON-style bundle finalization.
/// @dev Implements EIP-712 checks for leader signature and operator approval signatures.
///      NodeReport-level payload validation remains offchain and is linked through merkle roots.
contract DonConsensusRegistrySkeleton {
    uint8 private constant NODE_ACTION_ACTIVATED = 1;
    uint8 private constant NODE_ACTION_HEARTBEAT = 2;

    error UnauthorizedCoordinator();
    error UnauthorizedOwner();
    error InvalidCoordinator();
    error InvalidOwner();
    error AlreadyFinalized(bytes32 requestId);
    error InvalidScore();
    error InvalidResponderCount();
    error InvalidHash();
    error InvalidLeader();
    error InvalidBundleLengths();
    error InvalidSignature();
    error InvalidBundleHash();
    error DuplicateOperator(address operator);
    error OperatorNotAllowed(address operator);
    error InvalidNodeAction();
    error LifecycleAlreadyRecorded(bytes32 lifecycleId);
    error InvalidPorInputs();
    error PorProofAlreadyRecorded(uint32 marketId, uint64 epoch);
    error InvalidRewardRecipient();
    error NoPendingRewards(address operator);
    error RewardTransferFailed();
    error RewardWithdrawalExceedsAvailable(uint256 requested, uint256 available);

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant CONSENSUS_BUNDLE_TYPEHASH =
        keccak256(
            "ConsensusBundle(bytes32 requestId,bytes32 requestHash,uint32 round,int16 aggregateScoreBps,bool finalVerdict,uint8 responders,bytes32 reportsMerkleRoot,bytes32 attestationRootHash,bytes32 promptTemplateHash,uint64 consensusTimestamp)"
        );
    bytes32 private constant OPERATOR_APPROVAL_TYPEHASH =
        keccak256("OperatorApproval(bytes32 bundleHash,bytes32 requestId,uint32 round)");
    bytes32 private constant NAME_HASH = keccak256(bytes("CRE-DON-Consensus"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct BundleRecord {
        bytes32 requestId;
        bytes32 requestHash;
        uint32 round;
        int16 aggregateScoreBps;
        bool verdict;
        uint8 responders;
        bytes32 reportsMerkleRoot;
        bytes32 attestationRootHash;
        bytes32 bundleHash;
        bytes32 promptTemplateHash;
        uint64 consensusTimestamp;
        address leader;
        address coordinator;
        uint256 timestamp;
        string reportUri;
    }

    struct FinalizeWithBundleInput {
        bytes32 requestId;
        bytes32 requestHash;
        uint32 round;
        int16 aggregateScoreBps;
        bool verdict;
        uint8 responders;
        bytes32 reportsMerkleRoot;
        bytes32 attestationRootHash;
        bytes32 bundleHash;
        bytes32 promptTemplateHash;
        uint64 consensusTimestamp;
        address leader;
        address[] includedOperators;
        bytes[] reportSignatures;
        bytes leaderSignature;
        string reportUri;
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
    uint256 public rewardPerResponderWei;
    uint256 public leaderBonusWei;
    bool public rewardsEnabled;
    uint256 public totalPendingRewardsWei;

    mapping(bytes32 => BundleRecord) private _bundleRecords;
    mapping(bytes32 => bool) private _lifecycleRecords;
    mapping(bytes32 => PorProofRecord) private _porProofs;
    mapping(uint32 => uint64) private _latestPorEpochByMarket;
    mapping(address => bool) public operatorAllowlist;
    mapping(address => uint256) private _pendingRewardsWei;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event CoordinatorUpdated(address indexed previousCoordinator, address indexed newCoordinator);
    event OperatorPermissionUpdated(address indexed operator, bool allowed);
    event VerificationBundleFinalized(
        bytes32 indexed requestId,
        bytes32 indexed bundleHash,
        bool verdict,
        int16 aggregateScoreBps,
        uint8 responders,
        uint32 round,
        bytes32 reportsMerkleRoot,
        bytes32 attestationRootHash,
        bytes32 promptTemplateHash,
        uint64 consensusTimestamp,
        address leader,
        address coordinator,
        uint256 timestamp,
        string reportUri
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

    event RewardConfigUpdated(uint256 rewardPerResponderWei, uint256 leaderBonusWei, bool rewardsEnabled);
    event RewardPoolFunded(address indexed sender, uint256 amount, uint256 balanceAfter);
    event RewardAccrued(bytes32 indexed requestId, address indexed operator, uint256 amount, bool isLeader);
    event RewardClaimed(address indexed operator, address indexed recipient, uint256 amount);
    event RewardPoolWithdrawn(address indexed recipient, uint256 amount);

    constructor(address initialCoordinator) {
        if (initialCoordinator == address(0)) {
            revert InvalidCoordinator();
        }
        owner = msg.sender;
        coordinator = initialCoordinator;
        emit OwnershipTransferred(address(0), owner);
        emit CoordinatorUpdated(address(0), initialCoordinator);
    }

    receive() external payable {
        emit RewardPoolFunded(msg.sender, msg.value, address(this).balance);
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

    function setOperatorPermission(address operator, bool allowed) external onlyOwner {
        if (operator == address(0)) {
            revert InvalidLeader();
        }
        operatorAllowlist[operator] = allowed;
        emit OperatorPermissionUpdated(operator, allowed);
    }

    function setOperatorPermissions(address[] calldata operators, bool allowed) external onlyOwner {
        for (uint256 i = 0; i < operators.length; i++) {
            address operator = operators[i];
            if (operator == address(0)) {
                revert InvalidLeader();
            }
            operatorAllowlist[operator] = allowed;
            emit OperatorPermissionUpdated(operator, allowed);
        }
    }

    function setRewardConfig(uint256 newRewardPerResponderWei, uint256 newLeaderBonusWei, bool enabled) external onlyOwner {
        rewardPerResponderWei = newRewardPerResponderWei;
        leaderBonusWei = newLeaderBonusWei;
        rewardsEnabled = enabled;
        emit RewardConfigUpdated(newRewardPerResponderWei, newLeaderBonusWei, enabled);
    }

    function pendingRewardWei(address operator) external view returns (uint256) {
        return _pendingRewardsWei[operator];
    }

    function availableRewardPoolWei() public view returns (uint256) {
        uint256 balance = address(this).balance;
        if (balance <= totalPendingRewardsWei) {
            return 0;
        }
        return balance - totalPendingRewardsWei;
    }

    function claimRewards(address payable recipient) external {
        if (recipient == address(0)) {
            revert InvalidRewardRecipient();
        }

        uint256 amount = _pendingRewardsWei[msg.sender];
        if (amount == 0) {
            revert NoPendingRewards(msg.sender);
        }

        _pendingRewardsWei[msg.sender] = 0;
        totalPendingRewardsWei -= amount;

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            _pendingRewardsWei[msg.sender] = amount;
            totalPendingRewardsWei += amount;
            revert RewardTransferFailed();
        }

        emit RewardClaimed(msg.sender, recipient, amount);
    }

    function withdrawAvailableRewards(address payable recipient, uint256 amountWei) external onlyOwner {
        if (recipient == address(0)) {
            revert InvalidRewardRecipient();
        }

        uint256 available = availableRewardPoolWei();
        if (amountWei > available) {
            revert RewardWithdrawalExceedsAvailable(amountWei, available);
        }

        (bool success, ) = recipient.call{value: amountWei}("");
        if (!success) {
            revert RewardTransferFailed();
        }

        emit RewardPoolWithdrawn(recipient, amountWei);
    }

    function finalizeWithBundle(bytes calldata encodedInput) external onlyCoordinator {
        FinalizeWithBundleInput memory input = abi.decode(encodedInput, (FinalizeWithBundleInput));
        _finalizeWithBundle(input);
    }

    function _finalizeWithBundle(FinalizeWithBundleInput memory input) internal {
        _validateFinalizeInput(input);
        _verifyLeaderSignature(input);
        _verifyOperatorApprovals(input);

        BundleRecord memory record = _toBundleRecord(input);
        _bundleRecords[input.requestId] = record;
        _accrueRewards(input.requestId, input.includedOperators, input.leader);
        _emitVerificationBundleFinalized(record);
    }

    function _validateFinalizeInput(FinalizeWithBundleInput memory input) internal view {
        if (_bundleRecords[input.requestId].timestamp != 0) {
            revert AlreadyFinalized(input.requestId);
        }
        if (input.aggregateScoreBps < -10000 || input.aggregateScoreBps > 10000) {
            revert InvalidScore();
        }
        if (input.responders < 3 || input.responders > 4) {
            revert InvalidResponderCount();
        }
        if (
            input.requestId == bytes32(0) ||
            input.requestHash == bytes32(0) ||
            input.reportsMerkleRoot == bytes32(0) ||
            input.attestationRootHash == bytes32(0) ||
            input.bundleHash == bytes32(0) ||
            input.promptTemplateHash == bytes32(0)
        ) {
            revert InvalidHash();
        }
        if (input.leader == address(0)) {
            revert InvalidLeader();
        }
        if (input.consensusTimestamp == 0) {
            revert InvalidHash();
        }
        if (input.includedOperators.length != input.responders || input.reportSignatures.length != input.responders) {
            revert InvalidBundleLengths();
        }
        if (input.leaderSignature.length == 0) {
            revert InvalidSignature();
        }
    }

    function _verifyLeaderSignature(FinalizeWithBundleInput memory input) internal view {
        bytes32 bundleStructHash = keccak256(
            abi.encode(
                CONSENSUS_BUNDLE_TYPEHASH,
                input.requestId,
                input.requestHash,
                input.round,
                input.aggregateScoreBps,
                input.verdict,
                input.responders,
                input.reportsMerkleRoot,
                input.attestationRootHash,
                input.promptTemplateHash,
                input.consensusTimestamp
            )
        );

        if (bundleStructHash != input.bundleHash) {
            revert InvalidBundleHash();
        }

        bytes32 bundleDigest = _hashTypedDataV4(bundleStructHash);
        address recoveredLeader = _recoverSigner(bundleDigest, input.leaderSignature);
        if (recoveredLeader != input.leader) {
            revert InvalidSignature();
        }
    }

    function _verifyOperatorApprovals(FinalizeWithBundleInput memory input) internal view {
        bytes32 operatorApprovalStructHash =
            keccak256(abi.encode(OPERATOR_APPROVAL_TYPEHASH, input.bundleHash, input.requestId, input.round));
        bytes32 operatorApprovalDigest = _hashTypedDataV4(operatorApprovalStructHash);

        bool leaderIncluded = false;
        for (uint256 i = 0; i < input.includedOperators.length; i++) {
            address operator = input.includedOperators[i];
            if (operator == address(0) || input.reportSignatures[i].length == 0) {
                revert InvalidSignature();
            }
            if (!operatorAllowlist[operator]) {
                revert OperatorNotAllowed(operator);
            }
            if (operator == input.leader) {
                leaderIncluded = true;
            }

            for (uint256 j = 0; j < i; j++) {
                if (operator == input.includedOperators[j]) {
                    revert DuplicateOperator(operator);
                }
            }

            address recoveredOperator = _recoverSigner(operatorApprovalDigest, input.reportSignatures[i]);
            if (recoveredOperator != operator) {
                revert InvalidSignature();
            }
        }

        if (!leaderIncluded) {
            revert InvalidLeader();
        }
    }

    function _toBundleRecord(FinalizeWithBundleInput memory input) internal view returns (BundleRecord memory) {
        return BundleRecord({
            requestId: input.requestId,
            requestHash: input.requestHash,
            round: input.round,
            aggregateScoreBps: input.aggregateScoreBps,
            verdict: input.verdict,
            responders: input.responders,
            reportsMerkleRoot: input.reportsMerkleRoot,
            attestationRootHash: input.attestationRootHash,
            bundleHash: input.bundleHash,
            promptTemplateHash: input.promptTemplateHash,
            consensusTimestamp: input.consensusTimestamp,
            leader: input.leader,
            coordinator: msg.sender,
            timestamp: block.timestamp,
            reportUri: input.reportUri
        });
    }

    function _emitVerificationBundleFinalized(BundleRecord memory record) internal {
        emit VerificationBundleFinalized(
            record.requestId,
            record.bundleHash,
            record.verdict,
            record.aggregateScoreBps,
            record.responders,
            record.round,
            record.reportsMerkleRoot,
            record.attestationRootHash,
            record.promptTemplateHash,
            record.consensusTimestamp,
            record.leader,
            record.coordinator,
            record.timestamp,
            record.reportUri
        );
    }

    function hasBundle(bytes32 requestId) external view returns (bool) {
        return _bundleRecords[requestId].timestamp != 0;
    }

    function getBundle(bytes32 requestId) external view returns (BundleRecord memory) {
        return _bundleRecords[requestId];
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

    function _accrueRewards(bytes32 requestId, address[] memory includedOperators, address leader) internal {
        if (!rewardsEnabled) {
            return;
        }

        uint256 baseReward = rewardPerResponderWei;
        uint256 leaderRewardBonus = leaderBonusWei;
        if (baseReward == 0 && leaderRewardBonus == 0) {
            return;
        }

        for (uint256 i = 0; i < includedOperators.length; i++) {
            address operator = includedOperators[i];
            bool isLeader = operator == leader;
            uint256 reward = baseReward;
            if (isLeader) {
                reward += leaderRewardBonus;
            }
            if (reward == 0) {
                continue;
            }
            _pendingRewardsWei[operator] += reward;
            totalPendingRewardsWei += reward;
            emit RewardAccrued(requestId, operator, reward, isLeader);
        }
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }

    function _recoverSigner(bytes32 digest, bytes memory signature) internal pure returns (address signer) {
        if (signature.length != 65) {
            revert InvalidSignature();
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            revert InvalidSignature();
        }
        if (uint256(s) > SECP256K1_HALF_N) {
            revert InvalidSignature();
        }

        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) {
            revert InvalidSignature();
        }
    }
}
