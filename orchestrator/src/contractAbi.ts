export const LEGACY_REGISTRY_ABI = [
  "function finalizeVerification(bytes32 requestId, bytes32 questionHash, bytes32 sourcesHash, int16 aggregateScoreBps, bool verdict, uint8 responders, bytes32 reportHash, string reportUri) external",
  "function recordVectorScreening(bytes32 requestId, uint8 vectorStatus, uint8 queueDecision, uint16 similarityBps, bytes32 matchedRequestId, bytes32 screeningHash, bytes32 reasonHash, string evidenceUri) external",
  "function recordNodeLifecycle(bytes32 lifecycleId, address nodeId, uint8 action, bytes32 endpointHash, bytes32 payloadHash, string endpointUrl, string payloadUri) external",
  "function recordPorProof(uint32 marketId, uint64 epoch, uint256 assetsMicroUsdc, uint256 liabilitiesMicroUsdc, bytes32 proofHash, string proofUri) external"
] as const;

export const DON_CONSENSUS_ABI = [
  "function finalizeWithBundle(bytes encodedInput) external",
  "function recordVectorScreening(bytes32 requestId, uint8 vectorStatus, uint8 queueDecision, uint16 similarityBps, bytes32 matchedRequestId, bytes32 screeningHash, bytes32 reasonHash, string evidenceUri) external",
  "function recordNodeLifecycle(bytes32 lifecycleId, address nodeId, uint8 action, bytes32 endpointHash, bytes32 payloadHash, string endpointUrl, string payloadUri) external",
  "function recordPorProof(uint32 marketId, uint64 epoch, uint256 assetsMicroUsdc, uint256 liabilitiesMicroUsdc, bytes32 proofHash, string proofUri) external",
  "function setRewardConfig(uint256 newRewardPerResponderWei, uint256 newLeaderBonusWei, bool enabled) external",
  "function pendingRewardWei(address operator) external view returns (uint256)",
  "function availableRewardPoolWei() external view returns (uint256)",
  "function rewardPerResponderWei() external view returns (uint256)",
  "function leaderBonusWei() external view returns (uint256)",
  "function rewardsEnabled() external view returns (bool)",
  "function totalPendingRewardsWei() external view returns (uint256)"
] as const;

export const ONCHAIN_READER_ABI = [
  "event VerificationFinalized(bytes32 indexed requestId, bool verdict, int16 aggregateScoreBps, uint8 responders, bytes32 reportHash, string reportUri, address coordinator, uint256 timestamp)",
  "event VerificationBundleFinalized(bytes32 indexed requestId, bytes32 indexed bundleHash, bool verdict, int16 aggregateScoreBps, uint8 responders, uint32 round, bytes32 reportsMerkleRoot, bytes32 attestationRootHash, bytes32 promptTemplateHash, uint64 consensusTimestamp, address leader, address coordinator, uint256 timestamp, string reportUri)",
  "event VectorScreeningRecorded(bytes32 indexed requestId, uint8 vectorStatus, uint8 queueDecision, uint16 similarityBps, bytes32 indexed matchedRequestId, bytes32 screeningHash, bytes32 reasonHash, string evidenceUri, address coordinator, uint256 timestamp)",
  "event RewardConfigUpdated(uint256 rewardPerResponderWei, uint256 leaderBonusWei, bool rewardsEnabled)",
  "event RewardAccrued(bytes32 indexed requestId, address indexed operator, uint256 amount, bool isLeader)",
  "event RewardClaimed(address indexed operator, address indexed recipient, uint256 amount)",
  "event NodeLifecycleRecorded(bytes32 indexed lifecycleId, address indexed nodeId, uint8 indexed action, bytes32 endpointHash, bytes32 payloadHash, string endpointUrl, string payloadUri, address coordinator, uint256 timestamp)",
  "event PorProofRecorded(uint32 indexed marketId, uint64 indexed epoch, bytes32 indexed proofHash, uint256 assetsMicroUsdc, uint256 liabilitiesMicroUsdc, uint32 coverageBps, bool healthy, string proofUri, address coordinator, uint256 timestamp)",
  "function hasVerification(bytes32 requestId) external view returns (bool)",
  "function hasBundle(bytes32 requestId) external view returns (bool)",
  "function hasVectorScreening(bytes32 requestId) external view returns (bool)",
  "function hasPorProof(uint32 marketId, uint64 epoch) external view returns (bool)",
  "function getVerification(bytes32 requestId) external view returns (tuple(bytes32 requestId, bytes32 questionHash, bytes32 sourcesHash, int16 aggregateScoreBps, bool verdict, uint8 responders, bytes32 reportHash, string reportUri, address coordinator, uint256 timestamp))",
  "function getBundle(bytes32 requestId) external view returns (tuple(bytes32 requestId, bytes32 requestHash, uint32 round, int16 aggregateScoreBps, bool verdict, uint8 responders, bytes32 reportsMerkleRoot, bytes32 attestationRootHash, bytes32 bundleHash, bytes32 promptTemplateHash, uint64 consensusTimestamp, address leader, address coordinator, uint256 timestamp, string reportUri))",
  "function getVectorScreening(bytes32 requestId) external view returns (tuple(bytes32 requestId, uint8 vectorStatus, uint8 queueDecision, uint16 similarityBps, bytes32 matchedRequestId, bytes32 screeningHash, bytes32 reasonHash, string evidenceUri, address coordinator, uint256 timestamp))",
  "function pendingRewardWei(address operator) external view returns (uint256)",
  "function availableRewardPoolWei() external view returns (uint256)",
  "function rewardPerResponderWei() external view returns (uint256)",
  "function leaderBonusWei() external view returns (uint256)",
  "function rewardsEnabled() external view returns (bool)",
  "function totalPendingRewardsWei() external view returns (uint256)",
  "function getPorProof(uint32 marketId, uint64 epoch) external view returns (tuple(uint32 marketId, uint64 epoch, uint256 assetsMicroUsdc, uint256 liabilitiesMicroUsdc, uint32 coverageBps, bool healthy, bytes32 proofHash, string proofUri, address coordinator, uint256 timestamp))",
  "function getLatestPorProof(uint32 marketId) external view returns (tuple(uint32 marketId, uint64 epoch, uint256 assetsMicroUsdc, uint256 liabilitiesMicroUsdc, uint32 coverageBps, bool healthy, bytes32 proofHash, string proofUri, address coordinator, uint256 timestamp))"
] as const;
