// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DonConsensusRegistrySkeleton} from "../src/DonConsensusRegistrySkeleton.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes calldata) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external returns (address);
}

address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

contract DonConsensusRegistrySkeletonTest {
    Vm private constant VM = Vm(VM_ADDRESS);

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

    uint256 private constant LEADER_PK = 0x1000000000000000000000000000000000000000000000000000000000000001;
    uint256 private constant OPERATOR2_PK = 0x2000000000000000000000000000000000000000000000000000000000000002;
    uint256 private constant OPERATOR3_PK = 0x3000000000000000000000000000000000000000000000000000000000000003;

    address private coordinator = address(0xCAFE);
    bytes32 private requestId = keccak256("request-don-1");
    bytes32 private requestHash = keccak256("request-hash");
    uint32 private round = 1;
    int16 private aggregateScoreBps = 6200;
    bool private verdict = true;
    uint8 private responders = 3;
    bytes32 private reportsMerkleRoot = keccak256("reports-root");
    bytes32 private attestationRootHash = keccak256("attestation-root");
    bytes32 private promptTemplateHash = keccak256("prompt-template");
    uint64 private consensusTimestamp = 1_735_689_600;

    function testOnlyCoordinatorCanFinalizeWithBundle() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);
        _allowOperators(registry);

        (
            address leader,
            address[] memory operators,
            bytes[] memory operatorSignatures,
            bytes memory leaderSignature,
            bytes32 bundleHash
        ) = _buildBundleSignatures(registry);

        VM.prank(address(0xBEEF));
        VM.expectRevert(abi.encodeWithSelector(DonConsensusRegistrySkeleton.UnauthorizedCoordinator.selector));
        registry.finalizeWithBundle(
            _encodeFinalizeInput(leader, operators, operatorSignatures, leaderSignature, bundleHash, "report://don/1")
        );
    }

    function testFinalizeWithBundleSuccess() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);
        _allowOperators(registry);

        (
            address leader,
            address[] memory operators,
            bytes[] memory operatorSignatures,
            bytes memory leaderSignature,
            bytes32 bundleHash
        ) = _buildBundleSignatures(registry);

        VM.prank(coordinator);
        registry.finalizeWithBundle(
            _encodeFinalizeInput(leader, operators, operatorSignatures, leaderSignature, bundleHash, "report://don/1")
        );

        assertTrue(registry.hasBundle(requestId), "bundle should be finalized");
    }

    function testRejectInvalidOperatorApprovalSignature() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);
        _allowOperators(registry);

        (
            address leader,
            address[] memory operators,
            bytes[] memory operatorSignatures,
            bytes memory leaderSignature,
            bytes32 bundleHash
        ) = _buildBundleSignatures(registry);

        operatorSignatures[1] = operatorSignatures[0];

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(DonConsensusRegistrySkeleton.InvalidSignature.selector));
        registry.finalizeWithBundle(
            _encodeFinalizeInput(leader, operators, operatorSignatures, leaderSignature, bundleHash, "report://don/1")
        );
    }

    function testOnlyCoordinatorCanRecordNodeLifecycle() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);
        bytes32 lifecycleId = keccak256("don-lifecycle-1");

        VM.prank(address(0xBEEF));
        VM.expectRevert(abi.encodeWithSelector(DonConsensusRegistrySkeleton.UnauthorizedCoordinator.selector));
        registry.recordNodeLifecycle(
            lifecycleId,
            VM.addr(LEADER_PK),
            1,
            keccak256("endpoint"),
            keccak256("payload"),
            "http://127.0.0.1:19001",
            "node://challenge/1"
        );
    }

    function testCannotRecordDuplicateNodeLifecycle() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);
        bytes32 lifecycleId = keccak256("don-lifecycle-2");
        bytes32 endpointHash = keccak256("endpoint");
        bytes32 payloadHash = keccak256("payload");
        address nodeId = VM.addr(LEADER_PK);

        VM.prank(coordinator);
        registry.recordNodeLifecycle(
            lifecycleId,
            nodeId,
            2,
            endpointHash,
            payloadHash,
            "http://127.0.0.1:19001",
            "node://heartbeat/1"
        );
        assertTrue(registry.hasNodeLifecycle(lifecycleId), "lifecycle should be recorded");

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(DonConsensusRegistrySkeleton.LifecycleAlreadyRecorded.selector, lifecycleId));
        registry.recordNodeLifecycle(
            lifecycleId,
            nodeId,
            2,
            endpointHash,
            payloadHash,
            "http://127.0.0.1:19001",
            "node://heartbeat/1"
        );
    }

    function testOnlyCoordinatorCanRecordPorProof() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);

        VM.prank(address(0xBEEF));
        VM.expectRevert(abi.encodeWithSelector(DonConsensusRegistrySkeleton.UnauthorizedCoordinator.selector));
        registry.recordPorProof(1, 1, 1_000_000_000, 950_000_000, keccak256("don-por-proof-1"), "por://epoch/1");
    }

    function testCannotRecordDuplicatePorProof() external {
        DonConsensusRegistrySkeleton registry = new DonConsensusRegistrySkeleton(coordinator);

        VM.prank(coordinator);
        registry.recordPorProof(1, 1, 1_000_000_000, 950_000_000, keccak256("don-por-proof-1"), "por://epoch/1");
        assertTrue(registry.hasPorProof(1, 1), "por proof should be recorded");

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(DonConsensusRegistrySkeleton.PorProofAlreadyRecorded.selector, 1, 1));
        registry.recordPorProof(1, 1, 1_010_000_000, 955_000_000, keccak256("don-por-proof-2"), "por://epoch/1b");
    }

    function _allowOperators(DonConsensusRegistrySkeleton registry) private {
        address leader = VM.addr(LEADER_PK);
        address operator2 = VM.addr(OPERATOR2_PK);
        address operator3 = VM.addr(OPERATOR3_PK);
        registry.setOperatorPermission(leader, true);
        registry.setOperatorPermission(operator2, true);
        registry.setOperatorPermission(operator3, true);
    }

    function _buildBundleSignatures(DonConsensusRegistrySkeleton registry)
        private
        returns (
            address leader,
            address[] memory operators,
            bytes[] memory operatorSignatures,
            bytes memory leaderSignature,
            bytes32 bundleHash
        )
    {
        leader = VM.addr(LEADER_PK);
        address operator2 = VM.addr(OPERATOR2_PK);
        address operator3 = VM.addr(OPERATOR3_PK);
        operators = new address[](3);
        operators[0] = leader;
        operators[1] = operator2;
        operators[2] = operator3;

        bundleHash = keccak256(
            abi.encode(
                CONSENSUS_BUNDLE_TYPEHASH,
                requestId,
                requestHash,
                round,
                aggregateScoreBps,
                verdict,
                responders,
                reportsMerkleRoot,
                attestationRootHash,
                promptTemplateHash,
                consensusTimestamp
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(registry))
        );

        bytes32 leaderDigest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, bundleHash));
        leaderSignature = _signDigest(LEADER_PK, leaderDigest);

        bytes32 operatorApprovalStructHash = keccak256(abi.encode(OPERATOR_APPROVAL_TYPEHASH, bundleHash, requestId, round));
        bytes32 operatorApprovalDigest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, operatorApprovalStructHash));

        operatorSignatures = new bytes[](3);
        operatorSignatures[0] = _signDigest(LEADER_PK, operatorApprovalDigest);
        operatorSignatures[1] = _signDigest(OPERATOR2_PK, operatorApprovalDigest);
        operatorSignatures[2] = _signDigest(OPERATOR3_PK, operatorApprovalDigest);
    }

    function _signDigest(uint256 privateKey, bytes32 digest) private returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _encodeFinalizeInput(
        address leader,
        address[] memory operators,
        bytes[] memory operatorSignatures,
        bytes memory leaderSignature,
        bytes32 bundleHash,
        string memory reportUri
    ) private view returns (bytes memory) {
        DonConsensusRegistrySkeleton.FinalizeWithBundleInput memory input = DonConsensusRegistrySkeleton
            .FinalizeWithBundleInput({
            requestId: requestId,
            requestHash: requestHash,
            round: round,
            aggregateScoreBps: aggregateScoreBps,
            verdict: verdict,
            responders: responders,
            reportsMerkleRoot: reportsMerkleRoot,
            attestationRootHash: attestationRootHash,
            bundleHash: bundleHash,
            promptTemplateHash: promptTemplateHash,
            consensusTimestamp: consensusTimestamp,
            leader: leader,
            includedOperators: operators,
            reportSignatures: operatorSignatures,
            leaderSignature: leaderSignature,
            reportUri: reportUri
        });

        return abi.encode(input);
    }

    function assertTrue(bool condition, string memory message) private pure {
        require(condition, message);
    }
}
