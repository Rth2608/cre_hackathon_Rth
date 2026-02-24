// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MarketVerificationRegistry} from "../src/MarketVerificationRegistry.sol";

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function prank(address) external;
    function expectRevert(bytes calldata) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

contract MarketVerificationRegistryTest {
    Vm private constant VM = Vm(VM_ADDRESS);

    address private coordinator = address(0xCAFE);
    address private attacker = address(0xBEEF);

    bytes32 private requestId = keccak256("request-1");
    bytes32 private questionHash = keccak256("question");
    bytes32 private sourcesHash = keccak256("sources");
    bytes32 private reportHash = keccak256("report");

    function testOwnerAndCoordinatorInitialized() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        assertEqAddress(registry.owner(), address(this), "owner mismatch");
        assertEqAddress(registry.coordinator(), coordinator, "coordinator mismatch");
    }

    function testOnlyCoordinatorCanFinalize() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(attacker);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.UnauthorizedCoordinator.selector));
        registry.finalizeVerification(requestId, questionHash, sourcesHash, 6200, true, 4, reportHash, "report://1");
    }

    function testOnlyOwnerCanSetCoordinator() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.UnauthorizedOwner.selector));
        registry.setCoordinator(attacker);

        registry.setCoordinator(attacker);
        assertEqAddress(registry.coordinator(), attacker, "coordinator update failed");
    }

    function testTransferredOwnerCanManageCoordinator() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        registry.transferOwnership(attacker);

        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.UnauthorizedOwner.selector));
        registry.setCoordinator(address(0xA11CE));

        VM.prank(attacker);
        registry.setCoordinator(address(0xA11CE));

        assertEqAddress(registry.coordinator(), address(0xA11CE), "new owner should set coordinator");
    }

    function testFinalizedEventFields() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.recordLogs();
        VM.prank(coordinator);
        registry.finalizeVerification(requestId, questionHash, sourcesHash, 6400, true, 4, reportHash, "report://1");

        Vm.Log[] memory entries = VM.getRecordedLogs();
        assertTrue(entries.length > 0, "expected at least one log");

        Vm.Log memory log = entries[entries.length - 1];
        bytes32 eventSig = keccak256(
            "VerificationFinalized(bytes32,bool,int16,uint8,bytes32,string,address,uint256)"
        );

        assertEqBytes32(log.topics[0], eventSig, "wrong event signature");
        assertEqBytes32(log.topics[1], requestId, "wrong indexed requestId");

        (bool verdict, int16 score, uint8 responders, bytes32 emittedReportHash, string memory uri, address emittedCoordinator, ) =
            abi.decode(log.data, (bool, int16, uint8, bytes32, string, address, uint256));

        assertTrue(verdict, "verdict mismatch");
        assertEqInt16(score, 6400, "score mismatch");
        assertEqUint(responders, 4, "responder mismatch");
        assertEqBytes32(emittedReportHash, reportHash, "report hash mismatch");
        assertEqString(uri, "report://1", "uri mismatch");
        assertEqAddress(emittedCoordinator, coordinator, "coordinator mismatch");
    }

    function testCannotFinalizeSameRequestTwice() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(coordinator);
        registry.finalizeVerification(requestId, questionHash, sourcesHash, 6100, true, 4, reportHash, "report://1");

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.AlreadyFinalized.selector, requestId));
        registry.finalizeVerification(requestId, questionHash, sourcesHash, 6100, true, 4, reportHash, "report://1");
    }

    function testRejectOutOfRangeScore() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.InvalidScore.selector));
        registry.finalizeVerification(requestId, questionHash, sourcesHash, 10001, true, 4, reportHash, "report://1");
    }

    function testRejectInvalidResponderCount() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.InvalidResponderCount.selector));
        registry.finalizeVerification(requestId, questionHash, sourcesHash, 5000, true, 2, reportHash, "report://1");
    }

    function testOnlyCoordinatorCanRecordNodeLifecycle() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);
        bytes32 lifecycleId = keccak256("lifecycle-1");
        bytes32 endpointHash = keccak256("endpoint");
        bytes32 payloadHash = keccak256("payload");

        VM.prank(attacker);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.UnauthorizedCoordinator.selector));
        registry.recordNodeLifecycle(
            lifecycleId,
            coordinator,
            1,
            endpointHash,
            payloadHash,
            "http://127.0.0.1:19001",
            "node://challenge/1"
        );
    }

    function testCannotRecordSameNodeLifecycleTwice() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);
        bytes32 lifecycleId = keccak256("lifecycle-2");
        bytes32 endpointHash = keccak256("endpoint");
        bytes32 payloadHash = keccak256("payload");

        VM.prank(coordinator);
        registry.recordNodeLifecycle(
            lifecycleId,
            coordinator,
            2,
            endpointHash,
            payloadHash,
            "http://127.0.0.1:19001",
            "node://heartbeat/1"
        );

        assertTrue(registry.hasNodeLifecycle(lifecycleId), "lifecycle should be recorded");

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.LifecycleAlreadyRecorded.selector, lifecycleId));
        registry.recordNodeLifecycle(
            lifecycleId,
            coordinator,
            2,
            endpointHash,
            payloadHash,
            "http://127.0.0.1:19001",
            "node://heartbeat/1"
        );
    }

    function testOnlyCoordinatorCanRecordPorProof() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(attacker);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.UnauthorizedCoordinator.selector));
        registry.recordPorProof(1, 1, 1_000_000_000, 950_000_000, keccak256("por-proof-1"), "por://epoch/1");
    }

    function testCannotRecordDuplicatePorProof() external {
        MarketVerificationRegistry registry = new MarketVerificationRegistry(coordinator);

        VM.prank(coordinator);
        registry.recordPorProof(1, 1, 1_000_000_000, 950_000_000, keccak256("por-proof-1"), "por://epoch/1");
        assertTrue(registry.hasPorProof(1, 1), "por proof should be recorded");

        VM.prank(coordinator);
        VM.expectRevert(abi.encodeWithSelector(MarketVerificationRegistry.PorProofAlreadyRecorded.selector, 1, 1));
        registry.recordPorProof(1, 1, 1_010_000_000, 955_000_000, keccak256("por-proof-1b"), "por://epoch/1b");
    }

    function assertTrue(bool condition, string memory message) private pure {
        require(condition, message);
    }

    function assertEqUint(uint256 a, uint256 b, string memory message) private pure {
        require(a == b, message);
    }

    function assertEqInt16(int16 a, int16 b, string memory message) private pure {
        require(a == b, message);
    }

    function assertEqBytes32(bytes32 a, bytes32 b, string memory message) private pure {
        require(a == b, message);
    }

    function assertEqAddress(address a, address b, string memory message) private pure {
        require(a == b, message);
    }

    function assertEqString(string memory a, string memory b, string memory message) private pure {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), message);
    }
}
