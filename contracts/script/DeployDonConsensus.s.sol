// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DonConsensusRegistrySkeleton} from "../src/DonConsensusRegistrySkeleton.sol";

interface Vm {
    function envAddress(string calldata key) external returns (address);
    function startBroadcast() external;
    function stopBroadcast() external;
}

address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

contract DeployDonConsensus {
    Vm private constant VM = Vm(VM_ADDRESS);

    function run() external returns (DonConsensusRegistrySkeleton deployed) {
        address coordinator = VM.envAddress("COORDINATOR_ADDRESS");

        VM.startBroadcast();
        deployed = new DonConsensusRegistrySkeleton(coordinator);
        VM.stopBroadcast();
    }
}
