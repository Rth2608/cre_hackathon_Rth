// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MarketVerificationRegistry} from "../src/MarketVerificationRegistry.sol";

interface Vm {
    function envAddress(string calldata key) external returns (address);
    function startBroadcast() external;
    function stopBroadcast() external;
}

address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

contract Deploy {
    Vm private constant VM = Vm(VM_ADDRESS);

    function run() external returns (MarketVerificationRegistry deployed) {
        address coordinator = VM.envAddress("COORDINATOR_ADDRESS");

        VM.startBroadcast();
        deployed = new MarketVerificationRegistry(coordinator);
        VM.stopBroadcast();
    }
}
