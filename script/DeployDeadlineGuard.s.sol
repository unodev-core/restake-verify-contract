// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {DeadlineGuard} from "../src/DeadlineGuard.sol";
import {DeadlineGuardCreate2} from "./utils/DeadlineGuardCreate2.sol";

/// @notice Deploys only the DeadlineGuard at its cross-chain CREATE2 address. Re-running on a chain where it already
///         exists is a no-op.
///
/// The address depends only on the salt and the creation code, so every chain must be deployed from the same source
/// and the same foundry.toml compiler settings.
///
///   forge script script/DeployDeadlineGuard.s.sol --sig "predict()"
///   forge script script/DeployDeadlineGuard.s.sol --rpc-url base --broadcast --verify
contract DeployDeadlineGuard is Script {
    function run() external returns (DeadlineGuard guard) {
        address predicted = predict();
        if (predicted.code.length != 0) {
            console.log("DeadlineGuard already deployed at", predicted);
            return DeadlineGuard(predicted);
        }

        console.log("Sender   ", msg.sender);
        console.log("Balance  ", vm.toString(msg.sender.balance), "wei (must cover gas, ~113k units)");

        vm.startBroadcast();
        guard = DeadlineGuardCreate2.deploy();
        vm.stopBroadcast();

        console.log("DeadlineGuard deployed at", address(guard));
    }

    function predict() public pure returns (address predicted) {
        predicted = DeadlineGuardCreate2.predict();
        console.log("Factory  ", DeadlineGuardCreate2.FACTORY);
        console.log("Salt     ", vm.toString(DeadlineGuardCreate2.SALT));
        console.log("InitHash ", vm.toString(DeadlineGuardCreate2.initCodeHash()));
        console.log("Predicted", predicted);
    }
}
