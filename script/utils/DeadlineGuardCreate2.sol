// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {DeadlineGuard} from "../../src/DeadlineGuard.sol";

/// @notice CREATE2 deployment of DeadlineGuard through the canonical deterministic deployer, so it lands at the same
///         address on every chain. Shared by DeployDeadlineGuard and Deploy.
/// @dev Calls the factory explicitly instead of `new DeadlineGuard{salt: ...}()`: Foundry does not always route
///      salted `new` through the factory when broadcasting, and would then CREATE2 from the broadcaster's address.
library DeadlineGuardCreate2 {
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant SALT = keccak256("restake.DeadlineGuard.v1");

    error FactoryMissing();
    error DeployFailed();
    error AddressMismatch(address expected, address actual);

    function initCodeHash() internal pure returns (bytes32) {
        return keccak256(type(DeadlineGuard).creationCode);
    }

    function predict() internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), FACTORY, SALT, initCodeHash())))));
    }

    /// @dev Must run inside a broadcast. Returns the existing guard if it is already deployed.
    function deploy() internal returns (DeadlineGuard) {
        address predicted = predict();
        if (predicted.code.length != 0) return DeadlineGuard(predicted);
        if (FACTORY.code.length == 0) revert FactoryMissing();

        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(SALT, type(DeadlineGuard).creationCode));
        if (!ok || ret.length != 20) revert DeployFailed();
        address deployed = address(bytes20(ret));
        if (deployed != predicted) revert AddressMismatch(predicted, deployed);
        return DeadlineGuard(deployed);
    }
}
