// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PackedUserOperation} from "../types/Types.sol";

/// @notice EntryPoint v0.7 user operation hashing and field unpacking.
library UserOpLib {
    /// @notice v0.7 `getUserOpHash`: keccak256(abi.encode(keccak256(pack(op)), entryPoint, chainid)). Not EIP-712.
    function hash(PackedUserOperation calldata op, address entryPoint) internal view returns (bytes32) {
        bytes32 packed = keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                keccak256(op.paymasterAndData)
            )
        );
        return keccak256(abi.encode(packed, entryPoint, block.chainid));
    }

    function high128(bytes32 packed) internal pure returns (uint256) {
        return uint256(packed) >> 128;
    }

    function low128(bytes32 packed) internal pure returns (uint256) {
        return uint128(uint256(packed));
    }
}
