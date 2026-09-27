// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IModularAccountV2} from "../interfaces/IExternal.sol";
import {NO_INDEX, Reason, reject} from "../types/Errors.sol";
import {Call} from "../types/Types.sol";

/// @notice Decodes `op.callData`. Only MAv2 `executeBatch(Call[])` is accepted (§2.1 point 4): no `execute`, no
///         `executeUserOp` prefix, no module management, no `performCreate`.
library AccountCallDecoder {
    bytes4 internal constant EXECUTE_BATCH = IModularAccountV2.executeBatch.selector; // 0x34fcd5be

    function decode(bytes calldata callData) internal pure returns (Call[] memory calls) {
        if (callData.length < 4 + 64 || bytes4(callData[:4]) != EXECUTE_BATCH) reject(Reason.BAD_CALLDATA, NO_INDEX);
        calls = abi.decode(callData[4:], (Call[]));
        // Re-encoding must reproduce the input exactly: rejects trailing bytes and non-canonical offsets.
        if (keccak256(abi.encode(calls)) != keccak256(callData[4:])) reject(Reason.BAD_CALLDATA, NO_INDEX);
    }
}
