// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Reason, reject} from "../types/Errors.sol";

/// @notice Strict calldata helpers shared by the decoders.
library CallLib {
    uint256 internal constant ADDRESS_MASK = type(uint160).max;

    function selectorOf(bytes memory data) internal pure returns (bytes4) {
        if (data.length < 4) return bytes4(0);
        return bytes4(data);
    }

    /// @notice Copy of `data[start:end]`.
    function slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory out) {
        out = new bytes(end - start);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[start + i];
        }
    }

    /// @notice The ABI-encoded arguments after the selector. Rejects calldata shorter than `minArgsLen`, so a
    ///         following `abi.decode` of a static head cannot read out of bounds.
    function args(bytes memory data, uint256 minArgsLen, uint256 idx) internal pure returns (bytes memory) {
        if (data.length < 4 + minArgsLen) reject(Reason.MALFORMED_CALL, idx);
        return slice(data, 4, data.length);
    }

    /// @notice 32-byte argument word `i` (0-based, after the selector). Caller checks the length first.
    function word(bytes memory data, uint256 i) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(data, add(36, mul(i, 32))))
        }
    }

    /// @notice Rejects anything but the canonical ABI encoding: trailing bytes, dirty padding, odd offsets.
    function requireCanonical(bytes memory data, bytes memory expected, uint256 idx) internal pure {
        if (keccak256(data) != keccak256(expected)) reject(Reason.MALFORMED_CALL, idx);
    }

    /// @notice Address held in a word, requiring the upper 96 bits to be zero.
    function cleanAddress(uint256 w, uint256 idx) internal pure returns (address) {
        if (w > ADDRESS_MASK) reject(Reason.MALFORMED_CALL, idx);
        return address(uint160(w));
    }

    function endsWith(bytes memory data, bytes memory suffix) internal pure returns (bool) {
        if (suffix.length == 0 || data.length < suffix.length) return false;
        uint256 offset = data.length - suffix.length;
        for (uint256 i; i < suffix.length; ++i) {
            if (data[offset + i] != suffix[i]) return false;
        }
        return true;
    }
}
