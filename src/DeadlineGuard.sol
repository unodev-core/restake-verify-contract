// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title DeadlineGuard
/// @notice Called as the first call of every Restake batch, so the signed op itself carries an expiry (§3.1).
/// @dev Immutable and admin-less on purpose: it is a call target inside user-signed batches.
contract DeadlineGuard {
    error Expired();

    function requireBefore(uint256 deadline) external view {
        if (block.timestamp > deadline) revert Expired();
    }
}
