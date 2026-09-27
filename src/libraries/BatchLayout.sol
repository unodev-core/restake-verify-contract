// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {NO_INDEX, Reason, reject} from "../types/Errors.sol";
import {Call} from "../types/Types.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Positions of the calls in an accepted batch. Absent calls hold `NO_INDEX`.
///
///   [0] DeadlineGuard.requireBefore(d)     required (checked by the verifier)
///   [.] token.approve(spender, 0)          optional, USDT-style reset (only directly before the exact approve)
///   [.] token.approve(spender, amount)     optional
///   [.] main call                          required
///   [.] token.approve(spender, 0)          optional revoke
///   [.] feeToken.transfer(recipient, fee)  optional, always last
struct Layout {
    uint256 preCount;
    uint256 pre0;
    uint256 pre1;
    uint256 main;
    uint256 revoke;
    uint256 fee;
}

/// @notice What an action decoder learned from the main call.
struct MainResult {
    address token; // token the approvals / revoke must be on
    address spender; // spender the approvals / revoke must name
    uint256 pulled; // amount the main call pulls from the allowance
    uint256 notional; // fee-token notional for the backstop fee cap
}

library BatchLayout {
    function parse(Call[] memory calls, address feeToken) internal pure returns (Layout memory l) {
        l.pre0 = NO_INDEX;
        l.pre1 = NO_INDEX;
        l.main = NO_INDEX;
        l.revoke = NO_INDEX;
        l.fee = NO_INDEX;

        uint256 end = calls.length;
        if (end > 1 && calls[end - 1].target == feeToken && _is(calls[end - 1], IERC20.transfer.selector)) {
            l.fee = end - 1;
            end--;
        }

        uint256 i = 1;
        while (i < end && _is(calls[i], IERC20.approve.selector)) {
            if (l.preCount == 2) reject(Reason.UNEXPECTED_CALL, i);
            if (l.preCount == 0) l.pre0 = i;
            else l.pre1 = i;
            l.preCount++;
            i++;
        }
        if (i >= end) reject(Reason.MISSING_MAIN_CALL, NO_INDEX);
        // A fee transfer anywhere but last is never a main call.
        if (calls[i].target == feeToken && _is(calls[i], IERC20.transfer.selector)) reject(Reason.UNEXPECTED_CALL, i);
        l.main = i++;

        if (i < end) {
            if (!_is(calls[i], IERC20.approve.selector)) reject(Reason.UNEXPECTED_CALL, i);
            l.revoke = i++;
        }
        if (i < end) reject(Reason.UNEXPECTED_CALL, i);
    }

    function _is(Call memory c, bytes4 sel) private pure returns (bool) {
        return CallLib.selector(c.data) == sel;
    }
}
