// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Reason, reject} from "../types/Errors.sol";
import {Call} from "../types/Types.sol";
import {Layout, MainResult} from "./BatchLayout.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Shared approval rules (§3.3): exact approvals on the action's token to the action's spender, at most one
///         revoke after the main call, and zero residual allowance after the batch.
library AllowanceRules {
    function check(Call[] memory calls, Layout memory l, MainResult memory m, address user, bool allowPreApprove)
        internal
        view
    {
        if (l.preCount != 0) {
            if (!allowPreApprove) reject(Reason.UNEXPECTED_CALL, l.pre0);
            if (m.pulled == 0) reject(Reason.BAD_APPROVE, l.pre0);
            if (l.preCount == 2) {
                _approve(calls[l.pre0], l.pre0, m, 0);
                _approve(calls[l.pre1], l.pre1, m, m.pulled);
            } else {
                _approve(calls[l.pre0], l.pre0, m, m.pulled);
            }
        }

        if (l.revoke != type(uint256).max) {
            _approve(calls[l.revoke], l.revoke, m, 0);
            return;
        }
        // An exact approve is fully consumed by the main call.
        if (l.preCount != 0) return;

        // No approve and no revoke: whatever the user already allowed must be used up exactly. The token is
        // allowlisted (or the configured fee token), so this live read goes to a trusted contract.
        uint256 current = IERC20(m.token).allowance(user, m.spender);
        uint256 residual;
        if (current == type(uint256).max) residual = current; // tokens may not decrement an infinite allowance
        else if (current > m.pulled) residual = current - m.pulled;
        if (residual != 0) reject(Reason.RESIDUAL_ALLOWANCE, l.main);
    }

    function _approve(Call memory c, uint256 idx, MainResult memory m, uint256 expected) private pure {
        if (c.target != m.token) reject(Reason.BAD_APPROVE, idx);
        (address spender, uint256 amount) = abi.decode(CallLib.args(c.data, 64, idx), (address, uint256));
        CallLib.requireCanonical(c.data, abi.encodeCall(IERC20.approve, (spender, amount)), idx);
        if (spender != m.spender || amount != expected) reject(Reason.BAD_APPROVE, idx);
    }
}
