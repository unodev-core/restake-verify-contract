// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAaveV3Pool} from "../interfaces/IExternal.sol";
import {Reason, reject} from "../types/Errors.sol";
import {Call} from "../types/Types.sol";
import {MainResult} from "./BatchLayout.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Aave v3 stake / unstake rules (§3.3). The caller has checked that `c.target` is an allowlisted AAVE_POOL
///         equal to `intent.target`.
library AaveRules {
    /// @notice `pool.supply(feeToken, amount, user, 0)`.
    function stake(Call memory c, uint256 idx, address user, uint256 amount, address feeToken)
        internal
        pure
        returns (MainResult memory m)
    {
        if (CallLib.selectorOf(c.data) != IAaveV3Pool.supply.selector) reject(Reason.BAD_SELECTOR, idx);
        (address asset, uint256 value, address onBehalfOf, uint16 referral) =
            abi.decode(CallLib.args(c.data, 128, idx), (address, uint256, address, uint16));
        CallLib.requireCanonical(c.data, abi.encodeCall(IAaveV3Pool.supply, (asset, value, onBehalfOf, referral)), idx);
        if (asset != feeToken) reject(Reason.UNSUPPORTED_ASSET, idx);
        if (onBehalfOf != user) reject(Reason.BAD_RECEIVER, idx);
        if (amount == 0 || value != amount) reject(Reason.BAD_AMOUNT, idx);
        if (referral != 0) reject(Reason.MALFORMED_CALL, idx);
        m = MainResult({token: asset, spender: c.target, pulled: value, notional: value});
    }

    /// @notice `pool.withdraw(feeToken, amount, user)`. aTokens are 1:1 with the asset, so `amount` is both the
    ///         intent amount and the notional. `type(uint256).max` ("withdraw all") is rejected: its notional is
    ///         unbounded for the fee cap.
    function unstake(Call memory c, uint256 idx, address user, uint256 amount, address feeToken)
        internal
        pure
        returns (MainResult memory m)
    {
        if (CallLib.selectorOf(c.data) != IAaveV3Pool.withdraw.selector) reject(Reason.BAD_SELECTOR, idx);
        (address asset, uint256 value, address to) =
            abi.decode(CallLib.args(c.data, 96, idx), (address, uint256, address));
        CallLib.requireCanonical(c.data, abi.encodeCall(IAaveV3Pool.withdraw, (asset, value, to)), idx);
        if (asset != feeToken) reject(Reason.UNSUPPORTED_ASSET, idx);
        if (to != user) reject(Reason.BAD_RECEIVER, idx);
        if (amount == 0 || value != amount || value == type(uint256).max) reject(Reason.BAD_AMOUNT, idx);
        m = MainResult({token: asset, spender: c.target, pulled: 0, notional: value});
    }
}
