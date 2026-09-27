// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAllowlistRegistry} from "../interfaces/IAllowlistRegistry.sol";
import {Reason, reject} from "../types/Errors.sol";
import {Action, Call, Category, Config, Intent, RouterType} from "../types/Types.sol";
import {MainResult} from "./BatchLayout.sol";
import {OneInchRules, SwapData} from "./OneInchRules.sol";

/// @notice BUY / SELL rules shared by every router type (§3.3). The router's `RouterType` selects the decoder.
library SwapRules {
    function check(Call memory c, uint256 idx, Intent calldata intent, IAllowlistRegistry registry, Config memory cfg)
        internal
        view
        returns (MainResult memory m)
    {
        if (!registry.isAllowed(Category.ONDO_TOKEN, intent.target)) reject(Reason.TARGET_NOT_ALLOWED, idx);
        if (!registry.isAllowed(Category.ASSET, intent.payToken)) reject(Reason.TARGET_NOT_ALLOWED, idx);
        // v1: every notional is in the fee token, so trades must be paid in it.
        if (intent.payToken != cfg.feeToken) reject(Reason.UNSUPPORTED_ASSET, idx);
        if (!registry.isAllowed(Category.SWAP_ROUTER, c.target)) reject(Reason.TARGET_NOT_ALLOWED, idx);

        // slither-disable-next-line uninitialized-local (every other branch rejects)
        SwapData memory s;
        RouterType rt = registry.routerType(c.target);
        if (rt == RouterType.ONE_INCH_V6) s = OneInchRules.decode(c, idx, intent.user, registry);
        else reject(Reason.TARGET_NOT_ALLOWED, idx);

        bool buy = intent.action == Action.BUY;
        (address src, address dst) = buy ? (intent.payToken, intent.target) : (intent.target, intent.payToken);
        if (s.srcToken != src || s.dstToken != dst) reject(Reason.BAD_SWAP, idx);
        if (intent.amount == 0 || s.amount != intent.amount) reject(Reason.BAD_AMOUNT, idx);
        if (s.receiver != intent.user) reject(Reason.BAD_RECEIVER, idx);
        if (intent.minOut == 0 || s.minReturn < intent.minOut) reject(Reason.MIN_OUT_TOO_LOW, idx);

        m = MainResult({token: src, spender: c.target, pulled: s.amount, notional: buy ? s.amount : intent.minOut});
    }
}
