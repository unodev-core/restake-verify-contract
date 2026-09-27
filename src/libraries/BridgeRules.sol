// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IAllowlistRegistry} from "../interfaces/IAllowlistRegistry.sol";
import {Reason, reject} from "../types/Errors.sol";
import {BridgeConfig, BridgeDeposit, BridgeRoute, BridgeType, Call, Category, Config, Intent} from "../types/Types.sol";
import {AcrossRules} from "./AcrossRules.sol";
import {MainResult} from "./BatchLayout.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Provider-agnostic BRIDGE rules (§3.3). Provider details live in the decoder and the bridge's row.
library BridgeRules {
    function check(Call memory c, uint256 idx, Intent calldata intent, IAllowlistRegistry registry, Config memory cfg)
        internal
        view
        returns (MainResult memory m)
    {
        if (!registry.isAllowed(Category.BRIDGE, c.target)) reject(Reason.TARGET_NOT_ALLOWED, idx);
        BridgeConfig memory bc = registry.bridgeConfig(c.target);
        if (!_selectorEnabled(bc, CallLib.selector(c.data))) reject(Reason.BAD_SELECTOR, idx);

        BridgeDeposit memory d;
        if (bc.bridgeType == BridgeType.ACROSS) d = AcrossRules.decode(c.data, idx, bc);
        else reject(Reason.TARGET_NOT_ALLOWED, idx);

        _checkDeposit(d, c.target, bc, idx, intent, registry, cfg);
        m = MainResult({token: d.inputToken, spender: bc.spender, pulled: d.inputAmount, notional: d.inputAmount});
    }

    function _checkDeposit(
        BridgeDeposit memory d,
        address bridge,
        BridgeConfig memory bc,
        uint256 idx,
        Intent calldata intent,
        IAllowlistRegistry registry,
        Config memory cfg
    ) private view {
        // A destination message would call into the user's account on a chain this verifier cannot see.
        if (d.hasPayload) reject(Reason.BAD_BRIDGE_DEPOSIT, idx);

        if (d.inputToken != intent.payToken || !registry.isAllowed(Category.ASSET, d.inputToken)) {
            reject(Reason.TARGET_NOT_ALLOWED, idx);
        }
        if (intent.payToken != cfg.feeToken) reject(Reason.UNSUPPORTED_ASSET, idx);
        if (intent.amount == 0 || d.inputAmount != intent.amount) reject(Reason.BAD_AMOUNT, idx);

        if (d.dstChainId != intent.dstChainId || d.dstChainId == block.chainid) reject(Reason.BAD_ROUTE, idx);
        (BridgeRoute memory route, bool exists) = registry.bridgeRoute(bridge, d.inputToken, d.dstChainId);
        if (!exists || d.outputToken != route.outputToken) reject(Reason.BAD_ROUTE, idx);

        bytes32 user = bytes32(uint256(uint160(intent.user)));
        if (d.recipient != intent.recipient || intent.recipient != user) reject(Reason.BAD_RECEIVER, idx);
        if (d.refundTo != intent.user) reject(Reason.BAD_RECEIVER, idx);

        if (intent.minOut == 0 || d.outputAmount < intent.minOut) reject(Reason.OUTPUT_TOO_LOW, idx);
        uint256 rescaled = _rescale(d.inputAmount, route.inputDecimals, route.outputDecimals);
        if (d.outputAmount < Math.mulDiv(rescaled, 10_000 - cfg.maxBridgeFeeBps, 10_000)) {
            reject(Reason.OUTPUT_TOO_LOW, idx);
        }

        if (d.refundAfter > block.timestamp + bc.maxFillWindow) reject(Reason.FILL_WINDOW_TOO_LONG, idx);
    }

    function _selectorEnabled(BridgeConfig memory bc, bytes4 sel) private pure returns (bool) {
        for (uint256 i; i < bc.selectors.length; ++i) {
            if (bc.selectors[i] == sel) return true;
        }
        return false;
    }

    function _rescale(uint256 amount, uint8 fromDecimals, uint8 toDecimals) private pure returns (uint256) {
        if (toDecimals >= fromDecimals) return amount * 10 ** (toDecimals - fromDecimals);
        return amount / 10 ** (fromDecimals - toDecimals);
    }
}
