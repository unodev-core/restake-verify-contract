// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IAllowlistRegistry} from "../interfaces/IAllowlistRegistry.sol";
import {Reason, reject} from "../types/Errors.sol";
import {Call, Category, Config} from "../types/Types.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Fee rules (§3.3): one `feeToken.transfer(FEE_RECIPIENT, fee)` as the last call, with
///         `fee <= intent.maxFee` and `fee <= flatFee + notional * maxFeeBps / 10_000`.
/// @dev The layout parser already matched `target == feeToken` and the `transfer` selector.
library FeeRules {
    function check(
        Call memory c,
        uint256 idx,
        uint256 maxFee,
        uint256 notional,
        IAllowlistRegistry registry,
        Config memory cfg
    ) internal view {
        (address to, uint256 fee) = abi.decode(CallLib.args(c.data, 64, idx), (address, uint256));
        CallLib.requireCanonical(c.data, abi.encodeCall(IERC20.transfer, (to, fee)), idx);
        if (!registry.isAllowed(Category.FEE_RECIPIENT, to)) reject(Reason.BAD_FEE, idx);
        if (maxFee == 0 || fee > maxFee) reject(Reason.FEE_TOO_HIGH, idx);
        if (fee > cfg.flatFee + Math.mulDiv(notional, cfg.maxFeeBps, 10_000)) reject(Reason.FEE_TOO_HIGH, idx);
    }
}
