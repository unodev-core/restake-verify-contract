// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {Reason, reject} from "../types/Errors.sol";
import {Call} from "../types/Types.sol";
import {MainResult} from "./BatchLayout.sol";
import {CallLib} from "./CallLib.sol";

/// @notice ERC-4626 stake / unstake rules (§3.3). The caller has checked that `c.target` is an allowlisted
///         VAULT_4626 equal to `intent.target`, so the live `asset()` / `preview*` reads go to a trusted vault.
library Erc4626Rules {
    /// @notice `vault.deposit(amount, user)`. `mint` is rejected.
    function stake(Call memory c, uint256 idx, address user, uint256 amount, address feeToken)
        internal
        view
        returns (MainResult memory m)
    {
        if (CallLib.selectorOf(c.data) != IERC4626.deposit.selector) reject(Reason.BAD_SELECTOR, idx);
        (uint256 assets, address receiver) = abi.decode(CallLib.args(c.data, 64, idx), (uint256, address));
        CallLib.requireCanonical(c.data, abi.encodeCall(IERC4626.deposit, (assets, receiver)), idx);
        if (receiver != user) reject(Reason.BAD_RECEIVER, idx);
        if (amount == 0 || assets != amount) reject(Reason.BAD_AMOUNT, idx);

        address asset = _usdcAsset(c.target, feeToken, idx);
        m = MainResult({token: asset, spender: c.target, pulled: assets, notional: assets});
    }

    /// @notice `vault.redeem(amount, user, user)`, or `vault.withdraw(assets, user, user)` burning at most `amount`
    ///         shares. Nothing is pulled from the asset allowance; the revoke rule runs on the vault's asset.
    function unstake(Call memory c, uint256 idx, address user, uint256 amount, address feeToken)
        internal
        view
        returns (MainResult memory m)
    {
        bytes4 sel = CallLib.selectorOf(c.data);
        if (sel != IERC4626.redeem.selector && sel != IERC4626.withdraw.selector) reject(Reason.BAD_SELECTOR, idx);
        (uint256 value, address receiver, address owner) =
            abi.decode(CallLib.args(c.data, 96, idx), (uint256, address, address));
        CallLib.requireCanonical(c.data, abi.encodeWithSelector(sel, value, receiver, owner), idx);
        if (receiver != user || owner != user) reject(Reason.BAD_RECEIVER, idx);
        if (amount == 0 || value == 0) reject(Reason.BAD_AMOUNT, idx);

        address asset = _usdcAsset(c.target, feeToken, idx);
        uint256 notional;
        if (sel == IERC4626.redeem.selector) {
            if (value != amount) reject(Reason.BAD_AMOUNT, idx);
            notional = IERC4626(c.target).previewRedeem(value);
        } else {
            if (IERC4626(c.target).previewWithdraw(value) > amount) reject(Reason.BAD_AMOUNT, idx);
            notional = value;
        }
        m = MainResult({token: asset, spender: c.target, pulled: 0, notional: notional});
    }

    function _usdcAsset(address vault, address feeToken, uint256 idx) private view returns (address asset) {
        asset = IERC4626(vault).asset();
        if (asset != feeToken) reject(Reason.UNSUPPORTED_ASSET, idx);
    }
}
