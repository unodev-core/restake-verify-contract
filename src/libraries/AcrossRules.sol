// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAcrossSpokePool} from "../interfaces/IExternal.sol";
import {Reason, reject} from "../types/Errors.sol";
import {BridgeConfig, BridgeDeposit} from "../types/Types.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Across SpokePool decoder (`BridgeType.ACROSS`, §3.3). Turns `deposit` (bytes32 ABI) or `depositV3`
///         (address ABI) into a `BridgeDeposit`. Every other entry point (`depositNow`, `unsafeDeposit`, periphery
///         swap-and-bridge, ...) is rejected by the bridge row's selector list and by this decoder.
/// @dev Both ABIs share one layout: 11 static words, the `message` offset (must be 0x180), then `message`.
library AcrossRules {
    uint256 private constant STATIC_WORDS = 11;
    uint256 private constant MESSAGE_OFFSET = 0x180; // 12 words
    uint256 private constant EMPTY_MESSAGE_ARGS_LEN = 13 * 32;

    function decode(bytes memory data, uint256 idx, BridgeConfig memory cfg)
        internal
        view
        returns (BridgeDeposit memory d)
    {
        // The backend appends `0x1dc0de ‖ integratorId`. Only the configured suffix is tolerated.
        bytes memory body = data;
        if (CallLib.endsWith(data, cfg.integratorSuffix)) {
            body = CallLib.slice(data, 0, data.length - cfg.integratorSuffix.length);
        }

        bytes4 sel = CallLib.selectorOf(body);
        // slither-disable-next-line uninitialized-local (false is the intended default)
        bool legacy;
        if (sel == IAcrossSpokePool.depositV3.selector) legacy = true;
        else if (sel != IAcrossSpokePool.deposit.selector) reject(Reason.BAD_SELECTOR, idx);

        if (body.length < 4 + EMPTY_MESSAGE_ARGS_LEN) reject(Reason.MALFORMED_CALL, idx);
        if (CallLib.word(body, STATIC_WORDS) != MESSAGE_OFFSET) reject(Reason.MALFORMED_CALL, idx);
        d.hasPayload = CallLib.word(body, STATIC_WORDS + 1) != 0;
        // With an empty message the canonical encoding has an exact length; anything else is trailing data.
        if (!d.hasPayload && body.length != 4 + EMPTY_MESSAGE_ARGS_LEN) reject(Reason.MALFORMED_CALL, idx);

        // Addresses on this chain must be clean in both ABIs; in the legacy ABI every address field must be.
        d.refundTo = CallLib.cleanAddress(CallLib.word(body, 0), idx); // depositor
        d.inputToken = CallLib.cleanAddress(CallLib.word(body, 2), idx);
        d.recipient = bytes32(CallLib.word(body, 1));
        d.outputToken = bytes32(CallLib.word(body, 3));
        if (legacy) {
            // Validation only: cleanAddress rejects dirty upper bits.
            // slither-disable-start unused-return
            CallLib.cleanAddress(uint256(d.recipient), idx);
            CallLib.cleanAddress(uint256(d.outputToken), idx);
            CallLib.cleanAddress(CallLib.word(body, 7), idx); // exclusiveRelayer
            // slither-disable-end unused-return
        }
        d.inputAmount = CallLib.word(body, 4);
        d.outputAmount = CallLib.word(body, 5);
        d.dstChainId = CallLib.word(body, 6);
        // word 7 exclusiveRelayer and word 10 exclusivityParameter stay opaque: they can only delay a fill.
        uint256 quoteTimestamp = _uint32(CallLib.word(body, 8), idx);
        d.refundAfter = _uint32(CallLib.word(body, 9), idx); // fillDeadline
        _uint32(CallLib.word(body, 10), idx);

        if (quoteTimestamp > block.timestamp || quoteTimestamp + cfg.maxQuoteAge < block.timestamp) {
            reject(Reason.STALE_QUOTE, idx);
        }
    }

    function _uint32(uint256 w, uint256 idx) private pure returns (uint256) {
        if (w > type(uint32).max) reject(Reason.MALFORMED_CALL, idx);
        return w;
    }
}
