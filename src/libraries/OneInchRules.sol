// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAllowlistRegistry} from "../interfaces/IAllowlistRegistry.sol";
import {IAggregationRouterV6, IUniswapPool} from "../interfaces/IExternal.sol";
import {Reason, reject} from "../types/Errors.sol";
import {Call, Category, PoolType} from "../types/Types.sol";
import {CallLib} from "./CallLib.sol";

/// @notice Router-agnostic view of a swap call.
struct SwapData {
    address srcToken;
    address dstToken;
    uint256 amount;
    uint256 minReturn;
    address receiver;
}

/// @notice 1inch Aggregation Router v6 decoder (§3.3). Accepts `swap` and the `unoswap*` / `unoswapTo*` family;
///         everything else (`ethUnoswap*`, `clipperSwap*`, limit-order fills, ...) is rejected.
/// @dev Bit layout pinned from the verified v6 source (0x111111125421cA6dc452d289314280a0f8842A65):
///      ProtocolLib: protocol = dex >> 253 (0 UniswapV2, 1 UniswapV3, 2 Curve), WETH_UNWRAP = 1 << 252,
///      WETH_NOT_WRAP = 1 << 251, USE_PERMIT2 = 1 << 250. UnoswapRouter: zeroForOne = bit 247 (token0 in),
///      UniswapV2 fee numerator = bits 160..191. GenericRouter flags: PARTIAL_FILL = 1, REQUIRES_EXTRA_ETH = 2,
///      USE_PERMIT2 = 4.
library OneInchRules {
    uint256 private constant PROTOCOL_OFFSET = 253;
    uint256 private constant PROTOCOL_UNISWAP_V2 = 0;
    uint256 private constant PROTOCOL_UNISWAP_V3 = 1;
    uint256 private constant ZERO_FOR_ONE_OFFSET = 247;

    uint256 private constant ADDRESS_MASK = type(uint160).max;
    uint256 private constant ZERO_FOR_ONE_BIT = 1 << ZERO_FOR_ONE_OFFSET;
    uint256 private constant PROTOCOL_MASK = uint256(7) << PROTOCOL_OFFSET;
    uint256 private constant V2_NUMERATOR_MASK = uint256(type(uint32).max) << 160;
    /// Every bit a UniswapV3 hop may set; unwrap / not-wrap / Permit2 and all unused bits must be zero.
    uint256 private constant V3_ALLOWED_BITS = ADDRESS_MASK | ZERO_FOR_ONE_BIT | PROTOCOL_MASK;
    uint256 private constant V2_ALLOWED_BITS = V3_ALLOWED_BITS | V2_NUMERATOR_MASK;

    function decode(Call memory c, uint256 idx, address user, IAllowlistRegistry registry)
        internal
        view
        returns (SwapData memory s)
    {
        bytes4 sel = CallLib.selector(c.data);
        if (sel == IAggregationRouterV6.swap.selector) return _swap(c.data, idx);

        (uint256 hops, bool hasTo) = _unoswapShape(sel);
        if (hops == 0) reject(Reason.BAD_SELECTOR, idx);

        uint256 first = hasTo ? 1 : 0;
        uint256 words = first + 3 + hops;
        if (c.data.length != 4 + 32 * words) reject(Reason.MALFORMED_CALL, idx);

        // unoswap sends the output to msg.sender, which is the user's account.
        s.receiver = hasTo ? CallLib.cleanAddress(CallLib.word(c.data, 0), idx) : user;
        s.srcToken = CallLib.cleanAddress(CallLib.word(c.data, first), idx);
        s.amount = CallLib.word(c.data, first + 1);
        s.minReturn = CallLib.word(c.data, first + 2);

        // The output token is not in the calldata: walk the hops through allowlisted pools.
        address token = s.srcToken;
        for (uint256 h; h < hops; ++h) {
            token = _hop(CallLib.word(c.data, first + 3 + h), token, idx, registry);
        }
        s.dstToken = token;
    }

    function _swap(bytes memory data, uint256 idx) private pure returns (SwapData memory s) {
        (address executor, IAggregationRouterV6.SwapDescription memory d, bytes memory execData) =
            abi.decode(CallLib.args(data, 320, idx), (address, IAggregationRouterV6.SwapDescription, bytes));
        CallLib.requireCanonical(data, abi.encodeCall(IAggregationRouterV6.swap, (executor, d, execData)), idx);
        // No partial fill (minReturn must apply to the whole amount), no extra ETH, no Permit2.
        if (d.flags != 0) reject(Reason.BAD_SWAP, idx);
        s = SwapData({
            srcToken: d.srcToken,
            dstToken: d.dstToken,
            amount: d.amount,
            minReturn: d.minReturnAmount,
            receiver: d.dstReceiver
        });
    }

    /// @return out The token this hop outputs, given that `tokenIn` goes in.
    function _hop(uint256 dex, address tokenIn, uint256 idx, IAllowlistRegistry registry)
        private
        view
        returns (address out)
    {
        uint256 protocol = dex >> PROTOCOL_OFFSET;
        PoolType expected;
        uint256 allowedBits;
        if (protocol == PROTOCOL_UNISWAP_V2) {
            expected = PoolType.UNISWAP_V2;
            allowedBits = V2_ALLOWED_BITS;
        } else if (protocol == PROTOCOL_UNISWAP_V3) {
            expected = PoolType.UNISWAP_V3;
            allowedBits = V3_ALLOWED_BITS;
        } else {
            reject(Reason.BAD_SWAP, idx); // Curve and unknown protocols
        }
        if (dex & ~allowedBits != 0) reject(Reason.BAD_SWAP, idx);

        address pool = address(uint160(dex));
        if (!registry.isAllowed(Category.SWAP_POOL, pool) || registry.poolType(pool) != expected) {
            reject(Reason.POOL_NOT_ALLOWED, idx);
        }

        bool zeroForOne = dex & ZERO_FOR_ONE_BIT != 0;
        address token0 = IUniswapPool(pool).token0();
        address token1 = IUniswapPool(pool).token1();
        (address inToken, address outToken) = zeroForOne ? (token0, token1) : (token1, token0);
        if (inToken != tokenIn) reject(Reason.BAD_SWAP, idx);
        out = outToken;
    }

    function _unoswapShape(bytes4 sel) private pure returns (uint256 hops, bool hasTo) {
        if (sel == IAggregationRouterV6.unoswap.selector) return (1, false);
        if (sel == IAggregationRouterV6.unoswap2.selector) return (2, false);
        if (sel == IAggregationRouterV6.unoswap3.selector) return (3, false);
        if (sel == IAggregationRouterV6.unoswapTo.selector) return (1, true);
        if (sel == IAggregationRouterV6.unoswapTo2.selector) return (2, true);
        if (sel == IAggregationRouterV6.unoswapTo3.selector) return (3, true);
        return (0, false);
    }
}
