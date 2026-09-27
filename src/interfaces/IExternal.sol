// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Call} from "../types/Types.sol";

/// @notice Alchemy Modular Account v2 batch entry point (selector 0x34fcd5be).
interface IModularAccountV2 {
    function executeBatch(Call[] calldata calls) external payable;
}

/// @notice Aave v3 Pool (subset).
interface IAaveV3Pool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}

/// @notice 1inch Aggregation Router v6 (subset). `Address` words are passed as uint256.
interface IAggregationRouterV6 {
    struct SwapDescription {
        address srcToken;
        address dstToken;
        address srcReceiver;
        address dstReceiver;
        uint256 amount;
        uint256 minReturnAmount;
        uint256 flags;
    }

    function swap(address executor, SwapDescription calldata desc, bytes calldata data)
        external
        payable
        returns (uint256 returnAmount, uint256 spentAmount);

    function unoswap(uint256 token, uint256 amount, uint256 minReturn, uint256 dex) external returns (uint256);
    function unoswap2(uint256 token, uint256 amount, uint256 minReturn, uint256 dex, uint256 dex2)
        external
        returns (uint256);
    function unoswap3(uint256 token, uint256 amount, uint256 minReturn, uint256 dex, uint256 dex2, uint256 dex3)
        external
        returns (uint256);
    function unoswapTo(uint256 to, uint256 token, uint256 amount, uint256 minReturn, uint256 dex)
        external
        returns (uint256);
    function unoswapTo2(uint256 to, uint256 token, uint256 amount, uint256 minReturn, uint256 dex, uint256 dex2)
        external
        returns (uint256);
    function unoswapTo3(
        uint256 to,
        uint256 token,
        uint256 amount,
        uint256 minReturn,
        uint256 dex,
        uint256 dex2,
        uint256 dex3
    ) external returns (uint256);
}

/// @notice Across SpokePool deposit entry points.
interface IAcrossSpokePool {
    function deposit(
        bytes32 depositor,
        bytes32 recipient,
        bytes32 inputToken,
        bytes32 outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        bytes32 exclusiveRelayer,
        uint32 quoteTimestamp,
        uint32 fillDeadline,
        uint32 exclusivityParameter,
        bytes calldata message
    ) external payable;

    function depositV3(
        address depositor,
        address recipient,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        address exclusiveRelayer,
        uint32 quoteTimestamp,
        uint32 fillDeadline,
        uint32 exclusivityDeadline,
        bytes calldata message
    ) external payable;
}

/// @notice Uniswap v2 / v3 style pool (and PancakeSwap forks).
interface IUniswapPool {
    function token0() external view returns (address);
    function token1() external view returns (address);
}
