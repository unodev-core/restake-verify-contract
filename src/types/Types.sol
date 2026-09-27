// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice EntryPoint v0.7 user operation (§2.1).
/// @dev `accountGasLimits` = verificationGasLimit (high 128) ‖ callGasLimit (low 128).
///      `gasFees` = maxPriorityFeePerGas (high 128) ‖ maxFeePerGas (low 128).
///      `paymasterAndData` = paymaster (20 B) ‖ verificationGasLimit (16 B) ‖ postOpGasLimit (16 B) ‖ data.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice EIP-7702 authorization tuple. `delegate == address(0)` means the op is sent without a new authorization.
struct Authorization {
    uint256 chainId;
    address delegate;
    uint256 nonce;
}

enum Action {
    STAKE,
    UNSTAKE,
    BUY,
    SELL,
    BRIDGE
}

/// @notice The intent the user saw in the partner UI (§3.2).
struct Intent {
    Action action;
    address user;
    address target; // vault / pool / Ondo token; 0 for BRIDGE
    address payToken; // buy/sell: payment asset; bridge: token sent; ignored for vaults
    uint256 amount; // asset (stake), shares (unstake), payToken (buy), stock (sell), payToken (bridge)
    uint256 minOut; // buy/sell slippage bound; bridge: min received on destination (dst decimals); 0 for vaults
    uint256 maxFee; // fee shown to the user, fee-token units; 0 = no fee call allowed
    uint256 dstChainId; // BRIDGE only
    bytes32 recipient; // BRIDGE only
}

/// @notice Alchemy Modular Account v2 `executeBatch` element.
struct Call {
    address target;
    uint256 value;
    bytes data;
}

enum Category {
    PAYMASTER,
    VAULT_4626,
    AAVE_POOL,
    ASSET,
    ONDO_TOKEN,
    SWAP_ROUTER,
    SWAP_POOL,
    BRIDGE,
    FEE_RECIPIENT
}

enum PoolType {
    NONE,
    UNISWAP_V2,
    UNISWAP_V3
}

enum RouterType {
    NONE,
    ONE_INCH_V6
}

enum BridgeType {
    NONE,
    ACROSS
}

struct BridgeConfig {
    BridgeType bridgeType; // selects the decoder
    address spender; // approve target (Across: the SpokePool itself)
    uint32 maxFillWindow; // max seconds from now until refundAfter
    uint32 maxQuoteAge; // max age of the provider quote timestamp; 0 if the provider has none
    bytes4[] selectors; // accepted deposit entry points
    bytes integratorSuffix; // exact trailing bytes allowed after the ABI args; empty = none
}

struct BridgeRoute {
    bytes32 outputToken; // token on the destination chain
    uint8 inputDecimals;
    uint8 outputDecimals;
}

/// @notice A route row as listed by `listRoutes()`.
struct RouteEntry {
    address bridge;
    address inputToken;
    uint256 dstChainId;
    BridgeRoute route;
}

/// @notice Provider-agnostic view of a bridge deposit call (§3.3 BRIDGE).
struct BridgeDeposit {
    address inputToken;
    uint256 inputAmount;
    bytes32 outputToken;
    uint256 outputAmount;
    uint256 dstChainId;
    bytes32 recipient;
    address refundTo;
    uint256 refundAfter;
    bool hasPayload;
}

/// @notice Timelocked configuration values (§4.1).
struct Config {
    address feeToken; // chain USDC
    uint16 maxFeeBps; // backstop fee cap, bps of the notional
    uint16 maxBridgeFeeBps; // max provider fee on a bridge, bps of the rescaled input
    uint32 maxBatchTtl; // max seconds between now and the in-batch deadline
    uint256 flatFee; // backstop flat fee, fee-token units
    uint128 maxFeePerGas; // cap for ops without a paymaster
    uint128 maxTotalGas; // verificationGasLimit + callGasLimit + preVerificationGas, ops without a paymaster
}
