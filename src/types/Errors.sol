// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Why a batch was rejected. The numeric value is the `errorCode` returned by `check()`.
/// @dev Append only: partners map these codes to UI messages.
enum Reason {
    NONE,
    PAUSED, // the registry is paused
    REVERTED, // check() only: verify reverted without a Rejected error (undecodable ABI, failing live read)
    HASH_MISMATCH, // userOpHash != v0.7 hash of op
    BAD_DELEGATE, // 7702 authorization delegate != MAv2 7702 implementation
    BAD_AUTH_CHAIN_ID, // authorization chainId != block.chainid (includes 0)
    BAD_ACCOUNT_CODE, // sender is a contract, delegated elsewhere, or undelegated without an authorization
    WRONG_SENDER, // op.sender != intent.user
    INIT_CODE_NOT_EMPTY,
    PAYMASTER_NOT_ALLOWED,
    GAS_CAP_EXCEEDED, // no paymaster and gas price / limits above the caps
    BAD_CALLDATA, // op.callData is not a canonical MAv2 executeBatch
    SELF_CALL_FORBIDDEN, // an inner call targets op.sender
    NATIVE_VALUE, // an inner call carries native value
    MISSING_DEADLINE, // call 0 is not DeadlineGuard.requireBefore
    BAD_DEADLINE, // deadline expired or beyond maxBatchTtl
    BAD_INTENT, // intent fields inconsistent with its action
    UNEXPECTED_CALL, // default deny: a call that matches no rule
    MISSING_MAIN_CALL,
    TARGET_NOT_ALLOWED, // a target or token is not allowlisted for its role
    UNSUPPORTED_ASSET, // v1 supports only fee-token (USDC) pools, trades and bridges
    BAD_SELECTOR, // main call uses a method not accepted for its target
    MALFORMED_CALL, // inner calldata is not canonically ABI-encoded (trailing bytes, dirty words)
    BAD_AMOUNT, // amount differs from the intent
    BAD_RECEIVER, // receiver / owner / recipient / refund address is not the user
    BAD_APPROVE, // approve on a wrong token, to a wrong spender, or for a wrong amount
    RESIDUAL_ALLOWANCE, // an allowance would remain after the batch
    BAD_FEE, // fee call to a wrong recipient
    FEE_TOO_HIGH, // fee above intent.maxFee or the backstop cap
    BAD_SWAP, // swap tokens, flags or hop chain do not match
    MIN_OUT_TOO_LOW, // swap minReturn below intent.minOut
    POOL_NOT_ALLOWED, // unoswap hop through a pool that is not allowlisted with the matching type
    BAD_ROUTE, // bridge route not allowlisted, wrong destination chain or output token
    BAD_BRIDGE_DEPOSIT, // bridge deposit carries a payload or an unexpected shape
    OUTPUT_TOO_LOW, // bridge outputAmount below intent.minOut or the provider fee cap
    FILL_WINDOW_TOO_LONG, // bridge refundAfter beyond maxFillWindow
    STALE_QUOTE // bridge quote timestamp in the future or older than maxQuoteAge
}

/// @notice The only error `verify` raises for a rule violation.
/// @param reason What failed.
/// @param callIndex Index of the offending call in `executeBatch`, or `NO_INDEX` for envelope-level failures.
error Rejected(Reason reason, uint256 callIndex);

uint256 constant NO_INDEX = type(uint256).max;

function reject(Reason reason, uint256 callIndex) pure {
    revert Rejected(reason, callIndex);
}
