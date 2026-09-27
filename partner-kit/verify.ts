/**
 * Restake Batch Verifier — partner kit (viem).
 *
 * Flow (plan §6):
 *   1. Get { op, userOpHash, authorization, intentId } from the Restake API.
 *   2. eth_call `verify(op, userOpHash, auth, intentFromUI)` on YOUR OWN node.
 *   3. Sign the returned `verifiedHash` (never the API's hash): personal_sign over the raw 32 bytes, then send
 *      `0xff00 ‖ sig` (67 bytes). Sign exactly the authorization tuple you passed to `verify`.
 *   4. Check `authorization.nonce == eth_getTransactionCount(user)`.
 *   5. Send the signatures to the Restake backend.
 *
 * `minOut` and `maxFee` must come from YOUR quote and the published fee table, never from the Restake API.
 */
import {
  type Address,
  type Hex,
  type LocalAccount,
  type PublicClient,
  concat,
  pad,
  parseAbi,
} from "viem";

export const BATCH_VERIFIER_ABI = parseAbi([
  "struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }",
  "struct Authorization { uint256 chainId; address delegate; uint256 nonce; }",
  "struct Intent { uint8 action; address user; address target; address payToken; uint256 amount; uint256 minOut; uint256 maxFee; uint256 dstChainId; bytes32 recipient; }",
  "function verify(PackedUserOperation op, bytes32 userOpHash, Authorization auth, Intent intent) view returns (bytes32 verifiedHash, uint256 deadline)",
  "function check(PackedUserOperation op, bytes32 userOpHash, Authorization auth, Intent intent) view returns (bool ok, uint8 errorCode, uint256 callIndex)",
  "error Rejected(uint8 reason, uint256 callIndex)",
]);

export enum Action {
  STAKE,
  UNSTAKE,
  BUY,
  SELL,
  BRIDGE,
}

/** Mirrors `Reason` in src/types/Errors.sol (append-only). */
export const REASONS = [
  "NONE", "PAUSED", "REVERTED", "HASH_MISMATCH", "BAD_DELEGATE", "BAD_AUTH_CHAIN_ID", "BAD_ACCOUNT_CODE",
  "WRONG_SENDER", "INIT_CODE_NOT_EMPTY", "PAYMASTER_NOT_ALLOWED", "GAS_CAP_EXCEEDED", "BAD_CALLDATA",
  "SELF_CALL_FORBIDDEN", "NATIVE_VALUE", "MISSING_DEADLINE", "BAD_DEADLINE", "BAD_INTENT", "UNEXPECTED_CALL",
  "MISSING_MAIN_CALL", "TARGET_NOT_ALLOWED", "UNSUPPORTED_ASSET", "BAD_SELECTOR", "MALFORMED_CALL", "BAD_AMOUNT",
  "BAD_RECEIVER", "BAD_APPROVE", "RESIDUAL_ALLOWANCE", "BAD_FEE", "FEE_TOO_HIGH", "BAD_SWAP", "MIN_OUT_TOO_LOW",
  "POOL_NOT_ALLOWED", "BAD_ROUTE", "BAD_BRIDGE_DEPOSIT", "OUTPUT_TOO_LOW", "FILL_WINDOW_TOO_LONG", "STALE_QUOTE",
] as const;

export const NO_INDEX = 2n ** 256n - 1n;

export type PackedUserOperation = {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterAndData: Hex;
  signature: Hex;
};

export type Authorization = { chainId: bigint; delegate: Address; nonce: bigint };

export type Intent = {
  action: Action;
  user: Address;
  target: Address;
  payToken: Address;
  amount: bigint;
  minOut: bigint;
  maxFee: bigint;
  dstChainId: bigint;
  recipient: Hex;
};

export class VerificationError extends Error {
  constructor(
    public readonly reason: (typeof REASONS)[number] | "UNKNOWN",
    public readonly callIndex: bigint,
  ) {
    super(`Restake batch rejected: ${reason}${callIndex === NO_INDEX ? "" : ` (call #${callIndex})`}`);
  }
}

/**
 * Steps 2–4. Returns the hash to sign and the batch deadline, or throws VerificationError.
 * `client` must point at the partner's own RPC node.
 */
export async function verifyBatch(
  client: PublicClient,
  verifier: Address,
  op: PackedUserOperation,
  apiUserOpHash: Hex,
  auth: Authorization,
  intentFromUI: Intent,
): Promise<{ verifiedHash: Hex; deadline: bigint }> {
  const [ok, errorCode, callIndex] = await client.readContract({
    address: verifier,
    abi: BATCH_VERIFIER_ABI,
    functionName: "check",
    args: [op, apiUserOpHash, auth, intentFromUI],
  });
  if (!ok) throw new VerificationError(REASONS[errorCode] ?? "UNKNOWN", callIndex);

  const [verifiedHash, deadline] = await client.readContract({
    address: verifier,
    abi: BATCH_VERIFIER_ABI,
    functionName: "verify",
    args: [op, apiUserOpHash, auth, intentFromUI],
  });

  if (auth.delegate !== "0x0000000000000000000000000000000000000000") {
    const txCount = await client.getTransactionCount({ address: intentFromUI.user, blockTag: "pending" });
    if (BigInt(txCount) !== auth.nonce) throw new Error("7702 authorization nonce does not match the account nonce");
  }
  return { verifiedHash, deadline };
}

/** Step 3: MAv2 owner signature — EIP-191 over the raw 32-byte hash, prefixed 0xff00 (67 bytes). */
export async function signUserOp(owner: LocalAccount, verifiedHash: Hex): Promise<Hex> {
  // `{ raw }` signs the bytes, not the 66-character hex string; EIP-191 is applied exactly once.
  const sig = await owner.signMessage({ message: { raw: verifiedHash } });
  return concat(["0xff00", sig]);
}

/**
 * The fee to show the user, and pass as `intent.maxFee`: tier (0.3% < $1k, 0.2% < $10k, 0.1% above) + $0.10 gas
 * coverage, rounded up to the fee token's smallest unit. Bridges pay the flat part only.
 * `notional` is in fee-token (USDC) units with `decimals` decimals (6 on Base, 18 on BSC).
 */
export function restakeFee(notional: bigint, decimals: number, action: Action): bigint {
  const unit = 10n ** BigInt(decimals);
  const flat = unit / 10n; // $0.10
  if (action === Action.BRIDGE) return flat;
  const bps = notional < 1_000n * unit ? 30n : notional < 10_000n * unit ? 20n : 10n;
  return (notional * bps + 9_999n) / 10_000n + flat;
}

/** `intent.recipient` for a bridge: the user's own address as bytes32. */
export const bridgeRecipient = (user: Address): Hex => pad(user, { size: 32 });
