# Restake Batch Verifier — Implementation Plan

Status: draft · 2026-09-27 (updated with the backend team's answers, see §10)

## 1. Problem

The Restake API builds unsigned EIP-7702 batch user operations (ERC-4337 `UserOperation` executed through the Alchemy bundler) for:

- stake / unstake into ERC-4626 vaults (and Aave v3 `A_TOKEN` pools),
- buy / sell Ondo tokenized stocks,
- bridge tokens to another chain (Across today, provider may change later).

Partners (iOS app, web, etc.) have the user sign the batch and return it to the Restake backend, which submits it. Today a partner has to trust whatever Restake returns. If the API were compromised, it could return a batch that drains the user, for example with an infinite approval, a deposit whose `receiver` is an attacker, or a 7702 delegation to a malicious account implementation.

**Goal:** an on-chain, read-only verifier that partners call with `eth_call` against **their own RPC node** before signing. It must answer: *"Does this exact user operation do only what the user asked for, touching only allowlisted contracts, and is this the hash I am about to sign?"*

## 2. Real batch shapes

Sources: the Restake MCP and the backend code (`restake-api`, `dev` branch).

`build_stake_transaction` returns:

- `signing.userOpHash`: the hash the wallet signs.
- `signing.authorization`: the EIP-7702 tuple `(chainId, address delegate, nonce)`.
- `intentId`: a single-use intent, valid for 300 s. This TTL is enforced only off-chain (`CONFIG_CACHE_BUNDLE_TX_TTL_MSEC`, 600 s in the local env), so a signed op is not bound by it; see the deadline guard in §3.1.

The batches the backend builds today:

| Action | Calls, in order |
|--------|-----------------|
| STAKE | `asset.approve(pool, amount)` → `deposit(amount, receiver)` / `supply(asset, amount, onBehalfOf, 0)` → fee |
| UNSTAKE | `withdraw` / `redeem` → `asset.approve(pool, 0)` (left out when the allowance is already 0; included if the read fails) → fee |
| BUY / SELL | `srcToken.approve(router, amount)` (left out when the existing allowance already covers `amount`) → 1inch swap → fee |
| BRIDGE | `usdc.approve(spokePool, amount)` → Across `deposit(...)` + integrator suffix → fee (gas coverage only) |

- **Fee:** always the chain's **USDC** (`CONFIG_SYSTEM_FEE_TOKEN_SYMBOL`), whatever the action's asset, sent as one `transfer(treasury, fee)` (`CONFIG_SYSTEM_FEE_RECIPIENT`) as the **last** call. Fee = tier (0.3% below $1k, 0.2% below $10k, 0.1% above) + flat $0.10 gas coverage, rounded up to the token's smallest unit. The bridge charges the flat part only. The call may be absent.
- **Stocks:** BSC only, all through the 1inch v6 API (`/swap/v6.1/{chainId}/swap`, `receiver = from = user`), paid in Binance-Peg USDC (`0x8ac7…580d`, **18 decimals**). There is no direct-Ondo integration; Ondo is used only for prices.
- **Bridge:** Across only, USDC Base ↔ BSC in both directions. `depositor = recipient = user`, `message` always empty, approve for the exact amount.
- **Staking pools:** ETH, Base, BSC, Arbitrum, Optimism, Polygon, Avalanche and Plasma, plus testnets. **v1 of the verifier supports USDC pools only** (pools whose asset is the chain's USDC); batches for any other pool are rejected.

> TODO: capture real payloads (a funded test wallet is needed; the dev bundler reverted with `0xe65b7a77` on an empty wallet). Record in `test/fixtures/` full op payloads, including `paymasterAndData`.

### 2.1 Account stack (confirmed)

- **Account:** Alchemy **Modular Account v2** (ERC-6900), 7702 variant (`0x69007702764179f14F51cdce752f4f775d74E139`), installed as the EOA's 7702 delegate. Same on every chain.
- **EntryPoint:** **v0.7** (`0x0000000071727De22E5E9d8BAf0edAc6f37da032`), **not** v0.8. Same on every chain.

Both addresses are hardcoded as `constant`s in `BatchVerifier` (`ENTRY_POINT`, `MAV2_7702_IMPL`), not stored in the registry. Supporting another delegate or EntryPoint means a verifier upgrade, which goes through the same 48 h timelock as a registry add; in exchange, no registry entry can ever introduce a delegate, and partners can read the pinned values from verified source.

What this means for the verifier:
1. **Op format:** v0.7 `PackedUserOperation` (`accountGasLimits` and `gasFees` packed as two `uint128` each; `paymasterAndData = paymaster ‖ verificationGasLimit (16 B) ‖ postOpGasLimit (16 B) ‖ data`).
2. **Hash:** v0.7 `getUserOpHash = keccak256(abi.encode(keccak256(pack(op)), entryPoint, block.chainid))`. It is a plain hash, not EIP-712 (EIP-712 arrives in v0.8), so the verifier can recompute it locally without calling the EntryPoint.
3. **The userOpHash does not cover the 7702 delegate.** v0.7 has no native 7702 support; v0.8 would commit to the delegate through the `0x7702` `initCode` marker. Here the delegate is bound only by the separate authorization signature, so the delegate checks in §3.1 are the only protection against a malicious delegate, and the partner must sign exactly the authorization tuple it passed to `verify`. `initCode` must be empty.
4. **`callData` entry point:** the backend always encodes MAv2 `executeBatch(Call[] calls)` (selector `0x34fcd5be`, `Call { address target; uint256 value; bytes data; }`) directly into `op.callData`, even for a single call (`eip-7702.service.ts`). It never uses the `executeUserOp` prefix (`0x8dd7712f`) or plain `execute`. The verifier therefore accepts **only** `callData` whose first 4 bytes are `0x34fcd5be`; `executeBatch` does plain calls only, with no exec mode and no `delegatecall`. Everything else is rejected, including `execute`, `executeUserOp`, `performCreate`, `executeWithRuntimeValidation`, and all module-management selectors.
5. **Self-calls:** MAv2 lets the account call itself to `installValidation`, `installExecution`, `upgradeToAndCall`, and similar. A malicious validation module installed this way would be a permanent backdoor that the 7702 delegate check cannot see. Any inner call with `target == op.sender` is rejected with an explicit `SelfCallForbidden()` error, on top of default deny.
6. **Signature format:** the owner signs the EIP-191 digest of the 32 raw bytes of `userOpHash` (`personal_sign` over `bytes32`, i.e. `toEthSignedMessageHash(userOpHash)`), and the 65-byte signature is prefixed with `0xff00` (67 bytes total): `0xff` = no hook data, `0x00` = the owner EOA's validation (MAv2 signature routing). A bare 65-byte signature is refused. Signing the hash as a hex *string* (66 characters of text) or applying EIP-191 twice yields a valid-looking signature over the wrong message; the bundler rejects it with AA23/AA24. The verifier does not check signatures (it runs before signing); these rules go in the partner kit (§6).

## 3. What the verifier checks

The rule is **default deny**. Every call in the batch must match a rule, and anything that matches none fails verification.

### 3.1 Envelope (user op + 7702)

| Check | Why |
|-------|-----|
| `userOpHash` equals the v0.7 hash of `op` for the pinned EntryPoint v0.7 (§2.1) | The signed hash commits to exactly the verified op, not to a different one. |
| 7702 `authorization.address == MAV2_7702_IMPL` (§2.1) | A malicious delegate means total account takeover. This is the most important check. |
| `authorization.chainId == block.chainid` (reject `0`) | `chainId = 0` would make the signature replayable on every chain. |
| If the EOA is already delegated, `sender.code == 0xef0100‖MAV2_7702_IMPL` | Covers ops that are sent without a new authorization. |
| `op.sender == expected user` | Prevents a batch built for a different account. |
| `callData` is MAv2 `executeBatch` (`0x34fcd5be`) and nothing else: no `execute`, no `executeUserOp` prefix (§2.1) | Other account entry points (`performCreate`, module management) would bypass every other check, and each extra accepted form is attack surface the backend doesn't need. |
| No inner call targets `op.sender` | A self-call could install a validation module or upgrade the account. |
| `initCode` is empty | EntryPoint v0.7 has no 7702 `initCode` path. |
| `paymasterAndData` is empty or its paymaster is allowlisted; if empty, `maxFeePerGas` and gas limits are ≤ configured caps | Stops gas griefing on the user's ETH. Ops built with `excludeGasFee` have no paymaster. |
| `value == 0` on every inner call (unless a rule explicitly allows native value) | |
| **Deadline guard:** call 0 is `DeadlineGuard.requireBefore(deadline)`, with `block.timestamp < deadline ≤ block.timestamp + maxBatchTtl` | See below. |

Off-chain partner check (the EVM cannot read an account nonce): `authorization.nonce == eth_getTransactionCount(user)`.

**Deadline guard.** The intent TTL exists only off-chain, so a signed op stays executable until its nonce is used. A deadline passed as a `verify` argument would not help: `verify` runs before signing, so it cannot bind execution. The deadline therefore has to be inside the signed batch. It cannot come from the paymaster data either, because sponsored ops carry Alchemy Gas Manager's `paymasterAndData` (a format we don't control) and `excludeGasFee` ops have no paymaster at all.

`DeadlineGuard` is a tiny, immutable, admin-less contract:

```solidity
function requireBefore(uint256 deadline) external view {
    if (block.timestamp > deadline) revert Expired();
}
```

The backend adds `requireBefore(intentExpiry)` as the first call of every batch. The verifier requires it, pins the guard address as an immutable in the `BatchVerifier` implementation, bounds `deadline` by `maxBatchTtl` (start at **600 s**: this covers the 300 s production TTL and the 600 s local one), and returns `deadline` to the partner (§6).

### 3.2 Intent binding

The partner passes the **intent the user saw in the UI**, and the verifier checks that the batch implements exactly that:

```solidity
struct Intent {
    Action action;      // STAKE, UNSTAKE, BUY, SELL, BRIDGE
    address user;
    address target;     // vault / pool / Ondo token; 0 for BRIDGE (the bridge is read from the call and must be allowlisted)
    address payToken;   // buy/sell: the payment asset (e.g. USDC); bridge: the token sent; ignored for vaults
    uint256 amount;     // input amount: asset (stake), shares (unstake), payToken (buy), stock (sell), payToken (bridge)
    uint256 minOut;     // buy/sell slippage bound; bridge: min amount received on the destination, in destination decimals; 0 for vaults
    uint256 maxFee;     // the fee shown to the user, in fee-token (USDC) units; 0 = no fee call allowed
    uint256 dstChainId; // BRIDGE only: destination chain id; 0 otherwise
    bytes32 recipient;  // BRIDGE only: receiver on the destination chain (bytes32 so non-EVM chains fit later); 0 otherwise
}
```

### 3.3 Call rules

#### Shared rules (every action)

**Approvals.**
1. Every approve is on a token and to a spender fixed by the action (the pool, the router, the bridge spender). No other approvals, no `increaseAllowance`, no `permit`, no `type(uint256).max`.
2. An approve before the main call is optional. When present, its amount equals exactly what the main call pulls (`intent.amount`). An `approve(spender, 0)` directly before it is allowed for USDT-style tokens.
3. A **revoke**, `approve(spender, 0)`, may appear at most once, **after the main call and before the fee**.
4. **Zero residual allowance:** after the batch, `allowance(user, spender)` must be 0, otherwise `ResidualAllowance()`. The verifier reads the current allowance live (the token is allowlisted) and computes the residual:
   - with an exact approve, the main call consumes it fully, so the residual is 0 and no revoke is needed;
   - without an approve, the residual is `current − pulled` (or stays `max` for tokens that don't decrement an infinite allowance), so a revoke is required unless that is 0;
   - UNSTAKE pulls nothing from the asset allowance, so a revoke is required exactly when the current allowance is non-zero.

This one rule covers the backend's current behaviour: the unstake revoke is left out when the allowance is already 0, and a trade may rely on a standing allowance as long as a revoke follows. It also cleans up legacy infinite allowances.

**Fee.**
1. At most one fee call, and it must be the **last** call: `feeToken.transfer(feeRecipient, fee)`, where `feeToken` is the chain's configured fee token (USDC) and `feeRecipient` is an allowlisted `FEE_RECIPIENT`.
2. `fee ≤ intent.maxFee`.
3. **Backstop cap**, applied to every action (in v1 every notional is in the fee token: pools are USDC-only, trades are paid in USDC, and bridges move USDC): `fee ≤ flatFee + notional × maxFeeBps / 10_000`. The notional is `intent.amount` for STAKE, BUY and BRIDGE; the withdrawn assets for UNSTAKE (`previewRedeem(shares)` on the allowlisted vault for `redeem`); `intent.minOut` for SELL.
4. Starting values: `maxFeeBps = 50` (the top tier is 30 bps, and SELL's notional `minOut` understates the real one by the slippage), `flatFee = $0.10` plus a rounding margin, in fee-token units per chain (6 decimals on Base, 18 on BSC). A pure bps cap would break small trades, where the flat part is most of the fee.

**Pool asset (v1):** every STAKE / UNSTAKE requires the pool's asset to equal `feeToken` (the chain's USDC), otherwise `UnsupportedAsset()`. For ERC-4626 the asset is `IERC4626(vault).asset()` read live; for Aave it is the `asset` argument. Only USDC pools are added to `VAULT_4626` / `AAVE_POOL`; the live check is defense in depth against a mis-added pool. Supporting other assets later means lifting this check and settling how to bound their fee, since the backstop cap needs a USDC notional (a price feed, or `intent.maxFee` alone).

#### STAKE (ERC-4626)
1. Optional `asset.approve(vault, X)` where `asset == IERC4626(vault).asset()` (read live, must be `feeToken`) and `X == intent.amount` (shared rules).
2. `vault.deposit(X, receiver)` with `receiver == user`. `mint` is rejected, or allowed only with `previewMint` bounds.
3. Optional revoke, then optional fee (shared rules).
4. No other calls.

**STAKE (Aave v3):** same pattern with `pool.supply(asset, X, onBehalfOf == user, 0)`, where `asset == feeToken` (chain USDC).

#### UNSTAKE (ERC-4626)
1. `vault.redeem(shares, receiver == user, owner == user)` or `withdraw(assets, user, user)`.
2. `asset.approve(vault, 0)`, where `asset == IERC4626(vault).asset()`, **required unless the current allowance is already 0** (zero-residual rule). It comes after the withdraw and before the fee.
3. Optional fee.
4. No other calls. In particular, no approvals of vault shares to anyone.

**UNSTAKE (Aave):** `pool.withdraw(asset, amount, to == user)`, then the same conditional revoke, `asset.approve(pool, 0)`.

#### BUY / SELL (Ondo stocks)

Buy and sell go through an allowlisted **swap router**. In v1 the only router type is the 1inch Aggregation Router v6, at `0x111111125421cA6dc452d289314280a0f8842A65` on every chain (pinned in the allowlist; the backend itself reads `tx.to` from the API). Each allowlisted router is stored with a `RouterType`, which selects its decoder:

```solidity
enum RouterType { NONE, ONE_INCH_V6 }   // ONDO_GM is added in v2, see Appendix A
```

The rules shared by every router type:

| Action | srcToken | dstToken |
|--------|----------|----------|
| BUY | `intent.payToken` (allowlisted `ASSET`) | `intent.target` (allowlisted `ONDO_TOKEN`) |
| SELL | `intent.target` (allowlisted `ONDO_TOKEN`) | `intent.payToken` (allowlisted `ASSET`) |

1. Optional `srcToken.approve(router, X)`, where `router` is an allowlisted `SWAP_ROUTER` and `X == intent.amount` (shared rules).
2. Exactly one swap call to that router. The decoded swap must satisfy: src and dst tokens match the table, input amount `== intent.amount`, output receiver `== user`, and `minReturn ≥ intent.minOut` (with `intent.minOut > 0`).
3. Optional revoke, then optional fee. For SELL the fee is paid from the USDC proceeds.
4. No other calls.

**1inch v6 decoder (`OneInchRules`)**

The 1inch API has no parameter that forces the generic `swap` method, and retrying returns the same route, so the verifier decodes the `unoswap` family too.

*Generic swap:* `swap(IAggregationExecutor executor, SwapDescription desc, bytes data)`. Every field the verifier needs is explicit in `desc`:
- `desc.srcToken`, `desc.dstToken`, `desc.amount`, `desc.minReturnAmount` are checked against the table and the intent.
- `desc.dstReceiver == user`. `address(0)` is rejected: it means "send to msg.sender", which is the user in practice, but the explicit form is easier to verify.
- The partial-fill flag must not be set, so the whole `amount` is swapped and `minReturn` applies to it.
- `executor` and `data` stay opaque. The router itself enforces `returnAmount ≥ minReturnAmount` and pays out to `dstReceiver`, so the executor is trusted only up to the `amount` it receives.

*Unoswap:* `unoswap`, `unoswap2`, `unoswap3` `(Address token, uint256 amount, uint256 minReturn, Address dex[, dex2[, dex3]])`, and the `unoswapTo*` variants with a leading `Address to`.
- srcToken is `token` (upper 96 bits must be zero). The receiver is `to` for the `To` variants, else `msg.sender` (the user); `to` must equal `user`.
- The output token is not in the calldata. Each `dex` word packs a pool address (low 160 bits) and flags (protocol id, swap direction, WETH wrap/unwrap, Permit2). The verifier derives the output token by walking the hops:
  - each pool is an allowlisted `SWAP_POOL`, and the protocol id in the word equals the pool's registered `PoolType` (`UNISWAP_V2`-style or `UNISWAP_V3`-style, which also covers PancakeSwap forks);
  - the direction flag picks `(tokenIn, tokenOut)` from the pool's live `token0()` / `token1()` (a read on an allowlisted contract);
  - the first `tokenIn` is srcToken, each hop's `tokenIn` is the previous hop's `tokenOut`, and the last `tokenOut` is dstToken;
  - any other flag bit (WETH unwrap, Permit2) or any other protocol (Curve, …) is rejected.
- The exact bit positions are pinned from the v6 router source (`ProtocolLib`) during Discovery.
- The pool allowlist is what makes this safe. A pool is the only thing that decides the output token, and a pool that is not allowlisted could lie about `token0` / `token1`. The cost is that a route through a new pool fails until that pool is added (48 h). The backend avoids that failure by refusing such routes before returning them (backend change 1, §10).

*Always rejected:* `ethUnoswap*` and native-ETH legs (`0xEeee…EEeE`), `clipperSwap`, limit-order fills, and every other router method.

Extra partner-side check, recommended for swaps: simulate the signed batch with `eth_simulateV1` / `debug_traceCall` and confirm the user's balance changes (src decreases by `amount`, dst increases by `≥ minOut`). The on-chain verifier cannot see the executor's internal route, so this simulation covers what it misses.

#### BRIDGE (cross-chain transfer)

A bridge moves `intent.payToken` from this chain to `intent.dstChainId`. In v1 the only provider is Across (its `SpokePool` contract), but the provider will change or be added to over time. The rules are therefore **provider-agnostic**: they are written against one normalized struct, and everything provider-specific lives in (a) a decoder library and (b) the bridge's row in the allowed-bridges table (§4.1).

Each allowlisted bridge is stored with a `BridgeType`, which selects its decoder, the same way `RouterType` selects a swap decoder:

```solidity
enum BridgeType { NONE, ACROSS }
```

The decoder turns the provider's deposit call into a `BridgeDeposit` and reverts on any selector not listed for that bridge. The shared rules only ever look at this struct:

```solidity
struct BridgeDeposit {
    address inputToken;    // token pulled from the user on this chain
    uint256 inputAmount;
    bytes32 outputToken;   // token delivered on the destination chain
    uint256 outputAmount;  // minimum the recipient receives on the destination
    uint256 dstChainId;
    bytes32 recipient;     // receiver on the destination chain
    address refundTo;      // who gets the input back on this chain if the deposit is never filled
    uint256 refundAfter;   // timestamp after which an unfilled deposit becomes refundable
    bool    hasPayload;    // any destination-side message / hook / call
}
```

Rules (every provider):
1. `inputToken.approve(spender, X)`, where `spender` is the `spender` column of the bridge's row (for Across, the SpokePool itself) and `X == intent.amount` (shared rules).
2. Exactly one deposit call to an allowlisted `BRIDGE`, using a selector listed for that bridge. The decoded `BridgeDeposit` must satisfy:
   - `inputToken == intent.payToken` (an allowlisted `ASSET`) and `inputAmount == intent.amount`.
   - `dstChainId == intent.dstChainId` and `dstChainId != block.chainid`.
   - **Route:** `(bridge, inputToken, dstChainId)` is an allowlisted route, and `outputToken == route.outputToken`. This stops a deposit that pays out a worthless token on the destination.
   - `recipient == intent.recipient`, and `intent.recipient == bytes32(uint256(uint160(user)))`: the user's EOA / 7702 account has the same address on every EVM chain. The backend never sends elsewhere.
   - `outputAmount ≥ intent.minOut`, with `intent.minOut > 0`. Backstop against a careless partner: `outputAmount ≥ inputAmount` rescaled from `route.inputDecimals` to `route.outputDecimals`, `× (10_000 − maxBridgeFeeBps) / 10_000`. The rescale matters: USDC has 6 decimals on Base and 18 on BSC, so raw amounts can't be compared across the route.
   - `refundTo == user`, so an unfilled deposit comes back to the user.
   - `refundAfter ≤ block.timestamp + bridge.maxFillWindow`. This caps how long funds can be locked if nobody fills the deposit (e.g. an unreachable `outputAmount` or a fake exclusive relayer).
   - `hasPayload == false`. A destination message makes the bridge call into the recipient on the destination chain. The user's 7702 account has code there, so that call would run on a chain this verifier cannot see. Bridge-then-stake is not planned.
   - No native value: the call's `value == 0`, and native-token legs are rejected in v1.
3. Optional fee (gas coverage only for the bridge).
4. No other calls.

What the verifier cannot check on this chain is the fill itself. The bridge's guarantee is: either `recipient` receives `≥ outputAmount` of `outputToken` on `dstChainId`, or `refundTo` gets `inputAmount` back after `refundAfter`. That guarantee is the trust assumption we accept for each allowlisted provider (see §7).

**Across decoder (`AcrossRules`, `BridgeType.ACROSS`)**

Accepted SpokePool entry points (which ones are enabled is set per bridge in the `selectors` column):

```solidity
// current ABI: addresses as bytes32 (for non-EVM chains)
function deposit(bytes32 depositor, bytes32 recipient, bytes32 inputToken, bytes32 outputToken,
    uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, bytes32 exclusiveRelayer,
    uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityParameter, bytes message);

// legacy ABI: addresses as address
function depositV3(address depositor, address recipient, address inputToken, address outputToken,
    uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer,
    uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityDeadline, bytes message);
```

| `BridgeDeposit` field | Across source |
|-----------------------|---------------|
| `inputToken` | `inputToken` |
| `inputAmount` | `inputAmount` |
| `outputToken` | `outputToken` |
| `outputAmount` | `outputAmount` (Across pays exactly this; the relayer fee is `inputAmount − outputAmount`) |
| `dstChainId` | `destinationChainId` |
| `recipient` | `recipient` |
| `refundTo` | `depositor` (Across refunds an expired deposit to the depositor on the origin chain) |
| `refundAfter` | `fillDeadline` |
| `hasPayload` | `message.length != 0` |

Across-specific checks:
- **Integrator suffix:** the backend appends `0x1dc0de ‖ integratorId` (2 bytes; today `0x035f`, from `CONFIG_ACROSS_INTEGRATOR_ID`) after the ABI-encoded arguments. The decoder accepts trailing bytes only when they equal the bridge row's `integratorSuffix` exactly; any other trailing data is rejected, as everywhere else (§7). Without this, every deposit would fail the exact-length check.
- In the bytes32 ABI, fields that name addresses on **this** chain (`depositor`, `inputToken`) must be clean left-padded addresses (upper 12 bytes zero). `recipient` and `outputToken` are compared as full `bytes32`.
- `quoteTimestamp ≤ block.timestamp` and `≥ block.timestamp − bridge.maxQuoteAge`. The SpokePool also enforces its own `depositQuoteTimeBuffer` (1 h) at execution.
- `exclusiveRelayer` and `exclusivityParameter` stay opaque. They can only delay a fill, never redirect funds, and the `fillDeadline` cap already bounds the worst case.
- Reject every other SpokePool entry point, in particular `depositNow` / `depositV3Now` (deadlines computed at execution), `unsafeDeposit`, and swap-and-bridge through `SpokePoolPeriphery`.
- Reject any non-zero `value` (the SpokePool accepts ETH when `inputToken` is WETH).

Adding a new provider later (e.g. Stargate, CCTP, Relay) means: a new `BridgeType` value, a decoder that outputs `BridgeDeposit`, and its rows in the bridge and route tables. The shared rules and the `Intent` stay unchanged. If a provider has no refund-to-depositor model or no enforceable deadline, it cannot fill `refundTo` / `refundAfter` and must not be allowlisted without extending the rules.

## 4. Allowlist registry

### 4.1 Data model

Every address we allowlist differs per chain (USDC, SpokePool, pools, fee token), so **each chain has its own registry** (§5). An OpenZeppelin `EnumerableSet` per category, so every table can be listed on-chain:

```solidity
enum Category {
    PAYMASTER,
    VAULT_4626,
    AAVE_POOL,
    ASSET,             // tokens allowed as approve/transfer targets (USDC, …)
    ONDO_TOKEN,
    SWAP_ROUTER,       // 1inch router v6
    SWAP_POOL,         // DEX pools a 1inch unoswap route may go through
    BRIDGE,            // bridge deposit contracts (Across SpokePool, …)
    FEE_RECIPIENT
}

enum PoolType { NONE, UNISWAP_V2, UNISWAP_V3 }

mapping(Category => EnumerableSet.AddressSet) allowed;
mapping(address router => RouterType) routerType;   // set in the same timelocked add as SWAP_ROUTER
mapping(address pool => PoolType) poolType;         // set in the same timelocked add as SWAP_POOL
```

**Allowed bridges table.** Every provider-specific detail of a bridge lives in its row, so the verifier logic does not need to know which provider it is talking to:

```solidity
struct BridgeConfig {
    BridgeType bridgeType;       // selects the decoder
    address    spender;          // approve target (Across: the SpokePool itself)
    uint32     maxFillWindow;    // max seconds from now until refundAfter
    uint32     maxQuoteAge;      // max age of the provider quote timestamp; 0 if the provider has none
    bytes4[]   selectors;        // accepted deposit entry points
    bytes      integratorSuffix; // exact trailing bytes allowed after the ABI args (Across: 0x1dc0de ‖ id); empty = none
}

struct BridgeRoute {
    bytes32 outputToken;     // token on the destination chain
    uint8   inputDecimals;   // for the maxBridgeFeeBps backstop
    uint8   outputDecimals;
}

mapping(address bridge => BridgeConfig) bridgeConfig;  // set in the same timelocked add as BRIDGE
mapping(bytes32 key => BridgeRoute) bridgeRoute;       // key = keccak256(abi.encode(bridge, inputToken, dstChainId))
EnumerableSet.Bytes32Set routeKeys;                    // so routes can be listed on-chain
```

Initial bridge content (addresses to be confirmed in Discovery, §9):

| Chain | Bridge (call target) | Type | Spender | Selectors | `maxFillWindow` | `maxQuoteAge` | `integratorSuffix` |
|---|---|---|---|---|---|---|---|
| Base | Across SpokePool `0x09ae…Ec64` | `ACROSS` | same as bridge | `deposit` (bytes32 ABI); `depositV3` only if the deployed pool still needs it | from live quotes (§11) | 300 s | `0x1dc0de035f` |
| BSC | Across SpokePool (TBD) | `ACROSS` | same as bridge | as above | from live quotes | 300 s | `0x1dc0de035f` |

| Origin | `inputToken` | `dstChainId` | `outputToken` | `inputDecimals` | `outputDecimals` |
|---|---|---|---|---|---|
| Base | USDC `0x8335…2913` | 56 (BSC) | Binance-Peg USDC `0x8ac7…580d` | 6 | 18 |
| BSC | Binance-Peg USDC `0x8ac7…580d` | 8453 (Base) | USDC `0x8335…2913` | 18 | 6 |

Routes are keyed by bridge, so the same token pair can be enabled for one provider and not another, and switching providers is: add the new bridge and its routes (48 h), then remove the old bridge (instant).

View API for partners and dashboards: `isAllowed(cat, addr)`, `list(cat)`, `poolType(pool)`, `bridgeConfig(bridge)`, `listRoutes()`, `pending()`.

Config values go through the same timelock as additions:

| Value | Start |
|-------|-------|
| `feeToken` | chain USDC |
| `maxFeeBps` / `flatFee` | 50 / $0.10 + rounding margin, in fee-token units |
| `maxBatchTtl` | 600 s |
| `maxBridgeFeeBps` | 50 (matches the route's `maxProviderFeeBps`) |
| gas caps (no-paymaster ops) | TBD in Discovery |

Bridge configs, routes and pool types are scheduled like address additions, as a `PendingOp` that carries the encoded row.

### 4.2 Change rules

| Operation | Delay | Role |
|-----------|-------|------|
| Add an address | **48 h**: `scheduleAdd` → `executeAdd` after `eta` | `MANAGER` schedules, anyone executes after `eta` |
| Add or change a bridge config / bridge route | **48 h** | `MANAGER` schedules, anyone executes after `eta` |
| Remove a bridge route | **none** | `GUARDIAN` or `MANAGER` |
| Change a config value (fees, caps) | **48 h** | `MANAGER` |
| Remove an address | **none**: takes effect immediately | `GUARDIAN` or `MANAGER` |
| Cancel a pending add | **none** | `GUARDIAN` or `MANAGER` |
| Upgrade an implementation | **48 h** (see §5) | `TimelockController` |
| `pause()` (all verifications fail) | **none** | `GUARDIAN` |

Pending additions are kept on-chain (`PendingOp { category, addr, eta }`) and emitted as `AdditionScheduled(id, cat, addr, eta)`. This lets partners watch for them and object during the 48 h window. Removals and pausing only make the verifier *stricter*, so they can safely be instant.

## 5. Architecture (storage vs logic)

```
             partners: eth_call
                    │
      ┌─────────────▼──────────────┐       reads      ┌──────────────────────────┐
      │ BatchVerifier (ERC1967 proxy)│ ───────────────▶ │ AllowlistRegistry (proxy) │
      │  logic only, stateless view │                  │  storage: sets, pending,  │
      │  UUPS impl                  │                  │  config (ERC-7201 layout) │
      └─────────────┬──────────────┘                  └────────────┬─────────────┘
                    │ upgradeTo (48 h)                              │ upgradeTo (48 h)
                    └──────────── TimelockController (48 h, multisig proposer) ◀──┘

      DeadlineGuard: immutable, no admin; called from inside the user's batch (§3.1)
```

- **AllowlistRegistry** holds the data and is proxied, so the data survives upgrades. It uses ERC-7201 namespaced storage and OZ `AccessControlUpgradeable` + `UUPSUpgradeable`.
- **BatchVerifier** holds only the logic and has no mutable state apart from the registry pointer. Its stable proxy address lets partners hard-code it. Decoders for each account format and action are internal libraries (`AccountCallDecoder`, `AllowanceRules`, `Erc4626Rules`, `AaveRules`, `SwapRules` → `OneInchRules`, `BridgeRules` → `AcrossRules`, `FeeRules`). Adding a new swap provider means adding a decoder library and a `RouterType` value; adding a new bridge provider means a decoder that outputs `BridgeDeposit` and a `BridgeType` value. Nothing else changes.
- **DeadlineGuard** is separate from the verifier on purpose: it is a call target inside every signed batch, so it must not be upgradeable.
- **TimelockController** (OZ, `minDelay = 48h`) is the only holder of `UPGRADER` on both proxies. Its proposer is a Restake multisig (Safe). `GUARDIAN` is a separate Safe that can only remove, cancel, or pause. Both Safes are 2-of-3 with the same signers for now (§11 Q2).
- **One deployment per chain**, each with its own registry, at deterministic CREATE2 addresses where possible. First chains: **Base and BSC** (stocks trade only on BSC; the bridge runs Base ↔ BSC). The other staking chains (Ethereum, Arbitrum, Optimism, Polygon, Avalanche, Plasma) follow with staking rows only.

## 6. Public interface (draft)

```solidity
function verify(
    PackedUserOperation calldata op,
    bytes32 userOpHash,
    Authorization calldata auth,  // 7702 tuple (chainId, delegate, nonce); delegate == 0 if none
    Intent calldata intent
) external view returns (bytes32 verifiedHash, uint256 deadline);   // reverts with a precise custom error

function check(...same args...)
    external view returns (bool ok, uint8 errorCode, uint256 callIndex); // non-reverting variant for UIs
```

Partner flow:
1. Receive `{ op, userOpHash, authorization, intentId }` from the Restake API.
2. `eth_call verify(op, userOpHash, auth, intentFromUI)` on the partner's own node.
3. Sign **the returned `verifiedHash`** and the authorization. Never sign a hash taken directly from the API response. `verifiedHash` is the raw v0.7 `userOpHash`; sign it with `personal_sign` over the 32 raw bytes (EIP-191 applied exactly once, never the hex string) and send `0xff00 ‖ sig` (67 bytes), per §2.1. `deadline` can be shown to the user as "valid until".
4. Check `auth.nonce` against `eth_getTransactionCount` off-chain.
5. Send the signatures to the Restake backend.

Partners should also subscribe to `AdditionScheduled`, `Upgraded`, and `CallScheduled` (timelock) events for the verifier and registry.

## 7. Security notes / threat model

- **Trust model:** partners trust the verifier code, not the API. Because a compromised Restake admin would still need 48 h to add a malicious target or upgrade the logic, partners get a public window to react.
- **Verifier bugs are the main risk.** Keep decoders strict: exact calldata length (`abi.decode` plus a length check, to reject trailing bytes; the only exception is a bridge's configured `integratorSuffix`), exact selectors, and no dynamic dispatch.
- Live reads (`vault.asset()`, `allowance`, pool `token0()` / `token1()`, `previewRedeem`) go only to allowlisted contracts, with no calls into user-supplied addresses.
- **Deadline:** without the guard call, a signed op stays executable until its nonce is used, so whoever holds it (the backend or bundler) could execute it much later. Swaps are still bounded by `minReturn` and bridges by the SpokePool's quote buffer, but stake/unstake and fees have no other time bound.
- **Residual allowance** is computed from the allowance at verify time. Only the user can raise it between verify and execution, so the check holds for the batch being signed.
- Tokens: USDC is upgradeable and has a blocklist. Document that the allowlist covers standard ERC-20s only; fee-on-transfer or rebasing assets need their own review (use the `token-integration-analyzer` skill).
- 1inch: the executor route is opaque by design. The safety of a swap rests on (a) an exact approve to an allowlisted router, (b) `dstReceiver == user`, (c) `minReturn ≥ intent.minOut`, and, for `unoswap`, (d) every hop going through an allowlisted pool so the output token is really `dstToken`. That makes the partner's `minOut` the real guarantee, so the partner UI must derive it from its own quote, never from the API.
- Ondo tokens may restrict transfers (KYC / sanctions). A swap can pass verification and still revert on-chain; that is safe but worth documenting.
- Bridges: the verifier only sees the origin chain. The safety of a bridge deposit rests on (a) an exact approve to the allowlisted spender, (b) the route table pinning the destination token, (c) `recipient == user` and `refundTo == user`, (d) `outputAmount ≥ intent.minOut`, and (e) the provider's fill-or-refund guarantee (for Across: relayers plus UMA optimistic-oracle settlement). The worst case after verification is funds locked until `refundAfter`, then refunded. The partner must take `minOut` from its own bridge quote (for Across, the public `suggested-fees` API), never from the Restake API.
- Bridge routes point at addresses on other chains, which this chain cannot check. Route additions deserve the closest review during the 48 h window, and partners can check the `outputToken` on the destination chain.
- Result binding: the verification result is only as good as the hash that gets signed. Partner SDK docs must enforce step 3 of §6.

## 8. Tooling

- Foundry, Solidity `0.8.28`, OpenZeppelin Contracts Upgradeable v5, and `openzeppelin-foundry-upgrades` for storage-layout validation.
- Fork tests on **Base** (real vaults such as `gauntlet-usdc-prime-base` `0x050c…56f0`, Aave v3 USDC, Across SpokePool) and **BSC** (1inch v6 router with real API swap payloads for Ondo tokens, both `swap` and `unoswap*`; Across SpokePool), against the real EntryPoint v0.7 and Alchemy Modular Account v2 (7702) implementation, with deposits built from real Across API quotes.
- Slither in CI, plus fuzz and invariant tests.

## 9. Milestones

1. **Discovery:** capture real stake, unstake, buy/sell, and bridge payloads; pin the paymaster, which 1inch methods and which pools / protocols BSC Ondo routes use (the initial `SWAP_POOL` set), the v6 `unoswap` flag layout, whether Binance-Peg USDC decrements an infinite allowance, the Across SpokePool address and ABI version (`deposit` bytes32 vs `depositV3`) on Base and BSC, and the `fillDeadline` offsets live Across quotes return. → `test/fixtures/*.json`
2. **Scaffold:** Foundry project, OZ deps, CI (build, test, slither, fmt).
3. **AllowlistRegistry:** enumerable sets, pool types, bridge configs and routes, timelocked add/config, instant remove/cancel, pause, events, UUPS + ERC-7201.
4. **BatchVerifier core:** envelope checks (§3.1), `DeadlineGuard`, userOpHash recomputation, account call decoder.
5. **Rules:** shared approval and fee rules (`AllowanceRules`, `FeeRules`) → ERC-4626 stake/unstake → Aave → buy/sell through 1inch (`OneInchRules`: `swap`, then `unoswap*` with the pool walk) → bridge (`BridgeRules` shared checks, `AcrossRules` decoder with the integrator suffix).
6. **Governance wiring:** TimelockController (48 h), Safe proposer, guardian, and deploy scripts for Base and BSC.
7. **Tests:** unit tests, fork tests on real API payloads, fuzz of malicious mutations, and invariants. Mutations to cover:
   - envelope: wrong delegate, chainId 0, self-call to the account (`installValidation`, `upgradeToAndCall`), `performCreate`, plain `execute`, `executeUserOp`-prefixed `executeBatch`, non-empty `initCode`, extra call, delegatecall mode, trailing calldata;
   - deadline: missing guard call, guard not first, expired deadline, deadline beyond `maxBatchTtl`;
   - approvals: infinite approve, approve amount ≠ intent, no approve and no revoke over a standing allowance, unstake without revoke over a non-zero allowance, non-zero "revoke", revoke before the main call or after the fee;
   - fee: fee not last, wrong fee token, unlisted recipient, fee above `intent.maxFee`, fee above the backstop cap;
   - stake/unstake: wrong receiver or owner, non-USDC vault or Aave asset (`UnsupportedAsset`);
   - 1inch: `dstReceiver` ≠ user, wrong dst token, `minReturn` below intent, partial-fill flag, `unoswapTo` with `to` ≠ user, unoswap through an unlisted pool, protocol id ≠ registered pool type, flipped direction bit, broken hop chain, unwrap / Permit2 flag, Curve hop, `ethUnoswap`, `clipperSwap`;
   - bridge: wrong `recipient` / `depositor`, unlisted route or `outputToken`, `outputAmount` below intent or fee cap (including a decimals mix-up), `fillDeadline` past `maxFillWindow`, stale `quoteTimestamp`, non-empty `message`, wrong or extra integrator suffix, dirty bytes32 address, `dstChainId == block.chainid`, `depositNow` / `unsafeDeposit` variant, native value.
8. **Partner kit:** TypeScript snippet (viem) for the §6 flow, the fee formula for `intent.maxFee`, ABI, and deployed addresses.
9. **Audit prep and external audit** (`audit-prep-assistant` skill), then Base and BSC mainnet deploys.

## 10. Decisions from the backend review (2026-09-27)

| Question | Decision | Where |
|----------|----------|-------|
| Can the backend force 1inch `swap`? | No. The verifier also decodes `unoswap*`, walking hops through allowlisted pools. | §3.3 |
| Router version | v6 on every chain, `0x1111…2A65`, pinned in the allowlist. | §3.3 |
| Direct Ondo | Not in v1: no backend integration exists, and the `GMTokenManager` details are unconfirmed. Design kept for v2. `maxOverpayBps` / `maxQuoteTtl` are Ondo-only and move with it; the backend's 1% default slippage is not a verifier parameter (`intent.minOut` is). | Appendix A |
| Staking pools | USDC pools only in v1; the verifier requires the pool asset to be `feeToken`. | §2, §3.3 |
| Fee token and cap | Always chain USDC, last call. `fee ≤ intent.maxFee`, plus a backstop of 50 bps + $0.10 on every action (every v1 notional is in USDC). | §3.3 |
| Chains | One deployment and registry per chain; Base and BSC first. | §4.1, §5 |
| Revoke position | Between the main call and the fee, and required only when an allowance would otherwise remain (zero-residual rule). Applies to every action, including BUY / SELL. | §3.3 |
| Bridge routes | USDC Base ↔ BSC, Across only. `recipient == user`, empty `message`, integrator suffix accepted. `maxBridgeFeeBps = 50`, `maxQuoteAge = 300 s`. Bridge-then-stake is not planned. | §3.3, §4.1 |
| EntryPoint and delegate | Same on every chain, so hardcoded as `constant`s in `BatchVerifier`: EntryPoint v0.7 `0x0000…a032`, MAv2 7702 `0x6900…E139`. No registry categories for them. | §2.1, §3.1 |
| `callData` form | Always `executeBatch` (`0x34fcd5be`), never `executeUserOp` or `execute`. The verifier accepts only that form. | §2.1, §3.1 |
| Signature format | EIP-191 over the raw 32-byte `userOpHash`, prefixed `0xff00` (67 bytes). `verifiedHash` is the raw hash. | §2.1, §6 |
| Batch deadline | Yes, as a `DeadlineGuard` call inside the batch (a `verify` argument could not bind execution). `maxBatchTtl = 600 s`. | §3.1 |

**Backend changes needed for v1:**
1. Refuse 1inch routes the verifier cannot decode: a method other than `swap` / `unoswap*`, a disallowed flag, or a pool not in the registry (`isAllowed(SWAP_POOL, pool)`).
2. Add `DeadlineGuard.requireBefore(intentExpiry)` as the first call of every batch.
3. Trades: either always include the exact approve (drop the "allowance already covers it" shortcut), or keep the shortcut and add a revoke after the swap. Both pass the zero-residual rule; always approving is simpler and one call shorter.

Lowering the DTO's 50% slippage ceiling is a product choice; the verifier does not depend on it.

## 11. Open questions

1. ~~Do the pools that BSC Ondo-stock routes use change often?~~ **Resolved:** keep the per-pool `SWAP_POOL` allowlist; no factory / CREATE2 derivation. The 1inch path is expected to give way to direct Ondo (Appendix A), which needs no pools at all, so the extra verifier code is not worth it. Trade-off: a route through a pool not yet added is refused by the backend until the 48 h add clears.
2. ~~Who holds `MANAGER` and `GUARDIAN`, and what are the Safe thresholds?~~ **Resolved:** both are 2-of-3 Safes, and for now the same Restake signers sit on both. Keeping them as two Safes lets the signer sets diverge later without touching roles on-chain. Trade-off: two compromised keys control both roles, so the guardian gives no check against a compromised manager. The remaining defense is the 48 h delay plus partners watching `AdditionScheduled`.
3. ~~How is `maxFillWindow` set?~~ **Resolved:** it is a fixed value in each bridge's `BridgeConfig` row. It bounds `fillDeadline − block.timestamp`. In Discovery, collect live Across quotes in both directions (Base → BSC, BSC → Base) and record `fillDeadline − timestamp` for each. Set the value to the largest offset seen plus 50% headroom, rounded up to the minute. It must stay below the SpokePool's own `fillDeadlineBuffer`, or the check adds nothing. Trade-off: if Across lengthens its deadlines, bridge batches fail until the bridge is removed and re-added with a new value (48 h).

## Appendix A. Direct Ondo (v2, deferred)

Not in v1: the backend has no direct-Ondo integration today. Kept here so the design is ready when it lands.

Ondo Global Markets tokens (e.g. `AAPLon`) are minted and redeemed through Ondo's `GMTokenManager` (Ethereum and BNB Chain). The router is added as `RouterType.ONDO_GM` with decoder `OndoRules`. Each trade needs an **attestation**: a quote signed by Ondo, requested by the Restake backend from the Ondo API. The quote is an EIP-712 struct:

```solidity
struct Quote {                 // "Quote(uint256 attestationId,uint256 chainId,bytes32 userId,uint8 side,
    uint256 attestationId;     //  address asset,uint256 price,uint256 quantity,uint256 expiration,bytes32 additionalData)"
    uint256 chainId;
    bytes32 userId;            // Ondo's on-chain id for a group of KYC'd wallets
    uint8   side;              // 0 = buy, 1 = sell
    address asset;             // GM token
    uint256 price;             // per token, in USDon, 18 decimals
    uint256 quantity;          // GM token amount, 18 decimals
    uint256 expiration;        // unix timestamp
    bytes32 additionalData;
}

function mintWithAttestation(Quote quote, bytes signature, address depositToken, uint256 depositTokenAmount);
function redeemWithAttestation(Quote quote, bytes signature, address receiveToken, uint256 minimumReceiveAmount);
```

BUY, which calls `mintWithAttestation`:
1. `payToken.approve(manager, depositTokenAmount)`, where `manager` is an allowlisted `SWAP_ROUTER` of type `ONDO_GM`, `depositToken == intent.payToken`, and `depositTokenAmount == intent.amount`.
2. `quote.side == 0`, `quote.asset == intent.target` (an allowlisted `ONDO_TOKEN`), and `quote.quantity ≥ intent.minOut`.
3. **Overpay bound:** the manager charges the full `depositTokenAmount`, not the quote's actual cost (a finding in Ondo's own audit), so any excess is lost. Require `depositTokenAmount ≤ price × quantity × (10_000 + maxOverpayBps) / 10_000`, converted from 18-decimal USDon to `payToken` decimals. `maxOverpayBps` is a timelocked config value; start around 100.

SELL, which calls `redeemWithAttestation`:
1. `quote.side == 1`, `quote.asset == intent.target`, and `quote.quantity == intent.amount`.
2. `receiveToken == intent.payToken` (an allowlisted `ASSET`) and `minimumReceiveAmount ≥ intent.minOut`. `minimumReceiveAmount` must not be `0`.
3. `asset.approve(manager, quote.quantity)` exactly, or no approve at all if the manager burns from `msg.sender` without an allowance.

Attestation checks, for both sides:
- `quote.chainId == block.chainid`.
- `quote.expiration > block.timestamp`, and at most `maxQuoteTtl` (start at 300 s) in the future. This rejects a quote that expires before the bundler can include the op.
- **Signature:** recover the EIP-712 signer using the manager's `getDomainSeparator()` and `QUOTE_TYPEHASH`, then require `manager.hasRole(ATTESTATION_SIGNER_ROLE, signer)`. This proves the quote really comes from Ondo and was not made up by the Restake API. Every read goes to the allowlisted manager, so no user-supplied address is called.
- Not checked on-chain by the verifier: attestation replay (the manager tracks used `attestationId`s) and whether `user` belongs to `quote.userId` (Ondo checks this at execution). If the op would fail these checks, it reverts on-chain, and no funds are lost.
- Recipient: the GM token or `receiveToken` goes to `msg.sender`, which is the user's 7702 account. There is no receiver parameter an attacker could redirect.

Trust: we trust that Ondo's attestation signer and the `GMTokenManager`, which Ondo can upgrade, behave as documented. If a manager upgrade changes the ABI or the role layout, verification fails closed, because decoding or `hasRole` no longer matches.

To confirm against the deployed `GMTokenManager` before v2:
- output goes to `msg.sender`;
- redeem needs a GM-token approve (or burns without one);
- the view names are exactly `getDomainSeparator()`, `QUOTE_TYPEHASH` and `ATTESTATION_SIGNER_ROLE`;
- the signature is plain ECDSA, not ERC-1271.

Tests to add in v2: forged or non-signer signature, wrong side / asset / chain, expired quote, overpaying `depositTokenAmount`, `minimumReceiveAmount = 0`.
