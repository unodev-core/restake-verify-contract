# Restake Batch Verifier — Implementation Plan

Status: draft · 2026-09-23

## 1. Problem

The Restake API builds unsigned EIP-7702 batch user operations (ERC-4337 `UserOperation` executed through the Alchemy bundler) for:

- stake / unstake into ERC-4626 vaults (and Aave v3 `A_TOKEN` pools),
- buy / sell Ondo tokenized stocks.

Partners (iOS app, web, etc.) have the user sign the batch and return it to the Restake backend, which submits it. Today a partner has to trust whatever Restake returns. If the API were compromised, it could return a batch that drains the user, for example with an infinite approval, a deposit whose `receiver` is an attacker, or a 7702 delegation to a malicious account implementation.

**Goal:** an on-chain, read-only verifier that partners call with `eth_call` against **their own RPC node** before signing. It must answer: *"Does this exact user operation do only what the user asked for, touching only allowlisted contracts, and is this the hash I am about to sign?"*

## 2. Real batch shape (from Restake MCP)

`build_stake_transaction` returns:

- `signing.userOpHash`: the hash the wallet signs.
- `signing.authorization`: the EIP-7702 tuple `(chainId, address delegate, nonce)`.
- `intentId`: a single-use intent, valid for 300 s.

The batch contains, in order:

| # | Target | Call |
|---|--------|------|
| 1 | base token (e.g. USDC `0x8335…2913` on Base) | `approve(vault, amount)` |
| 2 | pool (ERC-4626 vault / Aave pool) | `deposit(amount, receiver)` / `supply(asset, amount, onBehalfOf, 0)` |
| 3 | base token | `transfer(feeRecipient, fee)` (platform fee, may be 0 / absent) |

> TODO: capture a real payload (a funded test wallet is needed; the dev bundler reverted with `0xe65b7a77` on an empty wallet). Record in `test/fixtures/` the exact account implementation, EntryPoint version, `callData` encoding (`executeBatch` / ERC-7821 `execute(mode, data)` / ERC-7579), and `paymasterAndData`.

## 3. What the verifier checks

The rule is **default deny**. Every call in the batch must match a rule, and anything that matches none fails verification.

### 3.1 Envelope (user op + 7702)

| Check | Why |
|-------|-----|
| `userOpHash == EntryPoint.getUserOpHash(op)` for an allowlisted EntryPoint | The signed hash commits to exactly the verified op, not to a different one. |
| 7702 `authorization.address` is an allowlisted **delegate implementation** | A malicious delegate means total account takeover. This is the most important check. |
| `authorization.chainId == block.chainid` (reject `0`) | `chainId = 0` would make the signature replayable on every chain. |
| If the EOA is already delegated (`sender.code == 0xef0100‖delegate`), the delegate is allowlisted | Covers ops that are sent without a new authorization. |
| `op.sender == expected user` | Prevents a batch built for a different account. |
| `callData` selector is the allowlisted account's batch-execute entry point, and the exec mode is *call* only (no `delegatecall`, no `try` modes) | A `delegatecall` would bypass every other check. |
| `paymasterAndData` is empty or its paymaster is allowlisted; if empty, `maxFeePerGas` and gas limits are ≤ configured caps | Stops gas griefing on the user's ETH. |
| `value == 0` on every inner call (unless a rule explicitly allows native value) | |

Off-chain partner check (the EVM cannot read an account nonce): `authorization.nonce == eth_getTransactionCount(user)`.

### 3.2 Intent binding

The partner passes the **intent the user saw in the UI**, and the verifier checks that the batch implements exactly that:

```solidity
struct Intent {
    Action action;      // STAKE, UNSTAKE, BUY, SELL
    address user;
    address target;     // vault / pool / Ondo token
    address payToken;   // buy/sell: the payment asset (e.g. USDC); ignored for vaults
    uint256 amount;     // input amount: asset (stake), shares (unstake), payToken (buy), stock (sell)
    uint256 minOut;     // buy/sell slippage bound; 0 for vaults
}
```

### 3.3 Per-action call rules

**STAKE (ERC-4626)**
1. `asset.approve(vault, X)` where `asset == IERC4626(vault).asset()` (read live) and `X == intent.amount`, **exactly**. No `type(uint256).max`, no `increaseAllowance`, no `permit`.
   - Optionally allow a preceding `approve(vault, 0)` for USDT-style tokens.
2. `vault.deposit(X, receiver)` with `receiver == user`. `mint` is rejected, or allowed only with `previewMint` bounds.
3. Optional `asset.transfer(feeRecipient, fee)` with `feeRecipient` allowlisted and `fee ≤ amount × maxFeeBps / 10_000`.
4. No other calls.

**STAKE (Aave v3):** same pattern with `pool.supply(asset, X, onBehalfOf == user, 0)`, where `asset` is allowlisted for that pool.

**UNSTAKE (ERC-4626)**
1. `vault.redeem(shares, receiver == user, owner == user)` or `withdraw(assets, user, user)`.
2. **Required revoke approval:** `asset.approve(vault, 0)`, where `asset == IERC4626(vault).asset()`. The amount must be exactly `0` and the call must appear exactly once. If it is missing, verification fails with `MissingApprovalRevoke()`. This clears any allowance left over from staking, so the vault cannot pull the user's asset later.
3. Optional `asset.transfer(feeRecipient, fee)`, bounded as in STAKE.
4. No other calls. In particular, no approvals of vault shares to anyone.

**UNSTAKE (Aave):** `pool.withdraw(asset, amount, to == user)` plus the same **required** revoke approval, `asset.approve(pool, 0)`.

**BUY / SELL (Ondo stocks)**

Buy and sell go through a **swap router**. Two router types are in scope for v1: the 1inch Aggregation Router, used today, and Ondo's own `GMTokenManager` for direct mint/redeem. Each allowlisted router is stored with a `RouterType`, and the verifier sends its swap call to the matching decoder:

```solidity
enum RouterType { NONE, ONE_INCH_V6, ONDO_GM }
```

The rules shared by every router type:

| Action | srcToken | dstToken |
|--------|----------|----------|
| BUY | `intent.payToken` (allowlisted `ASSET`) | `intent.target` (allowlisted `ONDO_TOKEN`) |
| SELL | `intent.target` (allowlisted `ONDO_TOKEN`) | `intent.payToken` (allowlisted `ASSET`) |

1. `srcToken.approve(router, X)`, where `router` is an allowlisted `SWAP_ROUTER` and `X == intent.amount` exactly.
2. Exactly one swap call to that router. The decoded swap must satisfy: src and dst tokens match the table, input amount `== intent.amount`, output receiver `== user`, and `minReturn ≥ intent.minOut` (with `intent.minOut > 0`).
3. Optional fee transfer, bounded as in STAKE.
4. No other calls.

**1inch v6 decoder (`OneInchRules`)**
- Accept only `swap(IAggregationExecutor executor, SwapDescription desc, bytes data)`. Every field the verifier needs is explicit in `desc`: `srcToken`, `dstToken`, `dstReceiver`, `amount`, `minReturnAmount`, `flags`.
- Checks:
  - `desc.dstReceiver == user`. Reject `address(0)`: it means "send to msg.sender", which is the user in practice, but the explicit form is easier to verify.
  - The partial-fill flag must not be set, so the whole `amount` is swapped and `minReturn` applies to it.
  - `executor` and `data` stay opaque. The router itself enforces `returnAmount ≥ minReturnAmount` and pays out to `dstReceiver`, so the executor is trusted only up to the `amount` it receives.
- Reject the `unoswap*` / `ethUnoswap*` / `clipperSwap` / limit-order variants. Their output token is not in the calldata (it comes from packed pool addresses), so the verifier cannot check it. The Restake backend must request routes that encode as `swap`.
- Reject native-ETH legs (`0xEeee…EEeE`) unless a rule is added for them later.

**Direct Ondo decoder (`OndoRules`, `RouterType.ONDO_GM`)**

Ondo Global Markets tokens (e.g. `AAPLon`) are minted and redeemed through Ondo's `GMTokenManager`. Each trade needs an **attestation**: a quote signed by Ondo, requested by the Restake backend from the Ondo API. The quote is an EIP-712 struct:

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
3. **Overpay bound:** the manager charges the full `depositTokenAmount`, not the quote's actual cost (a finding in Ondo's own audit), so any excess is lost. Require `depositTokenAmount ≤ price × quantity × (10_000 + maxOverpayBps) / 10_000`, converted from 18-decimal USDon to `payToken` decimals. `maxOverpayBps` is a timelocked config value.

SELL, which calls `redeemWithAttestation`:
1. `quote.side == 1`, `quote.asset == intent.target`, and `quote.quantity == intent.amount`.
2. `receiveToken == intent.payToken` (an allowlisted `ASSET`) and `minimumReceiveAmount ≥ intent.minOut`. `minimumReceiveAmount` must not be `0`.
3. `asset.approve(manager, quote.quantity)` exactly, or no approve at all if the manager burns from `msg.sender` without an allowance (to be confirmed against the deployed contract).

Attestation checks, for both sides:
- `quote.chainId == block.chainid`.
- `quote.expiration > block.timestamp`, and at most `maxQuoteTtl` in the future. This rejects a quote that expires before the bundler can include the op.
- **Signature:** recover the EIP-712 signer using the manager's `getDomainSeparator()` and `QUOTE_TYPEHASH`, then require `manager.hasRole(ATTESTATION_SIGNER_ROLE, signer)`. This proves the quote really comes from Ondo and was not made up by the Restake API. Every read goes to the allowlisted manager, so no user-supplied address is called.
- Not checked on-chain by the verifier: attestation replay (the manager tracks used `attestationId`s) and whether `user` belongs to `quote.userId` (Ondo checks this at execution). If the op would fail these checks, it reverts on-chain, and no funds are lost.
- Recipient: the GM token or `receiveToken` goes to `msg.sender`, which is the user's 7702 account. There is no receiver parameter an attacker could redirect (to be confirmed against the deployed contract).

Chains: Ondo GM runs on Ethereum and BNB Chain, while the vaults are on Base. The verifier is deployed per chain (§5), and each chain's registry holds only the routers and tokens available on it.

Extra partner-side check, recommended for swaps: simulate the signed batch with `eth_simulateV1` / `debug_traceCall` and confirm the user's balance changes (src decreases by `amount`, dst increases by `≥ minOut`). The on-chain verifier cannot see the executor's internal route, so this simulation covers what it misses.

## 4. Allowlist registry

### 4.1 Data model

An OpenZeppelin `EnumerableSet` per category, so every table can be listed on-chain:

```solidity
enum Category {
    ENTRY_POINT,       // ERC-4337 EntryPoint
    DELEGATE_IMPL,     // 7702 account implementations
    PAYMASTER,
    VAULT_4626,
    AAVE_POOL,
    ASSET,             // tokens allowed as approve/transfer targets (USDC, …)
    ONDO_TOKEN,
    SWAP_ROUTER,       // 1inch router, Ondo GMTokenManager
    FEE_RECIPIENT
}

mapping(Category => EnumerableSet.AddressSet) allowed;
mapping(address router => RouterType) routerType;   // set in the same timelocked add as SWAP_ROUTER
```

View API for partners and dashboards: `isAllowed(cat, addr)`, `list(cat)`, `pending()`.

Config values (`maxFeeBps`, gas caps, `maxOverpayBps`, `maxQuoteTtl`) go through the same timelock as additions.

### 4.2 Change rules

| Operation | Delay | Role |
|-----------|-------|------|
| Add an address | **48 h**: `scheduleAdd` → `executeAdd` after `eta` | `MANAGER` schedules, anyone executes after `eta` |
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
```

- **AllowlistRegistry** holds the data and is proxied, so the data survives upgrades. It uses ERC-7201 namespaced storage and OZ `AccessControlUpgradeable` + `UUPSUpgradeable`.
- **BatchVerifier** holds only the logic and has no mutable state apart from the registry pointer. Its stable proxy address lets partners hard-code it. Decoders for each account format and action are internal libraries (`AccountCallDecoder`, `Erc4626Rules`, `AaveRules`, `SwapRules` → `OneInchRules` / `OndoRules`, `FeeRules`). Adding a new swap provider means adding a decoder library and a `RouterType` value; nothing else changes.
- **TimelockController** (OZ, `minDelay = 48h`) is the only holder of `UPGRADER` on both proxies. Its proposer is a Restake multisig (Safe). `GUARDIAN` is a separate, faster multisig that can only remove, cancel, or pause.
- Both contracts are deployed per chain (Base first), with deterministic CREATE2 addresses where possible.

## 6. Public interface (draft)

```solidity
function verify(
    PackedUserOperation calldata op,
    bytes32 userOpHash,
    Authorization calldata auth,  // 7702 tuple (chainId, delegate, nonce); delegate == 0 if none
    Intent calldata intent
) external view returns (bytes32 verifiedHash);   // reverts with a precise custom error

function check(...same args...)
    external view returns (bool ok, uint8 errorCode, uint256 callIndex); // non-reverting variant for UIs
```

Partner flow:
1. Receive `{ op, userOpHash, authorization, intentId }` from the Restake API.
2. `eth_call verify(op, userOpHash, auth, intentFromUI)` on the partner's own node.
3. Sign **the returned `verifiedHash`** and the authorization. Never sign a hash taken directly from the API response.
4. Check `auth.nonce` against `eth_getTransactionCount` off-chain.
5. Send the signatures to the Restake backend.

Partners should also subscribe to `AdditionScheduled`, `Upgraded`, and `CallScheduled` (timelock) events for the verifier and registry.

## 7. Security notes / threat model

- **Trust model:** partners trust the verifier code, not the API. Because a compromised Restake admin would still need 48 h to add a malicious target or upgrade the logic, partners get a public window to react.
- **Verifier bugs are the main risk.** Keep decoders strict: exact calldata length (`abi.decode` plus a length check, to reject trailing bytes), exact selectors, and no dynamic dispatch.
- Live reads (`vault.asset()`) go only to allowlisted contracts, with no calls into user-supplied addresses.
- Tokens: USDC is upgradeable and has a blocklist. Document that the allowlist covers standard ERC-20s only; fee-on-transfer or rebasing assets need their own review (use the `token-integration-analyzer` skill).
- 1inch: the executor route is opaque by design. The safety of a swap rests on (a) an exact approve to an allowlisted router, (b) `dstReceiver == user`, and (c) `minReturn ≥ intent.minOut`. That makes the partner's `minOut` the real guarantee, so the partner UI must derive it from its own quote, never from the API.
- Direct Ondo: we trust that Ondo's attestation signer and the `GMTokenManager`, which Ondo can upgrade, behave as documented. If a manager upgrade changes the ABI or the role layout, verification fails closed, because decoding or `hasRole` no longer matches. The signature check stops the Restake API from inventing a price or quantity. The overpay bound caps what a stale or padded `depositTokenAmount` can cost the user.
- Ondo tokens may restrict transfers (KYC / sanctions). A swap can pass verification and still revert on-chain; that is safe but worth documenting.
- Result binding: the verification result is only as good as the hash that gets signed. Partner SDK docs must enforce step 3 of §6.

## 8. Tooling

- Foundry, Solidity `0.8.28`, OpenZeppelin Contracts Upgradeable v5, and `openzeppelin-foundry-upgrades` for storage-layout validation.
- Base mainnet fork tests against real vaults (`gauntlet-usdc-prime-base` `0x050c…56f0`, Aave v3 USDC, etc.), the real EntryPoint and Alchemy account implementation, and the 1inch v6 router with real API swap payloads for Ondo tokens.
- Slither in CI, plus fuzz and invariant tests.

## 9. Milestones

1. **Discovery:** capture real stake, unstake, and buy/sell payloads; pin the EntryPoint version, 7702 delegate implementation, batch `callData` format, paymaster, the 1inch router address and version, and which 1inch methods the backend receives. → `test/fixtures/*.json`
2. **Scaffold:** Foundry project, OZ deps, CI (build, test, slither, fmt).
3. **AllowlistRegistry:** enumerable sets, timelocked add/config, instant remove/cancel, pause, events, UUPS + ERC-7201.
4. **BatchVerifier core:** envelope checks (§3.1), userOpHash recomputation, account call decoder.
5. **Rules:** ERC-4626 stake/unstake → Aave → fee → buy/sell through 1inch (`OneInchRules`) → direct Ondo mint/redeem (`OndoRules`: EIP-712 attestation recovery, signer role, overpay bound).
6. **Governance wiring:** TimelockController (48 h), Safe proposer, guardian, and deploy scripts.
7. **Tests:** unit tests, fork tests on real API payloads, fuzz of malicious mutations (infinite approve, unstake without revoke or with a non-zero "revoke", wrong receiver, 1inch `dstReceiver` ≠ user, wrong dst token, `minReturn` below intent, partial-fill flag, `unoswap` variant, Ondo quote with a forged or non-signer signature, wrong side/asset/chain, expired quote, overpaying `depositTokenAmount`, `minimumReceiveAmount = 0`, extra call, delegatecall mode, wrong delegate, chainId 0, trailing calldata), and invariants.
8. **Partner kit:** TypeScript snippet (viem) for the §6 flow, ABI, and deployed addresses.
9. **Audit prep and external audit** (`audit-prep-assistant` skill), then a Base mainnet deploy.

## 10. Open questions

1. Which 7702 account implementation and EntryPoint version does the Alchemy setup use (Modular Account v2 / EP v0.7 vs v0.8)? This decides the `callData` decoder and the hash computation.
2. Buy/sell:
   - Can the backend guarantee that 1inch returns the generic `swap` method (never `unoswap*`), e.g. through 1inch API parameters or by retrying?
   - Is it router v6 on every chain?
   - Direct Ondo: confirm against the deployed `GMTokenManager` (Ethereum / BNB) that:
     - output goes to `msg.sender`,
     - redeem needs a GM-token approve (or burns without one),
     - the view names are exactly `getDomainSeparator()`, `QUOTE_TYPEHASH` and `ATTESTATION_SIGNER_ROLE`,
     - the signature is plain ECDSA, not ERC-1271.
   - Which chains will use direct Ondo and which will use 1inch?
   - What values should `maxOverpayBps` and `maxQuoteTtl` start with?
3. Is the platform fee always paid in the base asset, and what should the max fee cap be?
4. Chains beyond Base: one deployment per chain, and are the allowlists per chain?
5. Who holds `MANAGER` and `GUARDIAN`, and what are the Safe thresholds?
6. Revoke approval on unstake: must it come at a fixed position (e.g. the last call), or can it appear anywhere in the batch? The draft allows any position. Should SELL (Ondo) also require revoking the spender's approval?
7. Should `verify` also enforce a batch deadline (e.g. `validUntil` in the paymaster data) to match the 300 s intent TTL?
