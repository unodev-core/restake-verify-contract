# Restake Batch Verifier

An on-chain, read-only verifier that lets partners check a Restake-built EIP-7702 batch user operation **before the user signs it**, using an `eth_call` on their own RPC node.

It answers one question:

> *Does this exact user operation do only what the user asked for, touch only allowlisted contracts, and is this the hash I am about to sign?*

> **Status:** design stage. The full specification is in [docs/restake-batch-verifier.md](docs/restake-batch-verifier.md). Contracts, tests and deploy scripts are not written yet (see [Roadmap](#roadmap)).

---

## Why

The Restake API builds unsigned ERC-4337 batches (EntryPoint v0.7, Alchemy Modular Account v2 as the 7702 delegate) for staking, unstaking, tokenized-stock trades and bridging. Today a partner wallet has to trust whatever the API returns. A compromised API could return a batch that:

- grants an infinite approval to an attacker,
- deposits or swaps with an attacker as `receiver`,
- delegates the EOA to a malicious 7702 implementation,
- installs a backdoor module through an account self-call.

The verifier moves that trust from the API to **public, timelocked on-chain code**.

---

## How it works

```
 ┌──────────────┐  1. build intent   ┌──────────────┐
 │ Partner app  │ ─────────────────▶ │ Restake API  │
 │ (wallet, UI) │ ◀───────────────── │  (untrusted) │
 └──────┬───────┘  op, userOpHash,   └──────▲───────┘
        │          authorization            │
        │                                   │ 5. signed op
        │ 2. eth_call verify(op, hash,      │
        │    auth, intentFromUI)            │
        ▼                                   │
 ┌──────────────────────┐                   │
 │ Partner's own RPC    │                   │
 │  └▶ BatchVerifier    │                   │
 └──────┬───────────────┘                   │
        │ 3. verifiedHash, deadline         │
        │    (or a precise revert reason)   │
        ▼                                   │
 ┌──────────────────────┐  4. sign verifiedHash + 7702 auth
 │ User signs           │ ──────────────────┘
 └──────────────────────┘
                           Restake backend ─▶ Alchemy bundler ─▶ EntryPoint v0.7
```

1. The partner receives `{ op, userOpHash, authorization, intentId }` from the Restake API.
2. It calls `verify(...)` on **its own node**, passing the intent the user actually saw in the UI.
3. The verifier returns `verifiedHash` and the batch `deadline`, or reverts with a custom error.
4. The user signs **`verifiedHash`**, never the hash from the API response, plus the 7702 authorization. The signature is `personal_sign` over the raw 32 bytes (EIP-191 once), sent as `0xff00 ‖ sig`. The partner also checks `auth.nonce == eth_getTransactionCount(user)` off-chain.
5. The signatures go to the Restake backend, which submits the op.

### Public interface

```solidity
function verify(PackedUserOperation calldata op, bytes32 userOpHash,
                Authorization calldata auth, Intent calldata intent)
    external view returns (bytes32 verifiedHash, uint256 deadline);   // reverts with a custom error

function check(/* same args */)
    external view returns (bool ok, uint8 errorCode, uint256 callIndex); // non-reverting, for UIs
```

`Intent` carries `action` (STAKE, UNSTAKE, BUY, SELL, BRIDGE), `user`, `target`, `payToken`, `amount`, `minOut`, `maxFee`, and for bridges `dstChainId` and `recipient`.

---

## Architecture

```
                  partners: eth_call
                         │
        ┌────────────────▼────────────────┐   reads   ┌─────────────────────────────┐
        │ BatchVerifier  (ERC-1967 proxy) │ ────────▶ │ AllowlistRegistry  (proxy)  │
        │  stateless view logic, UUPS     │           │  enumerable sets, pending   │
        │  decoder libraries per action   │           │  ops, config (ERC-7201)     │
        └────────────────┬────────────────┘           └──────────────┬──────────────┘
                         │ upgrade (48 h)                            │ upgrade (48 h)
                         └───────── TimelockController ◀─────────────┘
                                    (48 h, Safe multisig proposer)

        DeadlineGuard: immutable, admin-less; called as call 0 inside every signed batch
```

| Component | Role |
|-----------|------|
| **BatchVerifier** | Pure logic, no mutable state except the registry pointer. Stable proxy address that partners hard-code. EntryPoint v0.7 and the MAv2 7702 delegate are pinned as constants. Decoders are internal libraries: `AccountCallDecoder`, `AllowanceRules`, `FeeRules`, `Erc4626Rules`, `AaveRules`, `OneInchRules`, `BridgeRules` → `AcrossRules`. |
| **AllowlistRegistry** | Per-chain storage of allowlisted addresses by category (paymasters, vaults, Aave pools, assets, Ondo tokens, swap routers, swap pools, bridges, fee recipients), plus bridge configs, bridge routes and fee/TTL caps. Every table can be listed on-chain. |
| **DeadlineGuard** | `requireBefore(deadline)`. Binds an expiry into the signed batch itself. Never upgradeable, because it is a call target inside user batches. |
| **TimelockController** | Sole upgrader of both proxies, `minDelay = 48 h`. |

**One deployment per chain**, each with its own registry. Base and BSC first; Ethereum, Arbitrum, Optimism, Polygon, Avalanche and Plasma follow with staking rows only.

---

## Verification pipeline

The rule is **default deny**: every call in the batch must match a rule, and anything else fails.

```
 op + auth + intent
        │
        ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 1. Envelope                                                         │
 │    userOpHash == v0.7 hash(op) · delegate == MAv2 · chainId ≠ 0     │
 │    sender == user · initCode empty · paymaster allowlisted or caps  │
 │    callData is executeBatch only · no self-calls · value 0          │
 └──────────────────────────────┬──────────────────────────────────────┘
                                ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 2. Deadline: call 0 is DeadlineGuard.requireBefore(d),              │
 │    now < d ≤ now + maxBatchTtl (600 s)                              │
 └──────────────────────────────┬──────────────────────────────────────┘
                                ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 3. Action rules (intent-bound): STAKE · UNSTAKE · BUY/SELL · BRIDGE │
 └──────────────────────────────┬──────────────────────────────────────┘
                                ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 4. Shared rules: exact approvals · zero residual allowance ·        │
 │    single fee call, last, ≤ intent.maxFee and ≤ backstop cap        │
 └──────────────────────────────┬──────────────────────────────────────┘
                                ▼
                     verifiedHash, deadline
```

### Accepted batch shape

```
 [0] DeadlineGuard.requireBefore(d)       required
 [1] token.approve(spender, 0)            optional, USDT-style reset
 [2] token.approve(spender, amount)       optional, exact amount only
 [3] main call                            deposit / supply / redeem / withdraw / 1inch swap / Across deposit
 [4] token.approve(spender, 0)            revoke; required if an allowance would otherwise remain
 [5] USDC.transfer(feeRecipient, fee)     optional, always last
```

### Supported actions (v1)

| Action | Main call | Key checks |
|--------|-----------|------------|
| **STAKE** | ERC-4626 `deposit` / Aave v3 `supply` | vault or pool allowlisted, asset read live, `receiver` / `onBehalfOf == user` |
| **UNSTAKE** | ERC-4626 `redeem` / `withdraw`, Aave `withdraw` | `receiver == owner == user`, no share approvals |
| **BUY / SELL** | 1inch v6 `swap` or `unoswap*` (BSC, Ondo stocks) | tokens match the intent, `dstReceiver == user`, `minReturn ≥ intent.minOut`, no partial fill; for `unoswap` every hop goes through an allowlisted pool and the output token is derived from live `token0`/`token1` |
| **BRIDGE** | Across SpokePool `deposit` (USDC Base ↔ BSC) | allowlisted route pins the destination token, `recipient == refundTo == user`, `outputAmount ≥ minOut` (decimals-aware), bounded fill deadline and quote age, no destination message, exact integrator suffix |

Swap and bridge rules are provider-agnostic: a new provider is a new decoder library plus a `RouterType` / `BridgeType` value and registry rows. Direct Ondo minting is designed but deferred to v2.

---

## Security features

| Feature | Protects against |
|---------|------------------|
| 7702 delegate pinned to MAv2 (new and existing delegation) | Account takeover through a malicious implementation. This is the most important check, because the v0.7 `userOpHash` does not commit to the delegate. |
| `chainId ≠ 0` and `== block.chainid` | Cross-chain replay of the authorization |
| Local v0.7 `userOpHash` recomputation | Signing a hash that doesn't match the verified op |
| Entry-point allowlist on `callData`, `SelfCallForbidden()` | Module installs, `upgradeToAndCall`, `performCreate`, delegatecall |
| Exact approvals, zero-residual allowance | Infinite or leftover approvals; also cleans legacy infinite allowances |
| Receiver / owner / recipient / refund `== user` | Funds redirected to an attacker |
| `minOut` from the partner's own quote | Sandwiching or bad routes via the API |
| Fee cap (`intent.maxFee` + 50 bps + $0.10 backstop) | Fee inflation |
| In-batch `DeadlineGuard` | A signed op being held and executed much later |
| Strict decoding: exact selectors and calldata length, no dynamic dispatch | Trailing-data and selector-confusion tricks |
| Live reads only from allowlisted contracts | Malicious contracts lying through view calls |
| Paymaster allowlist or gas caps | Gas griefing on the user's native balance |

### Governance

| Operation | Delay | Who |
|-----------|-------|-----|
| Add address, bridge config/route, change config value | **48 h** | `MANAGER` schedules, anyone executes |
| Upgrade verifier or registry | **48 h** | `TimelockController` (Safe proposer) |
| Remove address or route, cancel pending add | instant | `GUARDIAN` or `MANAGER` |
| `pause()` (all verifications fail) | instant | `GUARDIAN` |

Anything that loosens the rules waits 48 h and emits `AdditionScheduled`, so partners can watch and object. Anything that tightens them is instant. Partners should subscribe to `AdditionScheduled`, `Upgraded` and `CallScheduled`.

---

## Benefits

- **Partners no longer trust the API.** They trust public code they call on their own node.
- **48 h public reaction window.** Even a compromised Restake admin can't add a malicious target or change logic without notice.
- **Intent binding.** The check is against what the user saw, not against what the API claims.
- **Fail closed.** Unknown selectors, routes, pools, tokens or ABI changes all revert.
- **Precise errors.** Custom errors and the `check` variant (with the failing `callIndex`) make integration and UI messaging simple.
- **Extensible.** New vaults, pools and routes are registry rows. New swap or bridge providers are one decoder each.
- **Zero cost at runtime.** Verification is a free `eth_call` and doesn't add gas to the user's op, apart from the tiny deadline call.

---

## Trust assumptions and limitations

- **Verifier bugs are the main risk**, hence strict decoders, fuzzing, invariants and an external audit.
- **1inch executor route is opaque.** Safety rests on exact approve, `dstReceiver == user`, `minReturn`, and allowlisted pools. Partners should also simulate balance changes (`eth_simulateV1` / `debug_traceCall`).
- **Bridge fill happens off this chain.** We rely on Across' fill-or-refund guarantee. The worst case after verification is funds locked until `fillDeadline`, then refunded.
- **Non-USDC pool fees** are bounded only by `intent.maxFee`, so partners must compute it from the published tier table.
- **Token assumptions:** standard ERC-20s only. USDC is upgradeable with a blocklist; Ondo tokens may restrict transfers (a verified op can still revert, safely).
- **Off-chain duties for the partner:** sign `verifiedHash`, check the 7702 nonce, and derive `minOut` / `maxFee` independently of the Restake API.

---

## Roadmap

1. **Discovery:** capture real payloads, pin the MAv2 7702 implementation, the 1inch flag layout and the Across ABI → `test/fixtures/`
2. **Scaffold:** Foundry, OZ Upgradeable v5, CI (build, test, Slither, fmt)
3. **AllowlistRegistry:** sets, timelocked adds, instant removes, pause, UUPS + ERC-7201
4. **BatchVerifier core:** envelope, `DeadlineGuard`, hash recomputation, account call decoder
5. **Rules:** allowance and fee → ERC-4626 → Aave → 1inch → Across
6. **Governance wiring:** Timelock, Safe proposer, guardian, deploy scripts for Base and BSC
7. **Tests:** unit, fork tests on real payloads, fuzzing of malicious mutations, invariants
8. **Partner kit:** viem snippet, fee formula, ABI, addresses
9. **Audit**, then Base and BSC mainnet

## Tooling

Foundry · Solidity `0.8.28` · OpenZeppelin Contracts Upgradeable v5 · `openzeppelin-foundry-upgrades` · Slither · fork tests on Base and BSC against the real EntryPoint v0.7 and Modular Account v2.

## Documentation

- [Implementation plan and full specification](docs/restake-batch-verifier.md)
