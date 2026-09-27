# Fixtures

Real Restake API payloads, captured during Discovery (plan §9) with a funded test wallet. One JSON file per case:

```json
{
  "chainId": 8453,
  "block": 0,
  "action": "STAKE",
  "intent": { "user": "0x…", "target": "0x…", "payToken": "0x…", "amount": "…", "minOut": "0", "maxFee": "…", "dstChainId": "0", "recipient": "0x00…" },
  "op": { "sender": "0x…", "nonce": "…", "initCode": "0x", "callData": "0x34fcd5be…", "accountGasLimits": "0x…", "preVerificationGas": "…", "gasFees": "0x…", "paymasterAndData": "0x…", "signature": "0x" },
  "userOpHash": "0x…",
  "authorization": { "chainId": 8453, "address": "0x69007702764179f14F51cdce752f4f775d74E139", "nonce": 0 }
}
```

Needed: stake + unstake (ERC-4626 and Aave), buy + sell on BSC (1inch `swap` and each `unoswap*` variant seen), bridge
Base → BSC and BSC → Base. Fork tests in `test/fork/` replay them at the recorded block.
