# Auxiliary Funds Support

This document explains how our 4337 verifying paymaster implementation supports auxiliary fund sources, such as Coinbase Magic Spend.

## Overview

Our paymaster implementation provides flexibility to accommodate alternative sources of funds that may not be directly visible on-chain. This is achieved through a combination of optional checks and configurable parameters in the `PaymasterData` struct.

## Implementation Details

1. **Optional Balance Precheck**: The `precheckBalance` flag in `PaymasterData` allows for optionally checking the sender's token balance during the validation phase. This can be disabled for cases where the user's funds may not be immediately visible on-chain.

2. **Flexible Prepayment**: The `prepaymentRequired` flag in `PaymasterData` allows for optional upfront token payment during the validation phase. This can be adjusted based on the specific requirements of the auxiliary fund source.

3. **Custom Exchange Rates**: The `exchangeRate` field in `PaymasterData` allows for setting a custom token exchange rate for each UserOp. This flexibility can accommodate different token valuations or special rates provided by auxiliary fund sources.

4. **Token and Receiver Specification**: The `token` and `receiver` fields in `PaymasterData` allow for specifying different tokens and receiving addresses for each UserOp, providing flexibility for various payment scenarios.

## Use Case: Coinbase Magic Spend

Coinbase Magic Spend is an example of an auxiliary fund source where the user's funds are managed by Coinbase and so the balance may not be visible until the execution phase (ie user holds 100$ in USDC they are bringing onchain in this txn but want to pay USDC for gas.)

Our flexible implementation allows the paymaster to:

1. Skip the balance precheck if necessary (`precheckBalance = false`)
2. Defer the prepayment requirement based on the specific use case (`prepaymentRequired = false`)
3. Use a custom exchange rate if needed
4. Specify a particular token and receiver address for the payment

## Security Considerations

While supporting auxiliary fund sources provides greater flexibility, it also introduces potential risks. Implementers should carefully consider:

- Proper verification of the auxiliary fund source (handled off-chain by the verifying signer)
- Implementing additional off-chain checks if necessary
- Monitoring for potential abuse or unexpected behavior
- Carefully managing the allowlist of bundlers when `allowAnyBundler` is set to `false`

## Configuration

The support for auxiliary fund sources is configured through the `PaymasterData` struct in the `paymasterAndData` field of each UserOp:

```solidity
struct PaymasterData {
    uint48 validUntil;
    uint48 validAfter;
    uint128 sponsorUUID;
    bool allowAnyBundler;
    bool precheckBalance;
    bool prepaymentRequired;
    address token;
    address receiver;
    uint256 exchangeRate;
    uint48 postOpGasCost;
}
```
