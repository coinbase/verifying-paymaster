# Attack Vector Mitigations

This document outlines key attack vectors and their mitigations for our 4337 verifying paymaster implementation.

## 1. Siphoning Funds from Developer's Paymaster

### Attack Vector
Malicious actors could find a paymaster that sponsors UserOps and submit UserOps through their own EOA bundler with higher preVerificationGas(PVG) and tip, effectively siphoning funds from the developer's paymaster.

Since Coinbase provides free credits on Coinbase Developer Platform (CDP) as well, this would give malicious users a way to extract value from the paymaster. 

### Mitigation
We've implemented a flag (`allowAnyBundler`) in the `PaymasterData` struct to optionally restrict UserOps to only allowlisted bundlers. When this flag is set to false, the `_postOp` function checks if the bundler (`tx.origin`) is in the allowlist. If not, it reverts with a `BundlerNotAllowed` error. This ensures that only trusted bundlers can submit UserOps to our paymaster when the restriction is enabled.

On Coinbase's paymaster, Coinbase Developer Platform and other major providers bundler addresses are allowlisted.

## 2. ERC20 Asset Changes Result in Sender Unable to Pay

### Attack Vector
Since we want to also allow approval to be batched in the same userOp and not require a separate transaction to approve a paymaster and the validation phase is run for all userOps prior to execution phase, there is risk that the paymaster could say it will pay for something and have the userOp unable to pay. 

Example

- Offchain signer simulates and sees token balance transfer sucessful. During block execution there is a previous transaction that removes the balance from the sender. 
- Offchain signer simulates and sees token balance transfer sucessful. During bundle execution there is a previous transaction that removes the balance from the sender. 

### Mitigation
Our implementation provides flexible options to mitigate this risk:

1. **Balance Precheck**: The `precheckBalance` flag in `PaymasterData` allows for checking the sender's token balance during the validation phase, without requiring a transfer.

2. **Prepayment Option**: The `prepaymentRequired` flag enables requiring token payment upfront during the validation phase. If set, the paymaster transfers the maximum possible token cost to itself and refunds any excess in the `_postOp` function.

It is up to the offchain signer to simulate the userOp including postOp phase and:
- Always use prepaymentRequired for senders once they have approved the paymaster for the token.
- Only use precheckBalance if sender is including an approval but has token balance.
- Only use neither if they are using auxilary funds such as Coinbase Magic Spend.
- Monitor for abuse from sybil attacks to grief the paymaster. 
