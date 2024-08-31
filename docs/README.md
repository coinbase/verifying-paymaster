# 4337 Verifying Paymaster

This repository contains a verifying paymaster implementation for EIP-4337 (Account Abstraction). The paymaster is responsible for sponsoring gas fees for user operations (UserOps) under certain conditions.

## Key Features

- Implements `validatePaymasterUserOp` and `postOp` methods as per the EIP-4337 specification
- Supports allowlisting of bundlers to mitigate certain attack vectors
- Handles ERC20 token payments with prechecks to prevent griefing
- Supports auxiliary fund sources (e.g., Coinbase Magic Spend)
- Implements a two-step ownership transfer process
- Allows for verifying signer rotation with a two-step process

## Important Notes

- An off-chain signer is responsible for signing UserOps
- Implementers should carefully consider the security implications and potential attack vectors
- The contract supports both native gas sponsorship and ERC20 token payments
- Bundler allowlisting can be enabled/disabled per UserOp

## Contract Details

- The contract inherits from `BasePaymaster` and `Ownable2Step`
- Uses OpenZeppelin's ECDSA for signature verification
- Supports setting validity periods for signatures
- Implements flexible options for token payments, including balance prechecks and prepayment

## References

- [EIP-4337 Specification](https://eips.ethereum.org/EIPS/eip-4337)
- [validatePaymasterUserOp Method](https://eips.ethereum.org/EIPS/eip-4337#paymaster-1)
- [postOp Method](https://eips.ethereum.org/EIPS/eip-4337#paymaster-1)

## Additional Documentation

- [Attack Vector Mitigations](./docs/attack-vector-mitigations.md)
- [Usage](./docs/usage.md)

## License

GPL-3.0 License
