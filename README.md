# VerifyingPaymaster

## Overview

VerifyingPaymaster is an ERC4337-compatible paymaster contract that accepts a signature for validation and can perform optional prechecks and ERC20 token transfers. It supports the option to restrict sponsorship to certain bundlers. 

This paymaster implementation is designed to work with EntryPoint v0.6 and provides flexibility in handling user operations, including sponsorship and token-based fee payments.

This contract is used as the Coinbase Developer Platform Paymaster for standard sponsorships.

## Features

- Signature-based validation of user operations
- Optional balance precheck for ERC20 tokens
- Optional prepayment in validation phase
- Support for sponsoring user operations with or without token transfers
- Configurable bundler restrictions 
- Owner-controlled management of bundler allowlist and verifying signer

View more information in the docs(./docs/README.md)

## ERC-4337 Overview

ERC-4337 is a standard for account abstraction in Ethereum. It introduces new concepts like EntryPoint contracts, Paymasters, and Bundlers to enable a more flexible and user-friendly transaction experience.

For more information on ERC-4337, please refer to the [official EIP](https://eips.ethereum.org/EIPS/eip-4337).

## Deployments

Contract addresses for VerifyingPaymaster:

- Base: ```0x2FAEB0760D4230Ef2aC21496Bb4F0b47D634FD4c```
- Base Sepolia: ```0x709a4bae3db73a8e717aefca13e88512f738b27f```

## Development

This project uses [Forge](https://github.com/foundry-rs/forge), a fast and flexible Ethereum testing framework.

After cloning the repo, installing deps and building the contracts you can run the tests.
```forge install```

```forge build```

```forge test```