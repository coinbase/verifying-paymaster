// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@account-abstraction/core/BasePaymaster.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title Coinbase Developer Platform Paymaster
///
/// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6.
///
/// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters.
contract VerifyingPaymaster is BasePaymaster, Ownable2Step {
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    /// @notice Context passed to postOp
    struct PostOpContextData {
        /// @dev MaxFeePerGas from userOp
        uint256 maxFeePerGas;
        /// @dev MaxPriorityFeePerGas from userOp
        uint256 maxPriorityFeePerGas;
        /// @dev UserOp sender
        address sender;
        /// @dev Hash of the userOp
        bytes32 userOpHash;
        /// @dev Sponsor uuid for offchain tracking
        uint128 sponsorUUID;
        /// @dev Flag to abort bundle in postOp if submitted by unallowlisted bundler
        bool allowAnyBundler;
        /// @dev Token to use for payment or address(0) if no token required
        address token;
        /// @dev Token payment sent to this address
        address receiver;
        /// @dev Exchange rate for the token
        uint256 exchangeRate;
    }

    /// @notice Paymaster data from the user operation
    struct PaymasterData {
        /// @dev Signature is valid until
        uint48 validUntil;
        /// @dev Signature is valid after
        uint48 validAfter;
        /// @dev Sponsor uuid for offchain tracking
        uint128 sponsorUUID;
        /// @dev Flag to reject userOp in postOp if submitted by unallowlisted bundler
        bool allowAnyBundler;
        /// @dev Flag to check sender token balance in validation phase
        bool preCheckBalance;
        /// @dev Flag to check if sender has approved this paymaster in validation phase
        bool preCheckAllowance;
        /// @dev Token to use for payment
        address token;
        /// @dev Token payment sent to this address
        address receiver;
        /// @dev Exchange rate for the token
        uint256 exchangeRate;
    }

    /// @notice PostOp gas overhead for token transfer fees
    uint256 public constant POST_OP_GAS_OVERHEAD = 24_000;

    /// @notice The address to verify the signature against
    address public verifyingSigner;

    /// @notice Pending verifyingSigner for a two-step rotation of the verifying signer
    address public pendingVerifyingSigner;

    /// @notice Allowlist of bundlers to use if restricting bundlers is enabled by flag
    mapping(address bundler => bool allowed) public bundlerAllowed;

    /// @notice Event for a sponsored user operation without a token payment (could be an unsuccessful transfer)
    ///
    /// @param userOperationHash Hash of the user operation.
    /// @param sponsorUUID Sponsor UUID for offchain tracking
    /// @param token Token address, will be address(0) for standard sponsorship and a valid token address on failed transfer
    event UserOperationSponsored(bytes32 indexed userOperationHash, uint128 indexed sponsorUUID, address token);

    /// @notice Event for a sponsored user operation with a token payment
    ///
    /// @param userOperationHash Hash of the user operation.
    /// @param sponsorUUID Sponsor UUID for offchain tracking
    /// @param token Token address used for transfer
    /// @param receiver Token receiver address
    /// @param amount Amount of token transferred
    event UserOperationSponsoredWithERC20(
        bytes32 indexed userOperationHash, uint128 indexed sponsorUUID, address indexed token, address receiver, uint256 amount
    );

    /// @notice Event for setting a pending verifying signer
    ///
    /// @param signer Address of the pending signer
    event PendingVerifyingSignerSet(address signer);

    /// @notice Event for rotating the verifying signer
    ///
    /// @param oldSigner Address of the old signer
    /// @param newSigner Address of the new signer
    event VerifyingSignerRotated(address oldSigner, address newSigner);

    /// @notice Event for changing a bundler allowlist configuration
    ///
    /// @param bundler Address of the bundler
    /// @param allowed True if was allowlisted, false if removed from allowlist
    event BundlerAllowlistUpdated(address bundler, bool allowed);

    /// @notice Error for invalid parameters
    ///
    /// @param errorMessage Error message for the param
    error InvalidParam(string errorMessage);

    /// @notice Error for not holding enough balance during prevalidation
    ///
    /// @param token Token address
    /// @param balance Balance of the sender in the specified token
    /// @param maxTokenCost Maximum token cost
    error SenderTokenBalanceTooLow(address token, uint256 balance, uint256 maxTokenCost);

    /// @notice Error for not having the paymaster approved during prevalidation
    ///
    /// @param token Token address
    /// @param approval Amount approved for the paymaster to withdraw
    /// @param maxTokenCost Maximum token cost
    error SenderTokenApprovalTooLow(address token, uint256 approval, uint256 maxTokenCost);

    /// @notice Error for bundler not allowed
    error BundlerNotAllowed();

    /// @notice Error for calling a disabled function
    error FunctionDisabled();

    /// @notice Error for deposit failure
    error DespositFailed();

    /// @notice Error for not having set verifying signer for rotation
    error NoPendingSigner();

    /// @notice Constructor for the paymaster setting the entrypoint, verifyingSigner and owner
    ///
    /// @param entryPoint the entrypoint contract
    /// @param initialVerifyingSigner the address to verify the signature against
    constructor(
        IEntryPoint entryPoint,
        address initialVerifyingSigner,
        address initialOwner
    )
        BasePaymaster(entryPoint)
        Ownable2Step()
    {
        if (address(entryPoint).code.length == 0) {
            revert InvalidParam("entryPoint is not a contract");
        }

        _transferOwnership(initialOwner);
        verifyingSigner = initialVerifyingSigner;
    }

    /// @notice Get the hash of the UserOperation and relavant paymaster data
    ///
    /// @param userOp UserOperation struct
    /// @param paymasterData PaymasterData struct
    ///
    /// @return bytes32 The hash to check the signature against
    function getHash(UserOperation calldata userOp, PaymasterData memory paymasterData) public view returns (bytes32) {
        // can't use userOp.hash(), since it contains also the paymasterAndData itself.
        return keccak256(
            abi.encode(
                userOp.getSender(),
                userOp.nonce,
                calldataKeccak(userOp.initCode),
                calldataKeccak(userOp.callData),
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                block.chainid,
                address(this),
                paymasterData
            )
        );
    }

    /// @inheritdoc BasePaymaster
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    )
        internal
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        (PaymasterData memory paymasterData, bytes memory signature) = _parsePaymasterAndData(userOp.paymasterAndData);

        // Only support 65-byte signatures, to avoid potential replay attacks.
        if (signature.length != 65) {
            revert InvalidParam("invalid signature length in paymasterAndData");
        }

        // Check signature is correct
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, paymasterData));
        address signedBy = ECDSA.recover(hash, signature);
        if(signedBy != verifyingSigner || signedBy != pendingVerifyingSigner) {
            return ("", _packValidationData(true, paymasterData.validUntil, paymasterData.validAfter));
        }

        // Perform any flagged prechecks if token is used
        if (paymasterData.token != address(0) && (paymasterData.preCheckBalance || paymasterData.preCheckAllowance)) {
            uint256 maxTokenCost = _calculateTokenCost(maxCost, paymasterData.exchangeRate);

            // Optionally check if sender has enough token balance. Should be true outside of auxillary funds (ie. Magic spend).
            if (paymasterData.preCheckBalance) {
                uint256 balance = IERC20(paymasterData.token).balanceOf(userOp.sender);
                if (balance < maxTokenCost) {
                    revert SenderTokenBalanceTooLow(paymasterData.token, balance, maxTokenCost);
                }
            }

            // Optionally check if sender has approved paymaster. Should be true to prevent front running unless approval in
            // userOp.
            if (paymasterData.preCheckAllowance) {
                uint256 allowance = IERC20(paymasterData.token).allowance(userOp.sender, address(this));
                if (allowance < maxTokenCost) {
                    revert SenderTokenApprovalTooLow(paymasterData.token, allowance, maxTokenCost);
                }
            }
        }

        // All checks have passed, prepare our postOp context data and return successfully
        return (
            _packPostOpContextData(userOp, userOpHash, paymasterData),
            _packValidationData(false, paymasterData.validUntil, paymasterData.validAfter)
        );
    }

    /// @notice Pack the context data for postOp
    ///
    /// @param userOp The user operation.
    /// @param userOpHash Hash of the user operation
    /// @param paymasterData PaymasterData struct
    ///
    /// @return bytes encoded PostOpContextData struct for use in postOp
    function _packPostOpContextData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        PaymasterData memory paymasterData
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            PostOpContextData({
                maxFeePerGas: userOp.maxFeePerGas,
                maxPriorityFeePerGas: userOp.maxPriorityFeePerGas,
                sender: userOp.sender,
                userOpHash: userOpHash,
                sponsorUUID: paymasterData.sponsorUUID,
                allowAnyBundler: paymasterData.allowAnyBundler,
                token: paymasterData.token,
                receiver: paymasterData.receiver,
                exchangeRate: paymasterData.exchangeRate
            })
        );
    }

    /// @notice Unpack the paymasterAndData field
    ///
    /// @param paymasterAndData PaymasterAndData field from userOp
    ///
    /// @return paymasterData Filled in PaymasterData struct
    /// @return signature Paymaster signature
    function _parsePaymasterAndData(bytes calldata paymasterAndData)
        internal
        pure
        returns (PaymasterData memory paymasterData, bytes calldata signature)
    {
        paymasterData.validUntil = uint48(bytes6(paymasterAndData[20:26]));
        paymasterData.validAfter = uint48(bytes6(paymasterAndData[26:32]));
        paymasterData.sponsorUUID = uint128(bytes16(paymasterAndData[32:48]));
        paymasterData.allowAnyBundler = paymasterAndData[48] > 0;
        paymasterData.preCheckBalance = paymasterAndData[49] > 0;
        paymasterData.preCheckAllowance = paymasterAndData[50] > 0;
        paymasterData.token = address(bytes20(paymasterAndData[51:71]));
        paymasterData.receiver = address(bytes20(paymasterAndData[71:91]));
        paymasterData.exchangeRate = uint256(bytes32(paymasterAndData[91:123]));
        signature = paymasterAndData[123:];
    }

    /// @inheritdoc BasePaymaster
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        PostOpContextData memory c = abi.decode(context, (PostOpContextData));

        // Reject if should restrict bundlers and bundler not on allowlist to prevent siphoning of funds
        if (!c.allowAnyBundler && !bundlerAllowed[tx.origin]) {
            revert BundlerNotAllowed();
        }

        // Attempt transfer if token is set and not mode not postOpReverted
        if (c.token != address(0) && mode != PostOpMode.postOpReverted) {
            // get current gas price and token cost
            uint256 gasPrice = _min(c.maxFeePerGas, c.maxPriorityFeePerGas + block.basefee);
            uint256 actualTokenCost = _calculateTokenCost((actualGasCost + (POST_OP_GAS_OVERHEAD * gasPrice)), c.exchangeRate);

            // attempt transfer, safe transfer will revert on failure and fail userOp
            IERC20(c.token).safeTransferFrom(c.sender, c.receiver, actualTokenCost);
            emit UserOperationSponsoredWithERC20(c.userOpHash, c.sponsorUUID, c.token, c.receiver, actualTokenCost);
        } else {
            emit UserOperationSponsored(c.userOpHash, c.sponsorUUID, c.token);
        }
    }

    /// @notice Renouce is disabled for this contract
    ///
    /// @dev Reverts if called.
    function renounceOwnership() public view override onlyOwner {
        revert FunctionDisabled();
    }

    /// @notice Transfer ownership to new owner using Ownable2Step
    ///
    /// @param newOwner newOwnerAddress
    function transferOwnership(address newOwner) public override(Ownable2Step, Ownable) onlyOwner {
        Ownable2Step.transferOwnership(newOwner);
    }

    /// @notice Transfer ownership to new owner using Ownable2Step
    ///
    /// @param newOwner newOwnerAddress
    function _transferOwnership(address newOwner) internal virtual override(Ownable2Step, Ownable) {
        Ownable2Step._transferOwnership(newOwner);
    }

    /// @notice Add a bundler to the allowlist
    ///
    /// @param bundler Bundler address
    function updateBundlerAllowlist(address bundler, bool allowed) public onlyOwner {
        bundlerAllowed[bundler] = allowed;
        emit BundlerAllowlistUpdated(bundler, allowed);
    }

    /// @notice Add pending verifying signer.
    ///
    /// @param signer Address of new signer to rotate to.
    function setPendingVerifyingSigner(address signer) external onlyOwner {
        pendingVerifyingSigner = signer;
        emit PendingVerifyingSignerSet(signer);
    }

    /// @notice Rotate verifying signer.
    function rotateVerifyingSigner() external onlyOwner {
        if (pendingVerifyingSigner == address(0)) {
            revert NoPendingSigner();
        }
        emit VerifyingSignerRotated(verifyingSigner, pendingVerifyingSigner);
        verifyingSigner = pendingVerifyingSigner;
        pendingVerifyingSigner = address(0);
    }

    /// @notice Calculate the token cost based on the gas cost and exchange rate
    ///
    /// @param gasCost Gas cost in wei
    /// @param tokenExchangeRate Exchange rate of token (Price of Eth in token * Token Decimals)
    ///
    /// @return uint256 Token amount
    function _calculateTokenCost(uint256 gasCost, uint256 tokenExchangeRate) internal pure returns (uint256) {
        return (gasCost * tokenExchangeRate) / 1e18;
    }

    /// @notice Simple min function
    ///
    /// @param a Integer a
    /// @param b Integer b
    ///
    /// @return uint256 Minimum of a and b
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /// @notice Withdraws ERC20 from this contract. This is to handle any ERC20 that was sent to this contract by mistake
    ///         and does not have ability to move assets from other addresses.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    ///
    /// @param asset  The asset to withdraw.
    /// @param to     The beneficiary address.
    /// @param amount The amount to withdraw.
    function ownerWithdrawERC20(address asset, address to, uint256 amount) external onlyOwner {
        IERC20(asset).safeTransfer(to, amount);
    }

    /// @notice Receive Eth and deposit it into the entrypoint
    receive() external payable {
        // use address(this).balance rather than msg.value in case of force-send
        (bool callSuccess,) = payable(address(entryPoint)).call{ value: address(this).balance }("");
        if (!callSuccess) {
            revert DespositFailed();
        }
    }
}
