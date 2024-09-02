// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@account-abstraction/core/BasePaymaster.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title VerifyingPaymaster
///
/// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6.
///
/// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters.
///
/// @author Coinbase
contract VerifyingPaymaster is BasePaymaster, Ownable2Step {
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

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
        bool precheckBalance;
        /// @dev Flag to require token payment in validation phase
        bool prepaymentRequired;
        /// @dev Token to use for payment
        address token;
        /// @dev Token payment sent to this address
        address receiver;
        /// @dev Exchange rate for the token
        uint256 exchangeRate;
        /// @dev Post op gas cost if using token
        uint48 postOpGasCost;
    }

    /// @notice Context passed to postOp
    struct PostOpContextData {
        /// @dev UserOp sender
        address sender;
        /// @dev Hash of the userOp
        bytes32 userOpHash;
        /// @dev Sponsor uuid for offchain tracking
        uint128 sponsorUUID;
        /// @dev Flag to abort bundle in postOp if submitted by unallowlisted bundler
        bool allowAnyBundler;
        /// @dev Prepaid token amount during validation
        uint256 prepaidAmount;
        /// @dev Overhead fee for postOp
        uint256 postOpOverheadFee;
        /// @dev Token to use for payment or address(0) if no token required
        address token;
        /// @dev Token payment sent to this address
        address receiver;
        /// @dev Exchange rate for the token
        uint256 exchangeRate;
    }

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

    /// @notice Error for invalid entrypoint 
    error InvalidEntryPoint();

    /// @notice Error for an invalid signature length
    error InvalidSignatureLength();

    /// @notice Error for not holding enough balance during prevalidation
    ///
    /// @param token Token address
    /// @param balance Balance of the sender in the specified token
    /// @param maxTokenCost Maximum token cost
    error SenderTokenBalanceTooLow(address token, uint256 balance, uint256 maxTokenCost);

    /// @notice Error for bundler not allowed
    error BundlerNotAllowed();

    /// @notice Error for calling renounceOwnership which has been disabled
    error RenouceOwnershipDisabled();

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
            revert InvalidEntryPoint();
        }

        _transferOwnership(initialOwner);
        verifyingSigner = initialVerifyingSigner;
    }

     /// @notice Receive Eth and deposit it into the entrypoint
    receive() external payable {
        // use address(this).balance rather than msg.value in case of force-send
        (bool callSuccess,) = payable(address(entryPoint)).call{ value: address(this).balance }("");
        if (!callSuccess) {
            revert DespositFailed();
        }
    }

     /// @notice Add a bundler to the allowlist
    ///
    /// @param bundler Bundler address
    function updateBundlerAllowlist(address bundler, bool allowed) external onlyOwner {
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

    /// @notice Renouce is disabled for this contract
    ///
    /// @dev Reverts if called.
    function renounceOwnership() public view override onlyOwner {
        revert RenouceOwnershipDisabled();
    }

    /// @notice Transfer ownership to new owner using Ownable2Step
    ///
    /// @param newOwner newOwnerAddress
    function transferOwnership(address newOwner) public override(Ownable2Step, Ownable) onlyOwner {
        Ownable2Step.transferOwnership(newOwner);
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

    /// @inheritdoc BasePaymaster
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    )
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        (PaymasterData memory paymasterData, bytes memory signature) = _parsePaymasterAndData(userOp.paymasterAndData);

        // Only support 65-byte signatures, to avoid potential replay attacks.
        if (signature.length != 65) {
            revert InvalidSignatureLength();
        }

        // Check signature is correct
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, paymasterData));
        address signedBy = ECDSA.recover(hash, signature);
        if (signedBy != verifyingSigner && signedBy != pendingVerifyingSigner) {
            return ("", _packValidationData(true, paymasterData.validUntil, paymasterData.validAfter));
        }

        // Init postOpContext
        PostOpContextData memory postOpContext = PostOpContextData({
            sender: userOp.sender,
            userOpHash: userOpHash,
            sponsorUUID: paymasterData.sponsorUUID,
            allowAnyBundler: paymasterData.allowAnyBundler,
            prepaidAmount: 0,
            postOpOverheadFee: 0,
            token: paymasterData.token,
            receiver: paymasterData.receiver,
            exchangeRate: paymasterData.exchangeRate
        });

        // Perform additional token logic
        if (paymasterData.token != address(0)) {
            uint256 gasPrice = _min(userOp.maxFeePerGas, userOp.maxPriorityFeePerGas + block.basefee);
            postOpContext.postOpOverheadFee = (paymasterData.postOpGasCost * gasPrice);
            if (paymasterData.precheckBalance || paymasterData.prepaymentRequired) {
                uint256 maxTokenCost =
                    _calculateTokenCost(maxCost + postOpContext.postOpOverheadFee, paymasterData.exchangeRate);

                // Optionally check if sender has enough token balance if prepayment isnt required
                if (paymasterData.precheckBalance) {
                    uint256 balance = IERC20(paymasterData.token).balanceOf(userOp.sender);
                    if (balance < maxTokenCost) {
                        revert SenderTokenBalanceTooLow(paymasterData.token, balance, maxTokenCost);
                    }
                }

                // Optionally require prepayment upfront with cost difference to be refunded postOp
                if (paymasterData.prepaymentRequired) {
                    // attempt transfer, safe transfer will revert on failure and fail validation for userOp
                    IERC20(paymasterData.token).safeTransferFrom(userOp.sender, address(this), maxTokenCost);
                    postOpContext.prepaidAmount = maxTokenCost;
                }
            }
        }

        // All checks have passed, prepare our postOp context data and return successfully
        return (abi.encode(postOpContext), _packValidationData(false, paymasterData.validUntil, paymasterData.validAfter));
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
            uint256 actualTokenCost = _calculateTokenCost(actualGasCost + c.postOpOverheadFee, c.exchangeRate);

            // If not prepaid transfer full amount to receiver else refund sender difference and transfer to receiver
            if (c.prepaidAmount == 0) {
                IERC20(c.token).safeTransferFrom(c.sender, c.receiver, actualTokenCost);
            } else {
                IERC20(c.token).safeTransfer(c.sender, c.prepaidAmount - actualTokenCost);
                IERC20(c.token).safeTransfer(c.receiver, actualTokenCost);
            }

            emit UserOperationSponsoredWithERC20(c.userOpHash, c.sponsorUUID, c.token, c.receiver, actualTokenCost);
        } else {
            emit UserOperationSponsored(c.userOpHash, c.sponsorUUID, c.token);
        }
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
        paymasterData.precheckBalance = paymasterAndData[49] > 0;
        paymasterData.prepaymentRequired = paymasterAndData[50] > 0;
        paymasterData.token = address(bytes20(paymasterAndData[51:71]));
        paymasterData.receiver = address(bytes20(paymasterAndData[71:91]));
        paymasterData.exchangeRate = uint256(bytes32(paymasterAndData[91:123]));
        paymasterData.postOpGasCost = uint48(bytes6(paymasterAndData[123:129]));
        signature = paymasterAndData[129:];
    }

    /// @notice Transfer ownership to new owner using Ownable2Step
    ///
    /// @param newOwner newOwnerAddress
    function _transferOwnership(address newOwner) internal virtual override(Ownable2Step, Ownable) {
        Ownable2Step._transferOwnership(newOwner);
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
}
