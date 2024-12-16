// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BasePaymaster} from "@account-abstraction/core/BasePaymaster.sol";
import {_packValidationData, calldataKeccak} from "@account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "@account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {FixedPointMathLib} from "@solady/utils/FixedPointMathLib.sol";
import {ERC20} from "@solady/tokens/ERC20.sol";
import {SafeTransferLib} from "@solady/utils/SafeTransferLib.sol";

/// @title VerifyingPaymaster
///
/// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.7.
///
/// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters.
///
/// @author Coinbase
contract VerifyingPaymaster is BasePaymaster, Ownable2Step {
    using UserOperationLib for PackedUserOperation;

    /// @notice Paymaster data from the user operation
    struct PaymasterData {
        /// @dev Signature is valid until
        uint48 validUntil;
        /// @dev Signature is valid after
        uint48 validAfter;
        /// @dev Sponsor uuid for offchain tracking
        uint128 sponsorUUID;
        /// @dev Flag to reject userOp in validation if submitted by unallowlisted bundler
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
        /// @dev Post op gas if using token
        uint48 postOpGas;
    }

    /// @notice Context passed to postOp
    struct PostOpContextData {
        /// @dev UserOp's sender
        address sender;
        /// @dev Hash of the userOp
        bytes32 userOpHash;
        /// @dev Sponsor uuid for offchain tracking
        uint128 sponsorUUID;
        /// @dev Prepaid token amount during validation
        uint256 prepaidAmount;
        /// @dev Overhead fee for postOp
        uint256 postOpGas;
        /// @dev Token to use for payment or address(0) if no token required
        address token;
        /// @dev Token payment sent to this address
        address receiver;
        /// @dev Exchange rate for the token
        uint256 exchangeRate;
        /// @dev Execution gas limit
        uint256 executionGasLimit;
        /// @dev PreOp gas approximation
        uint256 preOpGasApproximation;
    }

    /// @notice The address to verify the signature against
    address public verifyingSigner;

    /// @notice Pending verifyingSigner for a two-step rotation of the verifying signer
    address public pendingVerifyingSigner;

    /// @notice Allowlist of bundlers to use if restricting bundlers is enabled by flag
    mapping(address bundler => bool allowed) public isBundlerAllowed;

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

    /// @notice Error for an invalid signature length
    error InvalidSignatureLength();

    /// @notice Error for not holding enough balance during prevalidation
    ///
    /// @param token Token address
    /// @param balance Balance of the sender in the specified token
    /// @param maxTokenCost Maximum token cost
    error SenderTokenBalanceTooLow(address token, uint256 balance, uint256 maxTokenCost);

    /// @notice Error for bundler not allowed
    ///
    /// @param bundler address of the bundler that was not allowlisted
    error BundlerNotAllowed(address bundler);

    /// @notice Error for calling renounceOwnership which has been disabled
    error RenouceOwnershipDisabled();

    /// @notice Error for deposit failure
    error DespositFailed();

    /// @notice Error for not having set verifying signer for rotation
    error NoPendingSigner();

    /// @notice Error for postOpGas limit exceeded
    error PostOpGasLimitExceeded();

    /// @notice Constructor for the paymaster setting the entrypoint, verifyingSigner and owner
    ///
    /// @param entryPoint the entrypoint contract
    /// @param initialVerifyingSigner the address to verify the signature against
    constructor(IEntryPoint entryPoint, address initialVerifyingSigner, address initialOwner)
        BasePaymaster(entryPoint)
        Ownable2Step()
    {
        _transferOwnership(initialOwner);
        verifyingSigner = initialVerifyingSigner;
    }

    /// @notice Receive Eth and deposit it into the entrypoint
    receive() external payable {
        // use address(this).balance rather than msg.value in case of force-send
        (bool callSuccess,) = payable(address(entryPoint)).call{value: address(this).balance}("");
        if (!callSuccess) {
            revert DespositFailed();
        }
    }

    /// @notice Add or remove multiple bundlers to/from the allowlist
    ///
    /// @param bundlers Array of bundler addresses
    /// @param allowed Boolean indicating if bundlers should be allowed or not
    function updateBundlerAllowlist(address[] calldata bundlers, bool allowed) external onlyOwner {
        for (uint256 i = 0; i < bundlers.length; i++) {
            isBundlerAllowed[bundlers[i]] = allowed;
            emit BundlerAllowlistUpdated(bundlers[i], allowed);
        }
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

    /// @notice Withdraws ERC20 from this contract. This is to handle any ERC20 that was sent to this contract by mistake
    ///         and does not have ability to move assets from other addresses.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    ///
    /// @param asset  The asset to withdraw.
    /// @param to     The beneficiary address.
    /// @param amount The amount to withdraw.
    function ownerWithdrawERC20(address asset, address to, uint256 amount) external onlyOwner {
        SafeTransferLib.safeTransfer(asset, to, amount);
    }

    /// @notice Transfer ownership to new owner using Ownable2Step
    ///
    /// @param newOwner newOwnerAddress
    function transferOwnership(address newOwner) public override(Ownable2Step, Ownable) onlyOwner {
        Ownable2Step.transferOwnership(newOwner);
    }

    /// @notice Renouce is disabled for this contract
    ///
    /// @dev Reverts if called.
    function renounceOwnership() public view override onlyOwner {
        revert RenouceOwnershipDisabled();
    }

    /// @notice Get the hash of the UserOperation and relavant paymaster data
    ///
    /// @param userOp UserOperation struct
    /// @param paymasterData PaymasterData struct
    ///
    /// @return bytes32 The hash to check the signature against
    function getHash(PackedUserOperation calldata userOp, PaymasterData memory paymasterData, uint256 paymasterValidationGasLimit, uint256 postOpGasLimit) public view returns (bytes32) {
        // can't use userOp.hash(), since it contains also the paymasterAndData itself.
        return keccak256(
            abi.encode(
                userOp.getSender(),
                userOp.nonce,
                calldataKeccak(userOp.initCode),
                calldataKeccak(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                block.chainid,
                address(this),
                paymasterData,
                paymasterValidationGasLimit,
                postOpGasLimit
            )
        );
    }

    /// @notice Unpack the paymasterAndData field
    ///
    /// @param paymasterAndData PaymasterAndData field from userOp
    ///
    /// @return paymasterData Filled in PaymasterData struct
    /// @return signature Paymaster signature
    function parsePaymasterData(bytes calldata paymasterAndData)
        public
        pure
        returns (PaymasterData memory paymasterData, bytes calldata signature)
    {
        paymasterData.validUntil = uint48(bytes6(paymasterAndData[0:6]));
        paymasterData.validAfter = uint48(bytes6(paymasterAndData[6:12]));
        paymasterData.sponsorUUID = uint128(bytes16(paymasterAndData[12:28]));
        paymasterData.allowAnyBundler = paymasterAndData[28] != 0;
        paymasterData.precheckBalance = paymasterAndData[29] != 0;
        paymasterData.prepaymentRequired = paymasterAndData[30] != 0;
        paymasterData.token = address(bytes20(paymasterAndData[31:51]));
        paymasterData.receiver = address(bytes20(paymasterAndData[51:71]));
        paymasterData.exchangeRate = uint256(bytes32(paymasterAndData[71:103]));
        paymasterData.postOpGas = uint48(bytes6(paymasterAndData[103:109]));
        signature = paymasterAndData[109:];
    }

    /// @inheritdoc BasePaymaster
    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        (PaymasterData memory paymasterData, bytes memory signature) = parsePaymasterData(userOp.paymasterAndData[UserOperationLib.PAYMASTER_DATA_OFFSET:]);

        // Reject if postOpGas is greater than the userOp's postOpGasLimit
        if (paymasterData.postOpGas > userOp.unpackPostOpGasLimit()) {
            revert PostOpGasLimitExceeded();
        }
        
        // Reject if should restrict bundlers and bundler not on allowlist 
        if (!paymasterData.allowAnyBundler && !isBundlerAllowed[tx.origin]) {
            revert BundlerNotAllowed(tx.origin);
        }

        // Only support 65-byte signatures, to avoid potential replay attacks.
        if (signature.length != 65) {
            revert InvalidSignatureLength();
        }

        // Check signature is correct
        (, uint256 paymasterValidationGasLimit, uint256 postOpGasLimit) = UserOperationLib.unpackPaymasterStaticFields(userOp.paymasterAndData);
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(userOp, paymasterData, paymasterValidationGasLimit, postOpGasLimit));
        address signedBy = ECDSA.recover(hash, signature);
        if (signedBy != verifyingSigner && signedBy != pendingVerifyingSigner) {
            return ("", _packValidationData(true, paymasterData.validUntil, paymasterData.validAfter));
        }

        // Init postOpContext
        PostOpContextData memory postOpContext = PostOpContextData({
            sender: userOp.sender,
            userOpHash: userOpHash,
            sponsorUUID: paymasterData.sponsorUUID,
            prepaidAmount: 0,
            postOpGas: paymasterData.postOpGas,
            token: paymasterData.token,
            receiver: paymasterData.receiver,
            exchangeRate: paymasterData.exchangeRate,
            executionGasLimit: 0,
            preOpGasApproximation: 0
        });

        // Perform additional token logic
        if (paymasterData.token != address(0)) {
             postOpContext.executionGasLimit = userOp.unpackCallGasLimit() + userOp.unpackPostOpGasLimit();
             postOpContext.preOpGasApproximation =
                 userOp.preVerificationGas +
                 userOp.unpackVerificationGasLimit() +
                 paymasterValidationGasLimit;

            if (paymasterData.precheckBalance || paymasterData.prepaymentRequired) {
                uint256 maxTokenCost =
                    _calculateTokenCost(maxCost, paymasterData.exchangeRate);

                // Optionally check if sender has enough token balance if prepayment isnt required
                if (paymasterData.precheckBalance) {
                    uint256 balance = SafeTransferLib.balanceOf(paymasterData.token, userOp.sender);
                    if (balance < maxTokenCost) {
                        revert SenderTokenBalanceTooLow(paymasterData.token, balance, maxTokenCost);
                    }
                }

                // Optionally require prepayment upfront with cost difference to be refunded postOp
                if (paymasterData.prepaymentRequired) {
                    // attempt transfer, safe transfer will revert on failure and fail validation for userOp
                    SafeTransferLib.safeTransferFrom(paymasterData.token, userOp.sender, address(this), maxTokenCost);
                    postOpContext.prepaidAmount = maxTokenCost;
                }
            }
        }

        // All checks have passed, prepare our postOp context data and return successfully
        return (abi.encode(postOpContext), _packValidationData(false, paymasterData.validUntil, paymasterData.validAfter));
    }

    /// @inheritdoc BasePaymaster
    function _postOp(PostOpMode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas) internal override {
        PostOpContextData memory c = abi.decode(context, (PostOpContextData));

        // Attempt token transfer 
        if (c.token != address(0)) {
            uint256 actualGas = actualGasCost / actualUserOpFeePerGas;
            uint256 executionGasUsed;
            if (actualGas + c.postOpGas > c.preOpGasApproximation) {
                executionGasUsed = actualGas + c.postOpGas - c.preOpGasApproximation;
            }
            uint256 expectedPenaltyGas;
            if (c.executionGasLimit > executionGasUsed) {
                expectedPenaltyGas = (c.executionGasLimit - executionGasUsed) * 10 / 100;
            }

            // get current gas price and token cost
            uint256 actualTokenCost = _calculateTokenCost(actualGasCost + (c.postOpGas + expectedPenaltyGas) * actualUserOpFeePerGas, c.exchangeRate);

            // If not prepaid transfer full amount to receiver else refund sender difference and transfer to receiver
            if (c.prepaidAmount == 0) {
                bool success = SafeTransferLib.trySafeTransferFrom(c.token, c.sender, c.receiver, actualTokenCost);
                if (success) {
                    emit UserOperationSponsoredWithERC20(c.userOpHash, c.sponsorUUID, c.token, c.receiver, actualTokenCost);
                } else {
                    emit UserOperationSponsored(c.userOpHash, c.sponsorUUID, c.token);
                }
            } else {
                // Is prepaid attempt to refund difference   
                uint256 refund = c.prepaidAmount - actualTokenCost;
                bool success = true;
                if (refund != 0) {
                    success = success && _trySafeTransfer(c.token, c.sender, refund);
                }

                // Attempt to pay receiver
                if (success) {
                     success = success && _trySafeTransfer(c.token, c.receiver, actualTokenCost);
                }

                if (success) {
                    emit UserOperationSponsoredWithERC20(c.userOpHash, c.sponsorUUID, c.token, c.receiver, actualTokenCost);
                } else {
                   emit UserOperationSponsored(c.userOpHash, c.sponsorUUID, c.token);
                }
            }
        } else {
            emit UserOperationSponsored(c.userOpHash, c.sponsorUUID, c.token);
        }
    }

    /// @notice Transfer ownership to new owner using Ownable2Step
    ///
    /// @param newOwner newOwnerAddress
    function _transferOwnership(address newOwner) internal override(Ownable2Step, Ownable) {
        Ownable2Step._transferOwnership(newOwner);
    }

    /// @notice Calculate the token cost based on the gas cost and exchange rate
    ///
    /// @param gasCost Gas cost in wei
    /// @param tokenExchangeRate Exchange rate of token (Price of Eth in token * Token Decimals)
    ///
    /// @return uint256 Token amount
    function _calculateTokenCost(uint256 gasCost, uint256 tokenExchangeRate) internal pure returns (uint256) {
        // Use mul div up so min amount is 1
        return FixedPointMathLib.mulDivUp(gasCost, tokenExchangeRate, 1e18);
    }

    /// @notice Attempts to transfer `amount` of ERC20 `token` to `to`. 
    ///
    /// @param token token address
    /// @param to to address
    /// @param amount token amount
    ///
    /// @return bool `true` if successful
    function _trySafeTransfer(address token, address to, uint256 amount)
    internal
    returns (bool)
    {
        (bool success, bytes memory returnData) = token.call(
            abi.encodeWithSelector(ERC20.transfer.selector, to, amount)
        );
        return success && (returnData.length == 0 || abi.decode(returnData, (bool)));
    }
}
