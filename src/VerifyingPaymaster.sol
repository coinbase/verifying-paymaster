// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@account-abstraction/core/BasePaymaster.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title Coinbase Developer Platform Paymaster
///
/// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6.
///
/// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters.
contract VerifyingPaymaster is BasePaymaster {
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    /// @notice Context passed to postOp
    struct ContextData {
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        address sender;
        bytes32 userOpHash;
        uint128 sponsorId;
        bool allowAnyBundler;
        address token;
        address receiver;
        uint256 exchangeRate;
    }

    /// @notice Paymaster data from the user operation
    struct PaymasterData {
        uint48 validUntil;
        uint48 validAfter;
        uint128 sponsorId;
        bool allowAnyBundler;
        bool preCheckBalance;
        bool preCheckAllowance;
        address token;
        address receiver;
        uint256 exchangeRate;
    }

    uint256 public constant POST_OP_GAS_OVERHEAD = 24_000;

    /// @notice The address to verify the signature against
    address public verifyingSigner;
    address public pendingVerifyingSigner;

    /// @notice Allowlist of bundlers to use if restricting bundlers is enabled
    mapping(address bundler => bool allowed) public bundlerAllowed;

    /// @notice Event for a sponsored user operation without a token payment (could be an unsuccessful transfer)
    event UserOperationSponsored(bytes32 indexed userOperationHash, uint128 indexed sponsorId, address token);

    /// @notice Event for a sponsored user operation with a token payment
    event UserOperationSponsoredWithERC20(
        bytes32 indexed userOperationHash, uint128 indexed sponsorId, address indexed token, address receiver, uint256 amount
    );

    /// @notice Event for setting a pending verifying signer
    event PendingVerifyingSignerSet(address signer);

    /// @notice Event for rotating the verifying signer
    event VerifyingSignerRotated(address oldSigner, address newSigner);

    /// @notice Error for invalid parameters
    error InvalidParam(string errorMessage);

    /// @notice Error for not holding enough balance during prevalidation
    ///
    /// @param token - token address
    /// @param balance - balance of the sender in the specified token
    /// @param maxTokenCost - maximum token cost
    error SenderTokenBalanceTooLow(address token, uint256 balance, uint256 maxTokenCost);

    /// @notice Error for not having the paymaster approved during prevalidation
    ///
    /// @param token - token address
    /// @param approval - amount approved for the paymaster to withdraw
    /// @param maxTokenCost - maximum token cost
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
    /// @param _entryPoint - the entrypoint contract
    /// @param _verifyingSigner - the address to verify the signature against
    constructor(
        IEntryPoint _entryPoint,
        address _verifyingSigner,
        address _initialOwner
    )
        BasePaymaster(_entryPoint)
        Ownable()
    {
        if (address(_entryPoint).code.length == 0) {
            revert InvalidParam("entryPoint is not a contract");
        }

        if (_verifyingSigner == _initialOwner) {
            revert InvalidParam("verifyingSigner cannot be the owner");
        }

        _transferOwnership(_initialOwner);
        verifyingSigner = _verifyingSigner;
    }

    /// @notice Get the hash of the UserOperation and relavant paymaster data
    //
    /// @param userOp - UserOperation struct
    /// @param paymasterData - PaymasterData struct
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

        if (!_validateSignature(userOp, paymasterData, signature)) {
            return ("", _packValidationData(true, paymasterData.validUntil, paymasterData.validAfter));
        }

        if (paymasterData.token != address(0) && (paymasterData.preCheckBalance || paymasterData.preCheckAllowance)) {
            _performPrechecks(userOp, paymasterData, maxCost);
        }

        return (
            _packContextData(userOp, userOpHash, paymasterData),
            _packValidationData(false, paymasterData.validUntil, paymasterData.validAfter)
        );
    }

    /// @notice validate signature on userOp paymasterAndData
    function _validateSignature(
        UserOperation calldata userOp,
        PaymasterData memory paymasterData,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, paymasterData));
        return verifyingSigner == ECDSA.recover(hash, signature);
    }

    /// @notice perfrom balance and/or allowance checks
    function _performPrechecks(
        UserOperation calldata userOp,
        PaymasterData memory paymasterData,
        uint256 maxCost
    )
        internal
        view
    {
        uint256 maxTokenCost = _calculateTokenCost(maxCost, paymasterData.exchangeRate);
        if (paymasterData.preCheckBalance) {
            uint256 balance = IERC20(paymasterData.token).balanceOf(userOp.sender);
            if (balance < maxTokenCost) {
                revert SenderTokenBalanceTooLow(paymasterData.token, balance, maxTokenCost);
            }
        }

        if (paymasterData.preCheckAllowance) {
            uint256 allowance = IERC20(paymasterData.token).allowance(userOp.sender, address(this));
            if (allowance < maxTokenCost) {
                revert SenderTokenApprovalTooLow(paymasterData.token, allowance, maxTokenCost);
            }
        }
    }

    /// @notice Pack the context data for postOp
    function _packContextData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        PaymasterData memory paymasterData
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.sender,
            userOpHash,
            paymasterData.sponsorId,
            paymasterData.allowAnyBundler,
            paymasterData.token,
            paymasterData.receiver,
            paymasterData.exchangeRate
        );
    }

    /// @notice Unpack the paymasterAndData field
    ///
    /// @param paymasterAndData - paymasterAndData field from userOp
    function _parsePaymasterAndData(bytes calldata paymasterAndData)
        internal
        pure
        returns (PaymasterData memory paymasterData, bytes calldata signature)
    {
        paymasterData.validUntil = uint48(bytes6(paymasterAndData[20:26]));
        paymasterData.validAfter = uint48(bytes6(paymasterAndData[26:32]));
        paymasterData.sponsorId = uint128(bytes16(paymasterAndData[32:48]));
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
        ContextData memory c = abi.decode(context, (ContextData));

        if (!c.allowAnyBundler && !bundlerAllowed[tx.origin]) {
            revert BundlerNotAllowed();
        }

        if (c.token != address(0) && mode != PostOpMode.postOpReverted) {
            uint256 gasPrice = _min(c.maxFeePerGas, c.maxPriorityFeePerGas + block.basefee);
            uint256 actualTokenCost = _calculateTokenCost((actualGasCost + (POST_OP_GAS_OVERHEAD * gasPrice)), c.exchangeRate);
            IERC20(c.token).safeTransferFrom(c.sender, c.receiver, actualTokenCost);
            emit UserOperationSponsoredWithERC20(c.userOpHash, c.sponsorId, c.token, c.receiver, actualTokenCost);
        } else {
            emit UserOperationSponsored(c.userOpHash, c.sponsorId, c.token);
        }
    }

    /// @notice Renouce is disabled for this contract
    ///
    /// @dev Reverts if called.
    function renounceOwnership() public view override onlyOwner {
        revert FunctionDisabled();
    }

    /// @notice Transfer ownership over address
    ///
    /// @param newOwner - new owner address
    function transferOwnership(address newOwner) public override onlyOwner {
        if (newOwner == address(0)) {
            revert InvalidParam("newOwner cannot be address(0)");
        }

        if (newOwner == verifyingSigner) {
            revert InvalidParam("newOwner cannot be the verifyingSigner");
        }
        _transferOwnership(newOwner);
    }

    /// @notice Add a bundler to the allowlist
    ///
    /// @param bundler - bundler address
    function addBundler(address bundler) public onlyOwner {
        bundlerAllowed[bundler] = true;
    }

    /// @notice Remove a bundler from the allowlist
    ///
    /// @param bundler - bundler address
    function removeBundler(address bundler) public onlyOwner {
        bundlerAllowed[bundler] = false;
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
    /// @param gasCost - gas cost
    /// @param tokenExchangeRate - exchange rate of token (Price of Eth in token * Token Decimals)
    function _calculateTokenCost(uint256 gasCost, uint256 tokenExchangeRate) internal pure returns (uint256) {
        return (gasCost * tokenExchangeRate) / 1e18;
    }

    /// @notice Simple min function
    ///
    /// @param a - uint a
    /// @param b - uint b
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /// @notice Withdraws ERC20 from this contract - this is to handle any ERC20 that was sent to this contract by mistake
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
